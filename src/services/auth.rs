use crate::auth::{
    fetch_authentik_user_by_pk, fetch_authentik_users_list, generate_random_token, hash_token,
    issue_access_token, refresh_authentik_oidc_profile, verify_authentik_code_and_get_profile,
    verify_backchannel_logout_token, AuthentikApiUser, BackChannelLogoutClaims, OidcRefreshFailure,
    REFRESH_TOKEN_TTL_SEC,
};
use crate::error::{AppError, AppResult, ErrorCode};
use crate::infra::audit::AuditEvent;
use crate::infra::db::{LoginDeviceParams, UserDeviceRow, UserRow};
use crate::infra::redis::RedisStore;
use crate::state::AppState;

const MAX_DEVICE_FIELD_LEN: usize = 128;

pub struct SsoExchangeInput<'a> {
    pub code: &'a str,
    pub code_verifier: &'a str,
    pub redirect_uri: &'a str,
    pub device_id: &'a str,
    pub device_name: &'a str,
}

pub struct AuthSessionTokens {
    pub access_token: String,
    pub expires_in: i64,
    pub device_session_id: String,
    pub raw_refresh_token: String,
}

#[derive(Debug)]
pub enum BackchannelLogoutOutcome {
    Ok,
    BadRequest,
    TooManyRequests,
    InternalError,
}

pub struct AuthentikWebhookInput {
    pub action: String,
    pub model_name: String,
    pub pk: Option<serde_json::Value>,
    pub uid: Option<String>,
    pub is_active: Option<bool>,
    pub changes: Option<serde_json::Value>,
}

async fn revoke_devices_in_redis(
    redis: &RedisStore,
    device_ids: &[String],
    reason: &str,
) -> AppResult<()> {
    let mut first_err: Option<AppError> = None;
    for device_id in device_ids {
        if let Err(err) = redis.revoke_device_jwt(device_id, reason).await {
            tracing::error!(
                device_id,
                reason,
                error = %err.message,
                "failed to revoke device JWT in Redis"
            );
            if first_err.is_none() {
                first_err = Some(err);
            }
        }
    }
    match first_err {
        Some(err) => Err(err),
        None => Ok(()),
    }
}

fn issue_session_tokens(
    jwt_secret: &str,
    user_id: &str,
    device_id: &str,
    role: &str,
    raw_refresh_token: String,
    req_id: &str,
    now: i64,
) -> AppResult<AuthSessionTokens> {
    let (access_token, exp) = issue_access_token(jwt_secret, user_id, device_id, role, now)
        .map_err(|e| e.with_request_id(req_id))?;
    Ok(AuthSessionTokens {
        access_token,
        expires_in: (exp - now).max(0),
        device_session_id: device_id.to_owned(),
        raw_refresh_token,
    })
}

/// Evicts the least-recently-active online devices above `max_devices` for a user.
pub async fn evict_excess_devices_for_user(
    state: &AppState,
    user_id: &str,
    max_devices: i64,
    now: i64,
) -> AppResult<u64> {
    let evicted_ids = state
        .db
        .evict_excess_devices(user_id, max_devices, now)
        .await?;
    let count = evicted_ids.len() as u64;
    revoke_devices_in_redis(&state.redis, &evicted_ids, "kicked").await?;
    Ok(count)
}

async fn login_or_reuse_device(
    state: &AppState,
    params: LoginDeviceParams<'_>,
) -> AppResult<(UserDeviceRow, String)> {
    let raw_refresh = generate_random_token();
    let refresh_hash = hash_token(&raw_refresh);
    let (device, evicted_ids) = state
        .db
        .login_or_reuse_device_and_evict(LoginDeviceParams {
            refresh_hash: &refresh_hash,
            ..params
        })
        .await?;

    revoke_devices_in_redis(&state.redis, &evicted_ids, "kicked").await?;
    Ok((device, raw_refresh))
}

async fn disable_and_revoke_user(state: &AppState, user_id: &str, now: i64) -> AppResult<()> {
    state.db.disable_user_and_logout_devices(user_id).await?;
    state.redis.revoke_user_jwt(user_id, now).await?;
    Ok(())
}

/// Exchanges an Authentik OIDC PKCE authorization code for local access and refresh tokens.
pub async fn sso_exchange(
    state: &AppState,
    ip: &str,
    req_id: &str,
    input: SsoExchangeInput<'_>,
) -> AppResult<AuthSessionTokens> {
    let code = input.code.trim();
    let code_verifier = input.code_verifier.trim();
    let redirect_uri = input.redirect_uri.trim();
    let device_id = input.device_id.trim();
    let raw_device_name = input.device_name.trim();

    if code.is_empty()
        || code_verifier.is_empty()
        || redirect_uri.is_empty()
        || device_id.is_empty()
    {
        return Err(
            AppError::invalid("missing code, codeVerifier, redirectUri, or deviceId")
                .with_request_id(req_id),
        );
    }

    if device_id.len() > MAX_DEVICE_FIELD_LEN || raw_device_name.len() > MAX_DEVICE_FIELD_LEN {
        return Err(AppError::invalid(format!(
            "deviceId and deviceName must be <= {MAX_DEVICE_FIELD_LEN} characters"
        ))
        .with_request_id(req_id));
    }

    let cfg = state.db.get_system_config().await?;
    if !state
        .redis
        .check_rate_limit(
            &format!("sso_exchange:ip:{ip}"),
            cfg.rate_limits.sso_exchange_ip.max,
            cfg.rate_limits.sso_exchange_ip.window_sec,
        )
        .await?
    {
        return Err(
            AppError::new(ErrorCode::RateLimited, "rate limit exceeded").with_request_id(req_id),
        );
    }

    let profile = verify_authentik_code_and_get_profile(state, code, code_verifier, redirect_uri)
        .await
        .map_err(|e| e.with_request_id(req_id))?;

    let now = chrono::Utc::now().timestamp();
    if profile.is_active == Some(false) {
        if let Some(existing) = state.db.find_user_by_subject(&profile.sub).await? {
            let _ = disable_and_revoke_user(state, &existing.id, now).await;
        }
        return Err(AppError::forbidden("account is disabled").with_request_id(req_id));
    }

    let user = state
        .db
        .upsert_user_from_sso(
            &profile.sub,
            &profile.display_name,
            &profile.groups,
            &cfg.admin_groups,
            now,
        )
        .await
        .map_err(|e| e.with_request_id(req_id))?;

    let device_name = if raw_device_name.is_empty() {
        "Unknown Device"
    } else {
        raw_device_name
    };

    let (device, raw_refresh) = login_or_reuse_device(
        state,
        LoginDeviceParams {
            user_id: &user.id,
            device_id,
            device_name,
            sso_sid: profile.sid.as_deref(),
            sso_refresh_token: profile.refresh_token.as_deref(),
            refresh_hash: "",
            ip,
            max_devices: cfg.max_devices_per_user,
            now,
        },
    )
    .await
    .map_err(|e| e.with_request_id(req_id))?;

    issue_session_tokens(
        &state.config.jwt_secret,
        &user.id,
        &device.id,
        &user.role,
        raw_refresh,
        req_id,
        now,
    )
}

async fn revoke_refresh_family(state: &AppState, device_id: &str) -> AppResult<()> {
    let affected = state.db.revoke_device_refresh_family(device_id).await?;
    revoke_devices_in_redis(&state.redis, &affected, "logged_out").await
}

async fn refresh_authentik_session_and_sync(
    state: &AppState,
    device: &UserDeviceRow,
    user: &UserRow,
    sso_refresh_token: &str,
) -> AppResult<(UserRow, Option<String>)> {
    let profile = match refresh_authentik_oidc_profile(state, sso_refresh_token, &user.sso_subject)
        .await
    {
        Ok(p) => p,
        Err(OidcRefreshFailure::ClientRejected(status)) => {
            tracing::info!(
                user_id = %user.id,
                device_session_id = %device.id,
                status = %status,
                "Authentik rejected OIDC refresh_token; revoking local session"
            );
            let _ = state.db.logout_device(&device.id).await;
            let _ = state
                .redis
                .revoke_device_jwt(&device.id, "logged_out")
                .await;
            return Err(AppError::unauthorized(
                "SSO session expired or account disabled",
            ));
        }
        Err(OidcRefreshFailure::Other(err)) => return Err(err),
    };

    let cfg = state.db.get_system_config().await?;
    let effective_active = profile.is_active.unwrap_or(user.status == "active");
    let synced = state
        .db
        .sync_existing_user_from_sso(
            &user.sso_subject,
            &profile.display_name,
            &profile.groups,
            &cfg.admin_groups,
            effective_active,
        )
        .await?
        .unwrap_or_else(|| user.clone());
    if synced.status != "active" {
        return Err(AppError::forbidden("account is disabled"));
    }

    Ok((synced, profile.refresh_token))
}

/// Validates and rotates a refresh token, syncing upstream SSO session state.
pub async fn refresh_session(
    state: &AppState,
    ip: &str,
    req_id: &str,
    raw_refresh: &str,
) -> AppResult<AuthSessionTokens> {
    if !state
        .redis
        .check_rate_limit(&format!("auth:refresh:ip:{ip}"), 30, 60)
        .await?
    {
        return Err(
            AppError::new(ErrorCode::RateLimited, "rate limit exceeded").with_request_id(req_id),
        );
    }

    let now = chrono::Utc::now().timestamp();
    let old_hash = hash_token(raw_refresh);

    let Some(device) = state.db.find_device_by_refresh_hash(&old_hash).await? else {
        if let Some(device_id) = state.redis.lookup_used_refresh_token(&old_hash).await? {
            tracing::warn!(
                device_session_id = %device_id,
                "refresh token reuse detected; revoking refresh family"
            );
            revoke_refresh_family(state, &device_id)
                .await
                .map_err(|e| e.with_request_id(req_id))?;
        }
        return Err(AppError::unauthorized("invalid refresh token").with_request_id(req_id));
    };

    match device.status.as_str() {
        "kicked" => return Err(AppError::new(ErrorCode::DeviceKicked, "device kicked").with_request_id(req_id)),
        "online" => {}
        _ => return Err(AppError::unauthorized("token revoked").with_request_id(req_id)),
    }

    if now.saturating_sub(device.created_at) > REFRESH_TOKEN_TTL_SEC {
        state.db.mark_device_expired(&device.id).await?;
        return Err(AppError::unauthorized("refresh token expired").with_request_id(req_id));
    }

    let user = state
        .db
        .find_user_by_id(&device.user_id)
        .await?
        .ok_or_else(|| AppError::unauthorized("user not found").with_request_id(req_id))?;

    if user.status != "active" {
        return Err(AppError::forbidden("account is disabled").with_request_id(req_id));
    }

    let sso_rt = device
        .sso_refresh_token
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            AppError::unauthorized("missing SSO refresh token; re-authentication required")
                .with_request_id(req_id)
        })?;

    let (user, rotated_sso_rt) = refresh_authentik_session_and_sync(state, &device, &user, sso_rt)
        .await
        .map_err(|e| e.with_request_id(req_id))?;
    let next_sso_refresh_token = rotated_sso_rt.or_else(|| device.sso_refresh_token.clone());

    let new_raw_refresh = generate_random_token();
    let new_hash = hash_token(&new_raw_refresh);

    let rotated = state
        .db
        .rotate_device_refresh_token(
            &device.id,
            &old_hash,
            &new_hash,
            next_sso_refresh_token.as_deref(),
            ip,
            now,
        )
        .await?;

    if !rotated {
        tracing::warn!(
            device_session_id = %device.id,
            "concurrent refresh token reuse detected; revoking refresh family"
        );
        revoke_refresh_family(state, &device.id)
            .await
            .map_err(|e| e.with_request_id(req_id))?;
        return Err(AppError::unauthorized("invalid refresh token").with_request_id(req_id));
    }

    state
        .redis
        .mark_refresh_token_used(&old_hash, &device.id, REFRESH_TOKEN_TTL_SEC as u64)
        .await?;

    issue_session_tokens(
        &state.config.jwt_secret,
        &user.id,
        &device.id,
        &user.role,
        new_raw_refresh,
        req_id,
        now,
    )
}

/// Logs out a single device session in DB and revokes its JWTs in Redis.
pub async fn logout_session(state: &AppState, device_session_id: &str, req_id: &str) -> AppResult<()> {
    state
        .db
        .logout_device(device_session_id)
        .await
        .map_err(|e| e.with_request_id(req_id))?;
    state
        .redis
        .revoke_device_jwt(device_session_id, "logged_out")
        .await?;
    Ok(())
}

async fn apply_backchannel_logout(
    state: &AppState,
    claims: &BackChannelLogoutClaims,
    ip: &str,
    req_id: &str,
    now: i64,
) -> AppResult<()> {
    let user = match claims.sub.as_deref() {
        Some(sub) => state.db.find_user_by_subject(sub).await?,
        None => None,
    };

    let mut target_user_id = user.as_ref().map(|u| u.id.clone());

    if let Some(sid) = claims.sid.as_deref() {
        let devices = state
            .db
            .logout_online_devices_by_sid(target_user_id.as_deref(), sid)
            .await?;
        for dev in devices {
            if target_user_id.is_none() {
                target_user_id = Some(dev.user_id.clone());
            }
            state.redis.revoke_device_jwt(&dev.id, "logged_out").await?;
        }
    } else if let Some(ref user) = user {
        state.db.logout_online_devices_by_user(&user.id).await?;
        state.redis.revoke_user_jwt(&user.id, now).await?;
    }

    if let Some(uid) = target_user_id {
        state.audit.record(AuditEvent {
            actor_type: "system".into(),
            actor_id: "authentik".into(),
            action: "sso_backchannel_logout".into(),
            target_type: "user".into(),
            target_id: uid,
            result: "success".into(),
            detail: serde_json::json!({
                "sub": claims.sub,
                "sid": claims.sid,
                "jti": claims.jti,
            }),
            ip: ip.to_string(),
            request_id: req_id.to_string(),
        });
    }

    Ok(())
}

/// Validates and executes an OIDC Back-Channel Logout token with anti-replay JTI protection.
pub async fn process_backchannel_logout(
    state: &AppState,
    ip: &str,
    req_id: &str,
    raw_logout_token: &str,
) -> BackchannelLogoutOutcome {
    match state
        .redis
        .check_rate_limit(&format!("auth:bcl:ip:{ip}"), 60, 60)
        .await
    {
        Ok(true) => {}
        Ok(false) => return BackchannelLogoutOutcome::TooManyRequests,
        Err(e) => {
            tracing::error!(error = %e.message, "redis error on backchannel logout rate limit");
            return BackchannelLogoutOutcome::InternalError;
        }
    }

    let claims = match verify_backchannel_logout_token(state, raw_logout_token.trim()).await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e.message, "invalid backchannel logout_token");
            return BackchannelLogoutOutcome::BadRequest;
        }
    };

    let now = chrono::Utc::now().timestamp();
    let jti_ttl = (claims.exp - now).clamp(60, 86_400) as u64;

    match state.redis.claim_logout_jti(&claims.jti, jti_ttl).await {
        Ok(true) => {}
        Ok(false) => {
            tracing::warn!(jti = %claims.jti, "replayed backchannel logout_token");
            return BackchannelLogoutOutcome::BadRequest;
        }
        Err(e) => {
            tracing::error!(error = %e.message, "redis error on backchannel logout");
            return BackchannelLogoutOutcome::InternalError;
        }
    }

    if let Err(err) = apply_backchannel_logout(state, &claims, ip, req_id, now).await {
        tracing::error!(error = %err.message, jti = %claims.jti, "failed to apply backchannel logout");
        let _ = state.redis.release_logout_jti(&claims.jti).await;
        return BackchannelLogoutOutcome::InternalError;
    }

    BackchannelLogoutOutcome::Ok
}

async fn sync_api_user_to_local(
    state: &AppState,
    api_user: &AuthentikApiUser,
    admin_groups: &[String],
    now: i64,
) -> AppResult<Option<String>> {
    let updated = state
        .db
        .sync_existing_user_from_sso(
            &api_user.uid,
            api_user.display_name(),
            &api_user.group_names(),
            admin_groups,
            api_user.is_active,
        )
        .await?;

    if let Some(local) = updated {
        if !api_user.is_active {
            disable_and_revoke_user(state, &local.id, now).await?;
        }
        return Ok(Some(local.id));
    }
    Ok(None)
}

/// Processes an Authentik user/group webhook event and returns the count of synced local users.
pub async fn process_authentik_webhook(
    state: &AppState,
    ip: &str,
    req_id: &str,
    payload: AuthentikWebhookInput,
) -> AppResult<usize> {
    let now = chrono::Utc::now().timestamp();
    let cfg = state.db.get_system_config().await?;
    let action = payload.action.trim().to_ascii_lowercase();
    let model = payload.model_name.trim().to_ascii_lowercase();
    let pk_str = payload.pk.as_ref().and_then(|v| match v {
        serde_json::Value::String(s) => Some(s.trim().to_string()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    });

    let mut synced_user_ids: Vec<String> = Vec::new();

    if model == "user" || action == "user_write" || action == "user_offboarded" {
        let disabled_hint = action == "model_deleted"
            || action == "user_offboarded"
            || payload.is_active == Some(false)
            || payload
                .changes
                .as_ref()
                .and_then(|c| c.get("is_active"))
                .and_then(|arr| arr.as_array())
                .and_then(|arr| arr.get(1))
                .and_then(|v| v.as_bool())
                == Some(false);

        let api_user = if action == "model_deleted" {
            None
        } else {
            match pk_str.as_deref().filter(|s| !s.is_empty()) {
                Some(pk) => fetch_authentik_user_by_pk(state, pk).await?,
                None => None,
            }
        };

        if let Some(ref au) = api_user {
            if let Some(uid_local) =
                sync_api_user_to_local(state, au, &cfg.admin_groups, now).await?
            {
                synced_user_ids.push(uid_local);
            }
        } else if disabled_hint {
            if let Some(uid) = payload.uid.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                if let Some(local) = state.db.find_user_by_subject(uid).await? {
                    disable_and_revoke_user(state, &local.id, now).await?;
                    synced_user_ids.push(local.id);
                }
            }
        }
    } else if model == "group" {
        let local_subjects = state.db.list_all_user_subjects().await?;
        if !local_subjects.is_empty() {
            let api_users = fetch_authentik_users_list(state).await?;
            for au in &api_users {
                if !local_subjects.contains(&au.uid) {
                    continue;
                }
                if let Some(uid_local) =
                    sync_api_user_to_local(state, au, &cfg.admin_groups, now).await?
                {
                    synced_user_ids.push(uid_local);
                }
            }
        }
    }

    if !synced_user_ids.is_empty() || model == "user" || model == "group" {
        state.audit.record(AuditEvent {
            actor_type: "system".into(),
            actor_id: "authentik".into(),
            action: "authentik_webhook".into(),
            target_type: if model.is_empty() {
                "sso".into()
            } else {
                model
            },
            target_id: pk_str.unwrap_or_else(|| "unknown".into()),
            result: "success".into(),
            detail: serde_json::json!({
                "action": action,
                "syncedUserIds": synced_user_ids,
            }),
            ip: ip.to_string(),
            request_id: req_id.to_string(),
        });
    }

    Ok(synced_user_ids.len())
}

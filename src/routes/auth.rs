use crate::audit::AuditEvent;
use crate::auth::{
    authenticate_request, fetch_authentik_user_by_pk, fetch_authentik_users_list,
    issue_access_token, login_or_reuse_device, rotate_refresh_token,
    verify_authentik_code_and_get_profile, verify_backchannel_logout_token, AuthentikApiUser,
};
use crate::db::UserDeviceRow;
use crate::error::{AppError, AppResult, ApiEnvelope, ErrorCode};
use crate::routes::{extract_request_id, ClientIp};
use crate::state::AppState;
use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use axum_extra::extract::cookie::{Cookie, SameSite};
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use subtle::ConstantTimeEq;
use time::Duration as CookieDuration;

const REFRESH_COOKIE_NAME: &str = "user_refresh_token";
const MAX_DEVICE_FIELD_LEN: usize = 128;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SsoExchangeRequest {
    pub code: String,
    pub code_verifier: String,
    pub redirect_uri: String,
    pub device_id: String,
    #[serde(default)]
    pub device_name: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthTokenResponse {
    pub access_token: String,
    pub expires_in: i64,
    pub device_session_id: String,
}

fn build_refresh_cookie(token: String, secure: bool, max_age_secs: i64) -> Cookie<'static> {
    Cookie::build((REFRESH_COOKIE_NAME, token))
        .http_only(true)
        .secure(secure)
        .same_site(SameSite::Lax)
        .path("/api/auth")
        .max_age(CookieDuration::seconds(max_age_secs))
        .build()
}

fn attach_no_store(mut resp: Response) -> Response {
    let headers = resp.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    resp
}

pub async fn sso_exchange(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Json(body): Json<SsoExchangeRequest>,
) -> AppResult<Response> {
    let req_id = extract_request_id(&headers);

    let device_id = body.device_id.trim();
    if body.code.trim().is_empty()
        || body.code_verifier.trim().is_empty()
        || body.redirect_uri.trim().is_empty()
        || device_id.is_empty()
    {
        return Err(
            AppError::invalid("missing code, codeVerifier, redirectUri, or deviceId")
                .with_request_id(&req_id),
        );
    }

    let raw_device_name = body.device_name.trim();
    if device_id.len() > MAX_DEVICE_FIELD_LEN || raw_device_name.len() > MAX_DEVICE_FIELD_LEN {
        return Err(AppError::invalid(format!(
            "deviceId and deviceName must be <= {MAX_DEVICE_FIELD_LEN} characters"
        ))
        .with_request_id(&req_id));
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
            AppError::new(ErrorCode::RateLimited, "rate limit exceeded").with_request_id(&req_id)
        );
    }

    let profile = verify_authentik_code_and_get_profile(
        &state,
        body.code.trim(),
        body.code_verifier.trim(),
        body.redirect_uri.trim(),
    )
    .await
    .map_err(|e| e.with_request_id(&req_id))?;

    let cfg = state.db.get_system_config().await?;
    let now = chrono::Utc::now().timestamp();
    if profile.is_active == Some(false) {
        if let Some(existing) = state.db.find_user_by_subject(&profile.sub).await? {
            let _ = revoke_and_disable_local_user(&state, &existing.id, now).await;
        }
        return Err(AppError::forbidden("account is disabled").with_request_id(&req_id));
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
        .map_err(|e| e.with_request_id(&req_id))?;

    let device_name = if raw_device_name.is_empty() {
        "Unknown Device"
    } else {
        raw_device_name
    };

    let (device, raw_refresh) = login_or_reuse_device(
        &state,
        &user.id,
        device_id,
        device_name,
        profile.sid.as_deref(),
        profile.refresh_token.as_deref(),
        &ip,
        cfg.max_devices_per_user,
        now,
    )
    .await
    .map_err(|e| e.with_request_id(&req_id))?;

    let (access_token, exp) =
        issue_access_token(&state.config.jwt_secret, &user.id, &device.id, &user.role, now)
            .map_err(|e| e.with_request_id(&req_id))?;
    let expires_in = (exp - now).max(0);

    let cookie = build_refresh_cookie(raw_refresh, state.config.cookie_secure, 7 * 86_400);
    let jar = CookieJar::new().add(cookie);

    Ok(attach_no_store(
        (
            jar,
            ApiEnvelope::ok(
                AuthTokenResponse {
                    access_token,
                    expires_in,
                    device_session_id: device.id,
                },
                req_id,
            ),
        )
            .into_response(),
    ))
}

pub async fn refresh(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    jar: CookieJar,
) -> AppResult<Response> {
    let req_id = extract_request_id(&headers);

    let raw_refresh = jar
        .get(REFRESH_COOKIE_NAME)
        .map(|c| c.value().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::unauthorized("missing refresh cookie").with_request_id(&req_id))?;

    let now = chrono::Utc::now().timestamp();
    let (user, device, new_refresh) = rotate_refresh_token(&state, &raw_refresh, &ip, now)
        .await
        .map_err(|e| e.with_request_id(&req_id))?;

    let (access_token, exp) =
        issue_access_token(&state.config.jwt_secret, &user.id, &device.id, &user.role, now)
            .map_err(|e| e.with_request_id(&req_id))?;
    let expires_in = (exp - now).max(0);

    let cookie = build_refresh_cookie(new_refresh, state.config.cookie_secure, 7 * 86_400);
    let jar = CookieJar::new().add(cookie);

    Ok(attach_no_store(
        (
            jar,
            ApiEnvelope::ok(
                AuthTokenResponse {
                    access_token,
                    expires_in,
                    device_session_id: device.id,
                },
                req_id,
            ),
        )
            .into_response(),
    ))
}

pub async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Response> {
    let req_id = extract_request_id(&headers);
    let auth = authenticate_request(&state, &headers)
        .await
        .map_err(|e| e.with_request_id(&req_id))?;

    sqlx::query("UPDATE user_devices SET status = 'logged_out' WHERE id = ? AND status = 'online'")
        .bind(&auth.device_session_id)
        .execute(&state.db.pool)
        .await?;

    state
        .redis
        .revoke_device_jwt(&auth.device_session_id, "logged_out")
        .await?;

    let clear_cookie = build_refresh_cookie(String::new(), state.config.cookie_secure, 0);
    let jar = CookieJar::new().add(clear_cookie);

    Ok((
        jar,
        ApiEnvelope::ok(serde_json::json!({ "loggedOut": true }), req_id),
    )
        .into_response())
}

#[derive(Deserialize)]
pub struct BackChannelLogoutForm {
    pub logout_token: String,
}

fn is_ip_allowed(allowed_ips: &[IpAddr], ip: &str) -> bool {
    if allowed_ips.is_empty() {
        return true;
    }
    ip.parse::<IpAddr>()
        .ok()
        .is_some_and(|addr| allowed_ips.contains(&addr))
}

pub async fn backchannel_logout(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    axum::Form(form): axum::Form<BackChannelLogoutForm>,
) -> Response {
    let req_id = extract_request_id(&headers);

    if !is_ip_allowed(&state.config.backchannel_logout_allowed_ips, &ip) {
        return StatusCode::FORBIDDEN.into_response();
    }

    let claims = match verify_backchannel_logout_token(&state, form.logout_token.trim()).await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e.message, "invalid backchannel logout_token");
            return StatusCode::BAD_REQUEST.into_response();
        }
    };

    let now = chrono::Utc::now().timestamp();
    let jti_ttl = (claims.exp - now).clamp(60, 86_400) as u64;

    match state.redis.claim_logout_jti(&claims.jti, jti_ttl).await {
        Ok(true) => {}
        Ok(false) => {
            tracing::warn!(jti = %claims.jti, "replayed backchannel logout_token");
            return StatusCode::BAD_REQUEST.into_response();
        }
        Err(e) => {
            tracing::error!(error = %e.message, "redis error on backchannel logout");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    }

    if let Err(err) = execute_backchannel_logout(&state, &claims, &ip, &req_id, now).await {
        tracing::error!(error = %err.message, jti = %claims.jti, "failed to apply backchannel logout");
        let _ = state.redis.release_logout_jti(&claims.jti).await;
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    attach_no_store(StatusCode::OK.into_response())
}

async fn execute_backchannel_logout(
    state: &AppState,
    claims: &crate::auth::BackChannelLogoutClaims,
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
        let devices: Vec<UserDeviceRow> = match target_user_id.as_deref() {
            Some(uid) => {
                sqlx::query_as(
                    "SELECT * FROM user_devices WHERE user_id = ? AND sso_sid = ? AND status = 'online'",
                )
                .bind(uid)
                .bind(sid)
                .fetch_all(&state.db.pool)
                .await?
            }
            None => {
                sqlx::query_as(
                    "SELECT * FROM user_devices WHERE sso_sid = ? AND status = 'online'",
                )
                .bind(sid)
                .fetch_all(&state.db.pool)
                .await?
            }
        };

        for dev in devices {
            if target_user_id.is_none() {
                target_user_id = Some(dev.user_id.clone());
            }
            sqlx::query("UPDATE user_devices SET status = 'logged_out' WHERE id = ?")
                .bind(&dev.id)
                .execute(&state.db.pool)
                .await?;
            state.redis.revoke_device_jwt(&dev.id, "logged_out").await?;
        }
    } else if let Some(ref user) = user {
        sqlx::query(
            "UPDATE user_devices SET status = 'logged_out' WHERE user_id = ? AND status = 'online'",
        )
        .bind(&user.id)
        .execute(&state.db.pool)
        .await?;
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthentikWebhookPayload {
    #[serde(default)]
    pub action: String,
    #[serde(default, alias = "model_name")]
    pub model_name: String,
    #[serde(default)]
    pub pk: Option<serde_json::Value>,
    #[serde(default)]
    pub uid: Option<String>,
    #[serde(default, alias = "is_active")]
    pub is_active: Option<bool>,
    #[serde(default)]
    pub changes: Option<serde_json::Value>,
}

fn verify_webhook_secret(headers: &HeaderMap, expected: &str) -> bool {
    let candidate = headers
        .get("x-authentik-webhook-secret")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .or_else(|| {
            headers
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.strip_prefix("Bearer "))
                .map(str::trim)
        });
    let Some(got) = candidate else {
        return false;
    };
    got.len() == expected.len() && bool::from(got.as_bytes().ct_eq(expected.as_bytes()))
}

async fn revoke_and_disable_local_user(
    state: &AppState,
    user_id: &str,
    now: i64,
) -> AppResult<()> {
    sqlx::query("UPDATE users SET status = 'disabled' WHERE id = ?")
        .bind(user_id)
        .execute(&state.db.pool)
        .await?;
    sqlx::query(
        "UPDATE user_devices SET status = 'logged_out', sso_refresh_token = NULL
         WHERE user_id = ? AND status = 'online'",
    )
    .bind(user_id)
    .execute(&state.db.pool)
    .await?;
    state.redis.revoke_user_jwt(user_id, now).await?;
    Ok(())
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
            revoke_and_disable_local_user(state, &local.id, now).await?;
        }
        return Ok(Some(local.id));
    }
    Ok(None)
}

pub async fn authentik_webhook(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Json(body): Json<AuthentikWebhookPayload>,
) -> AppResult<Json<ApiEnvelope<serde_json::Value>>> {
    let req_id = extract_request_id(&headers);

    if !verify_webhook_secret(&headers, &state.config.authentik_webhook_secret) {
        return Err(AppError::unauthorized("invalid webhook secret").with_request_id(&req_id));
    }

    if !is_ip_allowed(&state.config.backchannel_logout_allowed_ips, &ip) {
        return Err(AppError::forbidden("webhook IP not allowed").with_request_id(&req_id));
    }

    let now = chrono::Utc::now().timestamp();
    let cfg = state.db.get_system_config().await?;
    let action = body.action.trim().to_ascii_lowercase();
    let model = body.model_name.trim().to_ascii_lowercase();
    let pk_str = body.pk.as_ref().and_then(|v| match v {
        serde_json::Value::String(s) => Some(s.trim().to_string()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    });

    let mut synced_user_ids: Vec<String> = Vec::new();

    if model == "user" || action == "user_write" || action == "user_offboarded" {
        let disabled_hint = action == "model_deleted"
            || action == "user_offboarded"
            || body.is_active == Some(false)
            || body
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
                Some(pk) => fetch_authentik_user_by_pk(&state, pk).await?,
                None => None,
            }
        };

        if let Some(ref au) = api_user {
            if let Some(uid_local) =
                sync_api_user_to_local(&state, au, &cfg.admin_groups, now).await?
            {
                synced_user_ids.push(uid_local);
            }
        } else if disabled_hint {
            if let Some(uid) = body.uid.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                if let Some(local) = state.db.find_user_by_subject(uid).await? {
                    revoke_and_disable_local_user(&state, &local.id, now).await?;
                    synced_user_ids.push(local.id);
                }
            }
        }
    } else if model == "group" {
        let api_users = fetch_authentik_users_list(&state).await?;
        for au in &api_users {
            if let Some(uid_local) =
                sync_api_user_to_local(&state, au, &cfg.admin_groups, now).await?
            {
                synced_user_ids.push(uid_local);
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
                model.clone()
            },
            target_id: pk_str.unwrap_or_else(|| "unknown".into()),
            result: "success".into(),
            detail: serde_json::json!({
                "action": action,
                "syncedUserIds": synced_user_ids,
            }),
            ip,
            request_id: req_id.clone(),
        });
    }

    Ok(ApiEnvelope::ok(
        serde_json::json!({
            "handled": true,
            "syncedUsers": synced_user_ids.len(),
        }),
        req_id,
    ))
}

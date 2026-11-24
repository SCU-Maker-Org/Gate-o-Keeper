//! Authentication primitives: token hashing, JWT access tokens, OIDC code
//! exchange, back-channel logout validation, and refresh-token rotation.

use crate::db::{UserDeviceRow, UserRow};
use crate::error::{AppError, AppResult, ErrorCode};
use crate::redis_store::JwtRevocationStatus;
use crate::state::AppState;
use axum::http::{header, HeaderMap};
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rand::RngCore;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Lifetime of a user access token, in seconds.
pub const ACCESS_TOKEN_TTL_SEC: i64 = 900;
/// Lifetime of a user refresh token, in seconds.
const REFRESH_TOKEN_TTL_SEC: i64 = 7 * 86_400;
/// Minimum interval between `user_devices.last_active_at` writes.
const DEVICE_ACTIVITY_UPDATE_SEC: i64 = 30;
/// Clock skew allowed while validating OIDC tokens.
const OIDC_LEEWAY_SEC: u64 = 30;
/// Cache lifetime for OIDC discovery documents and JWKS keys.
const OIDC_CACHE_TTL: Duration = Duration::from_secs(300);
const BACKCHANNEL_LOGOUT_EVENT: &str = "http://schemas.openid.net/event/backchannel-logout";

#[derive(Clone, Default)]
pub struct OidcCache {
    inner: Arc<RwLock<Option<CachedOidc>>>,
}

#[derive(Clone)]
struct CachedOidc {
    discovery: OidcDiscovery,
    jwks: JwkSet,
    fetched_at: Instant,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct AccessTokenClaims {
    pub sub: String,
    pub jti: String,
    pub device_session_id: String,
    pub role: String,
    pub iat: i64,
    pub exp: i64,
}

#[derive(Clone, Debug)]
pub struct AuthUser {
    pub user: UserRow,
    pub device_session_id: String,
    pub claims: AccessTokenClaims,
}

#[derive(Clone, Debug)]
pub struct OidcUserProfile {
    pub sub: String,
    pub display_name: String,
    pub sid: Option<String>,
    pub groups: Vec<String>,
    pub is_active: Option<bool>,
    pub refresh_token: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackChannelLogoutClaims {
    pub sub: Option<String>,
    pub sid: Option<String>,
    pub jti: String,
    pub exp: i64,
}

#[derive(Clone, Debug, Deserialize)]
struct OidcDiscovery {
    issuer: String,
    token_endpoint: String,
    jwks_uri: String,
    #[serde(default)]
    userinfo_endpoint: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TokenEndpointResponse {
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    id_token: Option<String>,
    #[serde(default)]
    refresh_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct IdTokenClaims {
    sub: String,
    #[serde(default)]
    sid: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    preferred_username: Option<String>,
    #[serde(default)]
    groups: Option<Vec<String>>,
    #[serde(default)]
    is_active: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct UserInfoClaims {
    #[serde(default)]
    sub: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    preferred_username: Option<String>,
    #[serde(default)]
    groups: Option<Vec<String>>,
    #[serde(default)]
    is_active: Option<bool>,
}

/// Returns the lowercase hex-encoded SHA-256 digest of `token`.
pub fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// Signs a short-lived HS256 access token.
///
/// Returns the compact JWT and its `exp` timestamp.
pub fn issue_access_token(
    jwt_secret: &str,
    user_id: &str,
    device_session_id: &str,
    role: &str,
    now: i64,
) -> AppResult<(String, i64)> {
    let exp = now + ACCESS_TOKEN_TTL_SEC;
    let claims = AccessTokenClaims {
        sub: user_id.to_owned(),
        jti: format!("jti_{}", uuid::Uuid::new_v4().simple()),
        device_session_id: device_session_id.to_owned(),
        role: role.to_owned(),
        iat: now,
        exp,
    };

    let token = jsonwebtoken::encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(jwt_secret.as_bytes()),
    )
    .map_err(|err| {
        tracing::error!(error = %err, "failed to sign access token");
        AppError::internal("failed to sign access token")
    })?;

    Ok((token, exp))
}

/// Verifies an HS256 access token and returns its claims.
pub fn verify_access_token(jwt_secret: &str, token: &str) -> AppResult<AccessTokenClaims> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.required_spec_claims = ["exp", "sub", "jti"]
        .into_iter()
        .map(String::from)
        .collect();
    validation.validate_exp = true;
    validation.validate_aud = false;
    validation.leeway = OIDC_LEEWAY_SEC;

    jsonwebtoken::decode::<AccessTokenClaims>(
        token,
        &DecodingKey::from_secret(jwt_secret.as_bytes()),
        &validation,
    )
    .map(|data| data.claims)
    .map_err(|err| {
        tracing::debug!(error = %err, "access token verification failed");
        AppError::unauthorized("invalid or expired access token")
    })
}

/// Authenticates an HTTP request from its `Authorization: Bearer` header.
pub async fn authenticate_request(state: &AppState, headers: &HeaderMap) -> AppResult<AuthUser> {
    let token = bearer_token(headers)?;
    let claims = verify_access_token(&state.config.jwt_secret, token)?;

    match state
        .redis
        .check_jwt_revocation(
            &claims.device_session_id,
            &claims.sub,
            &claims.jti,
            claims.iat,
        )
        .await?
    {
        JwtRevocationStatus::Active => {}
        JwtRevocationStatus::DeviceKicked => {
            return Err(AppError::new(ErrorCode::DeviceKicked, "device kicked"));
        }
        JwtRevocationStatus::Revoked => {
            return Err(AppError::unauthorized("token revoked"));
        }
    }

    let device = find_device_by_id(state, &claims.device_session_id)
        .await?
        .ok_or_else(|| AppError::unauthorized("device session not found"))?;
    if device.user_id != claims.sub {
        return Err(AppError::unauthorized("device session mismatch"));
    }
    match device.status.as_str() {
        "online" => {}
        "kicked" => return Err(AppError::new(ErrorCode::DeviceKicked, "device kicked")),
        _ => return Err(AppError::unauthorized("token revoked")),
    }

    let user = state
        .db
        .find_user_by_id(&claims.sub)
        .await?
        .ok_or_else(|| AppError::unauthorized("user not found"))?;

    if user.status != "active" {
        return Err(AppError::forbidden("account is disabled"));
    }

    touch_device_activity(state, &claims.device_session_id).await;

    Ok(AuthUser {
        user,
        device_session_id: claims.device_session_id.clone(),
        claims,
    })
}

/// Exchanges an Authentik authorization code for an ID token and returns the
/// identity and group information needed to upsert the local user.
pub async fn verify_authentik_code_and_get_profile(
    state: &AppState,
    code: &str,
    code_verifier: &str,
    redirect_uri: &str,
) -> AppResult<OidcUserProfile> {
    let cached = fetch_oidc_cached(state, false).await?;
    let discovery = &cached.discovery;

    let form = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("code_verifier", code_verifier),
        ("redirect_uri", redirect_uri),
        ("client_id", state.config.authentik_client_id.as_str()),
        (
            "client_secret",
            state.config.authentik_client_secret.as_str(),
        ),
    ];

    let response = state
        .http
        .post(&discovery.token_endpoint)
        .form(&form)
        .send()
        .await
        .map_err(|err| {
            tracing::error!(error = %err, "OIDC token endpoint request failed");
            AppError::internal("failed to exchange authorization code")
        })?;

    if !response.status().is_success() {
        tracing::warn!(
            status = %response.status(),
            "OIDC token endpoint rejected the code exchange"
        );
        return Err(AppError::unauthorized("authorization code exchange failed"));
    }

    let token_response: TokenEndpointResponse = response.json().await.map_err(|err| {
        tracing::error!(error = %err, "failed to parse OIDC token response");
        AppError::internal("invalid OIDC token response")
    })?;

    extract_profile_from_token_response(state, discovery, token_response, None).await
}

async fn extract_profile_from_token_response(
    state: &AppState,
    discovery: &OidcDiscovery,
    token_response: TokenEndpointResponse,
    expected_sub: Option<&str>,
) -> AppResult<OidcUserProfile> {
    let TokenEndpointResponse {
        access_token,
        id_token,
        refresh_token,
    } = token_response;

    let (mut sub, sid, mut display_name, mut groups, mut is_active, needs_userinfo) =
        match id_token.as_deref() {
            Some(raw_id_token) => {
                let claims: IdTokenClaims = verify_oidc_token(
                    state,
                    discovery,
                    raw_id_token,
                    &["exp", "iss", "aud", "sub"],
                )
                .await?;
                if let Some(exp_sub) = expected_sub {
                    if claims.sub != exp_sub {
                        return Err(AppError::unauthorized("OIDC subject mismatch"));
                    }
                }
                let needs_ui = claims.groups.is_none();
                (
                    Some(claims.sub),
                    claims.sid,
                    claims.name.or(claims.preferred_username),
                    claims.groups.into_iter().flatten().collect::<Vec<String>>(),
                    claims.is_active,
                    needs_ui,
                )
            }
            None => {
                if expected_sub.is_none() {
                    return Err(AppError::unauthorized(
                        "OIDC token response missing id_token",
                    ));
                }
                (
                    expected_sub.map(ToOwned::to_owned),
                    None,
                    None,
                    Vec::new(),
                    None,
                    true,
                )
            }
        };

    if needs_userinfo {
        if let Some(userinfo_endpoint) = discovery.userinfo_endpoint.as_deref() {
            let access_token = access_token.as_deref().ok_or_else(|| {
                AppError::unauthorized("OIDC token response missing access_token")
            })?;

            let response = state
                .http
                .get(userinfo_endpoint)
                .bearer_auth(access_token)
                .send()
                .await
                .map_err(|err| {
                    tracing::error!(error = %err, "OIDC userinfo request failed");
                    AppError::internal("failed to fetch userinfo")
                })?;

            if !response.status().is_success() {
                tracing::warn!(
                    status = %response.status(),
                    "OIDC userinfo endpoint returned an error"
                );
                return Err(AppError::internal("failed to fetch userinfo"));
            }

            let userinfo: UserInfoClaims = response.json().await.map_err(|err| {
                tracing::error!(error = %err, "failed to parse OIDC userinfo response");
                AppError::internal("invalid OIDC userinfo response")
            })?;

            if let Some(userinfo_sub) = userinfo.sub.as_deref() {
                if let Some(cur_sub) = sub.as_deref() {
                    if userinfo_sub != cur_sub {
                        tracing::warn!("OIDC userinfo subject does not match id_token subject");
                        return Err(AppError::unauthorized("userinfo subject mismatch"));
                    }
                } else {
                    sub = Some(userinfo_sub.to_string());
                }
            }

            if let Some(userinfo_groups) = userinfo.groups {
                groups = userinfo_groups;
            }
            if is_active.is_none() {
                is_active = userinfo.is_active;
            }
            if display_name.is_none() {
                display_name = userinfo.name.or(userinfo.preferred_username);
            }
        }
    }

    let sub = sub.ok_or_else(|| AppError::unauthorized("missing OIDC subject"))?;
    let display_name = match display_name {
        Some(display_name) => display_name,
        None => sub.clone(),
    };

    Ok(OidcUserProfile {
        display_name,
        sub,
        sid,
        groups,
        is_active,
        refresh_token,
    })
}

/// Verifies an OIDC Back-Channel Logout token and validates its claims.
pub async fn verify_backchannel_logout_token(
    state: &AppState,
    logout_token: &str,
) -> AppResult<BackChannelLogoutClaims> {
    let cached = fetch_oidc_cached(state, false).await?;
    let claims: serde_json::Value = verify_oidc_token(
        state,
        &cached.discovery,
        logout_token,
        &["exp", "iat", "iss", "aud"],
    )
    .await?;
    validate_backchannel_logout_claims(&claims)
}

/// Registers or refreshes an online device for `user_id`.
///
/// Returns the persisted device row and the raw refresh token. Only the hash of
/// the refresh token is stored.
#[allow(clippy::too_many_arguments)]
pub async fn login_or_reuse_device(
    state: &AppState,
    user_id: &str,
    device_id: &str,
    device_name: &str,
    sso_sid: Option<&str>,
    sso_refresh_token: Option<&str>,
    ip: &str,
    max_devices: i64,
    now: i64,
) -> AppResult<(UserDeviceRow, String)> {
    let raw_refresh = generate_refresh_token();
    let refresh_hash = hash_token(&raw_refresh);

    let mut conn = state.db.pool.acquire().await?;
    sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;

    let tx_result: AppResult<(UserDeviceRow, Vec<String>)> = async {
        let updated = sqlx::query_as::<_, UserDeviceRow>(
            "UPDATE user_devices
             SET device_name = ?, sso_sid = ?, sso_refresh_token = ?, refresh_token_hash = ?,
                 last_ip = ?, last_active_at = ?
             WHERE user_id = ? AND device_id = ? AND status = 'online'
             RETURNING *",
        )
        .bind(device_name)
        .bind(sso_sid)
        .bind(sso_refresh_token)
        .bind(&refresh_hash)
        .bind(ip)
        .bind(now)
        .bind(user_id)
        .bind(device_id)
        .fetch_optional(&mut *conn)
        .await?;

        let device = match updated {
            Some(device) => device,
            None => {
                let id = format!("ud_{}", uuid::Uuid::new_v4().simple());
                let family_id = format!("fam_{}", uuid::Uuid::new_v4().simple());

                sqlx::query_as::<_, UserDeviceRow>(
                    "INSERT INTO user_devices
                     (id, user_id, device_id, device_name, sso_sid, sso_refresh_token, refresh_token_hash,
                      refresh_family_id, last_ip, status, created_at, last_active_at, kicked_at)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'online', ?, ?, NULL)
                     RETURNING *",
                )
                .bind(&id)
                .bind(user_id)
                .bind(device_id)
                .bind(device_name)
                .bind(sso_sid)
                .bind(sso_refresh_token)
                .bind(&refresh_hash)
                .bind(&family_id)
                .bind(ip)
                .bind(now)
                .bind(now)
                .fetch_one(&mut *conn)
                .await?
            }
        };

        let other_devices: Vec<UserDeviceRow> = sqlx::query_as(
            "SELECT * FROM user_devices
             WHERE user_id = ? AND status = 'online' AND id != ?
             ORDER BY last_active_at ASC, created_at ASC, id ASC",
        )
        .bind(user_id)
        .bind(&device.id)
        .fetch_all(&mut *conn)
        .await?;

        let keep_others = (max_devices.max(1) - 1).max(0) as usize;
        let excess = other_devices.len().saturating_sub(keep_others);
        let mut evicted_ids = Vec::with_capacity(excess);
        for old_device in other_devices.into_iter().take(excess) {
            let res = sqlx::query(
                "UPDATE user_devices
                 SET status = 'kicked', kicked_at = ?
                 WHERE id = ? AND status = 'online'",
            )
            .bind(now)
            .bind(&old_device.id)
            .execute(&mut *conn)
            .await?;
            if res.rows_affected() > 0 {
                evicted_ids.push(old_device.id);
            }
        }

        Ok((device, evicted_ids))
    }
    .await;

    let (device, evicted_ids) = match tx_result {
        Ok(res) => {
            sqlx::query("COMMIT").execute(&mut *conn).await?;
            res
        }
        Err(err) => {
            let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            return Err(err);
        }
    };
    drop(conn);

    for evicted_id in evicted_ids {
        state.redis.revoke_device_jwt(&evicted_id, "kicked").await?;
    }

    Ok((device, raw_refresh))
}

/// Evicts the least-recently-active online devices above `max_devices`.
pub async fn evict_excess_devices_for_user(
    state: &AppState,
    user_id: &str,
    max_devices: i64,
    now: i64,
) -> AppResult<u64> {
    let mut conn = state.db.pool.acquire().await?;
    sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;

    let tx_result: AppResult<Vec<String>> = async {
        let devices: Vec<UserDeviceRow> = sqlx::query_as(
            "SELECT * FROM user_devices
             WHERE user_id = ? AND status = 'online'
             ORDER BY last_active_at ASC, created_at ASC, id ASC",
        )
        .bind(user_id)
        .fetch_all(&mut *conn)
        .await?;

        let effective_max = max_devices.max(1);
        let excess = devices.len() as i64 - effective_max;
        if excess <= 0 {
            return Ok(Vec::new());
        }

        let mut evicted_ids = Vec::with_capacity(excess as usize);
        for device in devices.into_iter().take(excess as usize) {
            let result = sqlx::query(
                "UPDATE user_devices
                 SET status = 'kicked', kicked_at = ?
                 WHERE id = ? AND status = 'online'",
            )
            .bind(now)
            .bind(&device.id)
            .execute(&mut *conn)
            .await?;

            if result.rows_affected() > 0 {
                evicted_ids.push(device.id);
            }
        }

        Ok(evicted_ids)
    }
    .await;

    let evicted_ids = match tx_result {
        Ok(ids) => {
            sqlx::query("COMMIT").execute(&mut *conn).await?;
            ids
        }
        Err(err) => {
            let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            return Err(err);
        }
    };
    drop(conn);

    let count = evicted_ids.len() as u64;
    for device_id in evicted_ids {
        state.redis.revoke_device_jwt(&device_id, "kicked").await?;
    }

    Ok(count)
}

/// Rotates a refresh token and returns the owning user, the updated device, and
/// the new raw refresh token.
pub async fn rotate_refresh_token(
    state: &AppState,
    raw_refresh: &str,
    ip: &str,
    now: i64,
) -> AppResult<(UserRow, UserDeviceRow, String)> {
    let old_hash = hash_token(raw_refresh);

    let device = sqlx::query_as::<_, UserDeviceRow>(
        "SELECT * FROM user_devices WHERE refresh_token_hash = ?",
    )
    .bind(&old_hash)
    .fetch_optional(&state.db.pool)
    .await?;

    let Some(device) = device else {
        if let Some(device_id) = lookup_used_refresh_token(state, &old_hash).await? {
            tracing::warn!(
                device_session_id = %device_id,
                "refresh token reuse detected; revoking refresh family"
            );
            revoke_refresh_family(state, &device_id).await?;
        }
        return Err(AppError::unauthorized("invalid refresh token"));
    };

    match device.status.as_str() {
        "kicked" => return Err(AppError::new(ErrorCode::DeviceKicked, "device kicked")),
        "online" => {}
        _ => return Err(AppError::unauthorized("token revoked")),
    }

    if now.saturating_sub(device.created_at) > REFRESH_TOKEN_TTL_SEC {
        sqlx::query(
            "UPDATE user_devices SET status = 'expired'
             WHERE id = ? AND status = 'online'",
        )
        .bind(&device.id)
        .execute(&state.db.pool)
        .await?;
        return Err(AppError::unauthorized("refresh token expired"));
    }

    let user = state
        .db
        .find_user_by_id(&device.user_id)
        .await?
        .ok_or_else(|| AppError::unauthorized("user not found"))?;

    if user.status != "active" {
        return Err(AppError::forbidden("account is disabled"));
    }

    let sso_rt = device
        .sso_refresh_token
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            AppError::unauthorized("missing SSO refresh token; re-authentication required")
        })?;

    let (user, rotated_sso_rt) =
        refresh_authentik_session_and_sync(state, &device, &user, sso_rt).await?;
    let next_sso_refresh_token = rotated_sso_rt.or_else(|| device.sso_refresh_token.clone());

    let new_raw_refresh = generate_refresh_token();
    let new_hash = hash_token(&new_raw_refresh);

    let updated = sqlx::query(
        "UPDATE user_devices
         SET refresh_token_hash = ?, sso_refresh_token = ?, last_ip = ?, last_active_at = ?
         WHERE id = ? AND refresh_token_hash = ? AND status = 'online'",
    )
    .bind(&new_hash)
    .bind(&next_sso_refresh_token)
    .bind(ip)
    .bind(now)
    .bind(&device.id)
    .bind(&old_hash)
    .execute(&state.db.pool)
    .await?;

    if updated.rows_affected() == 0 {
        tracing::warn!(
            device_session_id = %device.id,
            "concurrent refresh token reuse detected; revoking refresh family"
        );
        revoke_refresh_family(state, &device.id).await?;
        return Err(AppError::unauthorized("invalid refresh token"));
    }

    state
        .redis
        .mark_refresh_token_used(&old_hash, &device.id, REFRESH_TOKEN_TTL_SEC as u64)
        .await?;

    let device = find_device_by_id(state, &device.id)
        .await?
        .ok_or_else(|| AppError::internal("user device disappeared during refresh"))?;

    Ok((user, device, new_raw_refresh))
}

async fn refresh_authentik_session_and_sync(
    state: &AppState,
    device: &UserDeviceRow,
    user: &UserRow,
    sso_refresh_token: &str,
) -> AppResult<(UserRow, Option<String>)> {
    let cached = fetch_oidc_cached(state, false).await?;
    let discovery = &cached.discovery;

    let form = [
        ("grant_type", "refresh_token"),
        ("refresh_token", sso_refresh_token),
        ("client_id", state.config.authentik_client_id.as_str()),
        (
            "client_secret",
            state.config.authentik_client_secret.as_str(),
        ),
    ];

    let response = state
        .http
        .post(&discovery.token_endpoint)
        .form(&form)
        .send()
        .await
        .map_err(|err| AppError::internal(format!("OIDC refresh request failed: {err}")))?;

    let status = response.status();
    if status.is_client_error() {
        tracing::info!(
            user_id = %user.id,
            device_session_id = %device.id,
            status = %status,
            "Authentik rejected OIDC refresh_token; revoking local session"
        );
        let _ = sqlx::query(
            "UPDATE user_devices SET status = 'logged_out', sso_refresh_token = NULL WHERE id = ?",
        )
        .bind(&device.id)
        .execute(&state.db.pool)
        .await;
        let _ = state.redis.revoke_device_jwt(&device.id, "logged_out").await;
        return Err(AppError::unauthorized(
            "SSO session expired or account disabled",
        ));
    }

    if !status.is_success() {
        return Err(AppError::internal(format!(
            "OIDC refresh endpoint returned status {status}"
        )));
    }

    let token_response: TokenEndpointResponse = response
        .json()
        .await
        .map_err(|err| AppError::internal(format!("invalid OIDC refresh response: {err}")))?;

    let profile = extract_profile_from_token_response(
        state,
        discovery,
        token_response,
        Some(&user.sso_subject),
    )
    .await?;

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

#[derive(Debug, Deserialize)]
pub struct AuthentikGroupSummary {
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct AuthentikApiUser {
    pub pk: serde_json::Value,
    pub uid: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub username: String,
    pub is_active: bool,
    #[serde(default)]
    pub groups_obj: Vec<AuthentikGroupSummary>,
}

impl AuthentikApiUser {
    pub fn display_name(&self) -> &str {
        if !self.name.trim().is_empty() {
            self.name.trim()
        } else if !self.username.trim().is_empty() {
            self.username.trim()
        } else {
            &self.uid
        }
    }

    pub fn group_names(&self) -> Vec<String> {
        self.groups_obj.iter().map(|g| g.name.clone()).collect()
    }
}

#[derive(Debug, Deserialize)]
struct AuthentikUserListPage {
    #[serde(default)]
    results: Vec<AuthentikApiUser>,
}

pub async fn fetch_authentik_user_by_pk(
    state: &AppState,
    pk: &str,
) -> AppResult<Option<AuthentikApiUser>> {
    let token = &state.config.authentik_api_token;
    let url = format!(
        "{}/api/v3/core/users/{}/",
        state.config.authentik_api_base_url,
        pk.trim()
    );
    let resp = state
        .http
        .get(&url)
        .bearer_auth(token)
        .send()
        .await
        .map_err(|err| AppError::internal(format!("Authentik API request failed: {err}")))?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !resp.status().is_success() {
        return Err(AppError::internal(format!(
            "Authentik user API returned status {}",
            resp.status()
        )));
    }
    let user: AuthentikApiUser = resp
        .json()
        .await
        .map_err(|err| AppError::internal(format!("invalid Authentik user JSON: {err}")))?;
    Ok(Some(user))
}

pub async fn fetch_authentik_users_list(state: &AppState) -> AppResult<Vec<AuthentikApiUser>> {
    let token = &state.config.authentik_api_token;
    let url = format!(
        "{}/api/v3/core/users/?page_size=200",
        state.config.authentik_api_base_url
    );
    let resp = state
        .http
        .get(&url)
        .bearer_auth(token)
        .send()
        .await
        .map_err(|err| AppError::internal(format!("Authentik API request failed: {err}")))?;
    if !resp.status().is_success() {
        return Err(AppError::internal(format!(
            "Authentik users API returned status {}",
            resp.status()
        )));
    }
    let page: AuthentikUserListPage = resp
        .json()
        .await
        .map_err(|err| AppError::internal(format!("invalid Authentik users JSON: {err}")))?;
    Ok(page.results)
}

fn bearer_token(headers: &HeaderMap) -> AppResult<&str> {
    let value = headers
        .get(header::AUTHORIZATION)
        .ok_or_else(|| AppError::unauthorized("missing authorization header"))?
        .to_str()
        .map_err(|_| AppError::unauthorized("invalid authorization header"))?;

    let mut parts = value.split_whitespace();
    let scheme = parts
        .next()
        .ok_or_else(|| AppError::unauthorized("invalid authorization header"))?;
    let token = parts
        .next()
        .ok_or_else(|| AppError::unauthorized("invalid authorization header"))?;

    if !scheme.eq_ignore_ascii_case("bearer") || token.is_empty() || parts.next().is_some() {
        return Err(AppError::unauthorized("invalid authorization header"));
    }

    Ok(token)
}

async fn touch_device_activity(state: &AppState, device_session_id: &str) {
    let now = unix_now();
    let cutoff = now - DEVICE_ACTIVITY_UPDATE_SEC;

    let result = sqlx::query(
        "UPDATE user_devices SET last_active_at = ?
         WHERE id = ? AND status = 'online' AND last_active_at <= ?",
    )
    .bind(now)
    .bind(device_session_id)
    .bind(cutoff)
    .execute(&state.db.pool)
    .await;

    if let Err(err) = result {
        tracing::warn!(
            error = %err,
            device_session_id,
            "failed to update device activity"
        );
    }
}

async fn fetch_oidc_cached(state: &AppState, force_refresh: bool) -> AppResult<CachedOidc> {
    if !force_refresh {
        let guard = state.oidc_cache.inner.read().await;
        if let Some(ref cached) = *guard {
            if cached.fetched_at.elapsed() < OIDC_CACHE_TTL {
                return Ok(cached.clone());
            }
        }
    }

    let discovery = fetch_discovery(state).await?;
    let jwks = fetch_jwks(state, &discovery.jwks_uri).await?;
    let cached = CachedOidc {
        discovery,
        jwks,
        fetched_at: Instant::now(),
    };

    let mut guard = state.oidc_cache.inner.write().await;
    *guard = Some(cached.clone());
    Ok(cached)
}

async fn fetch_discovery(state: &AppState) -> AppResult<OidcDiscovery> {
    let url = match state.config.authentik_discovery_url.as_deref() {
        Some(url) => url.to_owned(),
        None => format!(
            "{}/.well-known/openid-configuration",
            state.config.authentik_issuer.trim_end_matches('/')
        ),
    };
    validate_oidc_url_scheme(state, &url)?;

    let response = state.http.get(&url).send().await.map_err(|err| {
        tracing::error!(error = %err, "failed to fetch OIDC discovery document");
        AppError::internal("failed to fetch OIDC discovery document")
    })?;

    if !response.status().is_success() {
        tracing::error!(
            status = %response.status(),
            "OIDC discovery endpoint returned an error"
        );
        return Err(AppError::internal("OIDC discovery failed"));
    }

    let mut discovery = response.json::<OidcDiscovery>().await.map_err(|err| {
        tracing::error!(error = %err, "failed to parse OIDC discovery document");
        AppError::internal("invalid OIDC discovery document")
    })?;

    if !state.config.authentik_issuer.is_empty() {
        let internal_issuer = state
            .config
            .authentik_discovery_url
            .as_deref()
            .and_then(|internal_url| {
                let pub_origin = url_origin(&state.config.authentik_issuer)?;
                let int_origin = url_origin(internal_url)?;
                state
                    .config
                    .authentik_issuer
                    .strip_prefix(pub_origin)
                    .map(|rest| format!("{int_origin}{rest}"))
            });

        let issuer_matches = discovery.issuer == state.config.authentik_issuer
            || internal_issuer
                .as_deref()
                .is_some_and(|int_iss| discovery.issuer == int_iss);

        if !issuer_matches {
            tracing::error!(
                discovered = %discovery.issuer,
                expected = %state.config.authentik_issuer,
                "OIDC discovery issuer mismatch"
            );
            return Err(AppError::internal("OIDC discovery issuer mismatch"));
        }
    }

    // When backend fetches discovery via an internal container URL (`AUTHENTIK_DISCOVERY_URL`)
    // while browsers use the public `AUTHENTIK_ISSUER`, rewrite any public origin prefix on
    // backend-to-backend endpoints to the internal discovery origin so container requests work.
    if let Some(internal_url) = state.config.authentik_discovery_url.as_deref() {
        if let (Some(pub_origin), Some(int_origin)) = (
            url_origin(&state.config.authentik_issuer),
            url_origin(internal_url),
        ) {
            if pub_origin != int_origin {
                let rewrite = |u: &mut String| {
                    if let Some(rest) = u.strip_prefix(pub_origin) {
                        *u = format!("{int_origin}{rest}");
                    }
                };
                rewrite(&mut discovery.token_endpoint);
                rewrite(&mut discovery.jwks_uri);
                if let Some(ref mut ui) = discovery.userinfo_endpoint {
                    rewrite(ui);
                }
            }
        }
    }

    validate_oidc_endpoint(state, &discovery.token_endpoint)?;
    validate_oidc_endpoint(state, &discovery.jwks_uri)?;
    if let Some(ref ui) = discovery.userinfo_endpoint {
        validate_oidc_endpoint(state, ui)?;
    }

    Ok(discovery)
}

fn validate_oidc_url_scheme(state: &AppState, url: &str) -> AppResult<()> {
    if url.starts_with("https://") {
        return Ok(());
    }
    if state.config.allow_insecure_oidc_http && url.starts_with("http://") {
        return Ok(());
    }
    Err(AppError::internal("OIDC endpoint must use HTTPS"))
}

fn validate_oidc_endpoint(state: &AppState, url: &str) -> AppResult<()> {
    validate_oidc_url_scheme(state, url)?;
    let origin = url_origin(url)
        .ok_or_else(|| AppError::internal("invalid OIDC endpoint URL"))?;
    let issuer_origin = url_origin(&state.config.authentik_issuer);
    let discovery_origin = state
        .config
        .authentik_discovery_url
        .as_deref()
        .and_then(url_origin);

    if Some(origin) != issuer_origin && Some(origin) != discovery_origin {
        tracing::error!(endpoint = %url, "OIDC discovery endpoint origin mismatch");
        return Err(AppError::internal("OIDC endpoint origin mismatch"));
    }
    Ok(())
}

fn url_origin(url: &str) -> Option<&str> {
    let scheme_end = url.find("://")? + 3;
    let rest = &url[scheme_end..];
    match rest.find('/') {
        Some(idx) => Some(&url[..scheme_end + idx]),
        None => Some(url),
    }
}

async fn fetch_jwks(state: &AppState, jwks_uri: &str) -> AppResult<JwkSet> {
    let response = state.http.get(jwks_uri).send().await.map_err(|err| {
        tracing::error!(error = %err, "failed to fetch OIDC JWKS");
        AppError::internal("failed to fetch OIDC JWKS")
    })?;

    if !response.status().is_success() {
        tracing::error!(
            status = %response.status(),
            "OIDC JWKS endpoint returned an error"
        );
        return Err(AppError::internal("failed to fetch OIDC JWKS"));
    }

    response.json::<JwkSet>().await.map_err(|err| {
        tracing::error!(error = %err, "failed to parse OIDC JWKS");
        AppError::internal("invalid OIDC JWKS")
    })
}

async fn verify_oidc_token<T: DeserializeOwned>(
    state: &AppState,
    discovery: &OidcDiscovery,
    token: &str,
    required_claims: &[&str],
) -> AppResult<T> {
    let header = jsonwebtoken::decode_header(token).map_err(|err| {
        tracing::warn!(error = %err, "failed to decode OIDC token header");
        AppError::unauthorized("invalid token header")
    })?;

    let alg = asymmetric_algorithm(header.alg)?;
    let kid = header
        .kid
        .as_deref()
        .ok_or_else(|| AppError::unauthorized("token missing key id"))?;

    let mut cached = fetch_oidc_cached(state, false).await?;
    let jwk = match cached.jwks.find(kid) {
        Some(jwk) => jwk,
        None => {
            // Key rotation recovery: force-refresh JWKS once before rejecting.
            cached = fetch_oidc_cached(state, true).await?;
            cached
                .jwks
                .find(kid)
                .ok_or_else(|| AppError::unauthorized("unknown signing key"))?
        }
    };

    let key = DecodingKey::from_jwk(jwk).map_err(|err| {
        tracing::warn!(error = %err, "failed to build OIDC decoding key");
        AppError::unauthorized("invalid signing key")
    })?;

    let mut validation = Validation::new(alg);
    if state.config.authentik_issuer == discovery.issuer {
        validation.set_issuer(&[discovery.issuer.as_str()]);
    } else {
        validation.set_issuer(&[
            state.config.authentik_issuer.as_str(),
            discovery.issuer.as_str(),
        ]);
    }
    validation.set_audience(&[state.config.authentik_client_id.as_str()]);
    validation.validate_exp = true;
    validation.leeway = OIDC_LEEWAY_SEC;
    validation.set_required_spec_claims(required_claims);

    jsonwebtoken::decode::<T>(token, &key, &validation)
        .map(|data| data.claims)
        .map_err(|err| {
            tracing::warn!(error = %err, "OIDC token verification failed");
            AppError::unauthorized("invalid token")
        })
}

fn asymmetric_algorithm(alg: Algorithm) -> AppResult<Algorithm> {
    match alg {
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::ES256
        | Algorithm::ES384
        | Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::PS512 => Ok(alg),
        _ => Err(AppError::unauthorized("unsupported token algorithm")),
    }
}

fn validate_backchannel_logout_claims(
    claims: &serde_json::Value,
) -> AppResult<BackChannelLogoutClaims> {
    if claims.get("nonce").is_some() {
        return Err(AppError::invalid("logout token must not contain nonce"));
    }

    let events = claims
        .get("events")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| AppError::invalid("logout token missing events"))?;

    if !events.contains_key(BACKCHANNEL_LOGOUT_EVENT) {
        return Err(AppError::invalid(
            "logout token missing backchannel-logout event",
        ));
    }

    let sub = claims
        .get("sub")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);

    let jti = claims
        .get("jti")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::invalid("logout token missing jti"))?
        .to_owned();

    let sid = claims
        .get("sid")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);

    if sub.is_none() && sid.is_none() {
        return Err(AppError::invalid(
            "logout token must contain at least sub or sid",
        ));
    }

    let exp = claims
        .get("exp")
        .and_then(serde_json::Value::as_i64)
        .ok_or_else(|| AppError::invalid("logout token missing exp"))?;

    Ok(BackChannelLogoutClaims { sub, sid, jti, exp })
}

fn generate_refresh_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

async fn find_device_by_id(state: &AppState, id: &str) -> AppResult<Option<UserDeviceRow>> {
    Ok(sqlx::query_as("SELECT * FROM user_devices WHERE id = ?")
        .bind(id)
        .fetch_optional(&state.db.pool)
        .await?)
}

async fn lookup_used_refresh_token(state: &AppState, hash: &str) -> AppResult<Option<String>> {
    state.redis.lookup_used_refresh_token(hash).await
}

async fn revoke_refresh_family(state: &AppState, device_id: &str) -> AppResult<()> {
    let family_id: Option<String> =
        sqlx::query_scalar("SELECT refresh_family_id FROM user_devices WHERE id = ?")
            .bind(device_id)
            .fetch_optional(&state.db.pool)
            .await?;

    let Some(family_id) = family_id else {
        return Ok(());
    };

    let family_device_ids: Vec<String> = sqlx::query_scalar(
        "SELECT id FROM user_devices
         WHERE refresh_family_id = ? AND status = 'online'",
    )
    .bind(&family_id)
    .fetch_all(&state.db.pool)
    .await?;

    sqlx::query(
        "UPDATE user_devices SET status = 'logged_out'
         WHERE refresh_family_id = ? AND status = 'online'",
    )
    .bind(&family_id)
    .execute(&state.db.pool)
    .await?;

    // Ensure the device that presented the reused token is logged out even if
    // it was no longer marked online.
    sqlx::query("UPDATE user_devices SET status = 'logged_out' WHERE id = ?")
        .bind(device_id)
        .execute(&state.db.pool)
        .await?;

    state
        .redis
        .revoke_device_jwt(device_id, "logged_out")
        .await?;

    for family_device_id in family_device_ids {
        if family_device_id != device_id {
            state
                .redis
                .revoke_device_jwt(&family_device_id, "logged_out")
                .await?;
        }
    }

    Ok(())
}

fn unix_now() -> i64 {
    chrono::Utc::now().timestamp()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_token_matches_known_sha256_vectors() {
        assert_eq!(
            hash_token("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hash_token(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(hash_token("locker").len(), 64);
    }

    #[test]
    fn access_token_round_trip_preserves_claims() {
        let now = unix_now();
        let (token, exp) = issue_access_token("test-secret", "usr_1", "ud_1", "admin", now)
            .expect("access token should be issued");

        assert_eq!(exp, now + ACCESS_TOKEN_TTL_SEC);

        let claims =
            verify_access_token("test-secret", &token).expect("access token should verify");

        assert_eq!(claims.sub, "usr_1");
        assert_eq!(claims.device_session_id, "ud_1");
        assert_eq!(claims.role, "admin");
        assert_eq!(claims.iat, now);
        assert_eq!(claims.exp, exp);
        assert!(!claims.jti.is_empty());
    }

    #[test]
    fn access_token_rejects_wrong_secret_and_tampering() {
        let (token, _) = issue_access_token("test-secret", "usr_1", "ud_1", "user", unix_now())
            .expect("access token should be issued");

        let wrong_secret =
            verify_access_token("other-secret", &token).expect_err("wrong secret must be rejected");
        assert_eq!(wrong_secret.code, ErrorCode::Unauthorized);

        let tampered = format!("{token}extra");
        let tampered_err = verify_access_token("test-secret", &tampered)
            .expect_err("tampered token must be rejected");
        assert_eq!(tampered_err.code, ErrorCode::Unauthorized);
    }

    #[test]
    fn access_token_rejects_expired_tokens() {
        let now = unix_now();
        let expired_claims = AccessTokenClaims {
            sub: "usr_1".to_owned(),
            jti: "jti_expired".to_owned(),
            device_session_id: "ud_1".to_owned(),
            role: "user".to_owned(),
            iat: now - 2_000,
            exp: now - 1_000,
        };

        let token = jsonwebtoken::encode(
            &Header::new(Algorithm::HS256),
            &expired_claims,
            &EncodingKey::from_secret(b"test-secret"),
        )
        .expect("expired token should still encode");

        let err =
            verify_access_token("test-secret", &token).expect_err("expired token must be rejected");
        assert_eq!(err.code, ErrorCode::Unauthorized);
    }

    #[test]
    fn backchannel_logout_accepts_valid_claims() {
        let claims = serde_json::json!({
            "sub": "user-1",
            "sid": "session-1",
            "jti": "logout-1",
            "exp": 2_000_000_000i64,
            "events": {
                "http://schemas.openid.net/event/backchannel-logout": {}
            }
        });

        let parsed = validate_backchannel_logout_claims(&claims)
            .expect("valid logout claims should be accepted");

        assert_eq!(parsed.sub.as_deref(), Some("user-1"));
        assert_eq!(parsed.sid.as_deref(), Some("session-1"));
        assert_eq!(parsed.jti, "logout-1");
        assert_eq!(parsed.exp, 2_000_000_000);
    }

    #[test]
    fn backchannel_logout_accepts_sid_without_sub() {
        let claims = serde_json::json!({
            "sid": "session-only",
            "jti": "logout-sid",
            "exp": 2_000_000_000i64,
            "events": {
                "http://schemas.openid.net/event/backchannel-logout": {}
            }
        });

        let parsed = validate_backchannel_logout_claims(&claims)
            .expect("sid-only logout claims should be accepted");
        assert!(parsed.sub.is_none());
        assert_eq!(parsed.sid.as_deref(), Some("session-only"));
    }

    #[test]
    fn backchannel_logout_rejects_missing_sub_and_sid() {
        let claims = serde_json::json!({
            "jti": "logout-1",
            "exp": 2_000_000_000i64,
            "events": {
                "http://schemas.openid.net/event/backchannel-logout": {}
            }
        });

        let err = validate_backchannel_logout_claims(&claims)
            .expect_err("missing both sub and sid must be rejected");
        assert_eq!(err.code, ErrorCode::InvalidArgument);
    }

    #[test]
    fn backchannel_logout_rejects_missing_exp() {
        let claims = serde_json::json!({
            "sub": "user-1",
            "jti": "logout-1",
            "events": {
                "http://schemas.openid.net/event/backchannel-logout": {}
            }
        });

        let err = validate_backchannel_logout_claims(&claims)
            .expect_err("missing exp must be rejected");
        assert_eq!(err.code, ErrorCode::InvalidArgument);
    }

    #[test]
    fn backchannel_logout_rejects_nonce() {
        let claims = serde_json::json!({
            "sub": "user-1",
            "jti": "logout-1",
            "exp": 2_000_000_000i64,
            "nonce": "must-not-be-here",
            "events": {
                "http://schemas.openid.net/event/backchannel-logout": {}
            }
        });

        let err = validate_backchannel_logout_claims(&claims).expect_err("nonce must be rejected");
        assert_eq!(err.code, ErrorCode::InvalidArgument);
    }

    #[test]
    fn backchannel_logout_requires_events_key() {
        let missing_events = serde_json::json!({
            "sub": "user-1",
            "jti": "logout-1",
            "exp": 2_000_000_000i64
        });

        let err = validate_backchannel_logout_claims(&missing_events)
            .expect_err("missing events must be rejected");
        assert_eq!(err.code, ErrorCode::InvalidArgument);

        let wrong_event = serde_json::json!({
            "sub": "user-1",
            "jti": "logout-1",
            "exp": 2_000_000_000i64,
            "events": {}
        });

        let err = validate_backchannel_logout_claims(&wrong_event)
            .expect_err("missing backchannel-logout event must be rejected");
        assert_eq!(err.code, ErrorCode::InvalidArgument);
    }

    #[test]
    fn backchannel_logout_requires_jti() {
        let claims = serde_json::json!({
            "sub": "user-1",
            "exp": 2_000_000_000i64,
            "events": {
                "http://schemas.openid.net/event/backchannel-logout": {}
            }
        });

        let err =
            validate_backchannel_logout_claims(&claims).expect_err("missing jti must be rejected");
        assert_eq!(err.code, ErrorCode::InvalidArgument);
    }

    #[test]
    fn authentik_api_user_requires_is_active() {
        let missing = serde_json::json!({
            "pk": 1,
            "uid": "u-1",
            "username": "alice"
        });
        assert!(serde_json::from_value::<AuthentikApiUser>(missing).is_err());

        let disabled = serde_json::json!({
            "pk": 1,
            "uid": "u-1",
            "username": "alice",
            "is_active": false
        });
        let parsed: AuthentikApiUser = serde_json::from_value(disabled).unwrap();
        assert!(!parsed.is_active);
    }
}

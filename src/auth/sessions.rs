use super::oidc::{extract_profile_from_token_response, fetch_oidc_cached, TokenEndpointResponse};
use super::{generate_random_token, hash_token, REFRESH_TOKEN_TTL_SEC};
use crate::db::{UserDeviceRow, UserRow};
use crate::error::{AppError, AppResult, ErrorCode};
use crate::redis_store::RedisStore;
use crate::state::AppState;
use sqlx::SqliteConnection;

async fn evict_excess_devices_tx(
    conn: &mut SqliteConnection,
    user_id: &str,
    keep_limit: usize,
    exclude_device_id: Option<&str>,
    now: i64,
) -> AppResult<Vec<String>> {
    let device_ids: Vec<String> = match exclude_device_id {
        Some(excluded) => {
            sqlx::query_scalar(
                "SELECT id FROM user_devices
                 WHERE user_id = ? AND status = 'online' AND id != ?
                 ORDER BY last_active_at ASC, created_at ASC, id ASC",
            )
            .bind(user_id)
            .bind(excluded)
            .fetch_all(&mut *conn)
            .await?
        }
        None => {
            sqlx::query_scalar(
                "SELECT id FROM user_devices
                 WHERE user_id = ? AND status = 'online'
                 ORDER BY last_active_at ASC, created_at ASC, id ASC",
            )
            .bind(user_id)
            .fetch_all(&mut *conn)
            .await?
        }
    };

    let excess = device_ids.len().saturating_sub(keep_limit);
    let mut evicted_ids = Vec::with_capacity(excess);
    for dev_id in device_ids.into_iter().take(excess) {
        let res = sqlx::query(
            "UPDATE user_devices
             SET status = 'kicked', kicked_at = ?, sso_refresh_token = NULL
             WHERE id = ? AND status = 'online'",
        )
        .bind(now)
        .bind(&dev_id)
        .execute(&mut *conn)
        .await?;
        if res.rows_affected() > 0 {
            evicted_ids.push(dev_id);
        }
    }
    Ok(evicted_ids)
}

async fn revoke_devices_in_redis(
    redis: &RedisStore,
    device_ids: &[String],
    reason: &str,
) -> AppResult<()> {
    let mut first_err: Option<AppError> = None;
    for device_id in device_ids {
        if let Err(err) = redis.revoke_device_jwt(device_id, reason).await {
            tracing::error!(device_id, reason, error = %err.message, "failed to revoke device JWT in Redis");
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
    let raw_refresh = generate_random_token();
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

        let keep_others = (max_devices.max(1) - 1).max(0) as usize;
        let evicted_ids =
            evict_excess_devices_tx(&mut conn, user_id, keep_others, Some(&device.id), now).await?;

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

    revoke_devices_in_redis(&state.redis, &evicted_ids, "kicked").await?;

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

    let tx_result =
        evict_excess_devices_tx(&mut conn, user_id, max_devices.max(1) as usize, None, now).await;

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
    revoke_devices_in_redis(&state.redis, &evicted_ids, "kicked").await?;

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
            "UPDATE user_devices SET status = 'expired', sso_refresh_token = NULL
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

    let new_raw_refresh = generate_random_token();
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

pub(super) async fn find_device_by_id(
    state: &AppState,
    id: &str,
) -> AppResult<Option<UserDeviceRow>> {
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

    let mut family_device_ids: Vec<String> = sqlx::query_scalar(
        "SELECT id FROM user_devices
         WHERE refresh_family_id = ? AND status = 'online'",
    )
    .bind(&family_id)
    .fetch_all(&state.db.pool)
    .await?;

    sqlx::query(
        "UPDATE user_devices SET status = 'logged_out', sso_refresh_token = NULL
         WHERE refresh_family_id = ? AND status = 'online'",
    )
    .bind(&family_id)
    .execute(&state.db.pool)
    .await?;

    sqlx::query("UPDATE user_devices SET status = 'logged_out', sso_refresh_token = NULL WHERE id = ?")
        .bind(device_id)
        .execute(&state.db.pool)
        .await?;

    if !family_device_ids.iter().any(|id| id == device_id) {
        family_device_ids.push(device_id.to_owned());
    }
    revoke_devices_in_redis(&state.redis, &family_device_ids, "logged_out").await
}

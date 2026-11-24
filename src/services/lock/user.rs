use super::dispatch::dispatch_unlock_command;
use super::{MeLockItem, MeResponse, UnlockAuditContext, UnlockResponse};
use crate::auth::AuthUser;
use crate::error::{AppError, AppResult, ErrorCode};
use crate::infra::audit::AuditEvent;
use crate::services::{compute_lock_view, is_valid_identifier, LockStatusView};
use crate::state::AppState;

/// Returns profile info and all locks accessible to the authenticated member.
pub async fn get_me(state: &AppState, auth: &AuthUser, req_id: &str) -> AppResult<MeResponse> {
    let cfg = state
        .db
        .get_system_config()
        .await
        .map_err(|e| e.with_request_id(req_id))?;
    let all_locks = state
        .db
        .list_locks()
        .await
        .map_err(|e| e.with_request_id(req_id))?;
    let adapters_map = state
        .db
        .list_all_adapters_map()
        .await
        .map_err(|e| e.with_request_id(req_id))?;
    let lock_groups_map = state
        .db
        .list_all_lock_groups_map()
        .await
        .map_err(|e| e.with_request_id(req_id))?;

    let is_admin = auth.user.role == "admin";
    let user_groups = auth.user.groups();
    let now = chrono::Utc::now().timestamp();
    let mut accessible = Vec::new();

    for lock in all_locks {
        let allowed = is_admin
            || lock_groups_map
                .get(&lock.id)
                .is_some_and(|rules| user_groups.iter().any(|ug| rules.iter().any(|ag| ag == ug)));
        if !allowed {
            continue;
        }
        let adapter = lock
            .adapter_id
            .as_deref()
            .and_then(|aid| adapters_map.get(aid));
        let view = compute_lock_view(&lock, adapter, &cfg, now);
        accessible.push(MeLockItem {
            id: view.lock_id,
            name: view.name,
            description: view.description,
            bound: view.bound,
            adapter_id: view.adapter_id,
            adapter_name: view.adapter_name,
            state: view.state,
            state_reported_at: view.state_reported_at,
            online: view.online,
            stale: view.stale,
        });
    }

    Ok(MeResponse {
        user_id: auth.user.id.clone(),
        display_name: auth.user.display_name.clone(),
        role: auth.user.role.clone(),
        groups: auth.user.groups(),
        locks: accessible,
    })
}

/// Returns projected status of a single lock if the member's groups permit access.
pub async fn get_user_lock_status(
    state: &AppState,
    auth: &AuthUser,
    lock_id: &str,
    req_id: &str,
) -> AppResult<LockStatusView> {
    let lock = state
        .db
        .find_lock_by_id(lock_id)
        .await?
        .ok_or_else(|| {
            AppError::new(ErrorCode::LockNotFound, "lock not found").with_request_id(req_id)
        })?;

    if !state.db.user_has_lock_access(&auth.user, &lock.id).await? {
        return Err(
            AppError::new(ErrorCode::LockForbidden, "no group permission for this lock")
                .with_request_id(req_id),
        );
    }

    let adapter = match lock.adapter_id.as_deref() {
        Some(aid) => state.db.find_adapter_by_id(aid).await?,
        None => None,
    };
    let cfg = state.db.get_system_config().await?;
    let now = chrono::Utc::now().timestamp();

    Ok(compute_lock_view(&lock, adapter.as_ref(), &cfg, now))
}

/// Executes a member unlock request with rate limits, replay window/nonce guards, and group checks.
pub async fn user_unlock(
    state: &AppState,
    auth: &AuthUser,
    ip: &str,
    req_id: &str,
    raw_lock_id: &str,
    raw_nonce: &str,
    ts: i64,
) -> AppResult<UnlockResponse> {
    let lock_id = raw_lock_id.trim();
    let nonce = raw_nonce.trim();
    if !is_valid_identifier(lock_id, 1, 64) || !is_valid_identifier(nonce, 8, 128) {
        return Err(AppError::invalid("invalid lockId or nonce").with_request_id(req_id));
    }

    let cfg = state.db.get_system_config().await?;
    if !state
        .redis
        .check_rate_limit(
            &format!("unlock:user:{}", auth.user.id),
            cfg.rate_limits.unlock_user.max,
            cfg.rate_limits.unlock_user.window_sec,
        )
        .await?
        || !state
            .redis
            .check_rate_limit(
                &format!("unlock:ip:{ip}"),
                cfg.rate_limits.unlock_ip.max,
                cfg.rate_limits.unlock_ip.window_sec,
            )
            .await?
    {
        return Err(
            AppError::new(ErrorCode::RateLimited, "rate limit exceeded").with_request_id(req_id),
        );
    }

    let now = chrono::Utc::now().timestamp();
    let window = cfg.unlock_replay_window_sec.max(10);
    if now.abs_diff(ts) > window as u64 {
        return Err(
            AppError::new(ErrorCode::ReplayRejected, "timestamp outside replay window")
                .with_request_id(req_id),
        );
    }

    let nonce_ttl_sec = (window * 2 + 5) as u64;
    if !state
        .redis
        .claim_unlock_nonce(&auth.user.id, nonce, nonce_ttl_sec)
        .await?
    {
        return Err(
            AppError::new(ErrorCode::ReplayRejected, "duplicate nonce").with_request_id(req_id),
        );
    }

    let lock = state
        .db
        .find_lock_by_id(lock_id)
        .await?
        .ok_or_else(|| {
            AppError::new(ErrorCode::LockNotFound, "lock not found").with_request_id(req_id)
        })?;

    if !state.db.user_has_lock_access(&auth.user, &lock.id).await? {
        state.audit.record(AuditEvent {
            actor_type: "user".into(),
            actor_id: auth.user.id.clone(),
            action: "unlock".into(),
            target_type: "lock".into(),
            target_id: lock.id.clone(),
            result: "denied".into(),
            detail: serde_json::json!({ "reason": "group_forbidden" }),
            ip: ip.to_string(),
            request_id: req_id.to_string(),
        });
        return Err(
            AppError::new(ErrorCode::LockForbidden, "no group permission for this lock")
                .with_request_id(req_id),
        );
    }

    let adapter_id = lock.adapter_id.as_deref().ok_or_else(|| {
        AppError::new(ErrorCode::LockUnbound, "lock is not bound to an adapter")
            .with_request_id(req_id)
    })?;

    let adapter = state
        .db
        .find_adapter_by_id(adapter_id)
        .await?
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::AdapterOffline,
                "bound adapter is not approved or missing",
            )
            .with_request_id(req_id)
        })?;

    dispatch_unlock_command(
        state,
        &adapter,
        UnlockAuditContext {
            lock_id: Some(&lock.id),
            actor_type: "user",
            actor_id: &auth.user.id,
            ip,
            req_id,
            reason: None,
        },
    )
    .await
}

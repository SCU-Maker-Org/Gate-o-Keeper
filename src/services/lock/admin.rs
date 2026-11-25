use super::dispatch::{execute_admin_refresh_state, execute_admin_unlock};
use super::{AdminLockView, UnlockResponse};
use crate::config::SystemConfig;
use crate::error::{AppError, AppResult, ErrorCode};
use crate::infra::db::{AdapterRow, LockRow};
use crate::services::{compute_lock_view, is_valid_identifier, require_non_empty_reason};
use crate::state::AppState;

fn project_admin_lock_view(
    lock: &LockRow,
    adapter: Option<&AdapterRow>,
    groups: Vec<String>,
    cfg: &SystemConfig,
    now: i64,
) -> AdminLockView {
    let view = compute_lock_view(lock, adapter, cfg, now);
    AdminLockView {
        id: lock.id.clone(),
        name: lock.name.clone(),
        description: lock.description.clone(),
        bound: view.bound,
        adapter_id: view.adapter_id,
        adapter_name: view.adapter_name,
        adapter_approval_status: adapter.map(|a| a.approval_status),
        adapter_online_status: adapter.map(|a| a.online_status),
        state: view.state,
        state_reported_at: view.state_reported_at,
        online: view.online,
        stale: view.stale,
        groups,
        created_by: lock.created_by.clone(),
        created_at: lock.created_at,
        updated_at: lock.updated_at,
    }
}

async fn build_admin_lock_view(
    state: &AppState,
    lock: &LockRow,
    cfg: &SystemConfig,
    now: i64,
) -> AppResult<AdminLockView> {
    let adapter = match lock.adapter_id.as_deref() {
        Some(aid) => state.db.find_adapter_by_id(aid).await?,
        None => None,
    };
    let groups = state.db.list_lock_groups(&lock.id).await?;
    Ok(project_admin_lock_view(
        lock,
        adapter.as_ref(),
        groups,
        cfg,
        now,
    ))
}

fn validate_lock_name(raw: &str) -> AppResult<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > 128 {
        return Err(AppError::invalid("lock name must be 1..=128 chars"));
    }
    Ok(trimmed.to_string())
}

fn validate_lock_description(raw: &str) -> AppResult<String> {
    let trimmed = raw.trim();
    if trimmed.len() > 256 {
        return Err(AppError::invalid("description must be <= 256 chars"));
    }
    Ok(trimmed.to_string())
}

async fn resolve_lock_bound_adapter(
    state: &AppState,
    lock_id: &str,
) -> AppResult<(LockRow, AdapterRow)> {
    let lock = state
        .db
        .find_lock_by_id(lock_id)
        .await?
        .ok_or_else(|| AppError::new(ErrorCode::LockNotFound, "lock not found"))?;
    let adapter_id = lock
        .adapter_id
        .as_deref()
        .ok_or_else(|| AppError::new(ErrorCode::LockUnbound, "lock is not bound to an adapter"))?;
    let adapter = state
        .db
        .find_adapter_by_id(adapter_id)
        .await?
        .ok_or_else(|| AppError::new(ErrorCode::AdapterNotFound, "bound adapter not found"))?;
    Ok((lock, adapter))
}

pub async fn list_admin_locks(state: &AppState) -> AppResult<Vec<AdminLockView>> {
    let cfg = state.db.get_system_config().await?;
    let locks = state.db.list_locks().await?;
    let adapters_map = state.db.list_all_adapters_map().await?;
    let mut groups_map = state.db.list_all_lock_groups_map().await?;
    let now = chrono::Utc::now().timestamp();

    Ok(locks
        .iter()
        .map(|lock| {
            let adapter = lock
                .adapter_id
                .as_deref()
                .and_then(|aid| adapters_map.get(aid));
            let groups = groups_map.remove(&lock.id).unwrap_or_default();
            project_admin_lock_view(lock, adapter, groups, &cfg, now)
        })
        .collect())
}

#[allow(clippy::too_many_arguments)]
pub async fn create_admin_lock(
    state: &AppState,
    admin_id: &str,
    ip: &str,
    req_id: &str,
    raw_id: Option<&str>,
    raw_name: &str,
    raw_description: &str,
    raw_adapter_id: Option<&str>,
    groups: &[String],
) -> AppResult<AdminLockView> {
    let lock_id = match raw_id.map(str::trim).filter(|s| !s.is_empty()) {
        Some(id) => {
            if !is_valid_identifier(id, 1, 64) {
                return Err(AppError::invalid("lock id must match [A-Za-z0-9_-]{1,64}"));
            }
            id.to_string()
        }
        None => {
            let suffix: String = uuid::Uuid::new_v4()
                .simple()
                .to_string()
                .chars()
                .take(12)
                .collect();
            format!("lock_{suffix}")
        }
    };

    let name = validate_lock_name(raw_name)?;
    let description = validate_lock_description(raw_description)?;
    let adapter_id = raw_adapter_id.map(str::trim).filter(|s| !s.is_empty());

    let now = chrono::Utc::now().timestamp();
    let row = state
        .db
        .create_lock(
            &lock_id,
            &name,
            &description,
            adapter_id,
            groups,
            admin_id,
            now,
        )
        .await?;

    state.audit.record_admin(
        admin_id,
        "create_lock",
        "lock",
        &row.id,
        serde_json::json!({
            "name": row.name,
            "adapterId": row.adapter_id,
            "groups": groups,
        }),
        ip,
        req_id,
    );

    let cfg = state.db.get_system_config().await?;
    build_admin_lock_view(state, &row, &cfg, now).await
}

#[allow(clippy::too_many_arguments)]
pub async fn update_admin_lock(
    state: &AppState,
    admin_id: &str,
    ip: &str,
    req_id: &str,
    id: &str,
    raw_name: Option<&str>,
    raw_description: Option<&str>,
) -> AppResult<AdminLockView> {
    let existing = state
        .db
        .find_lock_by_id(id)
        .await?
        .ok_or_else(|| AppError::new(ErrorCode::LockNotFound, "lock not found"))?;

    let new_name = match raw_name {
        Some(n) => validate_lock_name(n)?,
        None => existing.name,
    };
    let new_desc = match raw_description {
        Some(d) => validate_lock_description(d)?,
        None => existing.description,
    };

    let now = chrono::Utc::now().timestamp();
    let updated = state
        .db
        .update_lock_metadata(id, &new_name, &new_desc, now)
        .await?;

    state.audit.record_admin(
        admin_id,
        "update_lock",
        "lock",
        id,
        serde_json::json!({
            "name": new_name,
            "description": new_desc,
        }),
        ip,
        req_id,
    );

    let cfg = state.db.get_system_config().await?;
    build_admin_lock_view(state, &updated, &cfg, now).await
}

pub async fn bind_admin_lock(
    state: &AppState,
    admin_id: &str,
    ip: &str,
    req_id: &str,
    id: &str,
    raw_adapter_id: Option<&str>,
) -> AppResult<AdminLockView> {
    let target_adapter_id = raw_adapter_id.map(str::trim).filter(|s| !s.is_empty());
    let now = chrono::Utc::now().timestamp();
    let outcome = state
        .db
        .bind_lock_adapter(id, target_adapter_id, now)
        .await?;

    state.audit.record_admin(
        admin_id,
        if target_adapter_id.is_some() {
            "bind_lock"
        } else {
            "unbind_lock"
        },
        "lock",
        id,
        serde_json::json!({
            "previousAdapterId": outcome.previous_adapter_id,
            "adapterId": target_adapter_id,
        }),
        ip,
        req_id,
    );

    let cfg = state.db.get_system_config().await?;
    build_admin_lock_view(state, &outcome.lock, &cfg, now).await
}

pub async fn delete_admin_lock(
    state: &AppState,
    admin_id: &str,
    ip: &str,
    req_id: &str,
    id: &str,
    raw_reason: &str,
) -> AppResult<()> {
    let reason = require_non_empty_reason(raw_reason, req_id)?;
    if !state.db.delete_lock_by_id(id).await? {
        return Err(AppError::new(ErrorCode::LockNotFound, "lock not found"));
    }

    state.audit.record_admin(
        admin_id,
        "delete_lock",
        "lock",
        id,
        serde_json::json!({ "reason": reason }),
        ip,
        req_id,
    );
    Ok(())
}

pub async fn get_lock_groups(state: &AppState, id: &str, _req_id: &str) -> AppResult<Vec<String>> {
    if state.db.find_lock_by_id(id).await?.is_none() {
        return Err(AppError::new(ErrorCode::LockNotFound, "lock not found"));
    }
    state.db.list_lock_groups(id).await
}

pub async fn set_lock_groups(
    state: &AppState,
    admin_id: &str,
    ip: &str,
    req_id: &str,
    id: &str,
    groups: &[String],
) -> AppResult<Vec<String>> {
    if state.db.find_lock_by_id(id).await?.is_none() {
        return Err(AppError::new(ErrorCode::LockNotFound, "lock not found"));
    }

    let now = chrono::Utc::now().timestamp();
    state
        .db
        .replace_lock_groups(id, groups, admin_id, now)
        .await?;

    let updated = state.db.list_lock_groups(id).await?;
    state.audit.record_admin(
        admin_id,
        "update_lock_groups",
        "lock",
        id,
        serde_json::json!({ "groups": updated }),
        ip,
        req_id,
    );
    Ok(updated)
}

pub async fn admin_unlock_lock(
    state: &AppState,
    admin_id: &str,
    ip: &str,
    req_id: &str,
    id: &str,
    raw_reason: &str,
) -> AppResult<UnlockResponse> {
    let reason = require_non_empty_reason(raw_reason, req_id)?;
    let (lock, adapter) = resolve_lock_bound_adapter(state, id).await?;
    execute_admin_unlock(
        state,
        &adapter,
        Some(&lock.id),
        admin_id,
        ip,
        req_id,
        reason,
    )
    .await
}

pub async fn refresh_lock_state(
    state: &AppState,
    admin_id: &str,
    ip: &str,
    req_id: &str,
    id: &str,
) -> AppResult<String> {
    let (lock, adapter) = resolve_lock_bound_adapter(state, id).await?;
    execute_admin_refresh_state(state, &adapter, Some(&lock.id), admin_id, ip, req_id).await
}

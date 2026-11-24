use super::mqtt_events::stage_and_send_token_refresh;
use super::{AdminAdapterView, RevokeResetOutcome};
use crate::error::{AppError, AppResult, ErrorCode};
use crate::infra::audit::AuditEvent;
use crate::infra::db::AdapterFilter;
use crate::services::lock::{execute_admin_refresh_state, execute_admin_unlock, UnlockResponse};
use crate::services::{adapter_fingerprint, compute_adapter_view, require_non_empty_reason};
use crate::state::AppState;

pub async fn list_admin_adapters(
    state: &AppState,
    approval_status: Option<&str>,
    online_status: Option<&str>,
) -> AppResult<Vec<AdminAdapterView>> {
    let cfg = state.db.get_system_config().await?;
    let rows = state
        .db
        .list_adapters_filtered(&AdapterFilter {
            approval_status,
            online_status,
        })
        .await?;
    let mut bound_locks = state.db.list_bound_locks_map().await?;
    let now = chrono::Utc::now().timestamp();

    Ok(rows
        .into_iter()
        .map(|a| {
            let view = compute_adapter_view(&a, &cfg, now);
            let bound = bound_locks.remove(&a.id);
            AdminAdapterView {
                fingerprint: adapter_fingerprint(&a.id, &a.token_hash),
                id: a.id,
                name: view.name,
                approval_status: a.approval_status,
                online_status: a.online_status,
                state: view.state,
                state_reported_at: view.state_reported_at,
                stale: view.stale,
                bound_lock_id: bound.as_ref().map(|(id, _)| id.clone()),
                bound_lock_name: bound.map(|(_, name)| name),
                model: a.model,
                fw_version: a.fw_version,
                token_refresh_interval: a.token_refresh_interval,
                last_seen_at: a.last_seen_at,
                approved_by: a.approved_by,
                approved_at: a.approved_at,
                created_at: a.created_at,
            }
        })
        .collect())
}

async fn ensure_pending_update_target(state: &AppState, id: &str, req_id: &str) -> AppError {
    match state.db.find_adapter_by_id(id).await {
        Ok(None) => AppError::not_found("adapter not found").with_request_id(req_id),
        Ok(Some(a)) if a.approval_status == "pending" => AppError::conflict(
            "adapter has no credential yet; wait for the device to re-register before approving",
        )
        .with_request_id(req_id),
        Ok(Some(_)) => AppError::conflict("adapter is not pending").with_request_id(req_id),
        Err(err) => err.with_request_id(req_id),
    }
}

pub async fn approve_adapter(
    state: &AppState,
    admin_id: &str,
    ip: &str,
    req_id: &str,
    id: &str,
) -> AppResult<()> {
    let now = chrono::Utc::now().timestamp();
    let Some(adapter) = state.db.approve_pending_adapter(id, admin_id, now).await? else {
        return Err(ensure_pending_update_target(state, id, req_id).await);
    };

    state.audit.record(AuditEvent {
        actor_type: "admin".into(),
        actor_id: admin_id.to_string(),
        action: "approve_adapter".into(),
        target_type: "adapter".into(),
        target_id: id.to_string(),
        result: "success".into(),
        detail: serde_json::json!({
            "fingerprint": adapter_fingerprint(&adapter.id, &adapter.token_hash)
        }),
        ip: ip.to_string(),
        request_id: req_id.to_string(),
    });
    Ok(())
}

pub async fn reject_adapter(
    state: &AppState,
    admin_id: &str,
    ip: &str,
    req_id: &str,
    id: &str,
) -> AppResult<()> {
    let now = chrono::Utc::now().timestamp();
    if !state.db.reject_pending_adapter(id, now).await? {
        return Err(ensure_pending_update_target(state, id, req_id).await);
    }

    state.audit.record(AuditEvent {
        actor_type: "admin".into(),
        actor_id: admin_id.to_string(),
        action: "reject_adapter".into(),
        target_type: "adapter".into(),
        target_id: id.to_string(),
        result: "success".into(),
        detail: serde_json::json!({}),
        ip: ip.to_string(),
        request_id: req_id.to_string(),
    });
    Ok(())
}

pub async fn revoke_adapter(
    state: &AppState,
    admin_id: &str,
    ip: &str,
    req_id: &str,
    id: &str,
    raw_reason: &str,
) -> AppResult<RevokeResetOutcome> {
    let reason = require_non_empty_reason(raw_reason, req_id)?;
    let now = chrono::Utc::now().timestamp();
    let Some(unbound_lock_ids) = state.db.revoke_adapter_and_unbind_locks(id, now).await? else {
        return Err(match state.db.find_adapter_by_id(id).await {
            Ok(None) => AppError::not_found("adapter not found").with_request_id(req_id),
            Ok(Some(_)) => AppError::conflict(
                "only approved adapters can be revoked; use reject for pending ones",
            )
            .with_request_id(req_id),
            Err(err) => err.with_request_id(req_id),
        });
    };

    state.mqtt.kick_client(id).await;
    state.audit.record(AuditEvent {
        actor_type: "admin".into(),
        actor_id: admin_id.to_string(),
        action: "revoke_adapter".into(),
        target_type: "adapter".into(),
        target_id: id.to_string(),
        result: "success".into(),
        detail: serde_json::json!({
            "reason": reason,
            "unboundLockIds": unbound_lock_ids,
        }),
        ip: ip.to_string(),
        request_id: req_id.to_string(),
    });
    Ok(RevokeResetOutcome { unbound_lock_ids })
}

pub async fn reset_adapter(
    state: &AppState,
    admin_id: &str,
    ip: &str,
    req_id: &str,
    id: &str,
    raw_reason: &str,
) -> AppResult<RevokeResetOutcome> {
    let reason = require_non_empty_reason(raw_reason, req_id)?;
    let now = chrono::Utc::now().timestamp();
    let Some(unbound_lock_ids) = state.db.reset_adapter_and_unbind_locks(id, now).await? else {
        return Err(AppError::not_found("adapter not found").with_request_id(req_id));
    };

    state.mqtt.kick_client(id).await;
    state.audit.record(AuditEvent {
        actor_type: "admin".into(),
        actor_id: admin_id.to_string(),
        action: "reset_adapter".into(),
        target_type: "adapter".into(),
        target_id: id.to_string(),
        result: "success".into(),
        detail: serde_json::json!({
            "reason": reason,
            "approvalStatus": "pending",
            "unboundLockIds": unbound_lock_ids,
        }),
        ip: ip.to_string(),
        request_id: req_id.to_string(),
    });
    Ok(RevokeResetOutcome { unbound_lock_ids })
}

pub async fn delete_adapter(
    state: &AppState,
    admin_id: &str,
    ip: &str,
    req_id: &str,
    id: &str,
    raw_reason: &str,
) -> AppResult<()> {
    let reason = require_non_empty_reason(raw_reason, req_id)?;
    if !state.db.delete_adapter_by_id(id).await? {
        return Err(AppError::not_found("adapter not found").with_request_id(req_id));
    }

    state.mqtt.kick_client(id).await;
    state.audit.record(AuditEvent {
        actor_type: "admin".into(),
        actor_id: admin_id.to_string(),
        action: "delete_adapter".into(),
        target_type: "adapter".into(),
        target_id: id.to_string(),
        result: "success".into(),
        detail: serde_json::json!({ "reason": reason }),
        ip: ip.to_string(),
        request_id: req_id.to_string(),
    });
    Ok(())
}

pub async fn refresh_adapter_token(
    state: &AppState,
    admin_id: &str,
    ip: &str,
    req_id: &str,
    id: &str,
) -> AppResult<String> {
    let adapter = state
        .db
        .find_adapter_by_id(id)
        .await?
        .ok_or_else(|| AppError::not_found("adapter not found").with_request_id(req_id))?;

    if adapter.approval_status != "approved" || adapter.online_status != "online" {
        return Err(
            AppError::new(ErrorCode::AdapterOffline, "adapter is not online")
                .with_request_id(req_id),
        );
    }

    let now = chrono::Utc::now().timestamp();
    let msg_id = format!("msg_{}", uuid::Uuid::new_v4().simple());
    let staged = stage_and_send_token_refresh(&state.db, &state.mqtt, id, &msg_id, now, true)
        .await
        .map_err(|e| e.with_request_id(req_id))?;
    if !staged {
        return Err(AppError::conflict(
            "adapter already has a pending token rotation or is unavailable",
        )
        .with_request_id(req_id));
    }

    state.audit.record(AuditEvent {
        actor_type: "admin".into(),
        actor_id: admin_id.to_string(),
        action: "refresh_adapter_token".into(),
        target_type: "adapter".into(),
        target_id: id.to_string(),
        result: "success".into(),
        detail: serde_json::json!({ "msgId": msg_id }),
        ip: ip.to_string(),
        request_id: req_id.to_string(),
    });
    Ok(msg_id)
}

pub async fn update_adapter(
    state: &AppState,
    admin_id: &str,
    ip: &str,
    req_id: &str,
    id: &str,
    raw_name: Option<&str>,
    token_refresh_interval: Option<i64>,
) -> AppResult<()> {
    let existing = state
        .db
        .find_adapter_by_id(id)
        .await?
        .ok_or_else(|| AppError::not_found("adapter not found").with_request_id(req_id))?;

    let new_name = match raw_name {
        Some(n) => {
            let trimmed = n.trim();
            if trimmed.is_empty() || trimmed.len() > 128 {
                return Err(
                    AppError::invalid("adapter name must be 1..=128 chars").with_request_id(req_id)
                );
            }
            trimmed.to_string()
        }
        None => existing.name,
    };

    let new_interval = match token_refresh_interval {
        Some(v) => {
            if !(60..=30 * 86_400).contains(&v) {
                return Err(AppError::invalid(
                    "tokenRefreshInterval must be between 60 and 2592000 seconds",
                )
                .with_request_id(req_id));
            }
            v
        }
        None => existing.token_refresh_interval,
    };

    let now = chrono::Utc::now().timestamp();
    state
        .db
        .update_adapter_settings(id, &new_name, new_interval, now)
        .await?;

    state.audit.record(AuditEvent {
        actor_type: "admin".into(),
        actor_id: admin_id.to_string(),
        action: "update_adapter".into(),
        target_type: "adapter".into(),
        target_id: id.to_string(),
        result: "success".into(),
        detail: serde_json::json!({
            "name": new_name,
            "tokenRefreshInterval": new_interval,
        }),
        ip: ip.to_string(),
        request_id: req_id.to_string(),
    });
    Ok(())
}

pub async fn admin_unlock_adapter(
    state: &AppState,
    admin_id: &str,
    ip: &str,
    req_id: &str,
    id: &str,
    raw_reason: &str,
) -> AppResult<UnlockResponse> {
    let reason = require_non_empty_reason(raw_reason, req_id)?;
    let adapter = state.db.find_adapter_by_id(id).await?.ok_or_else(|| {
        AppError::new(ErrorCode::AdapterNotFound, "adapter not found").with_request_id(req_id)
    })?;
    execute_admin_unlock(state, &adapter, None, admin_id, ip, req_id, reason).await
}

pub async fn refresh_adapter_state(
    state: &AppState,
    admin_id: &str,
    ip: &str,
    req_id: &str,
    id: &str,
) -> AppResult<String> {
    let adapter = state.db.find_adapter_by_id(id).await?.ok_or_else(|| {
        AppError::new(ErrorCode::AdapterNotFound, "adapter not found").with_request_id(req_id)
    })?;
    execute_admin_refresh_state(state, &adapter, None, admin_id, ip, req_id).await
}

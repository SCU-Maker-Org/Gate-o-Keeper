mod adapters;
mod audit;
mod config;
mod locks;
mod users;

use crate::audit::AuditEvent;
use crate::db::AdapterRow;
use crate::error::{AppError, AppResult, ErrorCode};
use crate::routes::user::{dispatch_unlock_command, UnlockAuditContext, UnlockResponse};
use crate::state::AppState;
use rand::RngCore;
use serde::Deserialize;
use sha2::{Digest, Sha256};

pub use adapters::{
    approve_adapter, delete_adapter, list_adapters, refresh_adapter_state, refresh_adapter_token,
    reject_adapter, reset_adapter, revoke_adapter, update_adapter, admin_unlock,
    AdapterFilterQuery, AdminAdapterView, UpdateAdapterRequest,
};
pub use audit::{list_audit_logs, AuditQuery};
pub use config::{get_config, update_config, UpdateConfigRequest};
pub use locks::{
    admin_unlock_lock, bind_lock, create_lock, delete_lock, get_lock_groups, list_locks,
    refresh_lock_state, set_lock_groups, update_lock, AdminLockView, BindLockRequest,
    CreateLockRequest, SetLockGroupsRequest, UpdateLockRequest,
};
pub use users::{kick_user, list_users};

#[derive(Deserialize)]
pub struct ReasonBody {
    pub reason: String,
}

pub(super) fn adapter_fingerprint(id: &str, token_hash: &str) -> String {
    let mut h = Sha256::new();
    h.update(id.as_bytes());
    h.update(b":");
    h.update(token_hash.as_bytes());
    let hex_str = hex::encode(h.finalize());
    hex_str.chars().take(16).collect()
}

pub(super) fn generate_random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

pub(super) async fn execute_admin_unlock(
    state: &AppState,
    adapter: &AdapterRow,
    lock_id: Option<&str>,
    admin_user_id: &str,
    ip: &str,
    req_id: &str,
    reason: &str,
) -> AppResult<UnlockResponse> {
    match dispatch_unlock_command(
        state,
        adapter,
        UnlockAuditContext {
            lock_id,
            actor_type: "admin",
            actor_id: admin_user_id,
            ip,
            req_id,
            reason: Some(reason),
        },
    )
    .await
    {
        Ok(resp) => Ok(resp),
        Err(err) => {
            let (target_type, target_id, detail) = match lock_id {
                Some(lid) => (
                    "lock",
                    lid.to_string(),
                    serde_json::json!({
                        "adapterId": adapter.id,
                        "reason": reason,
                        "errorCode": err.code.as_str(),
                        "errorMessage": err.message,
                    }),
                ),
                None => (
                    "adapter",
                    adapter.id.clone(),
                    serde_json::json!({
                        "reason": reason,
                        "errorCode": err.code.as_str(),
                        "errorMessage": err.message,
                    }),
                ),
            };
            state.audit.record(AuditEvent {
                actor_type: "admin".into(),
                actor_id: admin_user_id.to_string(),
                action: "admin_unlock".into(),
                target_type: target_type.into(),
                target_id,
                result: "failed".into(),
                detail,
                ip: ip.to_string(),
                request_id: req_id.to_string(),
            });
            Err(err)
        }
    }
}

pub(super) async fn execute_admin_refresh_state(
    state: &AppState,
    adapter: &AdapterRow,
    lock_id: Option<&str>,
    admin_user_id: &str,
    ip: &str,
    req_id: &str,
) -> AppResult<String> {
    if adapter.approval_status != "approved" || adapter.online_status != "online" {
        return Err(
            AppError::new(ErrorCode::AdapterOffline, "adapter is offline").with_request_id(req_id),
        );
    }

    let msg_id = format!("msg_{}", uuid::Uuid::new_v4().simple());
    state
        .mqtt
        .publish_query_state(&adapter.id, &msg_id)
        .await
        .map_err(|e| e.with_request_id(req_id))?;

    let (target_type, target_id, detail) = match lock_id {
        Some(lid) => (
            "lock",
            lid.to_string(),
            serde_json::json!({ "msgId": msg_id, "adapterId": adapter.id }),
        ),
        None => (
            "adapter",
            adapter.id.clone(),
            serde_json::json!({ "msgId": msg_id }),
        ),
    };
    state.audit.record(AuditEvent {
        actor_type: "admin".into(),
        actor_id: admin_user_id.to_string(),
        action: "admin_refresh_state".into(),
        target_type: target_type.into(),
        target_id,
        result: "success".into(),
        detail,
        ip: ip.to_string(),
        request_id: req_id.to_string(),
    });

    Ok(msg_id)
}

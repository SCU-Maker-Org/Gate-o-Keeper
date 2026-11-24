use crate::audit::AuditEvent;
use crate::db::UserRow;
use crate::error::{AppError, AppResult};
use crate::state::AppState;

pub async fn list_users(state: &AppState) -> AppResult<Vec<UserRow>> {
    state.db.list_users().await
}

pub async fn kick_user(
    state: &AppState,
    admin_id: &str,
    ip: &str,
    req_id: &str,
    target_user_id: &str,
) -> AppResult<u64> {
    let existing = state
        .db
        .find_user_by_id(target_user_id)
        .await?
        .ok_or_else(|| AppError::not_found("user not found").with_request_id(req_id))?;

    if target_user_id == admin_id {
        return Err(
            AppError::forbidden("cannot kick your own admin account").with_request_id(req_id),
        );
    }

    let now = chrono::Utc::now().timestamp();
    let kicked_devices = state.db.kick_user_devices(target_user_id, now).await?;
    state.redis.revoke_user_jwt(target_user_id, now).await?;

    state.audit.record(AuditEvent {
        actor_type: "admin".into(),
        actor_id: admin_id.to_string(),
        action: "kick_user".into(),
        target_type: "user".into(),
        target_id: target_user_id.to_string(),
        result: "success".into(),
        detail: serde_json::json!({
            "displayName": existing.display_name,
            "kickedDevices": kicked_devices,
        }),
        ip: ip.to_string(),
        request_id: req_id.to_string(),
    });

    Ok(kicked_devices)
}

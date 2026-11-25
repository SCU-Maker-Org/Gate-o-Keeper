use crate::error::{AppError, AppResult};
use crate::infra::db::UserRow;
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
        .ok_or_else(|| AppError::not_found("user not found"))?;

    if target_user_id == admin_id {
        return Err(AppError::forbidden("cannot kick your own admin account"));
    }

    let now = chrono::Utc::now().timestamp();
    let kicked_devices = state.db.kick_user_devices(target_user_id, now).await?;
    state.redis.revoke_user_jwt(target_user_id, now).await?;

    state.audit.record_admin(
        admin_id,
        "kick_user",
        "user",
        target_user_id,
        serde_json::json!({
            "displayName": existing.display_name,
            "kickedDevices": kicked_devices,
        }),
        ip,
        req_id,
    );

    Ok(kicked_devices)
}

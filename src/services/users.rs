use crate::domain::UserStatus;
use crate::error::{AppError, AppResult};
use crate::infra::db::UserRow;
use crate::state::AppState;
use serde::Serialize;

pub const MAX_USER_PAGE_SIZE: i64 = 50;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserPage {
    pub items: Vec<UserRow>,
    pub total: i64,
    pub page: i64,
    pub page_size: i64,
    pub status: UserStatus,
}

pub async fn list_users(
    state: &AppState,
    status: UserStatus,
    page: i64,
    page_size: i64,
) -> AppResult<UserPage> {
    if page < 1 {
        return Err(AppError::invalid("page must be >= 1"));
    }
    if !(1..=MAX_USER_PAGE_SIZE).contains(&page_size) {
        return Err(AppError::invalid(format!(
            "pageSize must be between 1 and {MAX_USER_PAGE_SIZE}"
        )));
    }
    let offset = (page - 1) * page_size;
    let (items, total) = state
        .db
        .list_users_by_status(status, page_size, offset)
        .await?;
    Ok(UserPage {
        items,
        total,
        page,
        page_size,
        status,
    })
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

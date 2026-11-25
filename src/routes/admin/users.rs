use crate::domain::UserStatus;
use crate::error::{ApiEnvelope, AppResult};
use crate::routes::{AdminContext, ClientIp};
use crate::services::users::{self as users_svc, UserPage};
use crate::state::AppState;
use axum::extract::{Path, Query, State};
use axum::Json;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListUsersQuery {
    pub status: UserStatus,
    pub page_size: i64,
    pub page: Option<i64>,
}

pub async fn list_users(
    State(state): State<AppState>,
    AdminContext { req_id, .. }: AdminContext,
    Query(q): Query<ListUsersQuery>,
) -> AppResult<Json<ApiEnvelope<UserPage>>> {
    let page = q.page.unwrap_or(1);
    let out = users_svc::list_users(&state, q.status, page, q.page_size).await?;
    Ok(ApiEnvelope::ok(out, req_id))
}

pub async fn kick_user(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    AdminContext { auth, req_id }: AdminContext,
    Path(id): Path<String>,
) -> AppResult<Json<ApiEnvelope<serde_json::Value>>> {
    let kicked_devices = users_svc::kick_user(&state, &auth.user.id, &ip, &req_id, &id).await?;
    Ok(ApiEnvelope::ok(
        serde_json::json!({ "id": id, "kickedDevices": kicked_devices }),
        req_id,
    ))
}

use crate::error::{ApiEnvelope, AppResult};
use crate::infra::db::UserRow;
use crate::routes::{AdminContext, ClientIp};
use crate::services::users as users_svc;
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::Json;

pub async fn list_users(
    State(state): State<AppState>,
    AdminContext { req_id, .. }: AdminContext,
) -> AppResult<Json<ApiEnvelope<Vec<UserRow>>>> {
    let users = users_svc::list_users(&state).await?;
    Ok(ApiEnvelope::ok(users, req_id))
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

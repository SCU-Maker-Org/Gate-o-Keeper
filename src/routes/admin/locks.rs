use super::ReasonBody;
use crate::error::{ApiEnvelope, AppResult};
use crate::routes::{AdminContext, ClientIp};
use crate::services::lock::{self as lock_svc, AdminLockView, UnlockResponse};
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::Json;
use serde::Deserialize;

pub async fn list_locks(
    State(state): State<AppState>,
    AdminContext { req_id, .. }: AdminContext,
) -> AppResult<Json<ApiEnvelope<Vec<AdminLockView>>>> {
    let out = lock_svc::list_admin_locks(&state).await?;
    Ok(ApiEnvelope::ok(out, req_id))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateLockRequest {
    pub id: Option<String>,
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub adapter_id: Option<String>,
    #[serde(default)]
    pub groups: Vec<String>,
}

pub async fn create_lock(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    AdminContext { auth, req_id }: AdminContext,
    Json(body): Json<CreateLockRequest>,
) -> AppResult<Json<ApiEnvelope<AdminLockView>>> {
    let view = lock_svc::create_admin_lock(
        &state,
        &auth.user.id,
        &ip,
        &req_id,
        body.id.as_deref(),
        &body.name,
        &body.description,
        body.adapter_id.as_deref(),
        &body.groups,
    )
    .await?;
    Ok(ApiEnvelope::ok(view, req_id))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateLockRequest {
    pub name: Option<String>,
    pub description: Option<String>,
}

pub async fn update_lock(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    AdminContext { auth, req_id }: AdminContext,
    Path(id): Path<String>,
    Json(body): Json<UpdateLockRequest>,
) -> AppResult<Json<ApiEnvelope<AdminLockView>>> {
    let view = lock_svc::update_admin_lock(
        &state,
        &auth.user.id,
        &ip,
        &req_id,
        &id,
        body.name.as_deref(),
        body.description.as_deref(),
    )
    .await?;
    Ok(ApiEnvelope::ok(view, req_id))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BindLockRequest {
    pub adapter_id: Option<String>,
}

pub async fn bind_lock(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    AdminContext { auth, req_id }: AdminContext,
    Path(id): Path<String>,
    Json(body): Json<BindLockRequest>,
) -> AppResult<Json<ApiEnvelope<AdminLockView>>> {
    let view = lock_svc::bind_admin_lock(
        &state,
        &auth.user.id,
        &ip,
        &req_id,
        &id,
        body.adapter_id.as_deref(),
    )
    .await?;
    Ok(ApiEnvelope::ok(view, req_id))
}

pub async fn delete_lock(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    AdminContext { auth, req_id }: AdminContext,
    Path(id): Path<String>,
    Json(body): Json<ReasonBody>,
) -> AppResult<Json<ApiEnvelope<serde_json::Value>>> {
    lock_svc::delete_admin_lock(&state, &auth.user.id, &ip, &req_id, &id, &body.reason).await?;
    Ok(ApiEnvelope::ok(
        serde_json::json!({ "id": id, "deleted": true }),
        req_id,
    ))
}

pub async fn get_lock_groups(
    State(state): State<AppState>,
    AdminContext { req_id, .. }: AdminContext,
    Path(id): Path<String>,
) -> AppResult<Json<ApiEnvelope<Vec<String>>>> {
    let groups = lock_svc::get_lock_groups(&state, &id, &req_id).await?;
    Ok(ApiEnvelope::ok(groups, req_id))
}

#[derive(Deserialize)]
pub struct SetLockGroupsRequest {
    pub groups: Vec<String>,
}

pub async fn set_lock_groups(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    AdminContext { auth, req_id }: AdminContext,
    Path(id): Path<String>,
    Json(body): Json<SetLockGroupsRequest>,
) -> AppResult<Json<ApiEnvelope<Vec<String>>>> {
    let updated =
        lock_svc::set_lock_groups(&state, &auth.user.id, &ip, &req_id, &id, &body.groups).await?;
    Ok(ApiEnvelope::ok(updated, req_id))
}

pub async fn admin_unlock_lock(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    AdminContext { auth, req_id }: AdminContext,
    Path(id): Path<String>,
    Json(body): Json<ReasonBody>,
) -> AppResult<Json<ApiEnvelope<UnlockResponse>>> {
    let resp =
        lock_svc::admin_unlock_lock(&state, &auth.user.id, &ip, &req_id, &id, &body.reason).await?;
    Ok(ApiEnvelope::ok(resp, req_id))
}

pub async fn refresh_lock_state(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    AdminContext { auth, req_id }: AdminContext,
    Path(id): Path<String>,
) -> AppResult<Json<ApiEnvelope<serde_json::Value>>> {
    let msg_id = lock_svc::refresh_lock_state(&state, &auth.user.id, &ip, &req_id, &id).await?;
    Ok(ApiEnvelope::ok(
        serde_json::json!({ "msgId": msg_id }),
        req_id,
    ))
}

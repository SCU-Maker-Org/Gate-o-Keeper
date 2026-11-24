use super::ReasonBody;
use crate::error::{ApiEnvelope, AppResult};
use crate::routes::{AdminContext, ClientIp};
use crate::services::adapter::{self as adapter_svc, AdminAdapterView};
use crate::services::lock::UnlockResponse;
use crate::state::AppState;
use axum::extract::{Path, Query, State};
use axum::Json;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdapterFilterQuery {
    pub approval_status: Option<String>,
    pub online_status: Option<String>,
}

pub async fn list_adapters(
    State(state): State<AppState>,
    AdminContext { req_id, .. }: AdminContext,
    Query(q): Query<AdapterFilterQuery>,
) -> AppResult<Json<ApiEnvelope<Vec<AdminAdapterView>>>> {
    let out = adapter_svc::list_admin_adapters(
        &state,
        q.approval_status.as_deref(),
        q.online_status.as_deref(),
    )
    .await?;
    Ok(ApiEnvelope::ok(out, req_id))
}

pub async fn approve_adapter(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    AdminContext { auth, req_id }: AdminContext,
    Path(id): Path<String>,
) -> AppResult<Json<ApiEnvelope<serde_json::Value>>> {
    adapter_svc::approve_adapter(&state, &auth.user.id, &ip, &req_id, &id).await?;
    Ok(ApiEnvelope::ok(
        serde_json::json!({ "id": id, "approvalStatus": "approved" }),
        req_id,
    ))
}

pub async fn reject_adapter(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    AdminContext { auth, req_id }: AdminContext,
    Path(id): Path<String>,
) -> AppResult<Json<ApiEnvelope<serde_json::Value>>> {
    adapter_svc::reject_adapter(&state, &auth.user.id, &ip, &req_id, &id).await?;
    Ok(ApiEnvelope::ok(
        serde_json::json!({ "id": id, "approvalStatus": "rejected" }),
        req_id,
    ))
}

pub async fn revoke_adapter(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    AdminContext { auth, req_id }: AdminContext,
    Path(id): Path<String>,
    Json(body): Json<ReasonBody>,
) -> AppResult<Json<ApiEnvelope<serde_json::Value>>> {
    let outcome =
        adapter_svc::revoke_adapter(&state, &auth.user.id, &ip, &req_id, &id, &body.reason).await?;
    Ok(ApiEnvelope::ok(
        serde_json::json!({
            "id": id,
            "approvalStatus": "revoked",
            "unboundLockIds": outcome.unbound_lock_ids,
        }),
        req_id,
    ))
}

pub async fn reset_adapter(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    AdminContext { auth, req_id }: AdminContext,
    Path(id): Path<String>,
    Json(body): Json<ReasonBody>,
) -> AppResult<Json<ApiEnvelope<serde_json::Value>>> {
    let outcome =
        adapter_svc::reset_adapter(&state, &auth.user.id, &ip, &req_id, &id, &body.reason).await?;
    Ok(ApiEnvelope::ok(
        serde_json::json!({
            "id": id,
            "approvalStatus": "pending",
            "reset": true,
            "unboundLockIds": outcome.unbound_lock_ids,
        }),
        req_id,
    ))
}

pub async fn delete_adapter(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    AdminContext { auth, req_id }: AdminContext,
    Path(id): Path<String>,
    Json(body): Json<ReasonBody>,
) -> AppResult<Json<ApiEnvelope<serde_json::Value>>> {
    adapter_svc::delete_adapter(&state, &auth.user.id, &ip, &req_id, &id, &body.reason).await?;
    Ok(ApiEnvelope::ok(
        serde_json::json!({ "id": id, "deleted": true }),
        req_id,
    ))
}

pub async fn refresh_adapter_token(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    AdminContext { auth, req_id }: AdminContext,
    Path(id): Path<String>,
) -> AppResult<Json<ApiEnvelope<serde_json::Value>>> {
    let msg_id =
        adapter_svc::refresh_adapter_token(&state, &auth.user.id, &ip, &req_id, &id).await?;
    Ok(ApiEnvelope::ok(
        serde_json::json!({ "id": id, "msgId": msg_id }),
        req_id,
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateAdapterRequest {
    pub name: Option<String>,
    pub token_refresh_interval: Option<i64>,
}

pub async fn update_adapter(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    AdminContext { auth, req_id }: AdminContext,
    Path(id): Path<String>,
    Json(body): Json<UpdateAdapterRequest>,
) -> AppResult<Json<ApiEnvelope<serde_json::Value>>> {
    adapter_svc::update_adapter(
        &state,
        &auth.user.id,
        &ip,
        &req_id,
        &id,
        body.name.as_deref(),
        body.token_refresh_interval,
    )
    .await?;
    Ok(ApiEnvelope::ok(serde_json::json!({ "id": id }), req_id))
}

pub async fn admin_unlock(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    AdminContext { auth, req_id }: AdminContext,
    Path(id): Path<String>,
    Json(body): Json<ReasonBody>,
) -> AppResult<Json<ApiEnvelope<UnlockResponse>>> {
    let resp =
        adapter_svc::admin_unlock_adapter(&state, &auth.user.id, &ip, &req_id, &id, &body.reason)
            .await?;
    Ok(ApiEnvelope::ok(resp, req_id))
}

pub async fn refresh_adapter_state(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    AdminContext { auth, req_id }: AdminContext,
    Path(id): Path<String>,
) -> AppResult<Json<ApiEnvelope<serde_json::Value>>> {
    let msg_id =
        adapter_svc::refresh_adapter_state(&state, &auth.user.id, &ip, &req_id, &id).await?;
    Ok(ApiEnvelope::ok(
        serde_json::json!({ "msgId": msg_id }),
        req_id,
    ))
}

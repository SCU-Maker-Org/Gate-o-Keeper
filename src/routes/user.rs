use crate::error::{ApiEnvelope, AppResult};
use crate::routes::{AuthContext, ClientIp, LockStatusView, RequestId};
use crate::services::{
    self,
    lock::{MeResponse, UnlockResponse},
};
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::Json;
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthResponse {
    pub status: &'static str,
}

pub async fn healthz(
    State(state): State<AppState>,
    RequestId(req_id): RequestId,
) -> AppResult<Json<ApiEnvelope<HealthResponse>>> {
    services::health_check(&state)
        .await
        .map_err(|e| e.with_request_id(&req_id))?;

    Ok(ApiEnvelope::ok(HealthResponse { status: "ok" }, req_id))
}

pub async fn me(
    State(state): State<AppState>,
    AuthContext { auth, req_id }: AuthContext,
) -> AppResult<Json<ApiEnvelope<MeResponse>>> {
    let resp = services::lock::get_me(&state, &auth, &req_id).await?;
    Ok(ApiEnvelope::ok(resp, req_id))
}

pub async fn lock_status(
    State(state): State<AppState>,
    AuthContext { auth, req_id }: AuthContext,
    Path(lock_id): Path<String>,
) -> AppResult<Json<ApiEnvelope<LockStatusView>>> {
    let view = services::lock::get_user_lock_status(&state, &auth, &lock_id, &req_id).await?;
    Ok(ApiEnvelope::ok(view, req_id))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnlockRequest {
    pub lock_id: String,
    pub nonce: String,
    pub ts: i64,
}

pub async fn unlock(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    AuthContext { auth, req_id }: AuthContext,
    Json(body): Json<UnlockRequest>,
) -> AppResult<Json<ApiEnvelope<UnlockResponse>>> {
    let resp = services::lock::user_unlock(
        &state,
        &auth,
        &ip,
        &req_id,
        &body.lock_id,
        &body.nonce,
        body.ts,
    )
    .await?;
    Ok(ApiEnvelope::ok(resp, req_id))
}

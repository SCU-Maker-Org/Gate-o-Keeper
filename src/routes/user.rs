use crate::auth::authenticate_request;
use crate::error::{ApiEnvelope, AppResult};
use crate::routes::{extract_request_id, ClientIp, LockStatusView};
use crate::services::{self, lock::{MeResponse, UnlockResponse}};
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::Json;
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthResponse {
    pub status: &'static str,
}

pub async fn healthz(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<ApiEnvelope<HealthResponse>>> {
    let req_id = extract_request_id(&headers);
    services::health_check(&state)
        .await
        .map_err(|e| e.with_request_id(&req_id))?;

    Ok(ApiEnvelope::ok(HealthResponse { status: "ok" }, req_id))
}

pub async fn me(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<ApiEnvelope<MeResponse>>> {
    let req_id = extract_request_id(&headers);
    let auth = authenticate_request(&state, &headers)
        .await
        .map_err(|e| e.with_request_id(&req_id))?;

    let resp = services::lock::get_me(&state, &auth, &req_id).await?;
    Ok(ApiEnvelope::ok(resp, req_id))
}

pub async fn lock_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(lock_id): Path<String>,
) -> AppResult<Json<ApiEnvelope<LockStatusView>>> {
    let req_id = extract_request_id(&headers);
    let auth = authenticate_request(&state, &headers)
        .await
        .map_err(|e| e.with_request_id(&req_id))?;

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
    headers: HeaderMap,
    Json(body): Json<UnlockRequest>,
) -> AppResult<Json<ApiEnvelope<UnlockResponse>>> {
    let req_id = extract_request_id(&headers);
    let auth = authenticate_request(&state, &headers)
        .await
        .map_err(|e| e.with_request_id(&req_id))?;

    let resp =
        services::lock::user_unlock(&state, &auth, &ip, &req_id, &body.lock_id, &body.nonce, body.ts)
            .await?;
    Ok(ApiEnvelope::ok(resp, req_id))
}

use crate::error::{ApiEnvelope, AppResult};
use crate::routes::{BearerToken, ClientIp, RequestId};
use crate::services::adapter::{
    self as adapter_svc, AdapterStatusResponse, RegisterAdapterInput, RegisterAdapterResponse,
};
use crate::state::AppState;
use axum::extract::State;
use axum::Json;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterAdapterRequest {
    pub adapter_id: String,
    pub token: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub fw_version: String,
    pub cert_pem: String,
    pub ts: i64,
    pub signature: String,
}

pub async fn register(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    RequestId(req_id): RequestId,
    Json(body): Json<RegisterAdapterRequest>,
) -> AppResult<Json<ApiEnvelope<RegisterAdapterResponse>>> {
    let resp = adapter_svc::register_adapter(
        &state,
        &ip,
        &req_id,
        RegisterAdapterInput {
            adapter_id: &body.adapter_id,
            token: &body.token,
            name: &body.name,
            model: &body.model,
            fw_version: &body.fw_version,
            cert_pem: &body.cert_pem,
            ts: body.ts,
            signature: &body.signature,
        },
    )
    .await?;

    Ok(ApiEnvelope::ok(resp, req_id))
}

pub async fn status(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    RequestId(req_id): RequestId,
    BearerToken(bearer): BearerToken,
) -> AppResult<Json<ApiEnvelope<AdapterStatusResponse>>> {
    let resp = adapter_svc::get_adapter_status(&state, &ip, &req_id, &bearer).await?;
    Ok(ApiEnvelope::ok(resp, req_id))
}

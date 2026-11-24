use crate::error::{ApiEnvelope, AppError, AppResult};
use crate::routes::{extract_request_id, ClientIp};
use crate::services::adapter::{
    self as adapter_svc, AdapterStatusResponse, RegisterAdapterInput, RegisterAdapterResponse,
};
use crate::state::AppState;
use axum::extract::State;
use axum::http::{header, HeaderMap};
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
    headers: HeaderMap,
    Json(body): Json<RegisterAdapterRequest>,
) -> AppResult<Json<ApiEnvelope<RegisterAdapterResponse>>> {
    let req_id = extract_request_id(&headers);
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
    headers: HeaderMap,
) -> AppResult<Json<ApiEnvelope<AdapterStatusResponse>>> {
    let req_id = extract_request_id(&headers);

    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|raw| {
            let mut parts = raw.split_whitespace();
            let scheme = parts.next()?;
            let token = parts.next()?;
            if scheme.eq_ignore_ascii_case("bearer") && !token.is_empty() && parts.next().is_none()
            {
                Some(token)
            } else {
                None
            }
        })
        .ok_or_else(|| {
            AppError::unauthorized("missing adapter bearer token").with_request_id(&req_id)
        })?;

    let resp = adapter_svc::get_adapter_status(&state, &ip, &req_id, bearer).await?;
    Ok(ApiEnvelope::ok(resp, req_id))
}

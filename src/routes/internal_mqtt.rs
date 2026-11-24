use crate::error::{AppError, AppResult};
use crate::services::adapter as adapter_svc;
use crate::state::AppState;
use crate::utils::constant_time_eq;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct EmqxAuthRequest {
    pub clientid: String,
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub cert_cn: Option<String>,
}

#[derive(Serialize)]
pub struct EmqxAuthResponse {
    pub result: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_superuser: Option<bool>,
}

#[derive(Deserialize)]
pub struct EmqxAclRequest {
    pub clientid: String,
    pub username: String,
    pub topic: String,
    pub action: String,
}

#[derive(Serialize)]
pub struct EmqxAclResponse {
    pub result: &'static str,
}

fn check_internal_secret(state: &AppState, headers: &HeaderMap) -> AppResult<()> {
    let provided = headers
        .get("x-internal-secret")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !constant_time_eq(provided, &state.config.internal_mqtt_secret) {
        return Err(AppError::unauthorized("invalid internal mqtt secret"));
    }
    Ok(())
}

pub async fn mqtt_auth(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<EmqxAuthRequest>,
) -> AppResult<Json<EmqxAuthResponse>> {
    check_internal_secret(&state, &headers)?;

    let decision = adapter_svc::authenticate_mqtt(
        &state,
        &body.clientid,
        &body.username,
        &body.password,
        body.cert_cn.as_deref(),
    )
    .await?;

    Ok(Json(EmqxAuthResponse {
        result: if decision.allow { "allow" } else { "deny" },
        is_superuser: decision.is_superuser,
    }))
}

pub async fn mqtt_acl(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<EmqxAclRequest>,
) -> AppResult<Json<EmqxAclResponse>> {
    check_internal_secret(&state, &headers)?;

    let allowed = adapter_svc::authorize_mqtt_acl(
        &state,
        &body.clientid,
        &body.username,
        &body.topic,
        &body.action,
    )
    .await?;

    Ok(Json(EmqxAclResponse {
        result: if allowed { "allow" } else { "deny" },
    }))
}

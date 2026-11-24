use crate::config::{RateLimitConfig, SystemConfig};
use crate::error::{ApiEnvelope, AppResult};
use crate::routes::{AdminContext, ClientIp};
use crate::services::config::{self as cfg_svc, UpdateConfigInput};
use crate::state::AppState;
use axum::extract::State;
use axum::Json;
use serde::Deserialize;

pub async fn get_config(
    State(state): State<AppState>,
    AdminContext { req_id, .. }: AdminContext,
) -> AppResult<Json<ApiEnvelope<SystemConfig>>> {
    let cfg = cfg_svc::get_config(&state).await?;
    Ok(ApiEnvelope::ok(cfg, req_id))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateConfigRequest {
    pub unlock_replay_window_sec: Option<i64>,
    pub command_timeout_ms: Option<u64>,
    pub max_devices_per_user: Option<i64>,
    pub audit_retention_days: Option<i64>,
    pub offline_unknown_sec: Option<i64>,
    pub state_report_period_sec: Option<i64>,
    pub admin_groups: Option<Vec<String>>,
    pub rate_limits: Option<RateLimitConfig>,
}

pub async fn update_config(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    AdminContext { auth, req_id }: AdminContext,
    Json(body): Json<UpdateConfigRequest>,
) -> AppResult<Json<ApiEnvelope<SystemConfig>>> {
    let updated = cfg_svc::update_config(
        &state,
        &auth.user.id,
        &ip,
        &req_id,
        UpdateConfigInput {
            unlock_replay_window_sec: body.unlock_replay_window_sec,
            command_timeout_ms: body.command_timeout_ms,
            max_devices_per_user: body.max_devices_per_user,
            audit_retention_days: body.audit_retention_days,
            offline_unknown_sec: body.offline_unknown_sec,
            state_report_period_sec: body.state_report_period_sec,
            admin_groups: body.admin_groups,
            rate_limits: body.rate_limits,
        },
    )
    .await?;

    Ok(ApiEnvelope::ok(updated, req_id))
}

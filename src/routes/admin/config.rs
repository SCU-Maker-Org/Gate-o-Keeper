use crate::audit::AuditEvent;
use crate::auth::{authenticate_request, evict_excess_devices_for_user};
use crate::config::{RateLimitConfig, RateLimitRule, SystemConfig};
use crate::error::{ApiEnvelope, AppError, AppResult};
use crate::routes::{extract_request_id, require_admin, ClientIp};
use crate::state::AppState;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use serde::Deserialize;

pub async fn get_config(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<ApiEnvelope<SystemConfig>>> {
    let req_id = extract_request_id(&headers);
    let auth = authenticate_request(&state, &headers)
        .await
        .map_err(|e| e.with_request_id(&req_id))?;
    require_admin(&auth, &req_id)?;

    let cfg = state.db.get_system_config().await?;
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

fn validate_rate_limit_rule(name: &str, rule: &RateLimitRule, req_id: &str) -> AppResult<()> {
    if !(1..=100_000).contains(&rule.max) {
        return Err(AppError::invalid(format!(
            "rateLimits.{name}.max must be between 1 and 100000"
        ))
        .with_request_id(req_id));
    }
    if !(1..=86_400).contains(&rule.window_sec) {
        return Err(AppError::invalid(format!(
            "rateLimits.{name}.windowSec must be between 1 and 86400"
        ))
        .with_request_id(req_id));
    }
    Ok(())
}

pub async fn update_config(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Json(body): Json<UpdateConfigRequest>,
) -> AppResult<Json<ApiEnvelope<SystemConfig>>> {
    let req_id = extract_request_id(&headers);
    let auth = authenticate_request(&state, &headers)
        .await
        .map_err(|e| e.with_request_id(&req_id))?;
    require_admin(&auth, &req_id)?;

    let mut updates: Vec<(&'static str, String)> = Vec::new();
    if let Some(v) = body.unlock_replay_window_sec {
        if !(10..=3600).contains(&v) {
            return Err(
                AppError::invalid("unlockReplayWindowSec must be between 10 and 3600")
                    .with_request_id(&req_id),
            );
        }
        updates.push(("unlock_replay_window_sec", v.to_string()));
    }
    if let Some(v) = body.command_timeout_ms {
        if !(1000..=60_000).contains(&v) {
            return Err(
                AppError::invalid("commandTimeoutMs must be between 1000 and 60000")
                    .with_request_id(&req_id),
            );
        }
        updates.push(("command_timeout_ms", v.to_string()));
    }
    if let Some(v) = body.max_devices_per_user {
        if !(1..=50).contains(&v) {
            return Err(
                AppError::invalid("maxDevicesPerUser must be between 1 and 50")
                    .with_request_id(&req_id),
            );
        }
        updates.push(("max_devices_per_user", v.to_string()));
    }
    if let Some(v) = body.audit_retention_days {
        if !(1..=3650).contains(&v) {
            return Err(
                AppError::invalid("auditRetentionDays must be between 1 and 3650")
                    .with_request_id(&req_id),
            );
        }
        updates.push(("audit_retention_days", v.to_string()));
    }
    if let Some(v) = body.offline_unknown_sec {
        if !(30..=86_400).contains(&v) {
            return Err(
                AppError::invalid("offlineUnknownSec must be between 30 and 86400")
                    .with_request_id(&req_id),
            );
        }
        updates.push(("offline_unknown_sec", v.to_string()));
    }
    if let Some(v) = body.state_report_period_sec {
        if !(10..=3600).contains(&v) {
            return Err(
                AppError::invalid("stateReportPeriodSec must be between 10 and 3600")
                    .with_request_id(&req_id),
            );
        }
        updates.push(("state_report_period_sec", v.to_string()));
    }
    let mut updated_admin_groups: Option<Vec<String>> = None;
    if let Some(groups) = body.admin_groups {
        let normalized: Vec<String> = groups
            .into_iter()
            .map(|g| g.trim().to_string())
            .filter(|g| !g.is_empty())
            .collect();
        if normalized.is_empty() {
            return Err(
                AppError::invalid("adminGroups must contain at least one non-empty group")
                    .with_request_id(&req_id),
            );
        }
        let json = serde_json::to_string(&normalized)
            .map_err(|_| AppError::invalid("invalid adminGroups").with_request_id(&req_id))?;
        updates.push(("admin_groups", json));
        updated_admin_groups = Some(normalized);
    }
    if let Some(ref rl) = body.rate_limits {
        for (name, rule) in [
            ("unlockUser", &rl.unlock_user),
            ("unlockIp", &rl.unlock_ip),
            ("ssoExchangeIp", &rl.sso_exchange_ip),
            ("adapterRegisterId", &rl.adapter_register_id),
            ("adapterRegisterIp", &rl.adapter_register_ip),
            ("adapterStatusId", &rl.adapter_status_id),
            ("adapterStatusIp", &rl.adapter_status_ip),
            ("mqttConnClient", &rl.mqtt_conn_client),
        ] {
            validate_rate_limit_rule(name, rule, &req_id)?;
        }
        let json = serde_json::to_string(rl)
            .map_err(|_| AppError::invalid("invalid rateLimits").with_request_id(&req_id))?;
        updates.push(("rate_limits", json));
    }

    let now = chrono::Utc::now().timestamp();
    if !updates.is_empty() {
        let mut tx = state.db.pool.begin().await?;
        for (key, value) in &updates {
            sqlx::query(
                "INSERT INTO system_config (key, value_json, updated_at)
                 VALUES (?, ?, ?)
                 ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at",
            )
            .bind(*key)
            .bind(value)
            .bind(now)
            .execute(&mut *tx)
            .await?;
        }
        if let Some(ref admin_groups) = updated_admin_groups {
            let users: Vec<(String, String, String)> =
                sqlx::query_as("SELECT id, groups_json, role FROM users")
                    .fetch_all(&mut *tx)
                    .await?;
            for (uid, groups_json, current_role) in users {
                let user_groups: Vec<String> =
                    serde_json::from_str(&groups_json).unwrap_or_default();
                let new_role = if user_groups
                    .iter()
                    .any(|g| admin_groups.iter().any(|ag| ag == g))
                {
                    "admin"
                } else {
                    "user"
                };
                if new_role != current_role {
                    sqlx::query("UPDATE users SET role = ? WHERE id = ?")
                        .bind(new_role)
                        .bind(&uid)
                        .execute(&mut *tx)
                        .await?;
                }
            }
        }
        tx.commit().await?;
    }

    if let Some(v) = body.max_devices_per_user {
        let user_ids: Vec<(String,)> =
            sqlx::query_as("SELECT DISTINCT user_id FROM user_devices WHERE status = 'online'")
                .fetch_all(&state.db.pool)
                .await?;
        for (uid,) in user_ids {
            evict_excess_devices_for_user(&state, &uid, v, now).await?;
        }
    }

    let updated = state.db.get_system_config().await?;
    if body.state_report_period_sec.is_some() {
        let online_ids: Vec<(String,)> = sqlx::query_as(
            "SELECT id FROM adapters WHERE approval_status = 'approved' AND online_status = 'online'",
        )
        .fetch_all(&state.db.pool)
        .await?;
        let mqtt = state.mqtt.clone();
        let period = updated.state_report_period_sec;
        tokio::spawn(async move {
            for (adapter_id,) in online_ids {
                let msg_id = format!("cfg_{}", uuid::Uuid::new_v4().simple());
                let _ = mqtt.publish_set_config(&adapter_id, &msg_id, period).await;
            }
        });
    }
    state.audit.record(AuditEvent {
        actor_type: "admin".into(),
        actor_id: auth.user.id,
        action: "update_config".into(),
        target_type: "system_config".into(),
        target_id: "global".into(),
        result: "success".into(),
        detail: serde_json::to_value(&updated).unwrap_or(serde_json::Value::Null),
        ip,
        request_id: req_id.clone(),
    });

    Ok(ApiEnvelope::ok(updated, req_id))
}

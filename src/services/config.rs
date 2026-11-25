use super::auth::evict_excess_devices_for_user;
use crate::config::{RateLimitConfig, RateLimitRule, SystemConfig};
use crate::error::{AppError, AppResult};
use crate::state::AppState;

pub struct UpdateConfigInput {
    pub unlock_replay_window_sec: Option<i64>,
    pub command_timeout_ms: Option<u64>,
    pub max_devices_per_user: Option<i64>,
    pub audit_retention_days: Option<i64>,
    pub offline_unknown_sec: Option<i64>,
    pub state_report_period_sec: Option<i64>,
    pub admin_groups: Option<Vec<String>>,
    pub rate_limits: Option<RateLimitConfig>,
}

fn validate_range<T: Ord + std::fmt::Display>(
    val: Option<T>,
    min: T,
    max: T,
    field: &str,
    db_key: &'static str,
    updates: &mut Vec<(&'static str, String)>,
) -> AppResult<()> {
    if let Some(v) = val {
        if v < min || v > max {
            return Err(AppError::invalid(format!(
                "{field} must be between {min} and {max}"
            )));
        }
        updates.push((db_key, v.to_string()));
    }
    Ok(())
}

fn validate_rate_limit_rule(name: &str, rule: &RateLimitRule) -> AppResult<()> {
    if !(1..=100_000).contains(&rule.max) {
        return Err(AppError::invalid(format!(
            "rateLimits.{name}.max must be between 1 and 100000"
        )));
    }
    if !(1..=86_400).contains(&rule.window_sec) {
        return Err(AppError::invalid(format!(
            "rateLimits.{name}.windowSec must be between 1 and 86400"
        )));
    }
    Ok(())
}

pub async fn get_config(state: &AppState) -> AppResult<SystemConfig> {
    state.db.get_system_config().await
}

pub async fn update_config(
    state: &AppState,
    admin_id: &str,
    ip: &str,
    req_id: &str,
    input: UpdateConfigInput,
) -> AppResult<SystemConfig> {
    let mut updates: Vec<(&'static str, String)> = Vec::new();
    validate_range(
        input.unlock_replay_window_sec,
        10,
        3600,
        "unlockReplayWindowSec",
        "unlock_replay_window_sec",
        &mut updates,
    )?;
    validate_range(
        input.command_timeout_ms,
        1000,
        60_000,
        "commandTimeoutMs",
        "command_timeout_ms",
        &mut updates,
    )?;
    validate_range(
        input.max_devices_per_user,
        1,
        50,
        "maxDevicesPerUser",
        "max_devices_per_user",
        &mut updates,
    )?;
    validate_range(
        input.audit_retention_days,
        1,
        3650,
        "auditRetentionDays",
        "audit_retention_days",
        &mut updates,
    )?;
    validate_range(
        input.offline_unknown_sec,
        30,
        86_400,
        "offlineUnknownSec",
        "offline_unknown_sec",
        &mut updates,
    )?;
    validate_range(
        input.state_report_period_sec,
        10,
        3600,
        "stateReportPeriodSec",
        "state_report_period_sec",
        &mut updates,
    )?;

    let mut updated_admin_groups: Option<Vec<String>> = None;
    if let Some(groups) = input.admin_groups {
        let normalized: Vec<String> = groups
            .into_iter()
            .map(|g| g.trim().to_string())
            .filter(|g| !g.is_empty())
            .collect();
        if normalized.is_empty() {
            return Err(AppError::invalid(
                "adminGroups must contain at least one non-empty group",
            ));
        }
        let json = serde_json::to_string(&normalized)
            .map_err(|_| AppError::invalid("invalid adminGroups"))?;
        updates.push(("admin_groups", json));
        updated_admin_groups = Some(normalized);
    }

    if let Some(ref rl) = input.rate_limits {
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
            validate_rate_limit_rule(name, rule)?;
        }
        let json =
            serde_json::to_string(rl).map_err(|_| AppError::invalid("invalid rateLimits"))?;
        updates.push(("rate_limits", json));
    }

    let now = chrono::Utc::now().timestamp();
    let changed = !updates.is_empty();
    if changed {
        state
            .db
            .apply_config_updates(&updates, updated_admin_groups.as_deref(), now)
            .await?;
    }

    if let Some(v) = input.max_devices_per_user {
        let user_ids = state.db.list_online_device_user_ids().await?;
        for uid in user_ids {
            evict_excess_devices_for_user(state, &uid, v, now).await?;
        }
    }

    let updated = state.db.get_system_config().await?;
    if input.state_report_period_sec.is_some() {
        let online_ids = state.db.list_online_approved_adapter_ids().await?;
        let mqtt = state.mqtt.clone();
        let period = updated.state_report_period_sec;
        tokio::spawn(async move {
            for adapter_id in online_ids {
                let msg_id = format!("cfg_{}", uuid::Uuid::new_v4().simple());
                let _ = mqtt.publish_set_config(&adapter_id, &msg_id, period).await;
            }
        });
    }
    if changed {
        state.audit.record_admin(
            admin_id,
            "update_config",
            "system_config",
            "global",
            serde_json::to_value(&updated).unwrap_or(serde_json::Value::Null),
            ip,
            req_id,
        );
    }

    Ok(updated)
}

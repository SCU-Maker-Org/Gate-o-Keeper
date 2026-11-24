//! Business Logic Layer: orchestrates domain rules, views, and cross-component workflows
//! across database repositories, Redis, MQTT, OIDC, and asynchronous audit logging.

pub mod adapter;
pub mod audit;
pub mod auth;
pub mod config;
pub mod lock;
pub mod users;

use crate::config::SystemConfig;
use crate::error::{AppError, AppResult};
use crate::infra::db::{AdapterRow, LockRow};
use crate::state::AppState;
use serde::Serialize;
use sha2::{Digest, Sha256};

pub use crate::utils::is_valid_identifier;

/// Checks database and Redis connectivity for `/healthz`.
pub async fn health_check(state: &AppState) -> AppResult<()> {
    state.db.ping().await?;
    state.redis.ping().await?;
    Ok(())
}

/// Maps optional `lock_id` / `adapter_id` to `(target_type, target_id)` for audit logs.
pub fn target_ref(lock_id: Option<&str>, adapter_id: &str) -> (&'static str, String) {
    match lock_id {
        Some(lid) => ("lock", lid.to_string()),
        None => ("adapter", adapter_id.to_string()),
    }
}

/// Derives a short stable display fingerprint from adapter id and token hash.
pub fn adapter_fingerprint(id: &str, token_hash: &str) -> String {
    if token_hash.is_empty() {
        return String::new();
    }
    let mut h = Sha256::new();
    h.update(id.as_bytes());
    h.update(b":");
    h.update(token_hash.as_bytes());
    hex::encode(h.finalize()).chars().take(16).collect()
}

pub(crate) fn require_non_empty_reason<'a>(raw: &'a str, req_id: &str) -> AppResult<&'a str> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(AppError::invalid("reason is required").with_request_id(req_id));
    }
    Ok(trimmed)
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdapterStatusView {
    pub adapter_id: String,
    pub name: String,
    pub state: String,
    pub state_reported_at: Option<i64>,
    pub online: bool,
    pub stale: bool,
}

pub fn compute_adapter_view(
    adapter: &AdapterRow,
    cfg: &SystemConfig,
    now: i64,
) -> AdapterStatusView {
    let online = adapter.online_status == "online";
    let display_name = if adapter.name.trim().is_empty() {
        adapter.id.clone()
    } else {
        adapter.name.clone()
    };

    let effective_state = if !online {
        let offline_too_long = match adapter.last_seen_at {
            Some(ts) => now - ts > cfg.offline_unknown_sec,
            None => true,
        };
        if offline_too_long {
            "unknown".to_string()
        } else {
            adapter.reported_state.clone()
        }
    } else {
        adapter.reported_state.clone()
    };

    let stale = if online {
        match adapter.state_reported_at {
            Some(ts) => now - ts > cfg.state_report_period_sec * 2,
            None => true,
        }
    } else {
        false
    };

    AdapterStatusView {
        adapter_id: adapter.id.clone(),
        name: display_name,
        state: effective_state,
        state_reported_at: adapter.state_reported_at,
        online,
        stale,
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LockStatusView {
    pub lock_id: String,
    pub name: String,
    pub description: String,
    pub bound: bool,
    pub adapter_id: Option<String>,
    pub adapter_name: Option<String>,
    pub state: String,
    pub state_reported_at: Option<i64>,
    pub online: bool,
    pub stale: bool,
}

pub fn compute_lock_view(
    lock: &LockRow,
    adapter: Option<&AdapterRow>,
    cfg: &SystemConfig,
    now: i64,
) -> LockStatusView {
    match adapter {
        Some(ad) => {
            let av = compute_adapter_view(ad, cfg, now);
            let approved = ad.approval_status == "approved";
            LockStatusView {
                lock_id: lock.id.clone(),
                name: lock.name.clone(),
                description: lock.description.clone(),
                bound: true,
                adapter_id: Some(ad.id.clone()),
                adapter_name: Some(av.name),
                state: if approved {
                    av.state
                } else {
                    "unknown".to_string()
                },
                state_reported_at: ad.state_reported_at,
                online: approved && av.online,
                stale: approved && av.stale,
            }
        }
        None => LockStatusView {
            lock_id: lock.id.clone(),
            name: lock.name.clone(),
            description: lock.description.clone(),
            bound: false,
            adapter_id: None,
            adapter_name: None,
            state: "unknown".to_string(),
            state_reported_at: None,
            online: false,
            stale: false,
        },
    }
}

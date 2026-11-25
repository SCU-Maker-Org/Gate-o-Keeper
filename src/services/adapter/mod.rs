//! Adapter business workflows: HTTP bootstrap, EMQX auth/ACL, MQTT event processing, and admin lifecycle.

pub mod admin;
pub mod bootstrap;
pub mod emqx_auth;
pub mod mqtt_events;

use crate::domain::{ApprovalStatus, DoorState, OnlineStatus};
use serde::Serialize;

pub const PENDING_TOKEN_TTL_SEC: i64 = 600;

pub struct RegisterAdapterInput<'a> {
    pub adapter_id: &'a str,
    pub token: &'a str,
    pub name: &'a str,
    pub model: &'a str,
    pub fw_version: &'a str,
    pub cert_pem: &'a str,
    pub ts: i64,
    pub signature: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterAdapterResponse {
    pub adapter_id: String,
    pub approval_status: ApprovalStatus,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdapterStatusResponse {
    pub adapter_id: String,
    pub approval_status: ApprovalStatus,
    pub mqtt_endpoint: String,
    pub state_report_period_sec: i64,
}

pub struct MqttAuthDecision {
    pub allow: bool,
    pub is_superuser: Option<bool>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminAdapterView {
    pub id: String,
    pub name: String,
    pub fingerprint: String,
    pub approval_status: ApprovalStatus,
    pub online_status: OnlineStatus,
    pub state: DoorState,
    pub state_reported_at: Option<i64>,
    pub stale: bool,
    pub bound_lock_id: Option<String>,
    pub bound_lock_name: Option<String>,
    pub model: String,
    pub fw_version: String,
    pub token_refresh_interval: i64,
    pub last_seen_at: Option<i64>,
    pub approved_by: Option<String>,
    pub approved_at: Option<i64>,
    pub created_at: i64,
}

pub struct RevokeResetOutcome {
    pub unbound_lock_ids: Vec<String>,
}

pub use admin::{
    admin_unlock_adapter, approve_adapter, delete_adapter, list_admin_adapters,
    refresh_adapter_state, refresh_adapter_token, reject_adapter, reset_adapter, revoke_adapter,
    update_adapter,
};
pub use bootstrap::{get_adapter_status, register_adapter};
pub use emqx_auth::{authenticate_mqtt, authorize_mqtt_acl};
pub use mqtt_events::{
    expire_stale_pending_tokens, handle_mqtt_adapter_ack, handle_mqtt_adapter_presence,
    handle_mqtt_adapter_result, handle_mqtt_adapter_state, handle_mqtt_client_connected,
    handle_mqtt_client_disconnected, query_due_rotation_adapters, run_due_token_rotations,
    spawn_background_workers, stage_and_send_token_refresh,
};

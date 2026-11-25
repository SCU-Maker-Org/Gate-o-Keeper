//! Lock business workflows: command dispatch, member access/unlock, and admin lock management.

pub mod admin;
pub mod dispatch;
pub mod user;

use crate::domain::{
    ApprovalStatus, AuditActorType, DoorState, OnlineStatus, UnlockStatus, UserRole,
};
use serde::Serialize;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MeLockItem {
    pub id: String,
    pub name: String,
    pub description: String,
    pub bound: bool,
    pub adapter_id: Option<String>,
    pub adapter_name: Option<String>,
    pub state: DoorState,
    pub state_reported_at: Option<i64>,
    pub online: bool,
    pub stale: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MeResponse {
    pub user_id: String,
    pub display_name: String,
    pub role: UserRole,
    pub groups: Vec<String>,
    pub locks: Vec<MeLockItem>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnlockResponse {
    pub status: UnlockStatus,
    pub device_code: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminLockView {
    pub id: String,
    pub name: String,
    pub description: String,
    pub bound: bool,
    pub adapter_id: Option<String>,
    pub adapter_name: Option<String>,
    pub adapter_approval_status: Option<ApprovalStatus>,
    pub adapter_online_status: Option<OnlineStatus>,
    pub state: DoorState,
    pub state_reported_at: Option<i64>,
    pub online: bool,
    pub stale: bool,
    pub groups: Vec<String>,
    pub created_by: String,
    pub created_at: i64,
    pub updated_at: i64,
}

pub struct UnlockAuditContext<'a> {
    pub lock_id: Option<&'a str>,
    pub actor_type: AuditActorType,
    pub actor_id: &'a str,
    pub ip: &'a str,
    pub req_id: &'a str,
    pub reason: Option<&'a str>,
}

pub use admin::{
    admin_unlock_lock, bind_admin_lock, create_admin_lock, delete_admin_lock, get_lock_groups,
    list_admin_locks, refresh_lock_state, set_lock_groups, update_admin_lock,
};
pub use dispatch::{dispatch_unlock_command, execute_admin_refresh_state, execute_admin_unlock};
pub use user::{get_me, get_user_lock_status, user_unlock};

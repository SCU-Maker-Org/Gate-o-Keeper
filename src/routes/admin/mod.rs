mod adapters;
mod audit;
mod config;
mod locks;
mod users;

use serde::Deserialize;

pub use adapters::{
    admin_unlock, approve_adapter, delete_adapter, list_adapters, refresh_adapter_state,
    refresh_adapter_token, reject_adapter, reset_adapter, revoke_adapter, update_adapter,
    AdapterFilterQuery, UpdateAdapterRequest,
};
pub use audit::{list_audit_logs, AuditQuery};
pub use config::{get_config, update_config, UpdateConfigRequest};
pub use locks::{
    admin_unlock_lock, bind_lock, create_lock, delete_lock, get_lock_groups, list_locks,
    refresh_lock_state, set_lock_groups, update_lock, BindLockRequest, CreateLockRequest,
    SetLockGroupsRequest, UpdateLockRequest,
};
pub use users::{kick_user, list_users};

#[derive(Deserialize)]
pub struct ReasonBody {
    pub reason: String,
}

use super::{UnlockAuditContext, UnlockResponse};
use crate::error::{AppError, AppResult, ErrorCode};
use crate::infra::db::AdapterRow;
use crate::infra::mqtt::UnlockResultPayload;
use crate::infra::redis::RedisStore;
use crate::services::target_ref;
use crate::state::AppState;
use std::time::Duration;

/// Extra wait beyond the device-side command validity so a result sent right at the
/// deadline is not misreported as a timeout.
const REPLY_GRACE_MS: u64 = 2000;

struct AdapterMutexGuard {
    redis: RedisStore,
    adapter_id: String,
    msg_id: String,
    armed: bool,
}

impl AdapterMutexGuard {
    async fn release(mut self) {
        self.armed = false;
        let _ = self
            .redis
            .release_adapter_mutex(&self.adapter_id, &self.msg_id)
            .await;
    }
}

impl Drop for AdapterMutexGuard {
    fn drop(&mut self) {
        if self.armed {
            let redis = self.redis.clone();
            let adapter_id = std::mem::take(&mut self.adapter_id);
            let msg_id = std::mem::take(&mut self.msg_id);
            tokio::spawn(async move {
                let _ = redis.release_adapter_mutex(&adapter_id, &msg_id).await;
            });
        }
    }
}

pub(crate) fn record_unlock_failure(
    state: &AppState,
    ctx: &UnlockAuditContext<'_>,
    adapter_id: Option<&str>,
    err: &AppError,
) {
    let fallback_id = ctx.lock_id.unwrap_or("");
    let (target_type, target_id) = match adapter_id {
        Some(aid) => target_ref(ctx.lock_id, aid),
        None => ("lock", fallback_id.to_string()),
    };
    let mut detail = serde_json::json!({
        "errorCode": err.code.as_str(),
        "errorMessage": err.message,
    });
    if let Some(reason) = ctx.reason {
        detail["reason"] = serde_json::json!(reason);
    }
    if ctx.lock_id.is_some() {
        if let Some(aid) = adapter_id {
            detail["adapterId"] = serde_json::json!(aid);
        }
    }
    state.audit.record_event(
        ctx.actor_type,
        ctx.actor_id,
        if ctx.actor_type == "admin" {
            "admin_unlock"
        } else {
            "unlock"
        },
        target_type,
        target_id,
        "failed",
        detail,
        ctx.ip,
        ctx.req_id,
    );
}

/// Acquires the adapter mutex, publishes QoS 2 unlock command, awaits reply, and records audit log.
pub async fn dispatch_unlock_command(
    state: &AppState,
    adapter: &AdapterRow,
    ctx: UnlockAuditContext<'_>,
) -> AppResult<UnlockResponse> {
    let res = dispatch_unlock_command_inner(state, adapter, &ctx).await;
    if let Err(ref err) = res {
        record_unlock_failure(state, &ctx, Some(&adapter.id), err);
    }
    res
}

async fn dispatch_unlock_command_inner(
    state: &AppState,
    adapter: &AdapterRow,
    ctx: &UnlockAuditContext<'_>,
) -> AppResult<UnlockResponse> {
    let UnlockAuditContext {
        lock_id,
        actor_type,
        actor_id,
        ip,
        req_id,
        reason,
    } = *ctx;
    if adapter.approval_status != "approved" || adapter.online_status != "online" {
        return Err(AppError::new(
            ErrorCode::AdapterOffline,
            "adapter is offline",
        ));
    }

    let cfg = state.db.get_system_config().await?;
    let timeout_ms = cfg.command_timeout_ms.max(1000);
    let msg_id = format!("msg_{}", uuid::Uuid::new_v4().simple());

    if !state
        .redis
        .acquire_adapter_mutex(&adapter.id, &msg_id, timeout_ms + REPLY_GRACE_MS + 5000)
        .await?
    {
        return Err(AppError::new(
            ErrorCode::AdapterBusy,
            "adapter has an in-flight command",
        ));
    }

    let mutex_guard = AdapterMutexGuard {
        redis: state.redis.clone(),
        adapter_id: adapter.id.clone(),
        msg_id: msg_id.clone(),
        armed: true,
    };

    // Subscribe to reply channel BEFORE publishing command to avoid race condition.
    let pubsub = state
        .redis
        .subscribe_cmd_reply(&adapter.id, &msg_id)
        .await?;

    state
        .mqtt
        .publish_unlock(&adapter.id, &msg_id, timeout_ms)
        .await?;

    let reply_raw =
        RedisStore::wait_cmd_reply(pubsub, Duration::from_millis(timeout_ms + REPLY_GRACE_MS))
            .await;
    mutex_guard.release().await;

    let (status_str, audit_result, device_code) = match reply_raw {
        Ok(Some(json_str)) => {
            if let Ok(parsed) = serde_json::from_str::<UnlockResultPayload>(&json_str) {
                if parsed.ok {
                    (
                        "success".to_string(),
                        "success".to_string(),
                        Some(parsed.code),
                    )
                } else {
                    (
                        "failed".to_string(),
                        "failed".to_string(),
                        Some(parsed.code),
                    )
                }
            } else {
                (
                    "failed".to_string(),
                    "failed".to_string(),
                    Some("BAD_PAYLOAD".into()),
                )
            }
        }
        Ok(None) => ("timeout".to_string(), "timeout".to_string(), None),
        Err(e) => {
            tracing::error!(error = %e.message, "wait_cmd_reply failed");
            ("timeout".to_string(), "timeout".to_string(), None)
        }
    };

    let (target_type, target_id) = target_ref(lock_id, &adapter.id);

    state.audit.record_event(
        actor_type,
        actor_id,
        if actor_type == "admin" {
            "admin_unlock"
        } else {
            "unlock"
        },
        target_type,
        target_id,
        &audit_result,
        serde_json::json!({
            "msgId": msg_id,
            "adapterId": adapter.id,
            "deviceCode": device_code,
            "reason": reason,
        }),
        ip,
        req_id,
    );

    Ok(UnlockResponse {
        status: status_str,
        device_code,
    })
}

pub async fn execute_admin_unlock(
    state: &AppState,
    adapter: &AdapterRow,
    lock_id: Option<&str>,
    admin_user_id: &str,
    ip: &str,
    req_id: &str,
    reason: &str,
) -> AppResult<UnlockResponse> {
    dispatch_unlock_command(
        state,
        adapter,
        UnlockAuditContext {
            lock_id,
            actor_type: "admin",
            actor_id: admin_user_id,
            ip,
            req_id,
            reason: Some(reason),
        },
    )
    .await
}

pub async fn execute_admin_refresh_state(
    state: &AppState,
    adapter: &AdapterRow,
    lock_id: Option<&str>,
    admin_user_id: &str,
    ip: &str,
    req_id: &str,
) -> AppResult<String> {
    if adapter.approval_status != "approved" || adapter.online_status != "online" {
        return Err(AppError::new(
            ErrorCode::AdapterOffline,
            "adapter is offline",
        ));
    }

    let msg_id = format!("msg_{}", uuid::Uuid::new_v4().simple());
    state
        .mqtt
        .publish_query_state(&adapter.id, &msg_id)
        .await?;

    let (target_type, target_id) = target_ref(lock_id, &adapter.id);
    let mut detail = serde_json::json!({ "msgId": msg_id });
    if lock_id.is_some() {
        detail["adapterId"] = serde_json::json!(adapter.id);
    }
    state.audit.record_admin(
        admin_user_id,
        "admin_refresh_state",
        target_type,
        target_id,
        detail,
        ip,
        req_id,
    );

    Ok(msg_id)
}

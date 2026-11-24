use crate::audit::AuditEvent;
use crate::auth::authenticate_request;
use crate::db::AdapterRow;
use crate::error::{AppError, AppResult, ApiEnvelope, ErrorCode};
use crate::mqtt::UnlockResultPayload;
use crate::redis_store::RedisStore;
use crate::routes::{
    compute_lock_view, extract_request_id, is_valid_identifier, target_ref, ClientIp,
    LockStatusView,
};
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::Json;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthResponse {
    pub status: &'static str,
}

pub async fn healthz(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<ApiEnvelope<HealthResponse>>> {
    let req_id = extract_request_id(&headers);
    sqlx::query("SELECT 1")
        .execute(&state.db.pool)
        .await
        .map_err(|e| AppError::from(e).with_request_id(&req_id))?;

    state
        .redis
        .ping()
        .await
        .map_err(|e| e.with_request_id(&req_id))?;

    Ok(ApiEnvelope::ok(HealthResponse { status: "ok" }, req_id))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MeLockItem {
    pub id: String,
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MeResponse {
    pub user_id: String,
    pub display_name: String,
    pub role: String,
    pub groups: Vec<String>,
    pub locks: Vec<MeLockItem>,
}

pub async fn me(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<ApiEnvelope<MeResponse>>> {
    let req_id = extract_request_id(&headers);
    let auth = authenticate_request(&state, &headers)
        .await
        .map_err(|e| e.with_request_id(&req_id))?;

    let cfg = state
        .db
        .get_system_config()
        .await
        .map_err(|e| e.with_request_id(&req_id))?;
    let all_locks = state
        .db
        .list_locks()
        .await
        .map_err(|e| e.with_request_id(&req_id))?;
    let adapters_map = state
        .db
        .list_all_adapters_map()
        .await
        .map_err(|e| e.with_request_id(&req_id))?;
    let lock_groups_map = state
        .db
        .list_all_lock_groups_map()
        .await
        .map_err(|e| e.with_request_id(&req_id))?;

    let is_admin = auth.user.role == "admin";
    let user_groups = auth.user.groups();
    let now = chrono::Utc::now().timestamp();
    let mut accessible = Vec::new();
    for lock in all_locks {
        let allowed = is_admin
            || lock_groups_map
                .get(&lock.id)
                .is_some_and(|rules| user_groups.iter().any(|ug| rules.iter().any(|ag| ag == ug)));
        if !allowed {
            continue;
        }
        let adapter = lock
            .adapter_id
            .as_deref()
            .and_then(|aid| adapters_map.get(aid));
        let view = compute_lock_view(&lock, adapter, &cfg, now);
        accessible.push(MeLockItem {
            id: view.lock_id,
            name: view.name,
            description: view.description,
            bound: view.bound,
            adapter_id: view.adapter_id,
            adapter_name: view.adapter_name,
            state: view.state,
            state_reported_at: view.state_reported_at,
            online: view.online,
            stale: view.stale,
        });
    }

    Ok(ApiEnvelope::ok(
        MeResponse {
            user_id: auth.user.id.clone(),
            display_name: auth.user.display_name.clone(),
            role: auth.user.role.clone(),
            groups: auth.user.groups(),
            locks: accessible,
        },
        req_id,
    ))
}

pub async fn lock_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(lock_id): Path<String>,
) -> AppResult<Json<ApiEnvelope<LockStatusView>>> {
    let req_id = extract_request_id(&headers);
    let auth = authenticate_request(&state, &headers)
        .await
        .map_err(|e| e.with_request_id(&req_id))?;

    let lock = state
        .db
        .find_lock_by_id(&lock_id)
        .await?
        .ok_or_else(|| {
            AppError::new(ErrorCode::LockNotFound, "lock not found").with_request_id(&req_id)
        })?;

    if !state.db.user_has_lock_access(&auth.user, &lock.id).await? {
        return Err(
            AppError::new(ErrorCode::LockForbidden, "no group permission for this lock")
                .with_request_id(&req_id),
        );
    }

    let adapter = match lock.adapter_id.as_deref() {
        Some(aid) => state.db.find_adapter_by_id(aid).await?,
        None => None,
    };
    let cfg = state.db.get_system_config().await?;
    let now = chrono::Utc::now().timestamp();

    Ok(ApiEnvelope::ok(
        compute_lock_view(&lock, adapter.as_ref(), &cfg, now),
        req_id,
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnlockRequest {
    pub lock_id: String,
    pub nonce: String,
    pub ts: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnlockResponse {
    pub status: String,
    pub device_code: Option<String>,
}

pub async fn unlock(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Json(body): Json<UnlockRequest>,
) -> AppResult<Json<ApiEnvelope<UnlockResponse>>> {
    let req_id = extract_request_id(&headers);
    let auth = authenticate_request(&state, &headers)
        .await
        .map_err(|e| e.with_request_id(&req_id))?;

    let lock_id = body.lock_id.trim();
    let nonce = body.nonce.trim();
    if !is_valid_identifier(lock_id, 1, 64) || !is_valid_identifier(nonce, 8, 128) {
        return Err(AppError::invalid("invalid lockId or nonce").with_request_id(&req_id));
    }

    let cfg = state.db.get_system_config().await?;
    if !state
        .redis
        .check_rate_limit(
            &format!("unlock:user:{}", auth.user.id),
            cfg.rate_limits.unlock_user.max,
            cfg.rate_limits.unlock_user.window_sec,
        )
        .await?
        || !state
            .redis
            .check_rate_limit(
                &format!("unlock:ip:{ip}"),
                cfg.rate_limits.unlock_ip.max,
                cfg.rate_limits.unlock_ip.window_sec,
            )
            .await?
    {
        return Err(
            AppError::new(ErrorCode::RateLimited, "rate limit exceeded").with_request_id(&req_id),
        );
    }

    let now = chrono::Utc::now().timestamp();
    let window = cfg.unlock_replay_window_sec.max(10);
    if now.abs_diff(body.ts) > window as u64 {
        return Err(
            AppError::new(ErrorCode::ReplayRejected, "timestamp outside replay window")
                .with_request_id(&req_id),
        );
    }

    let nonce_ttl_sec = (window * 2 + 5) as u64;
    if !state
        .redis
        .claim_unlock_nonce(&auth.user.id, nonce, nonce_ttl_sec)
        .await?
    {
        return Err(
            AppError::new(ErrorCode::ReplayRejected, "duplicate nonce").with_request_id(&req_id),
        );
    }

    let lock = state
        .db
        .find_lock_by_id(lock_id)
        .await?
        .ok_or_else(|| {
            AppError::new(ErrorCode::LockNotFound, "lock not found").with_request_id(&req_id)
        })?;

    if !state.db.user_has_lock_access(&auth.user, &lock.id).await? {
        state.audit.record(AuditEvent {
            actor_type: "user".into(),
            actor_id: auth.user.id.clone(),
            action: "unlock".into(),
            target_type: "lock".into(),
            target_id: lock.id.clone(),
            result: "denied".into(),
            detail: serde_json::json!({ "reason": "group_forbidden" }),
            ip,
            request_id: req_id.clone(),
        });
        return Err(
            AppError::new(ErrorCode::LockForbidden, "no group permission for this lock")
                .with_request_id(&req_id),
        );
    }

    let adapter_id = lock.adapter_id.as_deref().ok_or_else(|| {
        AppError::new(ErrorCode::LockUnbound, "lock is not bound to an adapter")
            .with_request_id(&req_id)
    })?;

    let adapter = state
        .db
        .find_adapter_by_id(adapter_id)
        .await?
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::AdapterOffline,
                "bound adapter is not approved or missing",
            )
            .with_request_id(&req_id)
        })?;

    dispatch_unlock_command(
        &state,
        &adapter,
        UnlockAuditContext {
            lock_id: Some(&lock.id),
            actor_type: "user",
            actor_id: &auth.user.id,
            ip: &ip,
            req_id: &req_id,
            reason: None,
        },
    )
    .await
    .map(|resp| ApiEnvelope::ok(resp, req_id))
}

pub struct UnlockAuditContext<'a> {
    pub lock_id: Option<&'a str>,
    pub actor_type: &'a str,
    pub actor_id: &'a str,
    pub ip: &'a str,
    pub req_id: &'a str,
    pub reason: Option<&'a str>,
}

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

pub async fn dispatch_unlock_command(
    state: &AppState,
    adapter: &AdapterRow,
    ctx: UnlockAuditContext<'_>,
) -> AppResult<UnlockResponse> {
    let UnlockAuditContext {
        lock_id,
        actor_type,
        actor_id,
        ip,
        req_id,
        reason,
    } = ctx;
    if adapter.approval_status != "approved" || adapter.online_status != "online" {
        return Err(
            AppError::new(ErrorCode::AdapterOffline, "adapter is offline").with_request_id(req_id),
        );
    }

    let cfg = state.db.get_system_config().await?;
    let timeout_ms = cfg.command_timeout_ms.max(1000);
    let msg_id = format!("msg_{}", uuid::Uuid::new_v4().simple());

    if !state
        .redis
        .acquire_adapter_mutex(&adapter.id, &msg_id, timeout_ms + 5000)
        .await?
    {
        return Err(
            AppError::new(ErrorCode::AdapterBusy, "adapter has an in-flight command")
                .with_request_id(req_id),
        );
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
        .await
        .map_err(|e| e.with_request_id(req_id))?;

    state
        .mqtt
        .publish_unlock(&adapter.id, &msg_id, timeout_ms)
        .await
        .map_err(|e| e.with_request_id(req_id))?;

    let reply_raw = RedisStore::wait_cmd_reply(pubsub, Duration::from_millis(timeout_ms)).await;
    mutex_guard.release().await;

    let (status_str, audit_result, device_code) = match reply_raw {
        Ok(Some(json_str)) => {
            if let Ok(parsed) = serde_json::from_str::<UnlockResultPayload>(&json_str) {
                if parsed.ok {
                    ("success".to_string(), "success".to_string(), Some(parsed.code))
                } else {
                    ("failed".to_string(), "failed".to_string(), Some(parsed.code))
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

    state.audit.record(AuditEvent {
        actor_type: actor_type.to_string(),
        actor_id: actor_id.to_string(),
        action: if actor_type == "admin" {
            "admin_unlock".into()
        } else {
            "unlock".into()
        },
        target_type: target_type.to_string(),
        target_id,
        result: audit_result,
        detail: serde_json::json!({
            "msgId": msg_id,
            "adapterId": adapter.id,
            "deviceCode": device_code,
            "reason": reason,
        }),
        ip: ip.to_string(),
        request_id: req_id.to_string(),
    });

    Ok(UnlockResponse {
        status: status_str,
        device_code,
    })
}

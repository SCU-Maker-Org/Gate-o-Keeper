use crate::audit::AuditEvent;
use crate::auth::{authenticate_request, evict_excess_devices_for_user, hash_token};
use crate::config::{RateLimitConfig, RateLimitRule, SystemConfig};
use crate::db::{AdapterRow, AuditLogRow, LockRow, UserRow};
use crate::error::{AppError, AppResult, ApiEnvelope, ErrorCode};
use crate::routes::user::{dispatch_unlock_command, UnlockAuditContext, UnlockResponse};
use crate::routes::{
    compute_adapter_view, compute_lock_view, extract_request_id, is_valid_identifier,
    require_admin, ClientIp,
};
use crate::state::AppState;
use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::Json;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

fn adapter_fingerprint(id: &str, token_hash: &str) -> String {
    let mut h = Sha256::new();
    h.update(id.as_bytes());
    h.update(b":");
    h.update(token_hash.as_bytes());
    let hex_str = hex::encode(h.finalize());
    hex_str.chars().take(16).collect()
}

fn generate_random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdapterFilterQuery {
    pub approval_status: Option<String>,
    pub online_status: Option<String>,
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
    pub adapter_approval_status: Option<String>,
    pub adapter_online_status: Option<String>,
    pub state: String,
    pub state_reported_at: Option<i64>,
    pub online: bool,
    pub stale: bool,
    pub groups: Vec<String>,
    pub created_by: String,
    pub created_at: i64,
    pub updated_at: i64,
}

async fn build_admin_lock_view(
    state: &AppState,
    lock: &LockRow,
    cfg: &SystemConfig,
    now: i64,
) -> AppResult<AdminLockView> {
    let adapter = match lock.adapter_id.as_deref() {
        Some(aid) => state.db.find_adapter_by_id(aid).await?,
        None => None,
    };
    let view = compute_lock_view(lock, adapter.as_ref(), cfg, now);
    let groups = state.db.list_lock_groups(&lock.id).await?;
    Ok(AdminLockView {
        id: lock.id.clone(),
        name: lock.name.clone(),
        description: lock.description.clone(),
        bound: view.bound,
        adapter_id: view.adapter_id,
        adapter_name: view.adapter_name,
        adapter_approval_status: adapter.as_ref().map(|a| a.approval_status.clone()),
        adapter_online_status: adapter.as_ref().map(|a| a.online_status.clone()),
        state: view.state,
        state_reported_at: view.state_reported_at,
        online: view.online,
        stale: view.stale,
        groups,
        created_by: lock.created_by.clone(),
        created_at: lock.created_at,
        updated_at: lock.updated_at,
    })
}

pub async fn list_locks(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<ApiEnvelope<Vec<AdminLockView>>>> {
    let req_id = extract_request_id(&headers);
    let auth = authenticate_request(&state, &headers)
        .await
        .map_err(|e| e.with_request_id(&req_id))?;
    require_admin(&auth, &req_id)?;

    let cfg = state.db.get_system_config().await?;
    let locks = state.db.list_locks().await?;
    let now = chrono::Utc::now().timestamp();

    let mut out = Vec::with_capacity(locks.len());
    for lock in &locks {
        out.push(build_admin_lock_view(&state, lock, &cfg, now).await?);
    }

    Ok(ApiEnvelope::ok(out, req_id))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateLockRequest {
    pub id: Option<String>,
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub adapter_id: Option<String>,
    #[serde(default)]
    pub groups: Vec<String>,
}

pub async fn create_lock(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Json(body): Json<CreateLockRequest>,
) -> AppResult<Json<ApiEnvelope<AdminLockView>>> {
    let req_id = extract_request_id(&headers);
    let auth = authenticate_request(&state, &headers)
        .await
        .map_err(|e| e.with_request_id(&req_id))?;
    require_admin(&auth, &req_id)?;

    let lock_id = match body.id.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(id) => {
            if !is_valid_identifier(id, 1, 64) {
                return Err(
                    AppError::invalid("lock id must match [A-Za-z0-9_-]{1,64}")
                        .with_request_id(&req_id),
                );
            }
            id.to_string()
        }
        None => {
            let suffix: String = uuid::Uuid::new_v4()
                .simple()
                .to_string()
                .chars()
                .take(12)
                .collect();
            format!("lock_{suffix}")
        }
    };

    let name = body.name.trim();
    if name.is_empty() || name.len() > 128 {
        return Err(
            AppError::invalid("lock name must be 1..=128 chars").with_request_id(&req_id),
        );
    }
    let description = body.description.trim();
    if description.len() > 256 {
        return Err(
            AppError::invalid("description must be <= 256 chars").with_request_id(&req_id),
        );
    }

    let adapter_id = body
        .adapter_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned);

    let now = chrono::Utc::now().timestamp();
    let mut tx = state.db.pool.begin().await?;

    let existing_lock: Option<(String,)> =
        sqlx::query_as("SELECT id FROM locks WHERE id = ?")
            .bind(&lock_id)
            .fetch_optional(&mut *tx)
            .await?;
    if existing_lock.is_some() {
        return Err(AppError::conflict("lock id already exists").with_request_id(&req_id));
    }

    if let Some(ref aid) = adapter_id {
        let adapter: crate::db::AdapterRow = sqlx::query_as("SELECT * FROM adapters WHERE id = ?")
            .bind(aid)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| {
                AppError::new(ErrorCode::AdapterNotFound, "adapter not found")
                    .with_request_id(&req_id)
            })?;
        if adapter.approval_status != "approved" {
            return Err(
                AppError::conflict("only approved adapters can be bound to a lock")
                    .with_request_id(&req_id),
            );
        }
        let bound_lock: Option<(String,)> =
            sqlx::query_as("SELECT id FROM locks WHERE adapter_id = ?")
                .bind(aid)
                .fetch_optional(&mut *tx)
                .await?;
        if bound_lock.is_some() {
            return Err(
                AppError::conflict("adapter is already bound to another lock")
                    .with_request_id(&req_id),
            );
        }
    }

    let row_res: Result<LockRow, sqlx::Error> = sqlx::query_as(
        "INSERT INTO locks (id, name, description, adapter_id, created_by, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         RETURNING *",
    )
    .bind(&lock_id)
    .bind(name)
    .bind(description)
    .bind(&adapter_id)
    .bind(&auth.user.id)
    .bind(now)
    .bind(now)
    .fetch_one(&mut *tx)
    .await;

    let row = match row_res {
        Ok(row) => row,
        Err(sqlx::Error::Database(ref db_err)) if db_err.is_unique_violation() => {
            return Err(
                AppError::conflict("lock id or adapter binding already exists")
                    .with_request_id(&req_id),
            );
        }
        Err(err) => return Err(AppError::from(err).with_request_id(&req_id)),
    };

    if !body.groups.is_empty() {
        crate::db::Db::replace_lock_groups_tx(&mut tx, &row.id, &body.groups, &auth.user.id, now)
            .await?;
    }
    tx.commit().await?;

    state.audit.record(AuditEvent {
        actor_type: "admin".into(),
        actor_id: auth.user.id.clone(),
        action: "create_lock".into(),
        target_type: "lock".into(),
        target_id: row.id.clone(),
        result: "success".into(),
        detail: serde_json::json!({
            "name": row.name,
            "adapterId": row.adapter_id,
            "groups": body.groups,
        }),
        ip,
        request_id: req_id.clone(),
    });

    let cfg = state.db.get_system_config().await?;
    let view = build_admin_lock_view(&state, &row, &cfg, now).await?;
    Ok(ApiEnvelope::ok(view, req_id))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateLockRequest {
    pub name: Option<String>,
    pub description: Option<String>,
}

pub async fn update_lock(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<UpdateLockRequest>,
) -> AppResult<Json<ApiEnvelope<AdminLockView>>> {
    let req_id = extract_request_id(&headers);
    let auth = authenticate_request(&state, &headers)
        .await
        .map_err(|e| e.with_request_id(&req_id))?;
    require_admin(&auth, &req_id)?;

    let existing = state.db.find_lock_by_id(&id).await?.ok_or_else(|| {
        AppError::new(ErrorCode::LockNotFound, "lock not found").with_request_id(&req_id)
    })?;

    let new_name = match body.name {
        Some(n) => {
            let trimmed = n.trim();
            if trimmed.is_empty() || trimmed.len() > 128 {
                return Err(
                    AppError::invalid("lock name must be 1..=128 chars").with_request_id(&req_id),
                );
            }
            trimmed.to_string()
        }
        None => existing.name,
    };

    let new_desc = match body.description {
        Some(d) => {
            let trimmed = d.trim();
            if trimmed.len() > 256 {
                return Err(
                    AppError::invalid("description must be <= 256 chars").with_request_id(&req_id),
                );
            }
            trimmed.to_string()
        }
        None => existing.description,
    };

    let now = chrono::Utc::now().timestamp();
    let updated: LockRow = sqlx::query_as(
        "UPDATE locks SET name = ?, description = ?, updated_at = ? WHERE id = ? RETURNING *",
    )
    .bind(&new_name)
    .bind(&new_desc)
    .bind(now)
    .bind(&id)
    .fetch_one(&state.db.pool)
    .await?;

    state.audit.record(AuditEvent {
        actor_type: "admin".into(),
        actor_id: auth.user.id.clone(),
        action: "update_lock".into(),
        target_type: "lock".into(),
        target_id: id.clone(),
        result: "success".into(),
        detail: serde_json::json!({
            "name": new_name,
            "description": new_desc,
        }),
        ip,
        request_id: req_id.clone(),
    });

    let cfg = state.db.get_system_config().await?;
    let view = build_admin_lock_view(&state, &updated, &cfg, now).await?;
    Ok(ApiEnvelope::ok(view, req_id))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BindLockRequest {
    pub adapter_id: Option<String>,
}

pub async fn bind_lock(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<BindLockRequest>,
) -> AppResult<Json<ApiEnvelope<AdminLockView>>> {
    let req_id = extract_request_id(&headers);
    let auth = authenticate_request(&state, &headers)
        .await
        .map_err(|e| e.with_request_id(&req_id))?;
    require_admin(&auth, &req_id)?;

    let target_adapter_id = body
        .adapter_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned);

    let now = chrono::Utc::now().timestamp();
    let mut tx = state.db.pool.begin().await?;

    let existing: LockRow = sqlx::query_as("SELECT * FROM locks WHERE id = ?")
        .bind(&id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| {
            AppError::new(ErrorCode::LockNotFound, "lock not found").with_request_id(&req_id)
        })?;

    if let Some(ref aid) = target_adapter_id {
        let adapter: crate::db::AdapterRow = sqlx::query_as("SELECT * FROM adapters WHERE id = ?")
            .bind(aid)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| {
                AppError::new(ErrorCode::AdapterNotFound, "adapter not found")
                    .with_request_id(&req_id)
            })?;
        if adapter.approval_status != "approved" {
            return Err(
                AppError::conflict("only approved adapters can be bound to a lock")
                    .with_request_id(&req_id),
            );
        }
        let other_lock: Option<LockRow> =
            sqlx::query_as("SELECT * FROM locks WHERE adapter_id = ?")
                .bind(aid)
                .fetch_optional(&mut *tx)
                .await?;
        if let Some(other_lock) = other_lock {
            if other_lock.id != id {
                return Err(AppError::conflict(format!(
                    "adapter is already bound to lock {}",
                    other_lock.id
                ))
                .with_request_id(&req_id));
            }
        }
    }

    let updated_res: Result<LockRow, sqlx::Error> =
        sqlx::query_as("UPDATE locks SET adapter_id = ?, updated_at = ? WHERE id = ? RETURNING *")
            .bind(&target_adapter_id)
            .bind(now)
            .bind(&id)
            .fetch_one(&mut *tx)
            .await;

    let updated = match updated_res {
        Ok(row) => row,
        Err(sqlx::Error::Database(ref db_err)) if db_err.is_unique_violation() => {
            return Err(
                AppError::conflict("adapter is already bound to another lock")
                    .with_request_id(&req_id),
            );
        }
        Err(err) => return Err(AppError::from(err).with_request_id(&req_id)),
    };
    tx.commit().await?;

    state.audit.record(AuditEvent {
        actor_type: "admin".into(),
        actor_id: auth.user.id.clone(),
        action: if target_adapter_id.is_some() {
            "bind_lock".into()
        } else {
            "unbind_lock".into()
        },
        target_type: "lock".into(),
        target_id: id.clone(),
        result: "success".into(),
        detail: serde_json::json!({
            "previousAdapterId": existing.adapter_id,
            "adapterId": target_adapter_id,
        }),
        ip,
        request_id: req_id.clone(),
    });

    let cfg = state.db.get_system_config().await?;
    let view = build_admin_lock_view(&state, &updated, &cfg, now).await?;
    Ok(ApiEnvelope::ok(view, req_id))
}

pub async fn delete_lock(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<ReasonBody>,
) -> AppResult<Json<ApiEnvelope<serde_json::Value>>> {
    let req_id = extract_request_id(&headers);
    let auth = authenticate_request(&state, &headers)
        .await
        .map_err(|e| e.with_request_id(&req_id))?;
    require_admin(&auth, &req_id)?;

    if body.reason.trim().is_empty() {
        return Err(AppError::invalid("reason is required").with_request_id(&req_id));
    }

    let res = sqlx::query("DELETE FROM locks WHERE id = ?")
        .bind(&id)
        .execute(&state.db.pool)
        .await?;

    if res.rows_affected() == 0 {
        return Err(
            AppError::new(ErrorCode::LockNotFound, "lock not found").with_request_id(&req_id),
        );
    }

    state.audit.record(AuditEvent {
        actor_type: "admin".into(),
        actor_id: auth.user.id,
        action: "delete_lock".into(),
        target_type: "lock".into(),
        target_id: id.clone(),
        result: "success".into(),
        detail: serde_json::json!({ "reason": body.reason.trim() }),
        ip,
        request_id: req_id.clone(),
    });

    Ok(ApiEnvelope::ok(
        serde_json::json!({ "id": id, "deleted": true }),
        req_id,
    ))
}

pub async fn get_lock_groups(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> AppResult<Json<ApiEnvelope<Vec<String>>>> {
    let req_id = extract_request_id(&headers);
    let auth = authenticate_request(&state, &headers)
        .await
        .map_err(|e| e.with_request_id(&req_id))?;
    require_admin(&auth, &req_id)?;

    if state.db.find_lock_by_id(&id).await?.is_none() {
        return Err(
            AppError::new(ErrorCode::LockNotFound, "lock not found").with_request_id(&req_id),
        );
    }

    let groups = state.db.list_lock_groups(&id).await?;
    Ok(ApiEnvelope::ok(groups, req_id))
}

#[derive(Deserialize)]
pub struct SetLockGroupsRequest {
    pub groups: Vec<String>,
}

pub async fn set_lock_groups(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<SetLockGroupsRequest>,
) -> AppResult<Json<ApiEnvelope<Vec<String>>>> {
    let req_id = extract_request_id(&headers);
    let auth = authenticate_request(&state, &headers)
        .await
        .map_err(|e| e.with_request_id(&req_id))?;
    require_admin(&auth, &req_id)?;

    if state.db.find_lock_by_id(&id).await?.is_none() {
        return Err(
            AppError::new(ErrorCode::LockNotFound, "lock not found").with_request_id(&req_id),
        );
    }

    let now = chrono::Utc::now().timestamp();
    state
        .db
        .replace_lock_groups(&id, &body.groups, &auth.user.id, now)
        .await?;

    let updated = state.db.list_lock_groups(&id).await?;
    state.audit.record(AuditEvent {
        actor_type: "admin".into(),
        actor_id: auth.user.id,
        action: "update_lock_groups".into(),
        target_type: "lock".into(),
        target_id: id,
        result: "success".into(),
        detail: serde_json::json!({ "groups": updated }),
        ip,
        request_id: req_id.clone(),
    });

    Ok(ApiEnvelope::ok(updated, req_id))
}

async fn execute_admin_unlock(
    state: &AppState,
    adapter: &AdapterRow,
    lock_id: Option<&str>,
    admin_user_id: &str,
    ip: &str,
    req_id: &str,
    reason: &str,
) -> AppResult<UnlockResponse> {
    match dispatch_unlock_command(
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
    {
        Ok(resp) => Ok(resp),
        Err(err) => {
            let (target_type, target_id, detail) = match lock_id {
                Some(lid) => (
                    "lock",
                    lid.to_string(),
                    serde_json::json!({
                        "adapterId": adapter.id,
                        "reason": reason,
                        "errorCode": err.code.as_str(),
                        "errorMessage": err.message,
                    }),
                ),
                None => (
                    "adapter",
                    adapter.id.clone(),
                    serde_json::json!({
                        "reason": reason,
                        "errorCode": err.code.as_str(),
                        "errorMessage": err.message,
                    }),
                ),
            };
            state.audit.record(AuditEvent {
                actor_type: "admin".into(),
                actor_id: admin_user_id.to_string(),
                action: "admin_unlock".into(),
                target_type: target_type.into(),
                target_id,
                result: "failed".into(),
                detail,
                ip: ip.to_string(),
                request_id: req_id.to_string(),
            });
            Err(err)
        }
    }
}

async fn execute_admin_refresh_state(
    state: &AppState,
    adapter: &AdapterRow,
    lock_id: Option<&str>,
    admin_user_id: &str,
    ip: &str,
    req_id: &str,
) -> AppResult<String> {
    if adapter.approval_status != "approved" || adapter.online_status != "online" {
        return Err(
            AppError::new(ErrorCode::AdapterOffline, "adapter is offline").with_request_id(req_id),
        );
    }

    let msg_id = format!("msg_{}", uuid::Uuid::new_v4().simple());
    state
        .mqtt
        .publish_query_state(&adapter.id, &msg_id)
        .await
        .map_err(|e| e.with_request_id(req_id))?;

    let (target_type, target_id, detail) = match lock_id {
        Some(lid) => (
            "lock",
            lid.to_string(),
            serde_json::json!({ "msgId": msg_id, "adapterId": adapter.id }),
        ),
        None => (
            "adapter",
            adapter.id.clone(),
            serde_json::json!({ "msgId": msg_id }),
        ),
    };
    state.audit.record(AuditEvent {
        actor_type: "admin".into(),
        actor_id: admin_user_id.to_string(),
        action: "admin_refresh_state".into(),
        target_type: target_type.into(),
        target_id,
        result: "success".into(),
        detail,
        ip: ip.to_string(),
        request_id: req_id.to_string(),
    });

    Ok(msg_id)
}

pub async fn admin_unlock_lock(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<ReasonBody>,
) -> AppResult<Json<ApiEnvelope<UnlockResponse>>> {
    let req_id = extract_request_id(&headers);
    let auth = authenticate_request(&state, &headers)
        .await
        .map_err(|e| e.with_request_id(&req_id))?;
    require_admin(&auth, &req_id)?;

    let reason = body.reason.trim();
    if reason.is_empty() {
        return Err(AppError::invalid("reason is required").with_request_id(&req_id));
    }

    let lock = state.db.find_lock_by_id(&id).await?.ok_or_else(|| {
        AppError::new(ErrorCode::LockNotFound, "lock not found").with_request_id(&req_id)
    })?;

    let adapter_id = lock.adapter_id.as_deref().ok_or_else(|| {
        AppError::new(ErrorCode::LockUnbound, "lock is not bound to an adapter")
            .with_request_id(&req_id)
    })?;

    let adapter = state
        .db
        .find_adapter_by_id(adapter_id)
        .await?
        .ok_or_else(|| {
            AppError::new(ErrorCode::AdapterNotFound, "bound adapter not found")
                .with_request_id(&req_id)
        })?;

    let resp = execute_admin_unlock(
        &state,
        &adapter,
        Some(&lock.id),
        &auth.user.id,
        &ip,
        &req_id,
        reason,
    )
    .await?;
    Ok(ApiEnvelope::ok(resp, req_id))
}

pub async fn refresh_lock_state(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> AppResult<Json<ApiEnvelope<serde_json::Value>>> {
    let req_id = extract_request_id(&headers);
    let auth = authenticate_request(&state, &headers)
        .await
        .map_err(|e| e.with_request_id(&req_id))?;
    require_admin(&auth, &req_id)?;

    let lock = state.db.find_lock_by_id(&id).await?.ok_or_else(|| {
        AppError::new(ErrorCode::LockNotFound, "lock not found").with_request_id(&req_id)
    })?;

    let adapter_id = lock.adapter_id.as_deref().ok_or_else(|| {
        AppError::new(ErrorCode::LockUnbound, "lock is not bound to an adapter")
            .with_request_id(&req_id)
    })?;

    let adapter = state
        .db
        .find_adapter_by_id(adapter_id)
        .await?
        .ok_or_else(|| {
            AppError::new(ErrorCode::AdapterNotFound, "bound adapter not found")
                .with_request_id(&req_id)
        })?;

    let msg_id = execute_admin_refresh_state(
        &state,
        &adapter,
        Some(&lock.id),
        &auth.user.id,
        &ip,
        &req_id,
    )
    .await?;

    Ok(ApiEnvelope::ok(serde_json::json!({ "msgId": msg_id }), req_id))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminAdapterView {
    pub id: String,
    pub name: String,
    pub fingerprint: String,
    pub approval_status: String,
    pub online_status: String,
    pub state: String,
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

pub async fn list_adapters(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<AdapterFilterQuery>,
) -> AppResult<Json<ApiEnvelope<Vec<AdminAdapterView>>>> {
    let req_id = extract_request_id(&headers);
    let auth = authenticate_request(&state, &headers)
        .await
        .map_err(|e| e.with_request_id(&req_id))?;
    require_admin(&auth, &req_id)?;

    let cfg = state.db.get_system_config().await?;
    let rows: Vec<AdapterRow> = sqlx::query_as("SELECT * FROM adapters ORDER BY created_at DESC")
        .fetch_all(&state.db.pool)
        .await?;
    let now = chrono::Utc::now().timestamp();

    let mut out = Vec::new();
    for a in rows {
        let approval_ok = q
            .approval_status
            .as_ref()
            .map(|s| &a.approval_status == s)
            .unwrap_or(true);
        let online_ok = q
            .online_status
            .as_ref()
            .map(|s| &a.online_status == s)
            .unwrap_or(true);
        if !approval_ok || !online_ok {
            continue;
        }
        let view = compute_adapter_view(&a, &cfg, now);
        let bound_lock = state.db.find_lock_by_adapter_id(&a.id).await?;
        out.push(AdminAdapterView {
            fingerprint: adapter_fingerprint(&a.id, &a.token_hash),
            id: a.id,
            name: view.name,
            approval_status: a.approval_status,
            online_status: a.online_status,
            state: view.state,
            state_reported_at: view.state_reported_at,
            stale: view.stale,
            bound_lock_id: bound_lock.as_ref().map(|l| l.id.clone()),
            bound_lock_name: bound_lock.map(|l| l.name),
            model: a.model,
            fw_version: a.fw_version,
            token_refresh_interval: a.token_refresh_interval,
            last_seen_at: a.last_seen_at,
            approved_by: a.approved_by,
            approved_at: a.approved_at,
            created_at: a.created_at,
        });
    }

    Ok(ApiEnvelope::ok(out, req_id))
}

#[derive(Deserialize)]
pub struct ReasonBody {
    pub reason: String,
}

pub async fn approve_adapter(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> AppResult<Json<ApiEnvelope<serde_json::Value>>> {
    let req_id = extract_request_id(&headers);
    let auth = authenticate_request(&state, &headers)
        .await
        .map_err(|e| e.with_request_id(&req_id))?;
    require_admin(&auth, &req_id)?;

    let now = chrono::Utc::now().timestamp();
    let updated: Option<AdapterRow> = sqlx::query_as(
        "UPDATE adapters SET approval_status = 'approved', approved_by = ?, approved_at = ?, token_rotated_at = ?, updated_at = ?
         WHERE id = ? AND approval_status = 'pending'
         RETURNING *",
    )
    .bind(&auth.user.id)
    .bind(now)
    .bind(now)
    .bind(now)
    .bind(&id)
    .fetch_optional(&state.db.pool)
    .await?;

    let adapter = match updated {
        Some(row) => row,
        None => {
            if state.db.find_adapter_by_id(&id).await?.is_none() {
                return Err(AppError::not_found("adapter not found").with_request_id(&req_id));
            }
            return Err(AppError::conflict("adapter is not pending").with_request_id(&req_id));
        }
    };

    state.audit.record(AuditEvent {
        actor_type: "admin".into(),
        actor_id: auth.user.id,
        action: "approve_adapter".into(),
        target_type: "adapter".into(),
        target_id: id.clone(),
        result: "success".into(),
        detail: serde_json::json!({ "fingerprint": adapter_fingerprint(&adapter.id, &adapter.token_hash) }),
        ip,
        request_id: req_id.clone(),
    });

    Ok(ApiEnvelope::ok(
        serde_json::json!({ "id": id, "approvalStatus": "approved" }),
        req_id,
    ))
}

pub async fn reject_adapter(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> AppResult<Json<ApiEnvelope<serde_json::Value>>> {
    let req_id = extract_request_id(&headers);
    let auth = authenticate_request(&state, &headers)
        .await
        .map_err(|e| e.with_request_id(&req_id))?;
    require_admin(&auth, &req_id)?;

    let now = chrono::Utc::now().timestamp();
    let res = sqlx::query(
        "UPDATE adapters SET approval_status = 'rejected', updated_at = ?
         WHERE id = ? AND approval_status = 'pending'",
    )
    .bind(now)
    .bind(&id)
    .execute(&state.db.pool)
    .await?;

    if res.rows_affected() == 0 {
        if state.db.find_adapter_by_id(&id).await?.is_none() {
            return Err(AppError::not_found("adapter not found").with_request_id(&req_id));
        }
        return Err(AppError::conflict("adapter is not pending").with_request_id(&req_id));
    }

    state.audit.record(AuditEvent {
        actor_type: "admin".into(),
        actor_id: auth.user.id,
        action: "reject_adapter".into(),
        target_type: "adapter".into(),
        target_id: id.clone(),
        result: "success".into(),
        detail: serde_json::json!({}),
        ip,
        request_id: req_id.clone(),
    });

    Ok(ApiEnvelope::ok(
        serde_json::json!({ "id": id, "approvalStatus": "rejected" }),
        req_id,
    ))
}

async fn unbind_adapter_locks(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    adapter_id: &str,
    now: i64,
) -> AppResult<Vec<String>> {
    let lock_ids: Vec<(String,)> = sqlx::query_as("SELECT id FROM locks WHERE adapter_id = ?")
        .bind(adapter_id)
        .fetch_all(&mut **tx)
        .await?;
    if !lock_ids.is_empty() {
        sqlx::query("UPDATE locks SET adapter_id = NULL, updated_at = ? WHERE adapter_id = ?")
            .bind(now)
            .bind(adapter_id)
            .execute(&mut **tx)
            .await?;
    }
    Ok(lock_ids.into_iter().map(|r| r.0).collect())
}

pub async fn revoke_adapter(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<ReasonBody>,
) -> AppResult<Json<ApiEnvelope<serde_json::Value>>> {
    let req_id = extract_request_id(&headers);
    let auth = authenticate_request(&state, &headers)
        .await
        .map_err(|e| e.with_request_id(&req_id))?;
    require_admin(&auth, &req_id)?;

    if body.reason.trim().is_empty() {
        return Err(AppError::invalid("reason is required").with_request_id(&req_id));
    }

    let now = chrono::Utc::now().timestamp();
    let mut tx = state.db.pool.begin().await?;
    let res = sqlx::query(
        "UPDATE adapters SET approval_status = 'revoked', online_status = 'offline', updated_at = ? WHERE id = ?",
    )
    .bind(now)
    .bind(&id)
    .execute(&mut *tx)
    .await?;

    if res.rows_affected() == 0 {
        return Err(AppError::not_found("adapter not found").with_request_id(&req_id));
    }

    let unbound_lock_ids = unbind_adapter_locks(&mut tx, &id, now).await?;
    tx.commit().await?;

    state.mqtt.kick_client(&id).await;

    state.audit.record(AuditEvent {
        actor_type: "admin".into(),
        actor_id: auth.user.id,
        action: "revoke_adapter".into(),
        target_type: "adapter".into(),
        target_id: id.clone(),
        result: "success".into(),
        detail: serde_json::json!({
            "reason": body.reason.trim(),
            "unboundLockIds": unbound_lock_ids,
        }),
        ip,
        request_id: req_id.clone(),
    });

    Ok(ApiEnvelope::ok(
        serde_json::json!({ "id": id, "approvalStatus": "revoked", "unboundLockIds": unbound_lock_ids }),
        req_id,
    ))
}

pub async fn reset_adapter(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<ReasonBody>,
) -> AppResult<Json<ApiEnvelope<serde_json::Value>>> {
    let req_id = extract_request_id(&headers);
    let auth = authenticate_request(&state, &headers)
        .await
        .map_err(|e| e.with_request_id(&req_id))?;
    require_admin(&auth, &req_id)?;

    if body.reason.trim().is_empty() {
        return Err(AppError::invalid("reason is required").with_request_id(&req_id));
    }

    let now = chrono::Utc::now().timestamp();
    let mut tx = state.db.pool.begin().await?;
    let res = sqlx::query(
        "UPDATE adapters
         SET approval_status = 'pending',
             online_status = 'offline',
             token_hash = '',
             approved_by = NULL,
             approved_at = NULL,
             pending_token_hash = NULL,
             pending_token_msg_id = NULL,
             pending_token_at = NULL,
             token_rotated_at = NULL,
             updated_at = ?
         WHERE id = ?",
    )
    .bind(now)
    .bind(&id)
    .execute(&mut *tx)
    .await?;

    if res.rows_affected() == 0 {
        return Err(AppError::not_found("adapter not found").with_request_id(&req_id));
    }

    let unbound_lock_ids = unbind_adapter_locks(&mut tx, &id, now).await?;
    tx.commit().await?;

    state.mqtt.kick_client(&id).await;

    state.audit.record(AuditEvent {
        actor_type: "admin".into(),
        actor_id: auth.user.id,
        action: "reset_adapter".into(),
        target_type: "adapter".into(),
        target_id: id.clone(),
        result: "success".into(),
        detail: serde_json::json!({
            "reason": body.reason.trim(),
            "approvalStatus": "pending",
            "unboundLockIds": unbound_lock_ids,
        }),
        ip,
        request_id: req_id.clone(),
    });

    Ok(ApiEnvelope::ok(
        serde_json::json!({ "id": id, "approvalStatus": "pending", "reset": true, "unboundLockIds": unbound_lock_ids }),
        req_id,
    ))
}

pub async fn delete_adapter(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<ReasonBody>,
) -> AppResult<Json<ApiEnvelope<serde_json::Value>>> {
    let req_id = extract_request_id(&headers);
    let auth = authenticate_request(&state, &headers)
        .await
        .map_err(|e| e.with_request_id(&req_id))?;
    require_admin(&auth, &req_id)?;

    if body.reason.trim().is_empty() {
        return Err(AppError::invalid("reason is required").with_request_id(&req_id));
    }

    let res = sqlx::query("DELETE FROM adapters WHERE id = ?")
        .bind(&id)
        .execute(&state.db.pool)
        .await?;

    if res.rows_affected() == 0 {
        return Err(AppError::not_found("adapter not found").with_request_id(&req_id));
    }

    state.mqtt.kick_client(&id).await;

    state.audit.record(AuditEvent {
        actor_type: "admin".into(),
        actor_id: auth.user.id,
        action: "delete_adapter".into(),
        target_type: "adapter".into(),
        target_id: id.clone(),
        result: "success".into(),
        detail: serde_json::json!({ "reason": body.reason.trim() }),
        ip,
        request_id: req_id.clone(),
    });

    Ok(ApiEnvelope::ok(
        serde_json::json!({ "id": id, "deleted": true }),
        req_id,
    ))
}

pub async fn refresh_adapter_token(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> AppResult<Json<ApiEnvelope<serde_json::Value>>> {
    let req_id = extract_request_id(&headers);
    let auth = authenticate_request(&state, &headers)
        .await
        .map_err(|e| e.with_request_id(&req_id))?;
    require_admin(&auth, &req_id)?;

    let adapter = state
        .db
        .find_adapter_by_id(&id)
        .await?
        .ok_or_else(|| AppError::not_found("adapter not found").with_request_id(&req_id))?;

    if adapter.approval_status != "approved" || adapter.online_status != "online" {
        return Err(
            AppError::new(ErrorCode::AdapterOffline, "adapter is not online")
                .with_request_id(&req_id),
        );
    }

    let new_token = generate_random_token();
    let new_hash = hash_token(&new_token);
    let now = chrono::Utc::now().timestamp();
    let msg_id = format!("msg_{}", uuid::Uuid::new_v4().simple());

    let res = sqlx::query(
        "UPDATE adapters
         SET pending_token_hash = ?, pending_token_msg_id = ?, pending_token_at = ?, updated_at = ?
         WHERE id = ?
           AND approval_status = 'approved'
           AND online_status = 'online'
           AND pending_token_hash IS NULL",
    )
    .bind(&new_hash)
    .bind(&msg_id)
    .bind(now)
    .bind(now)
    .bind(&id)
    .execute(&state.db.pool)
    .await?;

    if res.rows_affected() == 0 {
        return Err(
            AppError::conflict("adapter already has a pending token rotation or is unavailable")
                .with_request_id(&req_id),
        );
    }

    if let Err(err) = state
        .mqtt
        .publish_refresh_token(&id, &msg_id, &new_token)
        .await
    {
        let _ = sqlx::query(
            "UPDATE adapters
             SET pending_token_hash = NULL, pending_token_msg_id = NULL, pending_token_at = NULL
             WHERE id = ? AND pending_token_msg_id = ?",
        )
        .bind(&id)
        .bind(&msg_id)
        .execute(&state.db.pool)
        .await;
        return Err(err.with_request_id(&req_id));
    }

    state.audit.record(AuditEvent {
        actor_type: "admin".into(),
        actor_id: auth.user.id,
        action: "refresh_adapter_token".into(),
        target_type: "adapter".into(),
        target_id: id.clone(),
        result: "success".into(),
        detail: serde_json::json!({ "msgId": msg_id }),
        ip,
        request_id: req_id.clone(),
    });

    Ok(ApiEnvelope::ok(
        serde_json::json!({ "id": id, "msgId": msg_id }),
        req_id,
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateAdapterRequest {
    pub name: Option<String>,
    pub token_refresh_interval: Option<i64>,
}

pub async fn update_adapter(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<UpdateAdapterRequest>,
) -> AppResult<Json<ApiEnvelope<serde_json::Value>>> {
    let req_id = extract_request_id(&headers);
    let auth = authenticate_request(&state, &headers)
        .await
        .map_err(|e| e.with_request_id(&req_id))?;
    require_admin(&auth, &req_id)?;

    let existing = state
        .db
        .find_adapter_by_id(&id)
        .await?
        .ok_or_else(|| AppError::not_found("adapter not found").with_request_id(&req_id))?;

    let new_name = match body.name {
        Some(n) => {
            let trimmed = n.trim();
            if trimmed.is_empty() || trimmed.len() > 128 {
                return Err(
                    AppError::invalid("adapter name must be 1..=128 chars").with_request_id(&req_id),
                );
            }
            trimmed.to_string()
        }
        None => existing.name,
    };

    let new_interval = match body.token_refresh_interval {
        Some(v) => {
            if !(60..=30 * 86_400).contains(&v) {
                return Err(
                    AppError::invalid("tokenRefreshInterval must be between 60 and 2592000 seconds")
                        .with_request_id(&req_id),
                );
            }
            v
        }
        None => existing.token_refresh_interval,
    };

    let now = chrono::Utc::now().timestamp();
    sqlx::query(
        "UPDATE adapters SET name = ?, token_refresh_interval = ?, updated_at = ? WHERE id = ?",
    )
    .bind(&new_name)
    .bind(new_interval)
    .bind(now)
    .bind(&id)
    .execute(&state.db.pool)
    .await?;

    state.audit.record(AuditEvent {
        actor_type: "admin".into(),
        actor_id: auth.user.id,
        action: "update_adapter".into(),
        target_type: "adapter".into(),
        target_id: id.clone(),
        result: "success".into(),
        detail: serde_json::json!({
            "name": new_name,
            "tokenRefreshInterval": new_interval,
        }),
        ip,
        request_id: req_id.clone(),
    });

    Ok(ApiEnvelope::ok(serde_json::json!({ "id": id }), req_id))
}

pub async fn admin_unlock(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<ReasonBody>,
) -> AppResult<Json<ApiEnvelope<UnlockResponse>>> {
    let req_id = extract_request_id(&headers);
    let auth = authenticate_request(&state, &headers)
        .await
        .map_err(|e| e.with_request_id(&req_id))?;
    require_admin(&auth, &req_id)?;

    let reason = body.reason.trim();
    if reason.is_empty() {
        return Err(AppError::invalid("reason is required").with_request_id(&req_id));
    }

    let adapter = state
        .db
        .find_adapter_by_id(&id)
        .await?
        .ok_or_else(|| {
            AppError::new(ErrorCode::AdapterNotFound, "adapter not found").with_request_id(&req_id)
        })?;

    let resp =
        execute_admin_unlock(&state, &adapter, None, &auth.user.id, &ip, &req_id, reason).await?;
    Ok(ApiEnvelope::ok(resp, req_id))
}

pub async fn refresh_adapter_state(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> AppResult<Json<ApiEnvelope<serde_json::Value>>> {
    let req_id = extract_request_id(&headers);
    let auth = authenticate_request(&state, &headers)
        .await
        .map_err(|e| e.with_request_id(&req_id))?;
    require_admin(&auth, &req_id)?;

    let adapter = state
        .db
        .find_adapter_by_id(&id)
        .await?
        .ok_or_else(|| {
            AppError::new(ErrorCode::AdapterNotFound, "adapter not found").with_request_id(&req_id)
        })?;

    let msg_id =
        execute_admin_refresh_state(&state, &adapter, None, &auth.user.id, &ip, &req_id).await?;

    Ok(ApiEnvelope::ok(serde_json::json!({ "msgId": msg_id }), req_id))
}

pub async fn list_users(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<ApiEnvelope<Vec<UserRow>>>> {
    let req_id = extract_request_id(&headers);
    let auth = authenticate_request(&state, &headers)
        .await
        .map_err(|e| e.with_request_id(&req_id))?;
    require_admin(&auth, &req_id)?;

    let users: Vec<UserRow> = sqlx::query_as("SELECT * FROM users ORDER BY created_at DESC")
        .fetch_all(&state.db.pool)
        .await?;

    Ok(ApiEnvelope::ok(users, req_id))
}

pub async fn kick_user(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> AppResult<Json<ApiEnvelope<serde_json::Value>>> {
    let req_id = extract_request_id(&headers);
    let auth = authenticate_request(&state, &headers)
        .await
        .map_err(|e| e.with_request_id(&req_id))?;
    require_admin(&auth, &req_id)?;

    let existing = state
        .db
        .find_user_by_id(&id)
        .await?
        .ok_or_else(|| AppError::not_found("user not found").with_request_id(&req_id))?;

    if id == auth.user.id {
        return Err(
            AppError::forbidden("cannot kick your own admin account").with_request_id(&req_id),
        );
    }

    let now = chrono::Utc::now().timestamp();
    let res = sqlx::query(
        "UPDATE user_devices
         SET status = 'kicked', kicked_at = ?, sso_refresh_token = NULL
         WHERE user_id = ? AND status = 'online'",
    )
    .bind(now)
    .bind(&id)
    .execute(&state.db.pool)
    .await?;
    state.redis.revoke_user_jwt(&id, now).await?;

    state.audit.record(AuditEvent {
        actor_type: "admin".into(),
        actor_id: auth.user.id,
        action: "kick_user".into(),
        target_type: "user".into(),
        target_id: id.clone(),
        result: "success".into(),
        detail: serde_json::json!({
            "displayName": existing.display_name,
            "kickedDevices": res.rows_affected(),
        }),
        ip,
        request_id: req_id.clone(),
    });

    Ok(ApiEnvelope::ok(
        serde_json::json!({ "id": id, "kickedDevices": res.rows_affected() }),
        req_id,
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditQuery {
    pub actor_id: Option<String>,
    pub target_id: Option<String>,
    pub result: Option<String>,
    pub from: Option<i64>,
    pub to: Option<i64>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

pub async fn list_audit_logs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<AuditQuery>,
) -> AppResult<Json<ApiEnvelope<Vec<AuditLogRow>>>> {
    let req_id = extract_request_id(&headers);
    let auth = authenticate_request(&state, &headers)
        .await
        .map_err(|e| e.with_request_id(&req_id))?;
    require_admin(&auth, &req_id)?;

    if let (Some(from), Some(to)) = (q.from, q.to) {
        if from > to {
            return Err(AppError::invalid("from must be <= to").with_request_id(&req_id));
        }
    }
    if let Some(ref res_filter) = q.result {
        if !matches!(
            res_filter.as_str(),
            "success" | "denied" | "failed" | "timeout"
        ) {
            return Err(AppError::invalid("invalid result filter").with_request_id(&req_id));
        }
    }

    let limit = q.limit.unwrap_or(50).clamp(1, 500);
    let offset = q.offset.unwrap_or(0).max(0);

    let mut qb: sqlx::QueryBuilder<'_, sqlx::Sqlite> =
        sqlx::QueryBuilder::new("SELECT * FROM audit_logs WHERE 1=1");
    if let Some(ref actor_id) = q.actor_id {
        qb.push(" AND actor_id = ").push_bind(actor_id);
    }
    if let Some(ref target_id) = q.target_id {
        qb.push(" AND target_id = ").push_bind(target_id);
    }
    if let Some(ref result) = q.result {
        qb.push(" AND result = ").push_bind(result);
    }
    if let Some(from) = q.from {
        qb.push(" AND created_at >= ").push_bind(from);
    }
    if let Some(to) = q.to {
        qb.push(" AND created_at <= ").push_bind(to);
    }
    qb.push(" ORDER BY created_at DESC LIMIT ")
        .push_bind(limit)
        .push(" OFFSET ")
        .push_bind(offset);

    let rows: Vec<AuditLogRow> = qb.build_query_as().fetch_all(&state.db.pool).await?;

    Ok(ApiEnvelope::ok(rows, req_id))
}

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

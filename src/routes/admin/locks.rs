use super::{execute_admin_refresh_state, execute_admin_unlock, require_reason, ReasonBody};
use crate::audit::AuditEvent;
use crate::config::SystemConfig;
use crate::db::{AdapterRow, Db, LockRow};
use crate::error::{ApiEnvelope, AppError, AppResult, ErrorCode};
use crate::routes::user::UnlockResponse;
use crate::routes::{compute_lock_view, is_valid_identifier, AdminContext, ClientIp};
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use sqlx::{Sqlite, Transaction};

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

fn project_admin_lock_view(
    lock: &LockRow,
    adapter: Option<&AdapterRow>,
    groups: Vec<String>,
    cfg: &SystemConfig,
    now: i64,
) -> AdminLockView {
    let view = compute_lock_view(lock, adapter, cfg, now);
    AdminLockView {
        id: lock.id.clone(),
        name: lock.name.clone(),
        description: lock.description.clone(),
        bound: view.bound,
        adapter_id: view.adapter_id,
        adapter_name: view.adapter_name,
        adapter_approval_status: adapter.map(|a| a.approval_status.clone()),
        adapter_online_status: adapter.map(|a| a.online_status.clone()),
        state: view.state,
        state_reported_at: view.state_reported_at,
        online: view.online,
        stale: view.stale,
        groups,
        created_by: lock.created_by.clone(),
        created_at: lock.created_at,
        updated_at: lock.updated_at,
    }
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
    let groups = state.db.list_lock_groups(&lock.id).await?;
    Ok(project_admin_lock_view(
        lock,
        adapter.as_ref(),
        groups,
        cfg,
        now,
    ))
}

fn validate_lock_name(raw: &str, req_id: &str) -> AppResult<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > 128 {
        return Err(AppError::invalid("lock name must be 1..=128 chars").with_request_id(req_id));
    }
    Ok(trimmed.to_string())
}

fn validate_lock_description(raw: &str, req_id: &str) -> AppResult<String> {
    let trimmed = raw.trim();
    if trimmed.len() > 256 {
        return Err(AppError::invalid("description must be <= 256 chars").with_request_id(req_id));
    }
    Ok(trimmed.to_string())
}

async fn verify_adapter_bindable_tx(
    tx: &mut Transaction<'_, Sqlite>,
    adapter_id: &str,
    self_lock_id: Option<&str>,
    req_id: &str,
) -> AppResult<()> {
    let adapter: AdapterRow = sqlx::query_as("SELECT * FROM adapters WHERE id = ?")
        .bind(adapter_id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or_else(|| {
            AppError::new(ErrorCode::AdapterNotFound, "adapter not found").with_request_id(req_id)
        })?;
    if adapter.approval_status != "approved" {
        return Err(
            AppError::conflict("only approved adapters can be bound to a lock")
                .with_request_id(req_id),
        );
    }
    let other_lock: Option<(String,)> =
        sqlx::query_as("SELECT id FROM locks WHERE adapter_id = ?")
            .bind(adapter_id)
            .fetch_optional(&mut **tx)
            .await?;
    if let Some((other_id,)) = other_lock {
        if self_lock_id != Some(other_id.as_str()) {
            let msg = match self_lock_id {
                Some(_) => format!("adapter is already bound to lock {other_id}"),
                None => "adapter is already bound to another lock".to_string(),
            };
            return Err(AppError::conflict(msg).with_request_id(req_id));
        }
    }
    Ok(())
}

async fn resolve_lock_bound_adapter(
    state: &AppState,
    lock_id: &str,
    req_id: &str,
) -> AppResult<(LockRow, AdapterRow)> {
    let lock = state.db.find_lock_by_id(lock_id).await?.ok_or_else(|| {
        AppError::new(ErrorCode::LockNotFound, "lock not found").with_request_id(req_id)
    })?;
    let adapter_id = lock.adapter_id.as_deref().ok_or_else(|| {
        AppError::new(ErrorCode::LockUnbound, "lock is not bound to an adapter")
            .with_request_id(req_id)
    })?;
    let adapter = state
        .db
        .find_adapter_by_id(adapter_id)
        .await?
        .ok_or_else(|| {
            AppError::new(ErrorCode::AdapterNotFound, "bound adapter not found")
                .with_request_id(req_id)
        })?;
    Ok((lock, adapter))
}

pub async fn list_locks(
    State(state): State<AppState>,
    AdminContext { req_id, .. }: AdminContext,
) -> AppResult<Json<ApiEnvelope<Vec<AdminLockView>>>> {
    let cfg = state.db.get_system_config().await?;
    let locks = state.db.list_locks().await?;
    let adapters_map = state.db.list_all_adapters_map().await?;
    let mut groups_map = state.db.list_all_lock_groups_map().await?;
    let now = chrono::Utc::now().timestamp();

    let out = locks
        .iter()
        .map(|lock| {
            let adapter = lock
                .adapter_id
                .as_deref()
                .and_then(|aid| adapters_map.get(aid));
            let groups = groups_map.remove(&lock.id).unwrap_or_default();
            project_admin_lock_view(lock, adapter, groups, &cfg, now)
        })
        .collect();

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
    AdminContext { auth, req_id }: AdminContext,
    Json(body): Json<CreateLockRequest>,
) -> AppResult<Json<ApiEnvelope<AdminLockView>>> {
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

    let name = validate_lock_name(&body.name, &req_id)?;
    let description = validate_lock_description(&body.description, &req_id)?;
    let adapter_id = body
        .adapter_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned);

    let now = chrono::Utc::now().timestamp();
    let mut tx = state.db.pool.begin().await?;

    let existing_lock: Option<(String,)> = sqlx::query_as("SELECT id FROM locks WHERE id = ?")
        .bind(&lock_id)
        .fetch_optional(&mut *tx)
        .await?;
    if existing_lock.is_some() {
        return Err(AppError::conflict("lock id already exists").with_request_id(&req_id));
    }

    if let Some(ref aid) = adapter_id {
        verify_adapter_bindable_tx(&mut tx, aid, None, &req_id).await?;
    }

    let row_res: Result<LockRow, sqlx::Error> = sqlx::query_as(
        "INSERT INTO locks (id, name, description, adapter_id, created_by, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         RETURNING *",
    )
    .bind(&lock_id)
    .bind(&name)
    .bind(&description)
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
        Db::replace_lock_groups_tx(&mut tx, &row.id, &body.groups, &auth.user.id, now).await?;
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
    AdminContext { auth, req_id }: AdminContext,
    Path(id): Path<String>,
    Json(body): Json<UpdateLockRequest>,
) -> AppResult<Json<ApiEnvelope<AdminLockView>>> {
    let existing = state.db.find_lock_by_id(&id).await?.ok_or_else(|| {
        AppError::new(ErrorCode::LockNotFound, "lock not found").with_request_id(&req_id)
    })?;

    let new_name = match body.name {
        Some(ref n) => validate_lock_name(n, &req_id)?,
        None => existing.name,
    };
    let new_desc = match body.description {
        Some(ref d) => validate_lock_description(d, &req_id)?,
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
    AdminContext { auth, req_id }: AdminContext,
    Path(id): Path<String>,
    Json(body): Json<BindLockRequest>,
) -> AppResult<Json<ApiEnvelope<AdminLockView>>> {
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
        verify_adapter_bindable_tx(&mut tx, aid, Some(&id), &req_id).await?;
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
    AdminContext { auth, req_id }: AdminContext,
    Path(id): Path<String>,
    Json(body): Json<ReasonBody>,
) -> AppResult<Json<ApiEnvelope<serde_json::Value>>> {
    let reason = require_reason(&body, &req_id)?;

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
        detail: serde_json::json!({ "reason": reason }),
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
    AdminContext { req_id, .. }: AdminContext,
    Path(id): Path<String>,
) -> AppResult<Json<ApiEnvelope<Vec<String>>>> {
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
    AdminContext { auth, req_id }: AdminContext,
    Path(id): Path<String>,
    Json(body): Json<SetLockGroupsRequest>,
) -> AppResult<Json<ApiEnvelope<Vec<String>>>> {
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

pub async fn admin_unlock_lock(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    AdminContext { auth, req_id }: AdminContext,
    Path(id): Path<String>,
    Json(body): Json<ReasonBody>,
) -> AppResult<Json<ApiEnvelope<UnlockResponse>>> {
    let reason = require_reason(&body, &req_id)?;
    let (lock, adapter) = resolve_lock_bound_adapter(&state, &id, &req_id).await?;

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
    AdminContext { auth, req_id }: AdminContext,
    Path(id): Path<String>,
) -> AppResult<Json<ApiEnvelope<serde_json::Value>>> {
    let (lock, adapter) = resolve_lock_bound_adapter(&state, &id, &req_id).await?;

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

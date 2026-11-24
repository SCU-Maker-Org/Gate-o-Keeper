use super::{
    adapter_fingerprint, execute_admin_refresh_state, execute_admin_unlock, require_reason,
    ReasonBody,
};
use crate::audit::AuditEvent;
use crate::db::AdapterRow;
use crate::error::{ApiEnvelope, AppError, AppResult, ErrorCode};
use crate::mqtt::stage_and_send_token_refresh;
use crate::routes::user::UnlockResponse;
use crate::routes::{compute_adapter_view, AdminContext, ClientIp};
use crate::state::AppState;
use axum::extract::{Path, Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdapterFilterQuery {
    pub approval_status: Option<String>,
    pub online_status: Option<String>,
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
    AdminContext { req_id, .. }: AdminContext,
    Query(q): Query<AdapterFilterQuery>,
) -> AppResult<Json<ApiEnvelope<Vec<AdminAdapterView>>>> {
    let cfg = state.db.get_system_config().await?;
    let mut qb: sqlx::QueryBuilder<'_, sqlx::Sqlite> =
        sqlx::QueryBuilder::new("SELECT * FROM adapters WHERE 1=1");
    if let Some(ref approval) = q.approval_status {
        qb.push(" AND approval_status = ").push_bind(approval);
    }
    if let Some(ref online) = q.online_status {
        qb.push(" AND online_status = ").push_bind(online);
    }
    qb.push(" ORDER BY created_at DESC");

    let rows: Vec<AdapterRow> = qb.build_query_as().fetch_all(&state.db.pool).await?;
    let mut bound_locks = state.db.list_bound_locks_map().await?;
    let now = chrono::Utc::now().timestamp();

    let out = rows
        .into_iter()
        .map(|a| {
            let view = compute_adapter_view(&a, &cfg, now);
            let bound = bound_locks.remove(&a.id);
            AdminAdapterView {
                fingerprint: adapter_fingerprint(&a.id, &a.token_hash),
                id: a.id,
                name: view.name,
                approval_status: a.approval_status,
                online_status: a.online_status,
                state: view.state,
                state_reported_at: view.state_reported_at,
                stale: view.stale,
                bound_lock_id: bound.as_ref().map(|(id, _)| id.clone()),
                bound_lock_name: bound.map(|(_, name)| name),
                model: a.model,
                fw_version: a.fw_version,
                token_refresh_interval: a.token_refresh_interval,
                last_seen_at: a.last_seen_at,
                approved_by: a.approved_by,
                approved_at: a.approved_at,
                created_at: a.created_at,
            }
        })
        .collect();

    Ok(ApiEnvelope::ok(out, req_id))
}

async fn ensure_pending_update_target(
    state: &AppState,
    id: &str,
    req_id: &str,
) -> AppError {
    match state.db.find_adapter_by_id(id).await {
        Ok(None) => AppError::not_found("adapter not found").with_request_id(req_id),
        Ok(Some(_)) => AppError::conflict("adapter is not pending").with_request_id(req_id),
        Err(err) => err.with_request_id(req_id),
    }
}

pub async fn approve_adapter(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    AdminContext { auth, req_id }: AdminContext,
    Path(id): Path<String>,
) -> AppResult<Json<ApiEnvelope<serde_json::Value>>> {
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

    let Some(adapter) = updated else {
        return Err(ensure_pending_update_target(&state, &id, &req_id).await);
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
    AdminContext { auth, req_id }: AdminContext,
    Path(id): Path<String>,
) -> AppResult<Json<ApiEnvelope<serde_json::Value>>> {
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
        return Err(ensure_pending_update_target(&state, &id, &req_id).await);
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
    AdminContext { auth, req_id }: AdminContext,
    Path(id): Path<String>,
    Json(body): Json<ReasonBody>,
) -> AppResult<Json<ApiEnvelope<serde_json::Value>>> {
    let reason = require_reason(&body, &req_id)?;

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
            "reason": reason,
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
    AdminContext { auth, req_id }: AdminContext,
    Path(id): Path<String>,
    Json(body): Json<ReasonBody>,
) -> AppResult<Json<ApiEnvelope<serde_json::Value>>> {
    let reason = require_reason(&body, &req_id)?;

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
            "reason": reason,
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
    AdminContext { auth, req_id }: AdminContext,
    Path(id): Path<String>,
    Json(body): Json<ReasonBody>,
) -> AppResult<Json<ApiEnvelope<serde_json::Value>>> {
    let reason = require_reason(&body, &req_id)?;

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
        detail: serde_json::json!({ "reason": reason }),
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
    AdminContext { auth, req_id }: AdminContext,
    Path(id): Path<String>,
) -> AppResult<Json<ApiEnvelope<serde_json::Value>>> {
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

    let now = chrono::Utc::now().timestamp();
    let msg_id = format!("msg_{}", uuid::Uuid::new_v4().simple());
    let staged =
        stage_and_send_token_refresh(&state.db, &state.mqtt, &id, &msg_id, now, true)
            .await
            .map_err(|e| e.with_request_id(&req_id))?;
    if !staged {
        return Err(
            AppError::conflict("adapter already has a pending token rotation or is unavailable")
                .with_request_id(&req_id),
        );
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
    AdminContext { auth, req_id }: AdminContext,
    Path(id): Path<String>,
    Json(body): Json<UpdateAdapterRequest>,
) -> AppResult<Json<ApiEnvelope<serde_json::Value>>> {
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
    AdminContext { auth, req_id }: AdminContext,
    Path(id): Path<String>,
    Json(body): Json<ReasonBody>,
) -> AppResult<Json<ApiEnvelope<UnlockResponse>>> {
    let reason = require_reason(&body, &req_id)?;

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
    AdminContext { auth, req_id }: AdminContext,
    Path(id): Path<String>,
) -> AppResult<Json<ApiEnvelope<serde_json::Value>>> {
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

use super::{
    adapter_fingerprint, execute_admin_refresh_state, execute_admin_unlock, generate_random_token,
    ReasonBody,
};
use crate::audit::AuditEvent;
use crate::auth::{authenticate_request, hash_token};
use crate::db::AdapterRow;
use crate::error::{ApiEnvelope, AppError, AppResult, ErrorCode};
use crate::routes::user::UnlockResponse;
use crate::routes::{compute_adapter_view, extract_request_id, require_admin, ClientIp};
use crate::state::AppState;
use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
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

use crate::audit::AuditEvent;
use crate::auth::authenticate_request;
use crate::db::UserRow;
use crate::error::{ApiEnvelope, AppError, AppResult};
use crate::routes::{extract_request_id, require_admin, ClientIp};
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::Json;

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

use crate::audit::AuditEvent;
use crate::db::UserRow;
use crate::error::{ApiEnvelope, AppError, AppResult};
use crate::routes::{AdminContext, ClientIp};
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::Json;

pub async fn list_users(
    State(state): State<AppState>,
    AdminContext { req_id, .. }: AdminContext,
) -> AppResult<Json<ApiEnvelope<Vec<UserRow>>>> {
    let users: Vec<UserRow> = sqlx::query_as("SELECT * FROM users ORDER BY created_at DESC")
        .fetch_all(&state.db.pool)
        .await?;

    Ok(ApiEnvelope::ok(users, req_id))
}

pub async fn kick_user(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    AdminContext { auth, req_id }: AdminContext,
    Path(id): Path<String>,
) -> AppResult<Json<ApiEnvelope<serde_json::Value>>> {

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

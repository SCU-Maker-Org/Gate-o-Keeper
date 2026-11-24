use crate::auth::authenticate_request;
use crate::db::AuditLogRow;
use crate::error::{ApiEnvelope, AppError, AppResult};
use crate::routes::{extract_request_id, require_admin};
use crate::state::AppState;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::Json;
use serde::Deserialize;

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

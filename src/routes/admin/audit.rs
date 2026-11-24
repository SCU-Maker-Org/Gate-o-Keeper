use crate::error::{ApiEnvelope, AppResult};
use crate::infra::db::AuditLogRow;
use crate::routes::AdminContext;
use crate::services::audit::{self as audit_svc, AuditQueryInput};
use crate::state::AppState;
use axum::extract::{Query, State};
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
    AdminContext { req_id, .. }: AdminContext,
    Query(q): Query<AuditQuery>,
) -> AppResult<Json<ApiEnvelope<Vec<AuditLogRow>>>> {
    let rows = audit_svc::list_audit_logs(
        &state,
        &req_id,
        AuditQueryInput {
            actor_id: q.actor_id.as_deref(),
            target_id: q.target_id.as_deref(),
            result: q.result.as_deref(),
            from: q.from,
            to: q.to,
            limit: q.limit,
            offset: q.offset,
        },
    )
    .await?;

    Ok(ApiEnvelope::ok(rows, req_id))
}

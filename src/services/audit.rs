use crate::db::{AuditLogFilter, AuditLogRow};
use crate::error::{AppError, AppResult};
use crate::state::AppState;

pub struct AuditQueryInput<'a> {
    pub actor_id: Option<&'a str>,
    pub target_id: Option<&'a str>,
    pub result: Option<&'a str>,
    pub from: Option<i64>,
    pub to: Option<i64>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

pub async fn list_audit_logs(
    state: &AppState,
    req_id: &str,
    input: AuditQueryInput<'_>,
) -> AppResult<Vec<AuditLogRow>> {
    if let (Some(from), Some(to)) = (input.from, input.to) {
        if from > to {
            return Err(AppError::invalid("from must be <= to").with_request_id(req_id));
        }
    }
    if let Some(res_filter) = input.result {
        if !matches!(res_filter, "success" | "denied" | "failed" | "timeout") {
            return Err(AppError::invalid("invalid result filter").with_request_id(req_id));
        }
    }

    let limit = input.limit.unwrap_or(50).clamp(1, 500);
    let offset = input.offset.unwrap_or(0).max(0);

    state
        .db
        .query_audit_logs(&AuditLogFilter {
            actor_id: input.actor_id,
            target_id: input.target_id,
            result: input.result,
            from: input.from,
            to: input.to,
            limit,
            offset,
        })
        .await
}

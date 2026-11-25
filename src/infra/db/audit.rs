use super::Db;
use crate::domain::{AuditActorType, AuditResult};
use crate::error::AppResult;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Clone, Debug, FromRow, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditLogRow {
    pub id: String,
    pub actor_type: AuditActorType,
    pub actor_id: String,
    pub action: String,
    pub target_type: String,
    pub target_id: String,
    pub result: AuditResult,
    pub detail_json: String,
    pub ip: String,
    pub request_id: String,
    pub created_at: i64,
}

#[derive(Default)]
pub struct AuditLogFilter<'a> {
    pub actor_id: Option<&'a str>,
    pub target_id: Option<&'a str>,
    pub result: Option<&'a str>,
    pub from: Option<i64>,
    pub to: Option<i64>,
    pub limit: i64,
    pub offset: i64,
}

impl Db {
    pub async fn insert_audit_log(&self, row: &AuditLogRow) -> AppResult<()> {
        sqlx::query(
            "INSERT INTO audit_logs (id, actor_type, actor_id, action, target_type, target_id, result, detail_json, ip, request_id, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&row.id)
        .bind(&row.actor_type)
        .bind(&row.actor_id)
        .bind(&row.action)
        .bind(&row.target_type)
        .bind(&row.target_id)
        .bind(&row.result)
        .bind(&row.detail_json)
        .bind(&row.ip)
        .bind(&row.request_id)
        .bind(row.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn query_audit_logs(
        &self,
        filter: &AuditLogFilter<'_>,
    ) -> AppResult<Vec<AuditLogRow>> {
        let mut qb: sqlx::QueryBuilder<'_, sqlx::Sqlite> =
            sqlx::QueryBuilder::new("SELECT * FROM audit_logs WHERE 1=1");
        if let Some(actor_id) = filter.actor_id {
            qb.push(" AND actor_id = ").push_bind(actor_id);
        }
        if let Some(target_id) = filter.target_id {
            qb.push(" AND target_id = ").push_bind(target_id);
        }
        if let Some(result) = filter.result {
            qb.push(" AND result = ").push_bind(result);
        }
        if let Some(from) = filter.from {
            qb.push(" AND created_at >= ").push_bind(from);
        }
        if let Some(to) = filter.to {
            qb.push(" AND created_at <= ").push_bind(to);
        }
        qb.push(" ORDER BY created_at DESC LIMIT ")
            .push_bind(filter.limit)
            .push(" OFFSET ")
            .push_bind(filter.offset);

        Ok(qb.build_query_as().fetch_all(&self.pool).await?)
    }

    pub async fn cleanup_expired_audits(&self, retention_days: i64, now: i64) -> AppResult<u64> {
        let days = retention_days.clamp(1, 3650);
        let cutoff = now.saturating_sub(days.saturating_mul(86_400));
        let mut total = 0u64;
        loop {
            let res = sqlx::query(
                "DELETE FROM audit_logs WHERE id IN (
                    SELECT id FROM audit_logs WHERE created_at < ? LIMIT 1000
                )",
            )
            .bind(cutoff)
            .execute(&self.pool)
            .await?;
            let n = res.rows_affected();
            total += n;
            if n < 1000 {
                break;
            }
            tokio::task::yield_now().await;
        }
        Ok(total)
    }
}

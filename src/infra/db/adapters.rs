use super::{is_unique_violation, Db};
use crate::domain::{ApprovalStatus, DoorState, OnlineStatus};
use crate::error::{AppError, AppResult, ErrorCode};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, Sqlite, Transaction};
use std::collections::HashMap;

#[derive(Clone, Debug, FromRow, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdapterRow {
    pub id: String,
    pub name: String,
    pub approval_status: ApprovalStatus,
    pub online_status: OnlineStatus,
    pub reported_state: DoorState,
    pub state_reported_at: Option<i64>,
    pub model: String,
    pub fw_version: String,
    #[serde(skip_serializing)]
    pub token_hash: String,
    #[serde(skip_serializing)]
    pub pending_token_hash: Option<String>,
    #[serde(skip_serializing)]
    pub pending_token_msg_id: Option<String>,
    #[serde(skip_serializing)]
    pub pending_token_at: Option<i64>,
    #[serde(skip_serializing)]
    pub pending_token_stale_at: Option<i64>,
    pub token_rotated_at: Option<i64>,
    pub token_refresh_interval: i64,
    pub last_seen_at: Option<i64>,
    pub approved_by: Option<String>,
    pub approved_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Default)]
pub struct AdapterFilter<'a> {
    pub approval_status: Option<&'a str>,
    pub online_status: Option<&'a str>,
}

async fn unbind_adapter_locks_tx(
    tx: &mut Transaction<'_, Sqlite>,
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

impl Db {
    pub async fn find_adapter_by_id(&self, id: &str) -> AppResult<Option<AdapterRow>> {
        Ok(sqlx::query_as("SELECT * FROM adapters WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?)
    }

    pub async fn find_adapter_by_any_token_hash(
        &self,
        token_hash: &str,
    ) -> AppResult<Option<AdapterRow>> {
        Ok(sqlx::query_as(
            "SELECT * FROM adapters WHERE token_hash = ? OR pending_token_hash = ? LIMIT 1",
        )
        .bind(token_hash)
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await?)
    }

    /// Batch-loads all adapters keyed by `adapter.id` to avoid N+1 lookups.
    pub async fn list_all_adapters_map(&self) -> AppResult<HashMap<String, AdapterRow>> {
        let rows: Vec<AdapterRow> = sqlx::query_as("SELECT * FROM adapters")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().map(|a| (a.id.clone(), a)).collect())
    }

    pub async fn list_adapters_filtered(
        &self,
        filter: &AdapterFilter<'_>,
    ) -> AppResult<Vec<AdapterRow>> {
        let mut qb: sqlx::QueryBuilder<'_, Sqlite> =
            sqlx::QueryBuilder::new("SELECT * FROM adapters WHERE 1=1");
        if let Some(approval) = filter.approval_status {
            qb.push(" AND approval_status = ").push_bind(approval);
        }
        if let Some(online) = filter.online_status {
            qb.push(" AND online_status = ").push_bind(online);
        }
        qb.push(" ORDER BY created_at DESC");
        Ok(qb.build_query_as().fetch_all(&self.pool).await?)
    }

    pub async fn list_online_approved_adapter_ids(&self) -> AppResult<Vec<String>> {
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT id FROM adapters WHERE approval_status = 'approved' AND online_status = 'online'",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|r| r.0).collect())
    }

    pub async fn insert_pending_adapter(
        &self,
        adapter_id: &str,
        display_name: &str,
        model: &str,
        fw_version: &str,
        token_hash: &str,
        now: i64,
    ) -> AppResult<()> {
        let res = sqlx::query(
            "INSERT INTO adapters (id, name, approval_status, online_status, reported_state, model, fw_version, token_hash, token_refresh_interval, created_at, updated_at)
             VALUES (?, ?, 'pending', 'offline', 'unknown', ?, ?, ?, 43200, ?, ?)",
        )
        .bind(adapter_id)
        .bind(display_name)
        .bind(model)
        .bind(fw_version)
        .bind(token_hash)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await;

        match res {
            Ok(_) => Ok(()),
            Err(ref err) if is_unique_violation(err) => Err(AppError::new(
                ErrorCode::DeviceAlreadyRegistered,
                "adapter already registered",
            )),
            Err(err) => Err(AppError::from(err)),
        }
    }

    pub async fn claim_reset_pending_adapter(
        &self,
        adapter_id: &str,
        display_name: &str,
        model: &str,
        fw_version: &str,
        token_hash: &str,
        now: i64,
    ) -> AppResult<()> {
        let res = sqlx::query(
            "UPDATE adapters
             SET name = ?, model = ?, fw_version = ?, token_hash = ?, updated_at = ?
             WHERE id = ? AND approval_status = 'pending' AND token_hash = ''",
        )
        .bind(display_name)
        .bind(model)
        .bind(fw_version)
        .bind(token_hash)
        .bind(now)
        .bind(adapter_id)
        .execute(&self.pool)
        .await;

        match res {
            Ok(r) if r.rows_affected() > 0 => Ok(()),
            Ok(_) => Err(AppError::new(
                ErrorCode::DeviceAlreadyRegistered,
                "adapter state changed during registration",
            )),
            Err(ref err) if is_unique_violation(err) => Err(AppError::new(
                ErrorCode::DeviceAlreadyRegistered,
                "adapter credential already in use",
            )),
            Err(err) => Err(AppError::from(err)),
        }
    }

    pub async fn approve_pending_adapter(
        &self,
        id: &str,
        admin_id: &str,
        now: i64,
    ) -> AppResult<Option<AdapterRow>> {
        Ok(sqlx::query_as(
            "UPDATE adapters SET approval_status = 'approved', approved_by = ?, approved_at = ?, token_rotated_at = ?, updated_at = ?
             WHERE id = ? AND approval_status = 'pending' AND token_hash <> ''
             RETURNING *",
        )
        .bind(admin_id)
        .bind(now)
        .bind(now)
        .bind(now)
        .bind(id)
        .fetch_optional(&self.pool)
        .await?)
    }

    pub async fn reject_pending_adapter(&self, id: &str, now: i64) -> AppResult<bool> {
        let res = sqlx::query(
            "UPDATE adapters SET approval_status = 'rejected', updated_at = ?
             WHERE id = ? AND approval_status = 'pending'",
        )
        .bind(now)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Revokes an *approved* adapter and clears any lock bindings atomically; returns `None`
    /// if the adapter is missing or not currently approved.
    pub async fn revoke_adapter_and_unbind_locks(
        &self,
        id: &str,
        now: i64,
    ) -> AppResult<Option<Vec<String>>> {
        let mut tx = self.pool.begin().await?;
        let res = sqlx::query(
            "UPDATE adapters SET approval_status = 'revoked', online_status = 'offline', updated_at = ? WHERE id = ? AND approval_status = 'approved'",
        )
        .bind(now)
        .bind(id)
        .execute(&mut *tx)
        .await?;

        if res.rows_affected() == 0 {
            return Ok(None);
        }

        let unbound_lock_ids = unbind_adapter_locks_tx(&mut tx, id, now).await?;
        tx.commit().await?;
        Ok(Some(unbound_lock_ids))
    }

    /// Resets an adapter back to `pending` with empty credential and clears any lock bindings atomically.
    pub async fn reset_adapter_and_unbind_locks(
        &self,
        id: &str,
        now: i64,
    ) -> AppResult<Option<Vec<String>>> {
        let mut tx = self.pool.begin().await?;
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
                 pending_token_stale_at = NULL,
                 token_rotated_at = NULL,
                 updated_at = ?
             WHERE id = ?",
        )
        .bind(now)
        .bind(id)
        .execute(&mut *tx)
        .await?;

        if res.rows_affected() == 0 {
            return Ok(None);
        }

        let unbound_lock_ids = unbind_adapter_locks_tx(&mut tx, id, now).await?;
        tx.commit().await?;
        Ok(Some(unbound_lock_ids))
    }

    pub async fn delete_adapter_by_id(&self, id: &str) -> AppResult<bool> {
        let res = sqlx::query("DELETE FROM adapters WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    pub async fn update_adapter_settings(
        &self,
        id: &str,
        name: &str,
        token_refresh_interval: i64,
        now: i64,
    ) -> AppResult<()> {
        sqlx::query(
            "UPDATE adapters SET name = ?, token_refresh_interval = ?, updated_at = ? WHERE id = ?",
        )
        .bind(name)
        .bind(token_refresh_interval)
        .bind(now)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn stage_pending_token_hash(
        &self,
        adapter_id: &str,
        new_hash: &str,
        msg_id: &str,
        now: i64,
        require_online: bool,
    ) -> AppResult<bool> {
        let sql = if require_online {
            "UPDATE adapters
             SET pending_token_hash = ?, pending_token_msg_id = ?, pending_token_at = ?,
                 pending_token_stale_at = NULL, updated_at = ?
             WHERE id = ?
               AND approval_status = 'approved'
               AND online_status = 'online'
               AND pending_token_hash IS NULL"
        } else {
            "UPDATE adapters
             SET pending_token_hash = ?, pending_token_msg_id = ?, pending_token_at = ?,
                 pending_token_stale_at = NULL, updated_at = ?
             WHERE id = ?
               AND approval_status = 'approved'
               AND pending_token_hash IS NULL"
        };

        let res = sqlx::query(sql)
            .bind(new_hash)
            .bind(msg_id)
            .bind(now)
            .bind(now)
            .bind(adapter_id)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    pub async fn clear_pending_token_if_matches(
        &self,
        adapter_id: &str,
        msg_id: &str,
    ) -> AppResult<()> {
        sqlx::query(
            "UPDATE adapters
             SET pending_token_hash = NULL, pending_token_msg_id = NULL, pending_token_at = NULL,
                 pending_token_stale_at = NULL
             WHERE id = ? AND pending_token_msg_id = ?",
        )
        .bind(adapter_id)
        .bind(msg_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Clears a timed-out pending token when the adapter successfully authenticates with its
    /// existing `token_hash`, unblocking future automatic and manual token rotations.
    pub async fn clear_stale_pending_token_on_old_auth(
        &self,
        adapter_id: &str,
        expected_token_hash: &str,
        cutoff: i64,
        now: i64,
    ) -> AppResult<bool> {
        let res = sqlx::query(
            "UPDATE adapters
             SET pending_token_hash = NULL,
                 pending_token_msg_id = NULL,
                 pending_token_at = NULL,
                 pending_token_stale_at = NULL,
                 updated_at = ?
             WHERE id = ?
               AND approval_status = 'approved'
               AND token_hash = ?
               AND pending_token_hash IS NOT NULL
               AND (pending_token_stale_at IS NOT NULL OR COALESCE(pending_token_at, updated_at) <= ?)",
        )
        .bind(now)
        .bind(adapter_id)
        .bind(expected_token_hash)
        .bind(cutoff)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    pub async fn promote_pending_token_on_auth(
        &self,
        adapter_id: &str,
        incoming_hash: &str,
        now: i64,
    ) -> AppResult<bool> {
        let res = sqlx::query(
            "UPDATE adapters
             SET token_hash = ?, pending_token_hash = NULL, pending_token_msg_id = NULL,
                 pending_token_at = NULL,
                 pending_token_stale_at = NULL, token_rotated_at = ?, updated_at = ?
             WHERE id = ? AND pending_token_hash = ? AND approval_status = 'approved'",
        )
        .bind(incoming_hash)
        .bind(now)
        .bind(now)
        .bind(adapter_id)
        .bind(incoming_hash)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    pub async fn activate_pending_token_on_ack(
        &self,
        adapter_id: &str,
        msg_id: &str,
        now: i64,
    ) -> AppResult<()> {
        sqlx::query(
            "UPDATE adapters
             SET token_hash = COALESCE(pending_token_hash, token_hash),
                 pending_token_hash = NULL,
                 pending_token_msg_id = NULL,
                 pending_token_at = NULL,
                 pending_token_stale_at = NULL,
                 token_rotated_at = ?,
                 updated_at = ?
             WHERE id = ?
               AND approval_status = 'approved'
               AND pending_token_msg_id = ?
               AND pending_token_hash IS NOT NULL",
        )
        .bind(now)
        .bind(now)
        .bind(adapter_id)
        .bind(msg_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Flags (once) pending token rotations unacknowledged for longer than the TTL and
    /// returns the newly flagged rows. The pending token is intentionally kept valid so a
    /// device that persisted it but missed the ack can still reconnect and self-heal.
    pub async fn expire_stale_pending_tokens(
        &self,
        cutoff: i64,
        now: i64,
    ) -> AppResult<Vec<AdapterRow>> {
        let candidates: Vec<AdapterRow> = sqlx::query_as(
            "SELECT * FROM adapters
             WHERE pending_token_hash IS NOT NULL
               AND pending_token_stale_at IS NULL
               AND COALESCE(pending_token_at, updated_at) <= ?",
        )
        .bind(cutoff)
        .fetch_all(&self.pool)
        .await?;

        let mut flagged = Vec::new();
        for adapter in candidates {
            let res = sqlx::query(
                "UPDATE adapters SET pending_token_stale_at = ?, updated_at = ?
                 WHERE id = ? AND pending_token_hash IS NOT NULL AND pending_token_stale_at IS NULL",
            )
            .bind(now)
            .bind(now)
            .bind(&adapter.id)
            .execute(&self.pool)
            .await;
            match res {
                Ok(r) if r.rows_affected() > 0 => flagged.push(adapter),
                Ok(_) => {}
                Err(err) => tracing::error!(
                    adapter_id = %adapter.id,
                    error = %err,
                    "failed to flag stale pending adapter token"
                ),
            }
        }
        Ok(flagged)
    }

    pub async fn list_due_rotation_adapters(&self, now: i64) -> AppResult<Vec<AdapterRow>> {
        Ok(sqlx::query_as(
            "SELECT * FROM adapters
             WHERE approval_status = 'approved'
               AND online_status = 'online'
               AND pending_token_hash IS NULL
               AND token_refresh_interval > 0
               AND COALESCE(token_rotated_at, approved_at, created_at) + token_refresh_interval <= ?",
        )
        .bind(now)
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn mark_adapter_connected(
        &self,
        adapter_id: &str,
        event_ts: i64,
        now: i64,
    ) -> AppResult<bool> {
        let res = sqlx::query(
            "UPDATE adapters
             SET online_status = 'online', last_seen_at = MAX(COALESCE(last_seen_at, 0), ?), updated_at = ?
             WHERE id = ? AND approval_status = 'approved' AND COALESCE(last_seen_at, 0) <= ?",
        )
        .bind(event_ts)
        .bind(now)
        .bind(adapter_id)
        .bind(event_ts)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Marks an adapter offline. When `force` is set (the broker confirmed the client is
    /// gone) the event-time guard is skipped; otherwise stale events cannot override newer ones.
    pub async fn mark_adapter_disconnected(
        &self,
        adapter_id: &str,
        event_ts: i64,
        now: i64,
        force: bool,
    ) -> AppResult<()> {
        let guard = if force {
            ""
        } else {
            " AND COALESCE(last_seen_at, 0) <= ?"
        };
        let sql = format!(
            "UPDATE adapters
             SET online_status = 'offline', last_seen_at = MAX(COALESCE(last_seen_at, 0), ?), updated_at = ?
             WHERE id = ? AND approval_status = 'approved'{guard}"
        );
        let mut q = sqlx::query(&sql).bind(event_ts).bind(now).bind(adapter_id);
        if !force {
            q = q.bind(event_ts);
        }
        q.execute(&self.pool).await?;
        Ok(())
    }

    pub async fn update_adapter_reported_state(
        &self,
        adapter_id: &str,
        state: DoorState,
        now: i64,
    ) -> AppResult<bool> {
        let res = sqlx::query(
            "UPDATE adapters
             SET reported_state = ?, state_reported_at = ?, updated_at = ?
             WHERE id = ? AND approval_status = 'approved'",
        )
        .bind(state)
        .bind(now)
        .bind(now)
        .bind(adapter_id)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    pub async fn update_adapter_presence(
        &self,
        adapter_id: &str,
        online: bool,
        now: i64,
        force: bool,
    ) -> AppResult<()> {
        let status = if online { "online" } else { "offline" };
        // Presence has no broker timestamp (arrival time only), so the ordering guard is
        // meaningful only when the broker could not confirm the live state.
        let guard = if force {
            ""
        } else {
            " AND COALESCE(last_seen_at, 0) <= ?"
        };
        let sql = format!(
            "UPDATE adapters
             SET online_status = ?, last_seen_at = MAX(COALESCE(last_seen_at, 0), ?), updated_at = ?
             WHERE id = ? AND approval_status = 'approved'{guard}"
        );
        let mut q = sqlx::query(&sql)
            .bind(status)
            .bind(now)
            .bind(now)
            .bind(adapter_id);
        if !force {
            q = q.bind(now);
        }
        q.execute(&self.pool).await?;
        Ok(())
    }
}

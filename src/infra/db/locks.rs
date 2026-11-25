use super::{is_unique_violation, AdapterRow, Db, UserRow};
use crate::domain::{ApprovalStatus, UserRole};
use crate::error::{AppError, AppResult, ErrorCode};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, Sqlite, Transaction};
use std::collections::HashMap;

#[derive(Clone, Debug, FromRow, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LockRow {
    pub id: String,
    pub name: String,
    pub description: String,
    pub adapter_id: Option<String>,
    pub created_by: String,
    pub created_at: i64,
    pub updated_at: i64,
}

pub struct BindLockOutcome {
    pub lock: LockRow,
    pub previous_adapter_id: Option<String>,
}

async fn verify_adapter_bindable_tx(
    tx: &mut Transaction<'_, Sqlite>,
    adapter_id: &str,
    self_lock_id: Option<&str>,
) -> AppResult<()> {
    let adapter: AdapterRow = sqlx::query_as("SELECT * FROM adapters WHERE id = ?")
        .bind(adapter_id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or_else(|| AppError::new(ErrorCode::AdapterNotFound, "adapter not found"))?;
    if adapter.approval_status != ApprovalStatus::Approved {
        return Err(AppError::conflict(
            "only approved adapters can be bound to a lock",
        ));
    }
    let other_lock: Option<(String,)> = sqlx::query_as("SELECT id FROM locks WHERE adapter_id = ?")
        .bind(adapter_id)
        .fetch_optional(&mut **tx)
        .await?;
    if let Some((other_id,)) = other_lock {
        if self_lock_id != Some(other_id.as_str()) {
            let msg = match self_lock_id {
                Some(_) => format!("adapter is already bound to lock {other_id}"),
                None => "adapter is already bound to another lock".to_string(),
            };
            return Err(AppError::conflict(msg));
        }
    }
    Ok(())
}

impl Db {
    pub async fn find_lock_by_id(&self, id: &str) -> AppResult<Option<LockRow>> {
        Ok(sqlx::query_as("SELECT * FROM locks WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?)
    }

    pub async fn find_lock_by_adapter_id(&self, adapter_id: &str) -> AppResult<Option<LockRow>> {
        Ok(sqlx::query_as("SELECT * FROM locks WHERE adapter_id = ?")
            .bind(adapter_id)
            .fetch_optional(&self.pool)
            .await?)
    }

    pub async fn list_locks(&self) -> AppResult<Vec<LockRow>> {
        Ok(sqlx::query_as("SELECT * FROM locks ORDER BY name, id")
            .fetch_all(&self.pool)
            .await?)
    }

    /// Batch-loads all lock group rules keyed by `lock_id` to avoid N+1 lookups.
    pub async fn list_all_lock_groups_map(&self) -> AppResult<HashMap<String, Vec<String>>> {
        let rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT lock_id, authentik_group FROM lock_group_rules ORDER BY lock_id, authentik_group",
        )
        .fetch_all(&self.pool)
        .await?;
        let mut map: HashMap<String, Vec<String>> = HashMap::new();
        for (lock_id, group) in rows {
            map.entry(lock_id).or_default().push(group);
        }
        Ok(map)
    }

    /// Batch-loads `(lock_id, lock_name)` keyed by `adapter_id` for bound locks.
    pub async fn list_bound_locks_map(&self) -> AppResult<HashMap<String, (String, String)>> {
        let rows: Vec<(String, String, String)> =
            sqlx::query_as("SELECT adapter_id, id, name FROM locks WHERE adapter_id IS NOT NULL")
                .fetch_all(&self.pool)
                .await?;
        Ok(rows
            .into_iter()
            .map(|(aid, lid, lname)| (aid, (lid, lname)))
            .collect())
    }

    pub async fn list_lock_groups(&self, lock_id: &str) -> AppResult<Vec<String>> {
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT authentik_group FROM lock_group_rules WHERE lock_id = ? ORDER BY authentik_group",
        )
        .bind(lock_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|r| r.0).collect())
    }

    pub async fn replace_lock_groups_tx(
        tx: &mut Transaction<'_, Sqlite>,
        lock_id: &str,
        groups: &[String],
        actor_id: &str,
        now: i64,
    ) -> AppResult<()> {
        sqlx::query("DELETE FROM lock_group_rules WHERE lock_id = ?")
            .bind(lock_id)
            .execute(&mut **tx)
            .await?;
        for g in groups {
            let trimmed = g.trim();
            if trimmed.is_empty() {
                continue;
            }
            sqlx::query(
                "INSERT OR IGNORE INTO lock_group_rules (lock_id, authentik_group, created_by, created_at)
                 VALUES (?, ?, ?, ?)",
            )
            .bind(lock_id)
            .bind(trimmed)
            .bind(actor_id)
            .bind(now)
            .execute(&mut **tx)
            .await?;
        }
        Ok(())
    }

    pub async fn replace_lock_groups(
        &self,
        lock_id: &str,
        groups: &[String],
        actor_id: &str,
        now: i64,
    ) -> AppResult<()> {
        let mut tx = self.pool.begin().await?;
        Self::replace_lock_groups_tx(&mut tx, lock_id, groups, actor_id, now).await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn user_has_lock_access(&self, user: &UserRow, lock_id: &str) -> AppResult<bool> {
        if user.role == UserRole::Admin {
            return Ok(true);
        }
        let user_groups = user.groups();
        if user_groups.is_empty() {
            return Ok(false);
        }
        let allowed = self.list_lock_groups(lock_id).await?;
        Ok(user_groups
            .iter()
            .any(|ug| allowed.iter().any(|ag| ag == ug)))
    }

    /// Creates a lock, optionally validates and binds an adapter, and initializes group rules atomically.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_lock(
        &self,
        lock_id: &str,
        name: &str,
        description: &str,
        adapter_id: Option<&str>,
        groups: &[String],
        actor_id: &str,
        now: i64,
    ) -> AppResult<LockRow> {
        let mut tx = self.pool.begin().await?;

        let existing_lock: Option<(String,)> = sqlx::query_as("SELECT id FROM locks WHERE id = ?")
            .bind(lock_id)
            .fetch_optional(&mut *tx)
            .await?;
        if existing_lock.is_some() {
            return Err(AppError::conflict("lock id already exists"));
        }

        if let Some(aid) = adapter_id {
            verify_adapter_bindable_tx(&mut tx, aid, None).await?;
        }

        let row_res: Result<LockRow, sqlx::Error> = sqlx::query_as(
            "INSERT INTO locks (id, name, description, adapter_id, created_by, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)
             RETURNING *",
        )
        .bind(lock_id)
        .bind(name)
        .bind(description)
        .bind(adapter_id)
        .bind(actor_id)
        .bind(now)
        .bind(now)
        .fetch_one(&mut *tx)
        .await;

        let row = match row_res {
            Ok(row) => row,
            Err(ref err) if is_unique_violation(err) => {
                return Err(AppError::conflict(
                    "lock id or adapter binding already exists",
                ));
            }
            Err(err) => return Err(AppError::from(err)),
        };

        if !groups.is_empty() {
            Self::replace_lock_groups_tx(&mut tx, &row.id, groups, actor_id, now).await?;
        }
        tx.commit().await?;
        Ok(row)
    }

    pub async fn update_lock_metadata(
        &self,
        lock_id: &str,
        name: &str,
        description: &str,
        now: i64,
    ) -> AppResult<LockRow> {
        Ok(sqlx::query_as(
            "UPDATE locks SET name = ?, description = ?, updated_at = ? WHERE id = ? RETURNING *",
        )
        .bind(name)
        .bind(description)
        .bind(now)
        .bind(lock_id)
        .fetch_one(&self.pool)
        .await?)
    }

    /// Binds or unbinds an adapter on `lock_id` atomically, enforcing 1-to-1 adapter exclusivity.
    pub async fn bind_lock_adapter(
        &self,
        lock_id: &str,
        target_adapter_id: Option<&str>,
        now: i64,
    ) -> AppResult<BindLockOutcome> {
        let mut tx = self.pool.begin().await?;

        let existing: LockRow = sqlx::query_as("SELECT * FROM locks WHERE id = ?")
            .bind(lock_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| AppError::new(ErrorCode::LockNotFound, "lock not found"))?;

        if let Some(aid) = target_adapter_id {
            verify_adapter_bindable_tx(&mut tx, aid, Some(lock_id)).await?;
        }

        let updated_res: Result<LockRow, sqlx::Error> = sqlx::query_as(
            "UPDATE locks SET adapter_id = ?, updated_at = ? WHERE id = ? RETURNING *",
        )
        .bind(target_adapter_id)
        .bind(now)
        .bind(lock_id)
        .fetch_one(&mut *tx)
        .await;

        let lock = match updated_res {
            Ok(row) => row,
            Err(ref err) if is_unique_violation(err) => {
                return Err(AppError::conflict(
                    "adapter is already bound to another lock",
                ));
            }
            Err(err) => return Err(AppError::from(err)),
        };
        tx.commit().await?;

        Ok(BindLockOutcome {
            lock,
            previous_adapter_id: existing.adapter_id,
        })
    }

    pub async fn delete_lock_by_id(&self, id: &str) -> AppResult<bool> {
        let res = sqlx::query("DELETE FROM locks WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }
}

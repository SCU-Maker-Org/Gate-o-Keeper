use crate::config::SystemConfig;
use crate::error::{AppError, AppResult};
use serde::{Deserialize, Serialize};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::{FromRow, SqlitePool};
use std::str::FromStr;
use std::time::Duration;

#[derive(Clone)]
pub struct Db {
    pub pool: SqlitePool,
}

#[derive(Clone, Debug, FromRow, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserRow {
    pub id: String,
    pub sso_subject: String,
    pub display_name: String,
    pub groups_json: String,
    pub role: String,
    pub status: String,
    pub created_at: i64,
    pub last_login_at: i64,
}

impl UserRow {
    pub fn groups(&self) -> Vec<String> {
        serde_json::from_str(&self.groups_json).unwrap_or_default()
    }
}

#[derive(Clone, Debug, FromRow, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserDeviceRow {
    pub id: String,
    pub user_id: String,
    pub device_id: String,
    pub device_name: String,
    pub sso_sid: Option<String>,
    #[serde(skip_serializing)]
    pub sso_refresh_token: Option<String>,
    #[serde(skip_serializing)]
    pub refresh_token_hash: String,
    #[serde(skip_serializing)]
    pub refresh_family_id: String,
    pub last_ip: String,
    pub status: String,
    pub created_at: i64,
    pub last_active_at: i64,
    pub kicked_at: Option<i64>,
}

#[derive(Clone, Debug, FromRow, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdapterRow {
    pub id: String,
    pub name: String,
    pub approval_status: String,
    pub online_status: String,
    pub reported_state: String,
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
    pub token_rotated_at: Option<i64>,
    pub token_refresh_interval: i64,
    pub last_seen_at: Option<i64>,
    pub approved_by: Option<String>,
    pub approved_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
}

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

#[derive(Clone, Debug, FromRow, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditLogRow {
    pub id: String,
    pub actor_type: String,
    pub actor_id: String,
    pub action: String,
    pub target_type: String,
    pub target_id: String,
    pub result: String,
    pub detail_json: String,
    pub ip: String,
    pub request_id: String,
    pub created_at: i64,
}

impl Db {
    pub async fn connect(database_url: &str) -> anyhow::Result<Self> {
        let opts = SqliteConnectOptions::from_str(database_url)?
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal)
            .foreign_keys(true)
            .busy_timeout(Duration::from_millis(5000));

        let max_conns = if database_url.contains(":memory:") {
            1
        } else {
            8
        };

        let pool = SqlitePoolOptions::new()
            .max_connections(max_conns)
            .connect_with(opts)
            .await?;

        sqlx::migrate!("./migrations").run(&pool).await?;
        Ok(Self { pool })
    }

    pub async fn seed_admin_groups_if_default(&self, env_groups: &[String]) -> AppResult<()> {
        let row: Option<(String, i64)> =
            sqlx::query_as("SELECT value_json, updated_at FROM system_config WHERE key = 'admin_groups'")
                .fetch_optional(&self.pool)
                .await?;
        if let Some((_, updated_at)) = row {
            // Only overwrite untouched migration seed (`updated_at == 0`)
            if updated_at == 0 {
                let json = serde_json::to_string(env_groups).unwrap_or_else(|_| "[]".into());
                sqlx::query("UPDATE system_config SET value_json = ? WHERE key = 'admin_groups' AND updated_at = 0")
                    .bind(&json)
                    .execute(&self.pool)
                    .await?;
            }
        }
        Ok(())
    }

    pub async fn get_system_config(&self) -> AppResult<SystemConfig> {
        let rows: Vec<(String, String)> =
            sqlx::query_as("SELECT key, value_json FROM system_config")
                .fetch_all(&self.pool)
                .await?;
        let mut cfg = SystemConfig::default();
        for (k, v) in rows {
            let parse_err = |err: serde_json::Error| {
                tracing::error!(key = %k, error = %err, "corrupted system_config entry");
                AppError::internal(format!("corrupted system_config entry '{k}'"))
            };
            match k.as_str() {
                "unlock_replay_window_sec" => {
                    cfg.unlock_replay_window_sec = serde_json::from_str(&v).map_err(parse_err)?;
                }
                "command_timeout_ms" => {
                    cfg.command_timeout_ms = serde_json::from_str(&v).map_err(parse_err)?;
                }
                "max_devices_per_user" => {
                    cfg.max_devices_per_user = serde_json::from_str(&v).map_err(parse_err)?;
                }
                "audit_retention_days" => {
                    cfg.audit_retention_days = serde_json::from_str(&v).map_err(parse_err)?;
                }
                "offline_unknown_sec" => {
                    cfg.offline_unknown_sec = serde_json::from_str(&v).map_err(parse_err)?;
                }
                "state_report_period_sec" => {
                    cfg.state_report_period_sec = serde_json::from_str(&v).map_err(parse_err)?;
                }
                "admin_groups" => {
                    cfg.admin_groups = serde_json::from_str(&v).map_err(parse_err)?;
                }
                "rate_limits" => {
                    cfg.rate_limits = serde_json::from_str(&v).map_err(parse_err)?;
                }
                _ => {}
            }
        }
        Ok(cfg)
    }

    pub async fn set_system_config_key(&self, key: &str, value_json: &str, now: i64) -> AppResult<()> {
        sqlx::query(
            "INSERT INTO system_config (key, value_json, updated_at) VALUES (?, ?, ?)
             ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at",
        )
        .bind(key)
        .bind(value_json)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn find_user_by_id(&self, id: &str) -> AppResult<Option<UserRow>> {
        Ok(sqlx::query_as("SELECT * FROM users WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?)
    }

    pub async fn find_user_by_subject(&self, sub: &str) -> AppResult<Option<UserRow>> {
        Ok(sqlx::query_as("SELECT * FROM users WHERE sso_subject = ?")
            .bind(sub)
            .fetch_optional(&self.pool)
            .await?)
    }

    /// Atomic upsert by `sso_subject` using `ON CONFLICT` so concurrent first logins never hit 500.
    pub async fn upsert_user_from_sso(
        &self,
        sub: &str,
        display_name: &str,
        groups: &[String],
        admin_groups: &[String],
        now: i64,
    ) -> AppResult<UserRow> {
        let groups_json = serde_json::to_string(groups).unwrap_or_else(|_| "[]".into());
        let role = if groups.iter().any(|g| admin_groups.iter().any(|ag| ag == g)) {
            "admin"
        } else {
            "user"
        };
        let new_id = format!("usr_{}", uuid::Uuid::new_v4().simple());

        let user: UserRow = sqlx::query_as(
            "INSERT INTO users (id, sso_subject, display_name, groups_json, role, status, created_at, last_login_at)
             VALUES (?, ?, ?, ?, ?, 'active', ?, ?)
             ON CONFLICT(sso_subject) DO UPDATE SET
                display_name = excluded.display_name,
                groups_json = excluded.groups_json,
                role = excluded.role,
                last_login_at = excluded.last_login_at
             RETURNING *",
        )
        .bind(&new_id)
        .bind(sub)
        .bind(display_name)
        .bind(&groups_json)
        .bind(role)
        .bind(now)
        .bind(now)
        .fetch_one(&self.pool)
        .await?;

        if user.status == "disabled" {
            return Err(AppError::forbidden("account is disabled"));
        }

        Ok(user)
    }

    /// Synchronizes an existing local user's profile, groups, role, and active status from Authentik SSO.
    pub async fn sync_existing_user_from_sso(
        &self,
        sub: &str,
        display_name: &str,
        groups: &[String],
        admin_groups: &[String],
        active: bool,
    ) -> AppResult<Option<UserRow>> {
        let groups_json = serde_json::to_string(groups).unwrap_or_else(|_| "[]".into());
        let role = if groups.iter().any(|g| admin_groups.iter().any(|ag| ag == g)) {
            "admin"
        } else {
            "user"
        };
        let status = if active { "active" } else { "disabled" };

        let updated: Option<UserRow> = sqlx::query_as(
            "UPDATE users
             SET display_name = ?,
                 groups_json = ?,
                 role = ?,
                 status = ?
             WHERE sso_subject = ?
             RETURNING *",
        )
        .bind(display_name)
        .bind(&groups_json)
        .bind(role)
        .bind(status)
        .bind(sub)
        .fetch_optional(&self.pool)
        .await?;

        Ok(updated)
    }

    pub async fn find_adapter_by_id(&self, id: &str) -> AppResult<Option<AdapterRow>> {
        Ok(sqlx::query_as("SELECT * FROM adapters WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?)
    }

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

    pub async fn list_lock_groups(&self, lock_id: &str) -> AppResult<Vec<String>> {
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT authentik_group FROM lock_group_rules WHERE lock_id = ? ORDER BY authentik_group",
        )
        .bind(lock_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|r| r.0).collect())
    }

    pub async fn replace_lock_groups(
        &self,
        lock_id: &str,
        groups: &[String],
        actor_id: &str,
        now: i64,
    ) -> AppResult<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM lock_group_rules WHERE lock_id = ?")
            .bind(lock_id)
            .execute(&mut *tx)
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
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn user_has_lock_access(&self, user: &UserRow, lock_id: &str) -> AppResult<bool> {
        if user.role == "admin" {
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

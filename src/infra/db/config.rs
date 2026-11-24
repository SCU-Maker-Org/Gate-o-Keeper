use super::Db;
use crate::config::SystemConfig;
use crate::error::{AppError, AppResult};
use crate::utils::compute_user_role;

impl Db {
    /// Seeds `admin_groups` from env only if the migration default has never been edited (`updated_at == 0`).
    pub async fn seed_admin_groups_if_default(&self, env_groups: &[String]) -> AppResult<()> {
        let row: Option<(String, i64)> = sqlx::query_as(
            "SELECT value_json, updated_at FROM system_config WHERE key = 'admin_groups'",
        )
        .fetch_optional(&self.pool)
        .await?;
        if let Some((_, updated_at)) = row {
            if updated_at == 0 {
                let json = serde_json::to_string(env_groups).unwrap_or_else(|_| "[]".into());
                sqlx::query(
                    "UPDATE system_config SET value_json = ? WHERE key = 'admin_groups' AND updated_at = 0",
                )
                .bind(&json)
                .execute(&self.pool)
                .await?;
            }
        }
        Ok(())
    }

    /// Loads and deserializes all `system_config` entries, failing closed on corrupted JSON.
    pub async fn get_system_config(&self) -> AppResult<SystemConfig> {
        let rows: Vec<(String, String)> = sqlx::query_as("SELECT key, value_json FROM system_config")
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

    pub async fn set_system_config_key(
        &self,
        key: &str,
        value_json: &str,
        now: i64,
    ) -> AppResult<()> {
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

    /// Atomically persists updated config keys and recomputes local user roles when `admin_groups` changes.
    pub async fn apply_config_updates(
        &self,
        updates: &[(&'static str, String)],
        updated_admin_groups: Option<&[String]>,
        now: i64,
    ) -> AppResult<()> {
        if updates.is_empty() {
            return Ok(());
        }
        let mut tx = self.pool.begin().await?;
        for (key, value) in updates {
            sqlx::query(
                "INSERT INTO system_config (key, value_json, updated_at)
                 VALUES (?, ?, ?)
                 ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at",
            )
            .bind(*key)
            .bind(value)
            .bind(now)
            .execute(&mut *tx)
            .await?;
        }
        if let Some(admin_groups) = updated_admin_groups {
            let users: Vec<(String, String, String)> =
                sqlx::query_as("SELECT id, groups_json, role FROM users")
                    .fetch_all(&mut *tx)
                    .await?;
            for (uid, groups_json, current_role) in users {
                let user_groups: Vec<String> =
                    serde_json::from_str(&groups_json).unwrap_or_default();
                let new_role = compute_user_role(&user_groups, admin_groups);
                if new_role != current_role {
                    sqlx::query("UPDATE users SET role = ? WHERE id = ?")
                        .bind(new_role)
                        .bind(&uid)
                        .execute(&mut *tx)
                        .await?;
                }
            }
        }
        tx.commit().await?;
        Ok(())
    }
}

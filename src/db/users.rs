use super::Db;
use crate::error::{AppError, AppResult};
use crate::utils::compute_user_role;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, SqliteConnection};
use std::collections::HashSet;

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

/// Parameters for creating or reusing a user device session inside a transaction.
pub struct LoginDeviceParams<'a> {
    pub user_id: &'a str,
    pub device_id: &'a str,
    pub device_name: &'a str,
    pub sso_sid: Option<&'a str>,
    pub sso_refresh_token: Option<&'a str>,
    pub refresh_hash: &'a str,
    pub ip: &'a str,
    pub max_devices: i64,
    pub now: i64,
}

async fn evict_excess_devices_tx(
    conn: &mut SqliteConnection,
    user_id: &str,
    keep_limit: usize,
    exclude_device_id: Option<&str>,
    now: i64,
) -> AppResult<Vec<String>> {
    let device_ids: Vec<String> = match exclude_device_id {
        Some(excluded) => {
            sqlx::query_scalar(
                "SELECT id FROM user_devices
                 WHERE user_id = ? AND status = 'online' AND id != ?
                 ORDER BY last_active_at ASC, created_at ASC, id ASC",
            )
            .bind(user_id)
            .bind(excluded)
            .fetch_all(&mut *conn)
            .await?
        }
        None => {
            sqlx::query_scalar(
                "SELECT id FROM user_devices
                 WHERE user_id = ? AND status = 'online'
                 ORDER BY last_active_at ASC, created_at ASC, id ASC",
            )
            .bind(user_id)
            .fetch_all(&mut *conn)
            .await?
        }
    };

    let excess = device_ids.len().saturating_sub(keep_limit);
    let mut evicted_ids = Vec::with_capacity(excess);
    for dev_id in device_ids.into_iter().take(excess) {
        let res = sqlx::query(
            "UPDATE user_devices
             SET status = 'kicked', kicked_at = ?, sso_refresh_token = NULL
             WHERE id = ? AND status = 'online'",
        )
        .bind(now)
        .bind(&dev_id)
        .execute(&mut *conn)
        .await?;
        if res.rows_affected() > 0 {
            evicted_ids.push(dev_id);
        }
    }
    Ok(evicted_ids)
}

impl Db {
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

    pub async fn list_users(&self) -> AppResult<Vec<UserRow>> {
        Ok(sqlx::query_as("SELECT * FROM users ORDER BY created_at DESC")
            .fetch_all(&self.pool)
            .await?)
    }

    pub async fn list_all_user_subjects(&self) -> AppResult<HashSet<String>> {
        let subs: Vec<String> = sqlx::query_scalar("SELECT sso_subject FROM users")
            .fetch_all(&self.pool)
            .await?;
        Ok(subs.into_iter().collect())
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
        let role = compute_user_role(groups, admin_groups);
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
        let role = compute_user_role(groups, admin_groups);
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

    /// Disables a user account and logs out all its online device sessions in one transaction.
    pub async fn disable_user_and_logout_devices(&self, user_id: &str) -> AppResult<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("UPDATE users SET status = 'disabled' WHERE id = ?")
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "UPDATE user_devices SET status = 'logged_out', sso_refresh_token = NULL
             WHERE user_id = ? AND status = 'online'",
        )
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Marks all online devices of a user as kicked and clears stored SSO refresh tokens.
    pub async fn kick_user_devices(&self, user_id: &str, now: i64) -> AppResult<u64> {
        let res = sqlx::query(
            "UPDATE user_devices
             SET status = 'kicked', kicked_at = ?, sso_refresh_token = NULL
             WHERE user_id = ? AND status = 'online'",
        )
        .bind(now)
        .bind(user_id)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    pub async fn list_online_device_user_ids(&self) -> AppResult<Vec<String>> {
        Ok(
            sqlx::query_scalar("SELECT DISTINCT user_id FROM user_devices WHERE status = 'online'")
                .fetch_all(&self.pool)
                .await?,
        )
    }

    pub async fn find_device_by_id(&self, id: &str) -> AppResult<Option<UserDeviceRow>> {
        Ok(sqlx::query_as("SELECT * FROM user_devices WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?)
    }

    pub async fn find_device_by_refresh_hash(&self, hash: &str) -> AppResult<Option<UserDeviceRow>> {
        Ok(
            sqlx::query_as("SELECT * FROM user_devices WHERE refresh_token_hash = ?")
                .bind(hash)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    pub async fn touch_device_activity(
        &self,
        device_session_id: &str,
        now: i64,
        cutoff: i64,
    ) -> AppResult<()> {
        sqlx::query(
            "UPDATE user_devices SET last_active_at = ?
             WHERE id = ? AND status = 'online' AND last_active_at <= ?",
        )
        .bind(now)
        .bind(device_session_id)
        .bind(cutoff)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Registers or updates a user's online device and evicts excess online devices in a `BEGIN IMMEDIATE` transaction.
    pub async fn login_or_reuse_device_and_evict(
        &self,
        params: LoginDeviceParams<'_>,
    ) -> AppResult<(UserDeviceRow, Vec<String>)> {
        let mut conn = self.pool.acquire().await?;
        sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;

        let tx_result: AppResult<(UserDeviceRow, Vec<String>)> = async {
            let updated = sqlx::query_as::<_, UserDeviceRow>(
                "UPDATE user_devices
                 SET device_name = ?, sso_sid = ?, sso_refresh_token = ?, refresh_token_hash = ?,
                     last_ip = ?, last_active_at = ?
                 WHERE user_id = ? AND device_id = ? AND status = 'online'
                 RETURNING *",
            )
            .bind(params.device_name)
            .bind(params.sso_sid)
            .bind(params.sso_refresh_token)
            .bind(params.refresh_hash)
            .bind(params.ip)
            .bind(params.now)
            .bind(params.user_id)
            .bind(params.device_id)
            .fetch_optional(&mut *conn)
            .await?;

            let device = match updated {
                Some(device) => device,
                None => {
                    let id = format!("ud_{}", uuid::Uuid::new_v4().simple());
                    let family_id = format!("fam_{}", uuid::Uuid::new_v4().simple());

                    sqlx::query_as::<_, UserDeviceRow>(
                        "INSERT INTO user_devices
                         (id, user_id, device_id, device_name, sso_sid, sso_refresh_token, refresh_token_hash,
                          refresh_family_id, last_ip, status, created_at, last_active_at, kicked_at)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'online', ?, ?, NULL)
                         RETURNING *",
                    )
                    .bind(&id)
                    .bind(params.user_id)
                    .bind(params.device_id)
                    .bind(params.device_name)
                    .bind(params.sso_sid)
                    .bind(params.sso_refresh_token)
                    .bind(params.refresh_hash)
                    .bind(&family_id)
                    .bind(params.ip)
                    .bind(params.now)
                    .bind(params.now)
                    .fetch_one(&mut *conn)
                    .await?
                }
            };

            let keep_others = (params.max_devices.max(1) - 1).max(0) as usize;
            let evicted_ids = evict_excess_devices_tx(
                &mut conn,
                params.user_id,
                keep_others,
                Some(&device.id),
                params.now,
            )
            .await?;

            Ok((device, evicted_ids))
        }
        .await;

        match tx_result {
            Ok(res) => {
                sqlx::query("COMMIT").execute(&mut *conn).await?;
                Ok(res)
            }
            Err(err) => {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                Err(err)
            }
        }
    }

    /// Evicts least-recently-active online devices above `max_devices` and returns evicted device session IDs.
    pub async fn evict_excess_devices(
        &self,
        user_id: &str,
        max_devices: i64,
        now: i64,
    ) -> AppResult<Vec<String>> {
        let mut conn = self.pool.acquire().await?;
        sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;

        let tx_result =
            evict_excess_devices_tx(&mut conn, user_id, max_devices.max(1) as usize, None, now)
                .await;

        match tx_result {
            Ok(ids) => {
                sqlx::query("COMMIT").execute(&mut *conn).await?;
                Ok(ids)
            }
            Err(err) => {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                Err(err)
            }
        }
    }

    pub async fn mark_device_expired(&self, device_id: &str) -> AppResult<()> {
        sqlx::query(
            "UPDATE user_devices SET status = 'expired', sso_refresh_token = NULL
             WHERE id = ? AND status = 'online'",
        )
        .bind(device_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Atomically rotates the refresh token hash on an online device, returning `false` on concurrent reuse.
    pub async fn rotate_device_refresh_token(
        &self,
        device_id: &str,
        old_hash: &str,
        new_hash: &str,
        next_sso_rt: Option<&str>,
        ip: &str,
        now: i64,
    ) -> AppResult<bool> {
        let updated = sqlx::query(
            "UPDATE user_devices
             SET refresh_token_hash = ?, sso_refresh_token = ?, last_ip = ?, last_active_at = ?
             WHERE id = ? AND refresh_token_hash = ? AND status = 'online'",
        )
        .bind(new_hash)
        .bind(next_sso_rt)
        .bind(ip)
        .bind(now)
        .bind(device_id)
        .bind(old_hash)
        .execute(&self.pool)
        .await?;
        Ok(updated.rows_affected() > 0)
    }

    pub async fn logout_device(&self, device_id: &str) -> AppResult<()> {
        sqlx::query(
            "UPDATE user_devices SET status = 'logged_out', sso_refresh_token = NULL WHERE id = ?",
        )
        .bind(device_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Logs out online devices matching an OIDC `sid` (optionally scoped to `user_id`) and returns them.
    pub async fn logout_online_devices_by_sid(
        &self,
        user_id: Option<&str>,
        sid: &str,
    ) -> AppResult<Vec<UserDeviceRow>> {
        let mut tx = self.pool.begin().await?;
        let devices: Vec<UserDeviceRow> = match user_id {
            Some(uid) => {
                sqlx::query_as(
                    "SELECT * FROM user_devices WHERE user_id = ? AND sso_sid = ? AND status = 'online'",
                )
                .bind(uid)
                .bind(sid)
                .fetch_all(&mut *tx)
                .await?
            }
            None => {
                sqlx::query_as(
                    "SELECT * FROM user_devices WHERE sso_sid = ? AND status = 'online'",
                )
                .bind(sid)
                .fetch_all(&mut *tx)
                .await?
            }
        };

        for dev in &devices {
            sqlx::query(
                "UPDATE user_devices SET status = 'logged_out', sso_refresh_token = NULL WHERE id = ?",
            )
            .bind(&dev.id)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(devices)
    }

    pub async fn logout_online_devices_by_user(&self, user_id: &str) -> AppResult<()> {
        sqlx::query(
            "UPDATE user_devices SET status = 'logged_out', sso_refresh_token = NULL
             WHERE user_id = ? AND status = 'online'",
        )
        .bind(user_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Revokes the refresh family owning `device_id` and returns all affected device session IDs.
    pub async fn revoke_device_refresh_family(&self, device_id: &str) -> AppResult<Vec<String>> {
        let mut tx = self.pool.begin().await?;
        let family_id: Option<String> =
            sqlx::query_scalar("SELECT refresh_family_id FROM user_devices WHERE id = ?")
                .bind(device_id)
                .fetch_optional(&mut *tx)
                .await?;

        let Some(family_id) = family_id else {
            return Ok(Vec::new());
        };

        let mut family_device_ids: Vec<String> = sqlx::query_scalar(
            "SELECT id FROM user_devices WHERE refresh_family_id = ? AND status = 'online'",
        )
        .bind(&family_id)
        .fetch_all(&mut *tx)
        .await?;

        sqlx::query(
            "UPDATE user_devices SET status = 'logged_out', sso_refresh_token = NULL
             WHERE refresh_family_id = ? AND status = 'online'",
        )
        .bind(&family_id)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            "UPDATE user_devices SET status = 'logged_out', sso_refresh_token = NULL WHERE id = ?",
        )
        .bind(device_id)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        if !family_device_ids.iter().any(|id| id == device_id) {
            family_device_ids.push(device_id.to_owned());
        }
        Ok(family_device_ids)
    }
}

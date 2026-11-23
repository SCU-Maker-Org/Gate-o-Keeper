use crate::error::AppResult;
use futures_util::StreamExt;
use redis::aio::{ConnectionManager, PubSub};
use redis::AsyncCommands;
use std::time::Duration;

/// Access token TTL (900s) + JWT validation leeway (30s) + 5s safety margin.
pub const JWT_REVOCATION_TTL_SEC: u64 = 935;

#[derive(Clone)]
pub struct RedisStore {
    pub client: redis::Client,
    pub conn: ConnectionManager,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JwtRevocationStatus {
    Active,
    DeviceKicked,
    Revoked,
}

impl RedisStore {
    pub async fn connect(redis_url: &str) -> anyhow::Result<Self> {
        let client = redis::Client::open(redis_url)?;
        let conn = ConnectionManager::new(client.clone()).await?;
        Ok(Self { client, conn })
    }

    /// Atomic anti-replay check for unlock nonce: returns true if inserted (fresh), false if duplicate.
    /// `ttl_sec` must cover the full `2 * window` validity span.
    pub async fn claim_unlock_nonce(
        &self,
        user_id: &str,
        nonce: &str,
        ttl_sec: u64,
    ) -> AppResult<bool> {
        let mut conn = self.conn.clone();
        let key = format!("unlock:nonce:{user_id}:{nonce}");
        let res: Option<String> = redis::cmd("SET")
            .arg(&key)
            .arg("1")
            .arg("NX")
            .arg("EX")
            .arg(ttl_sec)
            .query_async(&mut conn)
            .await?;
        Ok(res.is_some())
    }

    /// Prevent replay of OIDC Back-Channel Logout token `jti`.
    pub async fn claim_logout_jti(&self, jti: &str, ttl_sec: u64) -> AppResult<bool> {
        let mut conn = self.conn.clone();
        let key = format!("oidc:logout:jti:{jti}");
        let res: Option<String> = redis::cmd("SET")
            .arg(&key)
            .arg("1")
            .arg("NX")
            .arg("EX")
            .arg(ttl_sec.max(60))
            .query_async(&mut conn)
            .await?;
        Ok(res.is_some())
    }

    pub async fn release_logout_jti(&self, jti: &str) -> AppResult<()> {
        let mut conn = self.conn.clone();
        let key = format!("oidc:logout:jti:{jti}");
        let _: i64 = conn.del(&key).await?;
        Ok(())
    }

    pub async fn revoke_device_jwt(
        &self,
        device_session_id: &str,
        reason: &str,
    ) -> AppResult<()> {
        let mut conn = self.conn.clone();
        let key = format!("jwt:revoked:device:{device_session_id}");
        let _: () = conn.set_ex(key, reason, JWT_REVOCATION_TTL_SEC).await?;
        Ok(())
    }

    pub async fn revoke_user_jwt(&self, user_id: &str, revoked_at: i64) -> AppResult<()> {
        let mut conn = self.conn.clone();
        let key = format!("jwt:revoked:user:{user_id}");
        let _: () = conn.set_ex(key, revoked_at, JWT_REVOCATION_TTL_SEC).await?;
        Ok(())
    }

    pub async fn revoke_jti(&self, jti: &str, ttl_sec: u64) -> AppResult<()> {
        if ttl_sec == 0 {
            return Ok(());
        }
        let mut conn = self.conn.clone();
        let key = format!("jwt:revoked:jti:{jti}");
        let _: () = conn.set_ex(key, "1", ttl_sec).await?;
        Ok(())
    }

    /// Single MGET hot-path check across device, user, and jti revocation keys.
    pub async fn check_jwt_revocation(
        &self,
        device_session_id: &str,
        user_id: &str,
        jti: &str,
        iat: i64,
    ) -> AppResult<JwtRevocationStatus> {
        let mut conn = self.conn.clone();
        let keys = [
            format!("jwt:revoked:device:{device_session_id}"),
            format!("jwt:revoked:user:{user_id}"),
            format!("jwt:revoked:jti:{jti}"),
        ];
        let vals: Vec<Option<String>> = redis::cmd("MGET")
            .arg(&keys)
            .query_async(&mut conn)
            .await?;

        if let Some(reason) = vals.first().and_then(|v| v.as_deref()) {
            if reason == "kicked" {
                return Ok(JwtRevocationStatus::DeviceKicked);
            }
            return Ok(JwtRevocationStatus::Revoked);
        }
        if let Some(ts_str) = vals.get(1).and_then(|v| v.as_deref()) {
            match ts_str.parse::<i64>() {
                Ok(revoked_at) => {
                    if iat <= revoked_at {
                        return Ok(JwtRevocationStatus::Revoked);
                    }
                }
                Err(_) => {
                    // Fail closed if revocation timestamp is corrupted
                    return Ok(JwtRevocationStatus::Revoked);
                }
            }
        }
        if vals.get(2).and_then(|v| v.as_ref()).is_some() {
            return Ok(JwtRevocationStatus::Revoked);
        }
        Ok(JwtRevocationStatus::Active)
    }

    /// Per-adapter mutual exclusion lock for in-flight unlock command.
    pub async fn acquire_adapter_mutex(
        &self,
        adapter_id: &str,
        owner: &str,
        ttl_ms: u64,
    ) -> AppResult<bool> {
        let mut conn = self.conn.clone();
        let key = format!("adapter:busy:{adapter_id}");
        let res: Option<String> = redis::cmd("SET")
            .arg(&key)
            .arg(owner)
            .arg("NX")
            .arg("PX")
            .arg(ttl_ms)
            .query_async(&mut conn)
            .await?;
        Ok(res.is_some())
    }

    pub async fn release_adapter_mutex(&self, adapter_id: &str, owner: &str) -> AppResult<()> {
        let mut conn = self.conn.clone();
        let key = format!("adapter:busy:{adapter_id}");
        let script = redis::Script::new(
            r#"
            if redis.call("GET", KEYS[1]) == ARGV[1] then
                return redis.call("DEL", KEYS[1])
            else
                return 0
            end
            "#,
        );
        let _: i64 = script.key(key).arg(owner).invoke_async(&mut conn).await?;
        Ok(())
    }

    /// Atomic fixed-window rate limiter using Lua so keys can never become immortal without TTL.
    pub async fn check_rate_limit(
        &self,
        bucket: &str,
        limit: i64,
        window_sec: u64,
    ) -> AppResult<bool> {
        let mut conn = self.conn.clone();
        let key = format!("rl:{bucket}");
        let script = redis::Script::new(
            r#"
            local current = redis.call("INCR", KEYS[1])
            if current == 1 or redis.call("TTL", KEYS[1]) < 0 then
                redis.call("EXPIRE", KEYS[1], tonumber(ARGV[1]))
            end
            return current
            "#,
        );
        let count: i64 = script
            .key(key)
            .arg(window_sec.max(1) as i64)
            .invoke_async(&mut conn)
            .await?;
        Ok(count <= limit)
    }

    /// Publish command reply scoped to `(adapter_id, msg_id)` to prevent cross-adapter spoofing.
    pub async fn publish_cmd_reply(
        &self,
        adapter_id: &str,
        msg_id: &str,
        payload_json: &str,
    ) -> AppResult<()> {
        let mut conn = self.conn.clone();
        let channel = format!("reply:{adapter_id}:{msg_id}");
        let _: i64 = conn.publish(channel, payload_json).await?;
        Ok(())
    }

    /// Subscribe to `reply:{adapter_id}:{msg_id}` BEFORE publishing the MQTT command.
    pub async fn subscribe_cmd_reply(&self, adapter_id: &str, msg_id: &str) -> AppResult<PubSub> {
        let mut pubsub = self.client.get_async_pubsub().await?;
        let channel = format!("reply:{adapter_id}:{msg_id}");
        pubsub.subscribe(&channel).await?;
        Ok(pubsub)
    }

    /// Wait up to `timeout` on an already-subscribed `PubSub` channel.
    pub async fn wait_cmd_reply(
        mut pubsub: PubSub,
        timeout: Duration,
    ) -> AppResult<Option<String>> {
        let fut = async {
            let mut stream = pubsub.on_message();
            if let Some(msg) = stream.next().await {
                let payload: String = msg.get_payload()?;
                Ok::<Option<String>, redis::RedisError>(Some(payload))
            } else {
                Ok(None)
            }
        };
        match tokio::time::timeout(timeout, fut).await {
            Ok(res) => Ok(res?),
            Err(_) => Ok(None),
        }
    }
}

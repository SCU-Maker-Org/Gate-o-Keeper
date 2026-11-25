use crate::error::AppResult;
use futures_util::StreamExt;
use redis::aio::{ConnectionManager, PubSub};
use redis::AsyncCommands;
use std::sync::Arc;
use std::time::Duration;
#[cfg(feature = "test-utils")]
use std::collections::HashMap;
#[cfg(feature = "test-utils")]
use std::sync::Mutex;
#[cfg(feature = "test-utils")]
use std::time::Instant;
#[cfg(feature = "test-utils")]
use tokio::sync::broadcast;

/// Access token TTL (900s) + JWT validation leeway (30s) + 5s safety margin.
pub const JWT_REVOCATION_TTL_SEC: u64 = 935;

#[derive(Clone)]
pub struct RedisStore {
    inner: RedisBackend,
}

#[derive(Clone)]
enum RedisBackend {
    Live(Arc<LiveRedis>),
    #[cfg(feature = "test-utils")]
    Memory(Arc<MemoryRedis>),
}

struct LiveRedis {
    client: redis::Client,
    conn: ConnectionManager,
}

#[cfg(feature = "test-utils")]
#[derive(Default)]
struct MemoryRedis {
    kv: Mutex<HashMap<String, (String, Option<Instant>)>>,
    channels: Mutex<HashMap<String, broadcast::Sender<String>>>,
}

#[cfg(feature = "test-utils")]
impl MemoryRedis {
    fn purge_if_expired(map: &mut HashMap<String, (String, Option<Instant>)>, key: &str) {
        if let Some((_, Some(exp))) = map.get(key) {
            if Instant::now() >= *exp {
                map.remove(key);
            }
        }
    }

    fn set_nx(&self, key: &str, val: &str, ttl: Duration) -> bool {
        let mut map = self.kv.lock().expect("memory redis lock poisoned");
        Self::purge_if_expired(&mut map, key);
        if map.contains_key(key) {
            return false;
        }
        map.insert(
            key.to_string(),
            (val.to_string(), Some(Instant::now() + ttl)),
        );
        true
    }

    fn set_ex(&self, key: &str, val: String, ttl: Duration) {
        let mut map = self.kv.lock().expect("memory redis lock poisoned");
        map.insert(key.to_string(), (val, Some(Instant::now() + ttl)));
    }

    fn get(&self, key: &str) -> Option<String> {
        let mut map = self.kv.lock().expect("memory redis lock poisoned");
        Self::purge_if_expired(&mut map, key);
        map.get(key).map(|(v, _)| v.clone())
    }

    fn del(&self, key: &str) {
        let mut map = self.kv.lock().expect("memory redis lock poisoned");
        map.remove(key);
    }

    fn take(&self, key: &str) -> bool {
        let mut map = self.kv.lock().expect("memory redis lock poisoned");
        Self::purge_if_expired(&mut map, key);
        map.remove(key).is_some()
    }

    fn incr_with_window(&self, key: &str, window_sec: u64) -> i64 {
        let mut map = self.kv.lock().expect("memory redis lock poisoned");
        Self::purge_if_expired(&mut map, key);
        let next = map
            .get(key)
            .and_then(|(v, _)| v.parse::<i64>().ok())
            .unwrap_or(0)
            + 1;
        let exp = map
            .get(key)
            .and_then(|(_, e)| *e)
            .unwrap_or_else(|| Instant::now() + Duration::from_secs(window_sec.max(1)));
        map.insert(key.to_string(), (next.to_string(), Some(exp)));
        next
    }

    fn subscribe(&self, channel: &str) -> broadcast::Receiver<String> {
        let mut channels = self
            .channels
            .lock()
            .expect("memory redis channels poisoned");
        let tx = channels
            .entry(channel.to_string())
            .or_insert_with(|| broadcast::channel(16).0);
        tx.subscribe()
    }

    fn publish(&self, channel: &str, payload: &str) {
        let channels = self
            .channels
            .lock()
            .expect("memory redis channels poisoned");
        if let Some(tx) = channels.get(channel) {
            let _ = tx.send(payload.to_string());
        }
    }
}

pub enum CmdReplyWaiter {
    Live(PubSub),
    #[cfg(feature = "test-utils")]
    Memory(broadcast::Receiver<String>),
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
        Ok(Self {
            inner: RedisBackend::Live(Arc::new(LiveRedis { client, conn })),
        })
    }

    /// Creates an in-memory Redis substitute for hermetic unit/integration tests.
    #[cfg(feature = "test-utils")]
    pub fn new_in_memory() -> Self {
        Self {
            inner: RedisBackend::Memory(Arc::new(MemoryRedis::default())),
        }
    }

    pub async fn ping(&self) -> AppResult<()> {
        match &self.inner {
            RedisBackend::Live(live) => {
                let mut conn = live.conn.clone();
                let _: String = redis::cmd("PING").query_async(&mut conn).await?;
                Ok(())
            }
            #[cfg(feature = "test-utils")]
            RedisBackend::Memory(_) => Ok(()),
        }
    }

    pub async fn mark_refresh_token_used(
        &self,
        old_hash: &str,
        device_id: &str,
        ttl_sec: u64,
    ) -> AppResult<()> {
        let key = format!("rt:used:{old_hash}");
        match &self.inner {
            RedisBackend::Live(live) => {
                let mut conn = live.conn.clone();
                let _: () = conn.set_ex(&key, device_id, ttl_sec).await?;
            }
            #[cfg(feature = "test-utils")]
            RedisBackend::Memory(mem) => {
                mem.set_ex(&key, device_id.to_string(), Duration::from_secs(ttl_sec));
            }
        }
        Ok(())
    }

    pub async fn lookup_used_refresh_token(&self, hash: &str) -> AppResult<Option<String>> {
        let key = format!("rt:used:{hash}");
        match &self.inner {
            RedisBackend::Live(live) => {
                let mut conn = live.conn.clone();
                let device_id: Option<String> = conn.get(key).await?;
                Ok(device_id)
            }
            #[cfg(feature = "test-utils")]
            RedisBackend::Memory(mem) => Ok(mem.get(&key)),
        }
    }

    /// Marks an adapter for immediate token-rotation retry once it finishes subscribing
    /// (on `presence online`) after authenticating with an old token over a stale pending rotation.
    pub async fn mark_adapter_rotation_retry(
        &self,
        adapter_id: &str,
        ttl_sec: u64,
    ) -> AppResult<()> {
        let key = format!("adapter:rot_retry:{adapter_id}");
        match &self.inner {
            RedisBackend::Live(live) => {
                let mut conn = live.conn.clone();
                let _: () = conn.set_ex(&key, "1", ttl_sec).await?;
            }
            #[cfg(feature = "test-utils")]
            RedisBackend::Memory(mem) => {
                mem.set_ex(&key, "1".to_string(), Duration::from_secs(ttl_sec));
            }
        }
        Ok(())
    }

    /// Atomically consumes a pending rotation-retry marker for `adapter_id`.
    pub async fn take_adapter_rotation_retry(&self, adapter_id: &str) -> AppResult<bool> {
        let key = format!("adapter:rot_retry:{adapter_id}");
        match &self.inner {
            RedisBackend::Live(live) => {
                let mut conn = live.conn.clone();
                let deleted: i64 = conn.del(&key).await?;
                Ok(deleted > 0)
            }
            #[cfg(feature = "test-utils")]
            RedisBackend::Memory(mem) => Ok(mem.take(&key)),
        }
    }

    /// Atomic anti-replay check for unlock nonce: returns true if inserted (fresh), false if duplicate.
    /// `ttl_sec` must cover the full `2 * window` validity span.
    pub async fn claim_unlock_nonce(
        &self,
        user_id: &str,
        nonce: &str,
        ttl_sec: u64,
    ) -> AppResult<bool> {
        let key = format!("unlock:nonce:{user_id}:{nonce}");
        match &self.inner {
            RedisBackend::Live(live) => {
                let mut conn = live.conn.clone();
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
            #[cfg(feature = "test-utils")]
            RedisBackend::Memory(mem) => Ok(mem.set_nx(&key, "1", Duration::from_secs(ttl_sec))),
        }
    }

    /// Prevent replay of OIDC Back-Channel Logout token `jti`.
    pub async fn claim_logout_jti(&self, jti: &str, ttl_sec: u64) -> AppResult<bool> {
        let key = format!("oidc:logout:jti:{jti}");
        let ttl = ttl_sec.max(60);
        match &self.inner {
            RedisBackend::Live(live) => {
                let mut conn = live.conn.clone();
                let res: Option<String> = redis::cmd("SET")
                    .arg(&key)
                    .arg("1")
                    .arg("NX")
                    .arg("EX")
                    .arg(ttl)
                    .query_async(&mut conn)
                    .await?;
                Ok(res.is_some())
            }
            #[cfg(feature = "test-utils")]
            RedisBackend::Memory(mem) => Ok(mem.set_nx(&key, "1", Duration::from_secs(ttl))),
        }
    }

    pub async fn release_logout_jti(&self, jti: &str) -> AppResult<()> {
        let key = format!("oidc:logout:jti:{jti}");
        match &self.inner {
            RedisBackend::Live(live) => {
                let mut conn = live.conn.clone();
                let _: i64 = conn.del(&key).await?;
            }
            #[cfg(feature = "test-utils")]
            RedisBackend::Memory(mem) => mem.del(&key),
        }
        Ok(())
    }

    pub async fn revoke_device_jwt(&self, device_session_id: &str, reason: &str) -> AppResult<()> {
        let key = format!("jwt:revoked:device:{device_session_id}");
        match &self.inner {
            RedisBackend::Live(live) => {
                let mut conn = live.conn.clone();
                let _: () = conn.set_ex(key, reason, JWT_REVOCATION_TTL_SEC).await?;
            }
            #[cfg(feature = "test-utils")]
            RedisBackend::Memory(mem) => mem.set_ex(
                &key,
                reason.to_string(),
                Duration::from_secs(JWT_REVOCATION_TTL_SEC),
            ),
        }
        Ok(())
    }

    pub async fn revoke_user_jwt(&self, user_id: &str, revoked_at: i64) -> AppResult<()> {
        let key = format!("jwt:revoked:user:{user_id}");
        match &self.inner {
            RedisBackend::Live(live) => {
                let mut conn = live.conn.clone();
                let _: () = conn.set_ex(key, revoked_at, JWT_REVOCATION_TTL_SEC).await?;
            }
            #[cfg(feature = "test-utils")]
            RedisBackend::Memory(mem) => mem.set_ex(
                &key,
                revoked_at.to_string(),
                Duration::from_secs(JWT_REVOCATION_TTL_SEC),
            ),
        }
        Ok(())
    }

    pub async fn revoke_jti(&self, jti: &str, ttl_sec: u64) -> AppResult<()> {
        if ttl_sec == 0 {
            return Ok(());
        }
        let key = format!("jwt:revoked:jti:{jti}");
        match &self.inner {
            RedisBackend::Live(live) => {
                let mut conn = live.conn.clone();
                let _: () = conn.set_ex(key, "1", ttl_sec).await?;
            }
            #[cfg(feature = "test-utils")]
            RedisBackend::Memory(mem) => {
                mem.set_ex(&key, "1".to_string(), Duration::from_secs(ttl_sec));
            }
        }
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
        let keys = [
            format!("jwt:revoked:device:{device_session_id}"),
            format!("jwt:revoked:user:{user_id}"),
            format!("jwt:revoked:jti:{jti}"),
        ];
        let vals: Vec<Option<String>> = match &self.inner {
            RedisBackend::Live(live) => {
                let mut conn = live.conn.clone();
                redis::cmd("MGET").arg(&keys).query_async(&mut conn).await?
            }
            #[cfg(feature = "test-utils")]
            RedisBackend::Memory(mem) => keys.iter().map(|k| mem.get(k)).collect(),
        };

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
        let key = format!("adapter:busy:{adapter_id}");
        match &self.inner {
            RedisBackend::Live(live) => {
                let mut conn = live.conn.clone();
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
            #[cfg(feature = "test-utils")]
            RedisBackend::Memory(mem) => Ok(mem.set_nx(&key, owner, Duration::from_millis(ttl_ms))),
        }
    }

    pub async fn release_adapter_mutex(&self, adapter_id: &str, owner: &str) -> AppResult<()> {
        let key = format!("adapter:busy:{adapter_id}");
        match &self.inner {
            RedisBackend::Live(live) => {
                let mut conn = live.conn.clone();
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
            }
            #[cfg(feature = "test-utils")]
            RedisBackend::Memory(mem) => {
                let mut map = mem.kv.lock().expect("memory redis lock poisoned");
                if map.get(&key).is_some_and(|(v, _)| v == owner) {
                    map.remove(&key);
                }
            }
        }
        Ok(())
    }

    /// Atomic fixed-window rate limiter using Lua so keys can never become immortal without TTL.
    pub async fn check_rate_limit(
        &self,
        bucket: &str,
        limit: i64,
        window_sec: u64,
    ) -> AppResult<bool> {
        let key = format!("rl:{bucket}");
        let count: i64 = match &self.inner {
            RedisBackend::Live(live) => {
                let mut conn = live.conn.clone();
                let script = redis::Script::new(
                    r#"
                    local current = redis.call("INCR", KEYS[1])
                    if current == 1 or redis.call("TTL", KEYS[1]) < 0 then
                        redis.call("EXPIRE", KEYS[1], tonumber(ARGV[1]))
                    end
                    return current
                    "#,
                );
                script
                    .key(key)
                    .arg(window_sec.max(1) as i64)
                    .invoke_async(&mut conn)
                    .await?
            }
            #[cfg(feature = "test-utils")]
            RedisBackend::Memory(mem) => mem.incr_with_window(&key, window_sec),
        };
        Ok(count <= limit)
    }

    /// Publish command reply scoped to `(adapter_id, msg_id)` to prevent cross-adapter spoofing.
    pub async fn publish_cmd_reply(
        &self,
        adapter_id: &str,
        msg_id: &str,
        payload_json: &str,
    ) -> AppResult<()> {
        let channel = format!("reply:{adapter_id}:{msg_id}");
        match &self.inner {
            RedisBackend::Live(live) => {
                let mut conn = live.conn.clone();
                let _: i64 = conn.publish(channel, payload_json).await?;
            }
            #[cfg(feature = "test-utils")]
            RedisBackend::Memory(mem) => {
                mem.publish(&channel, payload_json);
            }
        }
        Ok(())
    }

    /// Subscribe to `reply:{adapter_id}:{msg_id}` BEFORE publishing the MQTT command.
    pub async fn subscribe_cmd_reply(
        &self,
        adapter_id: &str,
        msg_id: &str,
    ) -> AppResult<CmdReplyWaiter> {
        let channel = format!("reply:{adapter_id}:{msg_id}");
        match &self.inner {
            RedisBackend::Live(live) => {
                let mut pubsub = live.client.get_async_pubsub().await?;
                pubsub.subscribe(&channel).await?;
                Ok(CmdReplyWaiter::Live(pubsub))
            }
            #[cfg(feature = "test-utils")]
            RedisBackend::Memory(mem) => Ok(CmdReplyWaiter::Memory(mem.subscribe(&channel))),
        }
    }

    /// Wait up to `timeout` on an already-subscribed `CmdReplyWaiter`.
    pub async fn wait_cmd_reply(
        waiter: CmdReplyWaiter,
        timeout: Duration,
    ) -> AppResult<Option<String>> {
        match waiter {
            CmdReplyWaiter::Live(mut pubsub) => {
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
            #[cfg(feature = "test-utils")]
            CmdReplyWaiter::Memory(mut rx) => {
                match tokio::time::timeout(timeout, rx.recv()).await {
                    Ok(Ok(payload)) => Ok(Some(payload)),
                    Ok(Err(_)) | Err(_) => Ok(None),
                }
            }
        }
    }
}

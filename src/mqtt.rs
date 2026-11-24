use crate::audit::{AuditEvent, AuditHandle};
use crate::auth::hash_token;
use crate::config::AppConfig;
use crate::db::{AdapterRow, Db};
use crate::error::{AppError, AppResult};
use crate::redis_store::RedisStore;
use rand::RngCore;
use rumqttc::v5::{
    mqttbytes::{
        v5::{Packet, PublishProperties},
        QoS,
    },
    AsyncClient, Event, MqttOptions,
};
use rumqttc::{TlsConfiguration, Transport};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Semaphore;

const MAX_INFLIGHT_MQTT_HANDLERS: usize = 64;
const PENDING_TOKEN_TTL_SEC: i64 = 600;

#[derive(Clone, Debug)]
pub struct CapturedMqttMessage {
    pub topic: String,
    pub qos: QoS,
    pub retain: bool,
    pub payload: Vec<u8>,
    pub message_expiry_interval: Option<u32>,
}

#[derive(Clone)]
enum MqttTransport {
    Live(AsyncClient),
    Memory(Arc<Mutex<Vec<CapturedMqttMessage>>>),
}

#[derive(Clone)]
pub struct MqttClient {
    transport: MqttTransport,
    config: AppConfig,
    http: reqwest::Client,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MqttEnvelope<T> {
    pub v: u8,
    pub msg_id: String,
    pub ts: i64,
    pub payload: T,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnlockCmdPayload {
    pub command: String,
    pub timeout_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryStateCmdPayload {
    pub command: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshTokenCmdPayload {
    pub command: String,
    pub token: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetConfigCmdPayload {
    pub command: String,
    pub state_report_period_sec: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnlockResultPayload {
    pub ok: bool,
    pub code: String,
    #[serde(default)]
    pub message: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AckPayload {
    #[serde(default)]
    command: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StatePayload {
    state: String,
    #[serde(default)]
    snapshot: bool,
}

#[derive(Clone, Debug, Deserialize)]
struct PresencePayload {
    online: bool,
}

#[derive(Clone, Debug, Deserialize)]
struct SysClientEvent {
    #[serde(default)]
    ts: Option<i64>,
    #[serde(default)]
    connected_at: Option<i64>,
    #[serde(default)]
    disconnected_at: Option<i64>,
}

pub fn connect_and_spawn(
    config: AppConfig,
    db: Db,
    redis: RedisStore,
    audit: AuditHandle,
    http: reqwest::Client,
) -> anyhow::Result<MqttClient> {
    let mut opts = MqttOptions::new(&config.mqtt_client_id, &config.mqtt_host, config.mqtt_port);
    opts.set_credentials(&config.mqtt_username, &config.mqtt_password);
    opts.set_clean_start(true);
    opts.set_keep_alive(Duration::from_secs(30));

    let ca = std::fs::read(&config.mqtt_ca_cert)?;
    let cert = std::fs::read(&config.mqtt_client_cert)?;
    let key = std::fs::read(&config.mqtt_client_key)?;

    opts.set_transport(Transport::tls_with_config(TlsConfiguration::Simple {
        ca,
        alpn: None,
        client_auth: Some((cert, key)),
    }));

    let (client, mut eventloop) = AsyncClient::new(opts, 128);
    let sub_client = client.clone();
    let mqtt = MqttClient {
        transport: MqttTransport::Live(client),
        config: config.clone(),
        http,
    };
    let cfg_clone = config;
    let db_loop = db.clone();
    let audit_loop = audit.clone();
    let mqtt_loop = mqtt.clone();
    let sem = Arc::new(Semaphore::new(MAX_INFLIGHT_MQTT_HANDLERS));

    tokio::spawn(async move {
        loop {
            match eventloop.poll().await {
                Ok(Event::Incoming(Packet::ConnAck(_))) => {
                    tracing::info!("connected to EMQX over MQTTS (v5)");
                    let subs = [
                        ("$share/backend/adapter/+/ack", QoS::AtLeastOnce),
                        ("$share/backend/adapter/+/result", QoS::AtLeastOnce),
                        ("$share/backend/adapter/+/state", QoS::AtLeastOnce),
                        ("$share/backend/adapter/+/presence", QoS::AtLeastOnce),
                        ("$share/backend/adapter/+/error", QoS::AtMostOnce),
                        (
                            "$share/backend/$SYS/brokers/+/clients/+/connected",
                            QoS::AtMostOnce,
                        ),
                        (
                            "$share/backend/$SYS/brokers/+/clients/+/disconnected",
                            QoS::AtMostOnce,
                        ),
                    ];
                    for (topic, qos) in subs {
                        if let Err(err) = sub_client.subscribe(topic, qos).await {
                            tracing::error!(topic, error = %err, "failed to subscribe");
                        }
                    }
                }
                Ok(Event::Incoming(Packet::Publish(p))) => {
                    let permit = sem.clone();
                    let cfg = cfg_clone.clone();
                    let db = db_loop.clone();
                    let redis = redis.clone();
                    let audit = audit_loop.clone();
                    let mqtt = mqtt_loop.clone();
                    tokio::spawn(async move {
                        let Ok(_guard) = permit.acquire_owned().await else {
                            return;
                        };
                        let topic = String::from_utf8_lossy(&p.topic);
                        handle_publish(
                            &cfg,
                            &db,
                            &redis,
                            &audit,
                            &mqtt,
                            &topic,
                            p.retain,
                            &p.payload,
                        )
                        .await;
                    });
                }
                Ok(_) => {}
                Err(err) => {
                    tracing::warn!(error = %err, "MQTT eventloop error; reconnecting");
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }
        }
    });

    let rotation_client = mqtt.clone();
    tokio::spawn(async move {
        token_refresh_loop(rotation_client, db, audit).await;
    });

    Ok(mqtt)
}

pub async fn expire_stale_pending_tokens(db: &Db, audit: &AuditHandle, now: i64) {
    let cutoff = now - PENDING_TOKEN_TTL_SEC;
    let stale: Result<Vec<AdapterRow>, _> = sqlx::query_as(
        "SELECT * FROM adapters
         WHERE pending_token_hash IS NOT NULL
           AND COALESCE(pending_token_at, updated_at) <= ?",
    )
    .bind(cutoff)
    .fetch_all(&db.pool)
    .await;

    let adapters = match stale {
        Ok(list) => list,
        Err(err) => {
            tracing::error!(error = %err, "failed to query stale pending adapter tokens");
            return;
        }
    };

    for adapter in adapters {
        let res = sqlx::query(
            "UPDATE adapters
             SET pending_token_hash = NULL,
                 pending_token_msg_id = NULL,
                 pending_token_at = NULL,
                 updated_at = ?
             WHERE id = ? AND pending_token_hash IS NOT NULL AND COALESCE(pending_token_at, updated_at) <= ?",
        )
        .bind(now)
        .bind(&adapter.id)
        .bind(cutoff)
        .execute(&db.pool)
        .await;

        match res {
            Ok(r) if r.rows_affected() > 0 => {
                tracing::warn!(
                    adapter_id = %adapter.id,
                    msg_id = ?adapter.pending_token_msg_id,
                    "expired unacknowledged pending adapter token rotation"
                );
                audit.record(AuditEvent {
                    actor_type: "system".into(),
                    actor_id: "scheduler".into(),
                    action: "refresh_adapter_token_expired".into(),
                    target_type: "adapter".into(),
                    target_id: adapter.id,
                    result: "timeout".into(),
                    detail: serde_json::json!({
                        "msgId": adapter.pending_token_msg_id,
                        "pendingTokenAt": adapter.pending_token_at,
                    }),
                    ip: String::new(),
                    request_id: adapter.pending_token_msg_id.unwrap_or_default(),
                });
            }
            Ok(_) => {}
            Err(err) => {
                tracing::error!(
                    adapter_id = %adapter.id,
                    error = %err,
                    "failed to clear expired pending adapter token"
                );
            }
        }
    }
}

pub async fn query_due_rotation_adapters(
    db: &Db,
    now: i64,
) -> Result<Vec<AdapterRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT * FROM adapters
         WHERE approval_status = 'approved'
           AND online_status = 'online'
           AND pending_token_hash IS NULL
           AND token_refresh_interval > 0
           AND COALESCE(token_rotated_at, approved_at, created_at) + token_refresh_interval <= ?",
    )
    .bind(now)
    .fetch_all(&db.pool)
    .await
}

async fn token_refresh_loop(mqtt: MqttClient, db: Db, audit: AuditHandle) {
    let start = tokio::time::Instant::now() + Duration::from_secs(60);
    let mut ticker = tokio::time::interval_at(start, Duration::from_secs(60));
    loop {
        ticker.tick().await;
        let now = chrono::Utc::now().timestamp();
        expire_stale_pending_tokens(&db, &audit, now).await;

        let due = query_due_rotation_adapters(&db, now).await;

        let adapters = match due {
            Ok(list) => list,
            Err(err) => {
                tracing::error!(error = %err, "failed to query adapters due for token rotation");
                continue;
            }
        };

        for adapter in adapters {
            let mut bytes = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut bytes);
            let new_token = hex::encode(bytes);
            let new_hash = hash_token(&new_token);
            let msg_id = format!("rot_{}", uuid::Uuid::new_v4().simple());

            let res = sqlx::query(
                "UPDATE adapters
                 SET pending_token_hash = ?, pending_token_msg_id = ?, pending_token_at = ?, updated_at = ?
                 WHERE id = ? AND approval_status = 'approved' AND pending_token_hash IS NULL",
            )
            .bind(&new_hash)
            .bind(&msg_id)
            .bind(now)
            .bind(now)
            .bind(&adapter.id)
            .execute(&db.pool)
            .await;

            match res {
                Ok(r) if r.rows_affected() > 0 => {
                    if let Err(err) = mqtt
                        .publish_refresh_token(&adapter.id, &msg_id, &new_token)
                        .await
                    {
                        tracing::warn!(
                            adapter_id = %adapter.id,
                            error = %err.message,
                            "scheduled token refresh publish failed; rolling back pending token"
                        );
                        let _ = sqlx::query(
                            "UPDATE adapters
                             SET pending_token_hash = NULL, pending_token_msg_id = NULL, pending_token_at = NULL
                             WHERE id = ? AND pending_token_msg_id = ?",
                        )
                        .bind(&adapter.id)
                        .bind(&msg_id)
                        .execute(&db.pool)
                        .await;
                    }
                }
                Ok(_) => {}
                Err(err) => {
                    tracing::error!(
                        adapter_id = %adapter.id,
                        error = %err,
                        "failed to stage scheduled adapter token rotation"
                    );
                }
            }
        }
    }
}

impl MqttClient {
    /// Creates an in-memory MQTT client handle suitable for hermetic integration tests.
    pub fn new_disconnected(config: AppConfig, http: reqwest::Client) -> Self {
        Self {
            transport: MqttTransport::Memory(Arc::new(Mutex::new(Vec::new()))),
            config,
            http,
        }
    }

    pub fn take_captured_messages(&self) -> Vec<CapturedMqttMessage> {
        match &self.transport {
            MqttTransport::Live(_) => Vec::new(),
            MqttTransport::Memory(buf) => {
                let mut guard = buf.lock().expect("mqtt test capture lock poisoned");
                std::mem::take(&mut *guard)
            }
        }
    }

    async fn publish_raw(
        &self,
        topic: String,
        qos: QoS,
        retain: bool,
        bytes: Vec<u8>,
        props: Option<PublishProperties>,
    ) -> AppResult<()> {
        match &self.transport {
            MqttTransport::Live(client) => {
                if let Some(p) = props {
                    client
                        .publish_with_properties(topic, qos, retain, bytes, p)
                        .await
                        .map_err(|e| AppError::internal(format!("mqtt publish failed: {e}")))?;
                } else {
                    client
                        .publish(topic, qos, retain, bytes)
                        .await
                        .map_err(|e| AppError::internal(format!("mqtt publish failed: {e}")))?;
                }
            }
            MqttTransport::Memory(buf) => {
                let mut guard = buf.lock().expect("mqtt test capture lock poisoned");
                guard.push(CapturedMqttMessage {
                    topic,
                    qos,
                    retain,
                    payload: bytes,
                    message_expiry_interval: props.and_then(|p| p.message_expiry_interval),
                });
            }
        }
        Ok(())
    }

    pub async fn publish_unlock(
        &self,
        adapter_id: &str,
        msg_id: &str,
        timeout_ms: u64,
    ) -> AppResult<()> {
        let env = MqttEnvelope {
            v: 1,
            msg_id: msg_id.to_string(),
            ts: chrono::Utc::now().timestamp(),
            payload: UnlockCmdPayload {
                command: "unlock".to_string(),
                timeout_ms,
            },
        };
        let bytes = serde_json::to_vec(&env)
            .map_err(|e| AppError::internal(format!("json encode failed: {e}")))?;
        let topic = format!("adapter/{adapter_id}/cmd");
        let expiry_sec = timeout_ms.div_ceil(1000).clamp(1, u32::MAX as u64) as u32;
        let props = PublishProperties {
            message_expiry_interval: Some(expiry_sec),
            ..Default::default()
        };
        self.publish_raw(topic, QoS::ExactlyOnce, false, bytes, Some(props))
            .await
    }

    pub async fn publish_query_state(&self, adapter_id: &str, msg_id: &str) -> AppResult<()> {
        let env = MqttEnvelope {
            v: 1,
            msg_id: msg_id.to_string(),
            ts: chrono::Utc::now().timestamp(),
            payload: QueryStateCmdPayload {
                command: "query_state".to_string(),
            },
        };
        let bytes = serde_json::to_vec(&env)
            .map_err(|e| AppError::internal(format!("json encode failed: {e}")))?;
        let topic = format!("adapter/{adapter_id}/cmd");
        let props = PublishProperties {
            message_expiry_interval: Some(PENDING_TOKEN_TTL_SEC as u32),
            ..Default::default()
        };
        self.publish_raw(topic, QoS::AtLeastOnce, false, bytes, Some(props))
            .await
    }

    pub async fn publish_refresh_token(
        &self,
        adapter_id: &str,
        msg_id: &str,
        new_token: &str,
    ) -> AppResult<()> {
        let env = MqttEnvelope {
            v: 1,
            msg_id: msg_id.to_string(),
            ts: chrono::Utc::now().timestamp(),
            payload: RefreshTokenCmdPayload {
                command: "refresh_token".to_string(),
                token: new_token.to_string(),
            },
        };
        let bytes = serde_json::to_vec(&env)
            .map_err(|e| AppError::internal(format!("json encode failed: {e}")))?;
        let topic = format!("adapter/{adapter_id}/cmd");
        let props = PublishProperties {
            message_expiry_interval: Some(PENDING_TOKEN_TTL_SEC as u32),
            ..Default::default()
        };
        self.publish_raw(topic, QoS::AtLeastOnce, false, bytes, Some(props))
            .await
    }

    pub async fn publish_set_config(
        &self,
        adapter_id: &str,
        msg_id: &str,
        state_report_period_sec: i64,
    ) -> AppResult<()> {
        let env = MqttEnvelope {
            v: 1,
            msg_id: msg_id.to_string(),
            ts: chrono::Utc::now().timestamp(),
            payload: SetConfigCmdPayload {
                command: "set_config".to_string(),
                state_report_period_sec,
            },
        };
        let bytes = serde_json::to_vec(&env)
            .map_err(|e| AppError::internal(format!("json encode failed: {e}")))?;
        let topic = format!("adapter/{adapter_id}/cmd");
        let props = PublishProperties {
            message_expiry_interval: Some(PENDING_TOKEN_TTL_SEC as u32),
            ..Default::default()
        };
        self.publish_raw(topic, QoS::AtLeastOnce, false, bytes, Some(props))
            .await
    }

    pub async fn kick_client(&self, adapter_id: &str) {
        if self.config.mqtt_broker_api_key.is_empty() {
            tracing::warn!(
                adapter_id,
                "MQTT_BROKER_API_KEY is empty; skipping EMQX client kick"
            );
            return;
        }
        let url = format!(
            "{}/clients/{}",
            self.config.mqtt_broker_api_url.trim_end_matches('/'),
            adapter_id
        );
        let res = self
            .http
            .delete(&url)
            .basic_auth(
                &self.config.mqtt_broker_api_key,
                Some(&self.config.mqtt_broker_api_secret),
            )
            .timeout(Duration::from_secs(3))
            .send()
            .await;

        match res {
            Ok(resp)
                if !resp.status().is_success()
                    && resp.status() != reqwest::StatusCode::NOT_FOUND =>
            {
                tracing::warn!(
                    adapter_id,
                    status = %resp.status(),
                    "EMQX kick client API returned non-success status"
                );
            }
            Err(err) => {
                tracing::warn!(adapter_id, error = %err, "failed to kick MQTT client via EMQX API");
            }
            Ok(_) => {}
        }
    }
}

fn normalize_sys_ts_sec(payload: &[u8], fallback_now: i64) -> i64 {
    let Ok(ev) = serde_json::from_slice::<SysClientEvent>(payload) else {
        return fallback_now;
    };
    let raw = ev.disconnected_at.or(ev.connected_at).or(ev.ts);
    match raw {
        Some(v) if v > 10_000_000_000 => v / 1000,
        Some(v) if v > 0 => v,
        _ => fallback_now,
    }
}

async fn handle_publish(
    config: &AppConfig,
    db: &Db,
    redis: &RedisStore,
    audit: &AuditHandle,
    mqtt: &MqttClient,
    topic: &str,
    retain: bool,
    payload: &[u8],
) {
    if retain {
        tracing::warn!(topic, "ignoring retained MQTT message");
        return;
    }
    let now = chrono::Utc::now().timestamp();
    let parts: Vec<&str> = topic.split('/').collect();

    // $SYS/brokers/<node>/clients/<clientid>/connected|disconnected
    if parts.len() == 6 && parts[0] == "$SYS" && parts[1] == "brokers" && parts[3] == "clients" {
        let client_id = parts[4];
        if client_id == config.mqtt_client_id {
            return;
        }
        let event_ts = normalize_sys_ts_sec(payload, now);
        match parts[5] {
            "connected" => {
                if let Ok(res) = sqlx::query(
                    "UPDATE adapters
                     SET online_status = 'online', last_seen_at = MAX(COALESCE(last_seen_at, 0), ?), updated_at = ?
                     WHERE id = ? AND approval_status = 'approved'",
                )
                .bind(event_ts)
                .bind(now)
                .bind(client_id)
                .execute(&db.pool)
                .await
                {
                    if res.rows_affected() > 0 {
                        if let Ok(sys_cfg) = db.get_system_config().await {
                            let msg_id = format!("cfg_{}", uuid::Uuid::new_v4().simple());
                            let _ = mqtt
                                .publish_set_config(client_id, &msg_id, sys_cfg.state_report_period_sec)
                                .await;
                        }
                    }
                }
            }
            "disconnected" => {
                let _ = sqlx::query(
                    "UPDATE adapters
                     SET online_status = 'offline', last_seen_at = MAX(COALESCE(last_seen_at, 0), ?), updated_at = ?
                     WHERE id = ? AND approval_status = 'approved' AND COALESCE(last_seen_at, 0) <= ?",
                )
                .bind(event_ts)
                .bind(now)
                .bind(client_id)
                .bind(event_ts)
                .execute(&db.pool)
                .await;
            }
            _ => {}
        }
        return;
    }

    if parts.len() != 3 || parts[0] != "adapter" {
        return;
    }
    let adapter_id = parts[1];
    let kind = parts[2];

    let adapter = match db.find_adapter_by_id(adapter_id).await {
        Ok(Some(adapter)) if adapter.approval_status == "approved" => adapter,
        Ok(Some(adapter)) => {
            tracing::warn!(
                adapter_id,
                kind,
                approval_status = %adapter.approval_status,
                "ignoring MQTT publish from non-approved adapter"
            );
            return;
        }
        Ok(None) => {
            tracing::warn!(adapter_id, kind, "ignoring MQTT publish from unknown adapter");
            return;
        }
        Err(err) => {
            tracing::error!(adapter_id, kind, error = %err.message, "failed to verify adapter");
            return;
        }
    };
    let _ = adapter;

    match kind {
        "result" => match serde_json::from_slice::<MqttEnvelope<UnlockResultPayload>>(payload) {
            Ok(env) => {
                if let Ok(json_str) = serde_json::to_string(&env.payload) {
                    if let Err(err) = redis
                        .publish_cmd_reply(adapter_id, &env.msg_id, &json_str)
                        .await
                    {
                        tracing::error!(
                            adapter_id,
                            msg_id = %env.msg_id,
                            error = %err.message,
                            "failed to publish cmd reply"
                        );
                    }
                }
            }
            Err(err) => {
                tracing::warn!(adapter_id, error = %err, "malformed adapter result payload");
            }
        },
        "ack" => match serde_json::from_slice::<MqttEnvelope<AckPayload>>(payload) {
            Ok(env) => {
                if env.payload.command == "refresh_token" && !env.msg_id.is_empty() {
                    let _ = sqlx::query(
                        "UPDATE adapters
                         SET token_hash = COALESCE(pending_token_hash, token_hash),
                             pending_token_hash = NULL,
                             pending_token_msg_id = NULL,
                             pending_token_at = NULL,
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
                    .bind(&env.msg_id)
                    .execute(&db.pool)
                    .await;
                }
            }
            Err(err) => {
                tracing::warn!(adapter_id, error = %err, "malformed adapter ack payload");
            }
        },
        "state" => match serde_json::from_slice::<MqttEnvelope<StatePayload>>(payload) {
            Ok(env) => {
                if !matches!(env.payload.state.as_str(), "locked" | "unlocked" | "unknown") {
                    tracing::warn!(adapter_id, state = %env.payload.state, "ignoring invalid door state");
                    return;
                }
                let changed = adapter.reported_state != env.payload.state;
                let res = sqlx::query(
                    "UPDATE adapters
                     SET reported_state = ?, state_reported_at = ?, updated_at = ?
                     WHERE id = ? AND approval_status = 'approved'",
                )
                .bind(&env.payload.state)
                .bind(now)
                .bind(now)
                .bind(&adapter.id)
                .execute(&db.pool)
                .await;

                if changed && res.is_ok_and(|r| r.rows_affected() > 0) {
                    audit.record(AuditEvent {
                        actor_type: "adapter".into(),
                        actor_id: adapter_id.to_string(),
                        action: "adapter_state_change".into(),
                        target_type: "adapter".into(),
                        target_id: adapter.id,
                        result: "success".into(),
                        detail: serde_json::json!({
                            "from": adapter.reported_state,
                            "to": env.payload.state,
                            "snapshot": env.payload.snapshot,
                        }),
                        ip: String::new(),
                        request_id: env.msg_id,
                    });
                }
            }
            Err(err) => {
                tracing::warn!(adapter_id, error = %err, "malformed adapter state payload");
            }
        },
        "presence" => match serde_json::from_slice::<PresencePayload>(payload) {
            Ok(p) => {
                let status = if p.online { "online" } else { "offline" };
                let _ = sqlx::query(
                    "UPDATE adapters
                     SET online_status = ?, last_seen_at = ?, updated_at = ?
                     WHERE id = ? AND approval_status = 'approved'",
                )
                .bind(status)
                .bind(now)
                .bind(now)
                .bind(adapter_id)
                .execute(&db.pool)
                .await;
            }
            Err(err) => {
                tracing::warn!(adapter_id, error = %err, "malformed adapter presence payload");
            }
        },
        "error" => {
            let text = String::from_utf8_lossy(payload);
            tracing::warn!(adapter_id, payload = %text, "adapter protocol error");
        }
        _ => {}
    }
}

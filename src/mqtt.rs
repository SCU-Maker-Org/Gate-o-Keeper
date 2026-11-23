use crate::audit::{AuditEvent, AuditHandle};
use crate::auth::hash_token;
use crate::config::AppConfig;
use crate::db::{AdapterRow, Db};
use crate::error::{AppError, AppResult};
use crate::redis_store::RedisStore;
use rand::RngCore;
use rumqttc::{
    AsyncClient, Event, Incoming, MqttOptions, QoS, TlsConfiguration, Transport,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

const MAX_INFLIGHT_MQTT_HANDLERS: usize = 64;

#[derive(Clone)]
pub struct MqttClient {
    client: AsyncClient,
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
    opts.set_clean_session(true);
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
    let cfg_clone = config.clone();
    let db_loop = db.clone();
    let sem = Arc::new(Semaphore::new(MAX_INFLIGHT_MQTT_HANDLERS));

    tokio::spawn(async move {
        loop {
            match eventloop.poll().await {
                Ok(Event::Incoming(Incoming::ConnAck(_))) => {
                    tracing::info!("connected to EMQX over MQTTS");
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
                Ok(Event::Incoming(Incoming::Publish(p))) => {
                    let permit = sem.clone();
                    let cfg = cfg_clone.clone();
                    let db = db_loop.clone();
                    let redis = redis.clone();
                    let audit = audit.clone();
                    tokio::spawn(async move {
                        let Ok(_guard) = permit.acquire_owned().await else {
                            return;
                        };
                        handle_publish(&cfg, &db, &redis, &audit, &p.topic, &p.payload).await;
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

    let mqtt = MqttClient {
        client,
        config,
        http,
    };

    let rotation_client = mqtt.clone();
    tokio::spawn(async move {
        token_refresh_loop(rotation_client, db).await;
    });

    Ok(mqtt)
}

async fn token_refresh_loop(mqtt: MqttClient, db: Db) {
    let start = tokio::time::Instant::now() + Duration::from_secs(60);
    let mut ticker = tokio::time::interval_at(start, Duration::from_secs(60));
    loop {
        ticker.tick().await;
        let now = chrono::Utc::now().timestamp();
        let due: Result<Vec<AdapterRow>, _> = sqlx::query_as(
            "SELECT * FROM adapters
             WHERE approval_status = 'approved'
               AND online_status = 'online'
               AND pending_token_hash IS NULL
               AND token_refresh_interval > 0
               AND updated_at + token_refresh_interval <= ?",
        )
        .bind(now)
        .fetch_all(&db.pool)
        .await;

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
                 SET pending_token_hash = ?, pending_token_msg_id = ?, updated_at = ?
                 WHERE id = ? AND approval_status = 'approved' AND pending_token_hash IS NULL",
            )
            .bind(&new_hash)
            .bind(&msg_id)
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
                            "UPDATE adapters SET pending_token_hash = NULL, pending_token_msg_id = NULL
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
        self.client
            .publish(topic, QoS::ExactlyOnce, false, bytes)
            .await
            .map_err(|e| AppError::internal(format!("mqtt publish failed: {e}")))?;
        Ok(())
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
        self.client
            .publish(topic, QoS::AtLeastOnce, false, bytes)
            .await
            .map_err(|e| AppError::internal(format!("mqtt publish failed: {e}")))?;
        Ok(())
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
        self.client
            .publish(topic, QoS::AtLeastOnce, false, bytes)
            .await
            .map_err(|e| AppError::internal(format!("mqtt publish failed: {e}")))?;
        Ok(())
    }

    pub async fn kick_client(&self, adapter_id: &str) {
        if self.config.mqtt_broker_api_key.is_empty() {
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

        if let Err(err) = res {
            tracing::warn!(adapter_id, error = %err, "failed to kick MQTT client via EMQX API");
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
    topic: &str,
    payload: &[u8],
) {
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
                let _ = sqlx::query(
                    "UPDATE adapters
                     SET online_status = 'online', last_seen_at = MAX(COALESCE(last_seen_at, 0), ?), updated_at = ?
                     WHERE id = ? AND approval_status = 'approved'",
                )
                .bind(event_ts)
                .bind(now)
                .bind(client_id)
                .execute(&db.pool)
                .await;
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
                             updated_at = ?
                         WHERE id = ? AND pending_token_msg_id = ? AND pending_token_hash IS NOT NULL",
                    )
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
                let _ = sqlx::query(
                    "UPDATE adapters SET reported_state = ?, state_reported_at = ?, updated_at = ? WHERE id = ?",
                )
                .bind(&env.payload.state)
                .bind(now)
                .bind(now)
                .bind(&adapter.id)
                .execute(&db.pool)
                .await;

                if changed {
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
                    "UPDATE adapters SET online_status = ?, last_seen_at = ?, updated_at = ? WHERE id = ?",
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

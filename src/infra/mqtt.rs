//! MQTT Transport Layer: manages the MQTTS (v5) connection, subscriptions,
//! outbound command envelopes, EMQX client kick HTTP calls, and decodes
//! inbound MQTT packets into `InboundMqttEvent`s for the service layer.

use crate::config::AppConfig;
use crate::error::{AppError, AppResult};
use rumqttc::v5::{
    mqttbytes::{
        v5::{Packet, Publish, PublishProperties},
        QoS,
    },
    AsyncClient, Event, MqttOptions,
};
use rumqttc::{TlsConfiguration, Transport};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;

const DEFAULT_CMD_EXPIRY_SEC: u32 = 60;
const INBOUND_EVENT_CHANNEL_CAP: usize = 256;

#[derive(Clone, Debug)]
pub struct CapturedMqttMessage {
    pub topic: String,
    pub qos: QoS,
    pub retain: bool,
    pub payload: Vec<u8>,
    pub message_expiry_interval: Option<u32>,
}

#[derive(Clone, Debug)]
pub enum InboundMqttEvent {
    ClientConnected {
        client_id: String,
        event_ts: i64,
        now: i64,
    },
    ClientDisconnected {
        client_id: String,
        event_ts: i64,
        now: i64,
    },
    AdapterResult {
        adapter_id: String,
        msg_id: String,
        payload_json: String,
    },
    AdapterAck {
        adapter_id: String,
        command: String,
        msg_id: String,
        now: i64,
    },
    AdapterState {
        adapter_id: String,
        msg_id: String,
        state: String,
        snapshot: bool,
        now: i64,
    },
    AdapterPresence {
        adapter_id: String,
        online: bool,
        now: i64,
    },
    AdapterError {
        adapter_id: String,
        text: String,
    },
}

impl InboundMqttEvent {
    /// Adapter id this event concerns; used to serialize per-adapter processing.
    pub fn adapter_id(&self) -> &str {
        match self {
            Self::ClientConnected { client_id, .. } | Self::ClientDisconnected { client_id, .. } => {
                client_id
            }
            Self::AdapterResult { adapter_id, .. }
            | Self::AdapterAck { adapter_id, .. }
            | Self::AdapterState { adapter_id, .. }
            | Self::AdapterPresence { adapter_id, .. }
            | Self::AdapterError { adapter_id, .. } => adapter_id,
        }
    }
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

fn decode_publish(own_client_id: &str, pub_pkt: Publish) -> Option<InboundMqttEvent> {
    let topic = String::from_utf8_lossy(&pub_pkt.topic);
    if pub_pkt.retain {
        tracing::warn!(topic = %topic, "ignoring retained MQTT message");
        return None;
    }

    let now = chrono::Utc::now().timestamp();
    let parts: Vec<&str> = topic.split('/').collect();

    if parts.len() == 6 && parts[0] == "$SYS" && parts[1] == "brokers" && parts[3] == "clients" {
        let client_id = parts[4];
        if client_id == own_client_id {
            return None;
        }
        let event_ts = normalize_sys_ts_sec(&pub_pkt.payload, now);
        return match parts[5] {
            "connected" => Some(InboundMqttEvent::ClientConnected {
                client_id: client_id.to_string(),
                event_ts,
                now,
            }),
            "disconnected" => Some(InboundMqttEvent::ClientDisconnected {
                client_id: client_id.to_string(),
                event_ts,
                now,
            }),
            _ => None,
        };
    }

    if parts.len() != 3 || parts[0] != "adapter" {
        return None;
    }
    let adapter_id = parts[1];
    let kind = parts[2];
    let payload = &pub_pkt.payload;

    match kind {
        "result" => match serde_json::from_slice::<MqttEnvelope<UnlockResultPayload>>(payload) {
            Ok(env) => serde_json::to_string(&env.payload).ok().map(|payload_json| {
                InboundMqttEvent::AdapterResult {
                    adapter_id: adapter_id.to_string(),
                    msg_id: env.msg_id,
                    payload_json,
                }
            }),
            Err(err) => {
                tracing::warn!(adapter_id, error = %err, "malformed adapter result payload");
                None
            }
        },
        "ack" => match serde_json::from_slice::<MqttEnvelope<AckPayload>>(payload) {
            Ok(env) => Some(InboundMqttEvent::AdapterAck {
                adapter_id: adapter_id.to_string(),
                command: env.payload.command,
                msg_id: env.msg_id,
                now,
            }),
            Err(err) => {
                tracing::warn!(adapter_id, error = %err, "malformed adapter ack payload");
                None
            }
        },
        "state" => match serde_json::from_slice::<MqttEnvelope<StatePayload>>(payload) {
            Ok(env) => Some(InboundMqttEvent::AdapterState {
                adapter_id: adapter_id.to_string(),
                msg_id: env.msg_id,
                state: env.payload.state,
                snapshot: env.payload.snapshot,
                now,
            }),
            Err(err) => {
                tracing::warn!(adapter_id, error = %err, "malformed adapter state payload");
                None
            }
        },
        "presence" => match serde_json::from_slice::<PresencePayload>(payload) {
            Ok(p) => Some(InboundMqttEvent::AdapterPresence {
                adapter_id: adapter_id.to_string(),
                online: p.online,
                now,
            }),
            Err(err) => {
                tracing::warn!(adapter_id, error = %err, "malformed adapter presence payload");
                None
            }
        },
        "error" => Some(InboundMqttEvent::AdapterError {
            adapter_id: adapter_id.to_string(),
            text: String::from_utf8_lossy(payload).into_owned(),
        }),
        _ => None,
    }
}

impl MqttClient {
    /// Connects to EMQX over MQTTS (v5), spawns the packet event loop, and returns
    /// the client handle alongside the decoded inbound event stream.
    pub fn connect(
        config: AppConfig,
        http: reqwest::Client,
    ) -> anyhow::Result<(Self, mpsc::Receiver<InboundMqttEvent>)> {
        let mut opts =
            MqttOptions::new(&config.mqtt_client_id, &config.mqtt_host, config.mqtt_port);
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
        let mqtt = Self {
            transport: MqttTransport::Live(client),
            config: config.clone(),
            http,
        };
        let (tx, rx) = mpsc::channel(INBOUND_EVENT_CHANNEL_CAP);
        let own_client_id = config.mqtt_client_id;

        tokio::spawn(async move {
            let mut backoff_ms: u64 = 1_000;
            loop {
                match eventloop.poll().await {
                    Ok(Event::Incoming(Packet::ConnAck(_))) => {
                        backoff_ms = 1_000;
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
                        if let Some(ev) = decode_publish(&own_client_id, p) {
                            match tokio::time::timeout(Duration::from_secs(1), tx.send(ev)).await
                            {
                                Ok(Ok(())) => {}
                                Ok(Err(_)) => {
                                    tracing::warn!(
                                        "inbound MQTT event channel closed; stopping event loop"
                                    );
                                    break;
                                }
                                Err(_) => {
                                    tracing::error!(
                                        "inbound MQTT event channel blocked for 1s; dropping message"
                                    );
                                }
                            }
                        }
                    }
                    Ok(_) => {}
                    Err(err) => {
                        // Exponential backoff with jitter (1s -> 30s), reset on ConnAck.
                        let jitter = (chrono::Utc::now().timestamp_subsec_millis() as u64)
                            % (backoff_ms / 2 + 1);
                        let delay = backoff_ms / 2 + jitter;
                        tracing::warn!(error = %err, delay_ms = delay, "MQTT eventloop error; reconnecting");
                        tokio::time::sleep(Duration::from_millis(delay)).await;
                        backoff_ms = (backoff_ms * 2).min(30_000);
                    }
                }
            }
        });

        Ok((mqtt, rx))
    }

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

    async fn publish_cmd_envelope<T: Serialize>(
        &self,
        adapter_id: &str,
        msg_id: &str,
        qos: QoS,
        expiry_sec: Option<u32>,
        payload: T,
    ) -> AppResult<()> {
        let env = MqttEnvelope {
            v: 1,
            msg_id: msg_id.to_string(),
            ts: chrono::Utc::now().timestamp(),
            payload,
        };
        let bytes = serde_json::to_vec(&env)
            .map_err(|e| AppError::internal(format!("json encode failed: {e}")))?;
        let topic = format!("adapter/{adapter_id}/cmd");
        let props = expiry_sec.map(|sec| PublishProperties {
            message_expiry_interval: Some(sec),
            ..Default::default()
        });
        self.publish_raw(topic, qos, false, bytes, props).await
    }

    pub async fn publish_unlock(
        &self,
        adapter_id: &str,
        msg_id: &str,
        timeout_ms: u64,
    ) -> AppResult<()> {
        let expiry_sec = timeout_ms.div_ceil(1000).clamp(1, u32::MAX as u64) as u32;
        self.publish_cmd_envelope(
            adapter_id,
            msg_id,
            QoS::ExactlyOnce,
            Some(expiry_sec),
            UnlockCmdPayload {
                command: "unlock".to_string(),
                timeout_ms,
            },
        )
        .await
    }

    pub async fn publish_query_state(&self, adapter_id: &str, msg_id: &str) -> AppResult<()> {
        self.publish_cmd_envelope(
            adapter_id,
            msg_id,
            QoS::AtLeastOnce,
            Some(DEFAULT_CMD_EXPIRY_SEC),
            QueryStateCmdPayload {
                command: "query_state".to_string(),
            },
        )
        .await
    }

    pub async fn publish_refresh_token(
        &self,
        adapter_id: &str,
        msg_id: &str,
        new_token: &str,
        expiry_sec: u32,
    ) -> AppResult<()> {
        self.publish_cmd_envelope(
            adapter_id,
            msg_id,
            QoS::AtLeastOnce,
            Some(expiry_sec),
            RefreshTokenCmdPayload {
                command: "refresh_token".to_string(),
                token: new_token.to_string(),
            },
        )
        .await
    }

    pub async fn publish_set_config(
        &self,
        adapter_id: &str,
        msg_id: &str,
        state_report_period_sec: i64,
    ) -> AppResult<()> {
        self.publish_cmd_envelope(
            adapter_id,
            msg_id,
            QoS::AtLeastOnce,
            Some(DEFAULT_CMD_EXPIRY_SEC),
            SetConfigCmdPayload {
                command: "set_config".to_string(),
                state_report_period_sec,
            },
        )
        .await
    }

    /// Asks EMQX whether the client currently holds a live connection.
    /// Returns `None` when the answer is unknown (no API key, memory transport, API failure).
    pub async fn is_client_connected(&self, adapter_id: &str) -> Option<bool> {
        if matches!(self.transport, MqttTransport::Memory(_))
            || self.config.mqtt_broker_api_key.is_empty()
        {
            return None;
        }
        let url = format!(
            "{}/clients/{}",
            self.config.mqtt_broker_api_url.trim_end_matches('/'),
            adapter_id
        );
        let resp = self
            .http
            .get(&url)
            .basic_auth(
                &self.config.mqtt_broker_api_key,
                Some(&self.config.mqtt_broker_api_secret),
            )
            .timeout(Duration::from_secs(3))
            .send()
            .await
            .ok()?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Some(false);
        }
        if !resp.status().is_success() {
            return None;
        }
        let v: serde_json::Value = resp.json().await.ok()?;
        v.get("connected").and_then(|c| c.as_bool())
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

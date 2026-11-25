use super::PENDING_TOKEN_TTL_SEC;
use crate::domain::{ApprovalStatus, AuditActorType, AuditResult, DoorState};
use crate::error::AppResult;
use crate::infra::audit::AuditHandle;
use crate::infra::db::{AdapterRow, Db};
use crate::infra::mqtt::{InboundMqttEvent, MqttClient};
use crate::infra::redis::RedisStore;
use crate::utils::{generate_random_token, hash_token};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::Duration;
use tokio::sync::mpsc;

const EVENT_SHARDS: usize = 16;

/// Spawns the inbound MQTT event consumer and periodic adapter token-rotation worker.
pub fn spawn_background_workers(
    db: Db,
    redis: RedisStore,
    audit: AuditHandle,
    mqtt: MqttClient,
    mut rx: mpsc::Receiver<InboundMqttEvent>,
) {
    // Events for the same adapter are processed strictly in arrival order by a
    // fixed shard worker, so connect/disconnect/presence cannot race each other.
    let mut shard_txs = Vec::with_capacity(EVENT_SHARDS);
    for _ in 0..EVENT_SHARDS {
        let (stx, mut srx) = mpsc::channel::<InboundMqttEvent>(256);
        shard_txs.push(stx);
        let db = db.clone();
        let redis = redis.clone();
        let audit = audit.clone();
        let mqtt = mqtt.clone();
        tokio::spawn(async move {
            while let Some(ev) = srx.recv().await {
                handle_inbound_event(&db, &redis, &audit, &mqtt, ev).await;
            }
        });
    }

    let db_fast = db.clone();
    let redis_fast = redis.clone();
    tokio::spawn(async move {
        while let Some(ev) = rx.recv().await {
            if let InboundMqttEvent::AdapterResult {
                adapter_id,
                msg_id,
                payload_json,
            } = ev
            {
                let db = db_fast.clone();
                let redis = redis_fast.clone();
                tokio::spawn(async move {
                    if verify_approved_adapter(&db, &adapter_id, "result")
                        .await
                        .is_some()
                    {
                        handle_mqtt_adapter_result(&redis, &adapter_id, &msg_id, &payload_json)
                            .await;
                    }
                });
                continue;
            }
            let mut h = DefaultHasher::new();
            ev.adapter_id().hash(&mut h);
            let idx = (h.finish() as usize) % EVENT_SHARDS;
            if shard_txs[idx].send(ev).await.is_err() {
                break;
            }
        }
    });

    tokio::spawn(async move {
        token_refresh_loop(mqtt, db, audit).await;
    });
}

async fn token_refresh_loop(mqtt: MqttClient, db: Db, audit: AuditHandle) {
    let start = tokio::time::Instant::now() + Duration::from_secs(60);
    let mut ticker = tokio::time::interval_at(start, Duration::from_secs(60));
    loop {
        ticker.tick().await;
        let now = chrono::Utc::now().timestamp();
        expire_stale_pending_tokens(&db, &audit, now).await;
        run_due_token_rotations(&db, &mqtt, now).await;
    }
}

async fn verify_approved_adapter(db: &Db, adapter_id: &str, kind: &str) -> Option<AdapterRow> {
    match db.find_adapter_by_id(adapter_id).await {
        Ok(Some(adapter)) if adapter.approval_status == ApprovalStatus::Approved => Some(adapter),
        Ok(Some(adapter)) => {
            tracing::warn!(
                adapter_id,
                kind,
                approval_status = %adapter.approval_status,
                "ignoring MQTT publish from non-approved adapter"
            );
            None
        }
        Ok(None) => {
            tracing::warn!(
                adapter_id,
                kind,
                "ignoring MQTT publish from unknown adapter"
            );
            None
        }
        Err(err) => {
            tracing::error!(adapter_id, kind, error = %err.message, "failed to verify adapter");
            None
        }
    }
}

async fn handle_inbound_event(
    db: &Db,
    redis: &RedisStore,
    audit: &AuditHandle,
    mqtt: &MqttClient,
    ev: InboundMqttEvent,
) {
    match ev {
        InboundMqttEvent::ClientConnected {
            client_id,
            event_ts,
            now,
        } => {
            handle_mqtt_client_connected(db, &client_id, event_ts, now).await;
        }
        InboundMqttEvent::ClientDisconnected {
            client_id,
            event_ts,
            now,
        } => {
            handle_mqtt_client_disconnected(db, mqtt, &client_id, event_ts, now).await;
        }
        InboundMqttEvent::AdapterResult {
            adapter_id,
            msg_id,
            payload_json,
        } => {
            if verify_approved_adapter(db, &adapter_id, "result")
                .await
                .is_some()
            {
                handle_mqtt_adapter_result(redis, &adapter_id, &msg_id, &payload_json).await;
            }
        }
        InboundMqttEvent::AdapterAck {
            adapter_id,
            command,
            msg_id,
            now,
        } => {
            if verify_approved_adapter(db, &adapter_id, "ack")
                .await
                .is_some()
            {
                handle_mqtt_adapter_ack(db, &adapter_id, &command, &msg_id, now).await;
            }
        }
        InboundMqttEvent::AdapterState {
            adapter_id,
            msg_id,
            state,
            snapshot,
            now,
        } => {
            if let Some(adapter) = verify_approved_adapter(db, &adapter_id, "state").await {
                handle_mqtt_adapter_state(db, audit, adapter, msg_id, &state, snapshot, now).await;
            }
        }
        InboundMqttEvent::AdapterPresence {
            adapter_id,
            online,
            now,
        } => {
            if verify_approved_adapter(db, &adapter_id, "presence")
                .await
                .is_some()
            {
                handle_mqtt_adapter_presence(db, redis, mqtt, &adapter_id, online, now).await;
            }
        }
        InboundMqttEvent::AdapterError { adapter_id, text } => {
            if verify_approved_adapter(db, &adapter_id, "error")
                .await
                .is_some()
            {
                tracing::warn!(adapter_id, payload = %text, "adapter protocol error");
            }
        }
    }
}

/// Stages a new pending rotation token, publishes `refresh_token` over MQTT,
/// and rolls back the pending state if publishing fails.
pub async fn stage_and_send_token_refresh(
    db: &Db,
    mqtt: &MqttClient,
    adapter_id: &str,
    msg_id: &str,
    now: i64,
    require_online: bool,
) -> AppResult<bool> {
    let new_token = generate_random_token();
    let new_hash = hash_token(&new_token);

    if !db
        .stage_pending_token_hash(adapter_id, &new_hash, msg_id, now, require_online)
        .await?
    {
        return Ok(false);
    }

    if let Err(err) = mqtt
        .publish_refresh_token(adapter_id, msg_id, &new_token, PENDING_TOKEN_TTL_SEC as u32)
        .await
    {
        let _ = db.clear_pending_token_if_matches(adapter_id, msg_id).await;
        return Err(err);
    }

    Ok(true)
}

pub async fn expire_stale_pending_tokens(db: &Db, audit: &AuditHandle, now: i64) {
    let cutoff = now - PENDING_TOKEN_TTL_SEC;
    let expired = match db.expire_stale_pending_tokens(cutoff, now).await {
        Ok(list) => list,
        Err(err) => {
            tracing::error!(error = %err.message, "failed to expire stale pending adapter tokens");
            return;
        }
    };

    for adapter in expired {
        tracing::warn!(
            adapter_id = %adapter.id,
            msg_id = ?adapter.pending_token_msg_id,
            "adapter token rotation unacknowledged; pending token stays valid until device reconnects or admin reset"
        );
        let detail = serde_json::json!({
            "msgId": adapter.pending_token_msg_id,
            "pendingTokenAt": adapter.pending_token_at,
        });
        let req_id = adapter.pending_token_msg_id.unwrap_or_default();
        audit.record_event(
            AuditActorType::System,
            "scheduler",
            "refresh_adapter_token_unacked",
            "adapter",
            adapter.id,
            AuditResult::Timeout,
            detail,
            "",
            &req_id,
        );
    }
}

pub async fn query_due_rotation_adapters(db: &Db, now: i64) -> AppResult<Vec<AdapterRow>> {
    db.list_due_rotation_adapters(now).await
}

pub async fn run_due_token_rotations(db: &Db, mqtt: &MqttClient, now: i64) {
    let adapters = match db.list_due_rotation_adapters(now).await {
        Ok(list) => list,
        Err(err) => {
            tracing::error!(error = %err.message, "failed to query adapters due for token rotation");
            return;
        }
    };

    for adapter in adapters {
        let msg_id = format!("rot_{}", uuid::Uuid::new_v4().simple());
        if let Err(err) =
            stage_and_send_token_refresh(db, mqtt, &adapter.id, &msg_id, now, false).await
        {
            tracing::warn!(
                adapter_id = %adapter.id,
                error = %err.message,
                "scheduled token refresh failed"
            );
        }
    }
}

/// Marks the adapter online. `set_config` is intentionally NOT sent here: the
/// `$SYS` connected event fires before the adapter has subscribed to its `cmd`
/// topic, so it would be dropped. It is sent after the adapter's `presence online`.
pub async fn handle_mqtt_client_connected(db: &Db, adapter_id: &str, event_ts: i64, now: i64) {
    let _ = db.mark_adapter_connected(adapter_id, event_ts, now).await;
}

pub async fn handle_mqtt_client_disconnected(
    db: &Db,
    mqtt: &MqttClient,
    adapter_id: &str,
    event_ts: i64,
    now: i64,
) {
    // A takeover/reconnect can deliver the old session's disconnect after the new
    // session came up; trust the broker's live view when available.
    let live = mqtt.is_client_connected(adapter_id).await;
    if live == Some(true) {
        tracing::debug!(adapter_id, "ignoring stale disconnect; client is connected");
        return;
    }
    let _ = db
        .mark_adapter_disconnected(adapter_id, event_ts, now, live == Some(false))
        .await;
}

pub async fn handle_mqtt_adapter_result(
    redis: &RedisStore,
    adapter_id: &str,
    msg_id: &str,
    payload_json: &str,
) {
    if let Err(err) = redis
        .publish_cmd_reply(adapter_id, msg_id, payload_json)
        .await
    {
        tracing::error!(
            adapter_id,
            msg_id,
            error = %err.message,
            "failed to publish cmd reply"
        );
    }
}

pub async fn handle_mqtt_adapter_ack(
    db: &Db,
    adapter_id: &str,
    command: &str,
    msg_id: &str,
    now: i64,
) {
    if command == "refresh_token" && !msg_id.is_empty() {
        let _ = db
            .activate_pending_token_on_ack(adapter_id, msg_id, now)
            .await;
    }
}

pub async fn handle_mqtt_adapter_state(
    db: &Db,
    audit: &AuditHandle,
    adapter: AdapterRow,
    msg_id: String,
    state_str: &str,
    snapshot: bool,
    now: i64,
) {
    let Ok(next_state) = state_str.parse::<DoorState>() else {
        tracing::warn!(adapter_id = %adapter.id, state = %state_str, "ignoring invalid door state");
        return;
    };
    let changed = adapter.reported_state != next_state;
    let updated = db
        .update_adapter_reported_state(&adapter.id, next_state, now)
        .await
        .unwrap_or(false);

    if changed && updated {
        audit.record_event(
            AuditActorType::Adapter,
            &adapter.id,
            "adapter_state_change",
            "adapter",
            &adapter.id,
            AuditResult::Success,
            serde_json::json!({
                "from": adapter.reported_state,
                "to": next_state,
                "snapshot": snapshot,
            }),
            "",
            &msg_id,
        );
    }
}

pub async fn handle_mqtt_adapter_presence(
    db: &Db,
    redis: &RedisStore,
    mqtt: &MqttClient,
    adapter_id: &str,
    online: bool,
    now: i64,
) {
    // Presence carries no broker timestamp, so verify against the broker's live view:
    // a late `online` after the client dropped, or a late LWT `offline` after a reconnect,
    // must not overwrite the real state.
    let live = mqtt.is_client_connected(adapter_id).await;
    if live == Some(online) || live.is_none() {
        // consistent with broker (or unknown): apply
    } else {
        tracing::debug!(
            adapter_id,
            online,
            "ignoring stale presence; broker disagrees"
        );
        return;
    }
    let _ = db
        .update_adapter_presence(adapter_id, online, now, live.is_some())
        .await;
    if online {
        if let Ok(sys_cfg) = db.get_system_config().await {
            let msg_id = format!("cfg_{}", uuid::Uuid::new_v4().simple());
            let _ = mqtt
                .publish_set_config(adapter_id, &msg_id, sys_cfg.state_report_period_sec)
                .await;
        }
        if matches!(
            redis.take_adapter_rotation_retry(adapter_id).await,
            Ok(true)
        ) {
            let msg_id = format!("rot_{}", uuid::Uuid::new_v4().simple());
            if let Err(err) =
                stage_and_send_token_refresh(db, mqtt, adapter_id, &msg_id, now, true).await
            {
                tracing::warn!(
                    adapter_id,
                    error = %err.message,
                    "failed to re-send token rotation after stale pending cleanup"
                );
            }
        }
    }
}

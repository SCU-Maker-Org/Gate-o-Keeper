//! Asynchronous audit logging: a bounded channel feeds a background writer,
//! plus a periodic retention cleanup task with graceful flush on shutdown.

use crate::domain::{AuditActorType, AuditResult};
use crate::error::{AppError, ErrorCode};
use crate::infra::db::{AuditLogRow, Db};
use std::time::Duration;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::{Instant, MissedTickBehavior};

const CHANNEL_CAPACITY: usize = 1024;
const CLEANUP_INTERVAL: Duration = Duration::from_secs(3600);

#[derive(Clone, Debug)]
pub struct AuditEvent {
    pub actor_type: AuditActorType,
    pub actor_id: String,
    pub action: String,
    pub target_type: String,
    pub target_id: String,
    pub result: AuditResult,
    pub detail: serde_json::Value,
    pub ip: String,
    pub request_id: String,
}

#[derive(Clone)]
pub struct AuditHandle {
    tx: mpsc::Sender<AuditEvent>,
    db: Db,
}

impl AuditHandle {
    /// Enqueues an event without blocking. If the bounded channel is full or the
    /// worker has stopped, falls back asynchronously to direct DB insertion so
    /// audit events are not silently dropped.
    pub fn record(&self, event: AuditEvent) {
        match self.tx.try_send(event) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(ev)) => {
                tracing::warn!("audit channel is full; spilling audit event asynchronously");
                self.persist_fallback(ev);
            }
            Err(mpsc::error::TrySendError::Closed(ev)) => {
                tracing::warn!("audit worker has stopped; writing audit event directly");
                self.persist_fallback(ev);
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_event(
        &self,
        actor_type: AuditActorType,
        actor_id: impl Into<String>,
        action: impl Into<String>,
        target_type: &str,
        target_id: impl Into<String>,
        result: AuditResult,
        detail: serde_json::Value,
        ip: &str,
        request_id: &str,
    ) {
        self.record(AuditEvent {
            actor_type,
            actor_id: actor_id.into(),
            action: action.into(),
            target_type: target_type.to_string(),
            target_id: target_id.into(),
            result,
            detail,
            ip: ip.to_string(),
            request_id: request_id.to_string(),
        });
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_admin(
        &self,
        admin_id: &str,
        action: &str,
        target_type: &str,
        target_id: impl Into<String>,
        detail: serde_json::Value,
        ip: &str,
        request_id: &str,
    ) {
        self.record_event(
            AuditActorType::Admin,
            admin_id,
            action,
            target_type,
            target_id,
            AuditResult::Success,
            detail,
            ip,
            request_id,
        );
    }

    pub fn record_system(
        &self,
        actor_id: &str,
        action: &str,
        target_type: &str,
        target_id: impl Into<String>,
        result: AuditResult,
        detail: serde_json::Value,
    ) {
        self.record_event(
            AuditActorType::System,
            actor_id,
            action,
            target_type,
            target_id,
            result,
            detail,
            "",
            "",
        );
    }

    fn persist_fallback(&self, ev: AuditEvent) {
        let tx = self.tx.clone();
        let db = self.db.clone();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                match tokio::time::timeout(Duration::from_secs(2), tx.reserve()).await {
                    Ok(Ok(permit)) => {
                        permit.send(ev);
                    }
                    Ok(Err(_)) | Err(_) => {
                        let row = into_row(ev, unix_now());
                        insert_with_retry(&db, &row).await;
                    }
                }
            });
        } else {
            tracing::error!("no tokio runtime available for audit fallback persistence");
        }
    }
}

pub struct AuditWorkerControl {
    shutdown_tx: watch::Sender<bool>,
    worker_handle: JoinHandle<()>,
    cleanup_handle: JoinHandle<()>,
}

impl AuditWorkerControl {
    /// Drains queued audit events once all `AuditHandle` clones are dropped, then stops cleanup.
    pub async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        let _ = self.cleanup_handle.await;
        let _ = self.worker_handle.await;
    }
}

/// Spawns the audit writer and hourly retention cleanup task (first cleanup deferred by 1h).
pub fn spawn_audit_worker(db: Db) -> AuditHandle {
    let (handle, _ctrl) = spawn_audit_worker_with_control(db);
    handle
}

pub fn spawn_audit_worker_with_control(db: Db) -> (AuditHandle, AuditWorkerControl) {
    let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let cleanup_handle = tokio::spawn(cleanup_loop(db.clone(), shutdown_rx.clone()));
    let worker_handle = tokio::spawn(worker_loop(db.clone(), rx, shutdown_rx));

    (
        AuditHandle { tx, db },
        AuditWorkerControl {
            shutdown_tx,
            worker_handle,
            cleanup_handle,
        },
    )
}

async fn worker_loop(
    db: Db,
    mut rx: mpsc::Receiver<AuditEvent>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            maybe_event = rx.recv() => {
                let Some(event) = maybe_event else {
                    break;
                };
                let row = into_row(event, unix_now());
                insert_with_retry(&db, &row).await;
            }
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                    while let Ok(event) = rx.try_recv() {
                        let row = into_row(event, unix_now());
                        insert_with_retry(&db, &row).await;
                    }
                    break;
                }
            }
        }
    }
}

async fn insert_with_retry(db: &Db, row: &AuditLogRow) {
    let mut backoff = Duration::from_millis(100);
    for attempt in 0..3 {
        match db.insert_audit_log(row).await {
            Ok(()) => return,
            Err(err) if is_transient(&err) && attempt < 2 => {
                tracing::warn!(
                    audit_id = %row.id,
                    attempt,
                    error = %err.message,
                    "audit insert failed; retrying"
                );
                tokio::time::sleep(backoff).await;
                backoff *= 2;
            }
            Err(err) => {
                tracing::error!(
                    audit_id = %row.id,
                    error = %err.message,
                    "audit insert failed permanently; dropping event"
                );
                return;
            }
        }
    }
}

async fn cleanup_loop(db: Db, mut shutdown_rx: watch::Receiver<bool>) {
    let start = Instant::now() + CLEANUP_INTERVAL;
    let mut ticker = tokio::time::interval_at(start, CLEANUP_INTERVAL);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = ticker.tick() => {}
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    break;
                }
            }
        }

        if *shutdown_rx.borrow() {
            break;
        }

        let cfg = match db.get_system_config().await {
            Ok(cfg) => cfg,
            Err(err) => {
                tracing::warn!(
                    error = %err.message,
                    "failed to load system config for audit cleanup"
                );
                continue;
            }
        };

        let retention_days = cfg.audit_retention_days.clamp(1, 3650);
        match db.cleanup_expired_audits(retention_days, unix_now()).await {
            Ok(deleted) if deleted > 0 => {
                tracing::info!(deleted, retention_days, "expired audit logs cleaned up");
            }
            Ok(_) => {}
            Err(err) => {
                tracing::warn!(error = %err.message, "failed to clean up expired audit logs");
            }
        }
    }
}

fn into_row(event: AuditEvent, now: i64) -> AuditLogRow {
    AuditLogRow {
        id: format!("aud_{}", uuid::Uuid::new_v4().simple()),
        actor_type: event.actor_type,
        actor_id: event.actor_id,
        action: event.action,
        target_type: event.target_type,
        target_id: event.target_id,
        result: event.result,
        detail_json: event.detail.to_string(),
        ip: event.ip,
        request_id: event.request_id,
        created_at: now,
    }
}

fn is_transient(err: &AppError) -> bool {
    matches!(err.code, ErrorCode::Internal)
}

fn unix_now() -> i64 {
    chrono::Utc::now().timestamp()
}

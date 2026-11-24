use locker_backend::config::SystemConfig;
use locker_backend::infra::audit::{spawn_audit_worker, AuditEvent};
use locker_backend::infra::db::{AdapterRow, AuditLogRow, Db, LockRow};
use locker_backend::routes::{compute_adapter_view, compute_lock_view};
use locker_backend::services::adapter::{expire_stale_pending_tokens, query_due_rotation_adapters};

async fn temp_db() -> Db {
    Db::connect("sqlite::memory:")
        .await
        .expect("in-memory sqlite should connect and migrate")
}

#[tokio::test]
async fn test_authentik_group_rules_and_admin_override() {
    let db = temp_db().await;
    let now = 1_763_164_740;

    let user = db
        .upsert_user_from_sso(
            "sub_alice",
            "Alice",
            &["maker-members".into()],
            &["locker-admins".into()],
            now,
        )
        .await
        .unwrap();
    assert_eq!(user.role, "user");

    let admin = db
        .upsert_user_from_sso(
            "sub_bob",
            "Bob",
            &["locker-admins".into()],
            &["locker-admins".into()],
            now,
        )
        .await
        .unwrap();
    assert_eq!(admin.role, "admin");

    sqlx::query(
        "INSERT INTO adapters (id, name, approval_status, online_status, reported_state, model, fw_version, token_hash, token_refresh_interval, created_at, updated_at)
         VALUES ('ichuang', 'I-Chuang Gateway', 'approved', 'online', 'locked', 'm1', '1.0', 'h', 43200, ?, ?)",
    )
    .bind(now)
    .bind(now)
    .execute(&db.pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO locks (id, name, description, adapter_id, created_by, created_at, updated_at)
         VALUES ('lock-101', '101门锁', '一楼东侧', 'ichuang', ?, ?, ?)",
    )
    .bind(&admin.id)
    .bind(now)
    .bind(now)
    .execute(&db.pool)
    .await
    .unwrap();

    // No group rule yet: regular user denied, admin allowed
    assert!(!db.user_has_lock_access(&user, "lock-101").await.unwrap());
    assert!(db.user_has_lock_access(&admin, "lock-101").await.unwrap());

    // Bind `maker-members` group rule on the Lock
    db.replace_lock_groups("lock-101", &["maker-members".into()], &admin.id, now)
        .await
        .unwrap();
    assert!(db.user_has_lock_access(&user, "lock-101").await.unwrap());

    // 1-to-1 binding: binding a second lock to the same adapter must fail
    let dup_bind = sqlx::query(
        "INSERT INTO locks (id, name, description, adapter_id, created_by, created_at, updated_at)
         VALUES ('lock-102', '102门锁', '', 'ichuang', ?, ?, ?)",
    )
    .bind(&admin.id)
    .bind(now)
    .bind(now)
    .execute(&db.pool)
    .await;
    assert!(dup_bind.is_err());

    // Resetting/deleting the adapter clears locks.adapter_id (ON DELETE SET NULL) without losing lock or rules
    sqlx::query("DELETE FROM adapters WHERE id = 'ichuang'")
        .execute(&db.pool)
        .await
        .unwrap();
    let lock_after = db.find_lock_by_id("lock-101").await.unwrap().unwrap();
    assert_eq!(lock_after.adapter_id, None);
    assert!(db.user_has_lock_access(&user, "lock-101").await.unwrap());

    // Remove user from group -> immediately denied
    let user_removed = db
        .upsert_user_from_sso(
            "sub_alice",
            "Alice",
            &["other-group".into()],
            &["locker-admins".into()],
            now + 10,
        )
        .await
        .unwrap();
    assert!(!db
        .user_has_lock_access(&user_removed, "lock-101")
        .await
        .unwrap());
}

#[tokio::test]
async fn test_lock_state_projection_bound_unbound_and_revoked() {
    let cfg = SystemConfig::default();
    let now = 1_763_164_740;

    let lock = LockRow {
        id: "lock-101".into(),
        name: "101门锁".into(),
        description: "创客实验室正门".into(),
        adapter_id: Some("gw_1".into()),
        created_by: "adm".into(),
        created_at: now - 1000,
        updated_at: now - 10,
    };

    let unbound = compute_lock_view(
        &LockRow {
            adapter_id: None,
            ..lock.clone()
        },
        None,
        &cfg,
        now,
    );
    assert!(!unbound.bound);
    assert!(!unbound.online);
    assert_eq!(unbound.state, "unknown");

    let revoked_adapter = AdapterRow {
        id: "gw_1".into(),
        name: "GW 1".into(),
        approval_status: "revoked".into(),
        online_status: "online".into(),
        reported_state: "unlocked".into(),
        state_reported_at: Some(now - 5),
        model: "m1".into(),
        fw_version: "1.0".into(),
        token_hash: "h".into(),
        pending_token_hash: None,
        pending_token_msg_id: None,
        pending_token_at: None,
        pending_token_stale_at: None,
        token_rotated_at: Some(now - 500),
        token_refresh_interval: 43200,
        last_seen_at: Some(now - 5),
        approved_by: Some("adm".into()),
        approved_at: Some(now - 500),
        created_at: now - 1000,
        updated_at: now - 10,
    };
    let revoked_view = compute_lock_view(&lock, Some(&revoked_adapter), &cfg, now);
    assert!(revoked_view.bound);
    assert!(!revoked_view.online);
    assert_eq!(revoked_view.state, "unknown");

    let mut ok_adapter = revoked_adapter;
    ok_adapter.approval_status = "approved".into();
    let ok_view = compute_lock_view(&lock, Some(&ok_adapter), &cfg, now);
    assert!(ok_view.bound);
    assert!(ok_view.online);
    assert_eq!(ok_view.state, "unlocked");
}

#[tokio::test]
async fn test_adapter_state_unknown_and_stale_projection() {
    let cfg = SystemConfig::default(); // offline_unknown_sec = 300, state_report_period_sec = 60
    let now = 1_763_164_740;

    // Online + reported 200s ago (> 2 * 60s) => stale = true, state = locked
    let online_adapter = AdapterRow {
        id: "gw_1".into(),
        name: "I-Chuang".into(),
        approval_status: "approved".into(),
        online_status: "online".into(),
        reported_state: "locked".into(),
        state_reported_at: Some(now - 200),
        model: "m1".into(),
        fw_version: "1.0".into(),
        token_hash: "h".into(),
        pending_token_hash: None,
        pending_token_msg_id: None,
        pending_token_at: None,
        pending_token_stale_at: None,
        token_rotated_at: Some(now - 500),
        token_refresh_interval: 43200,
        last_seen_at: Some(now - 10),
        approved_by: Some("adm".into()),
        approved_at: Some(now - 500),
        created_at: now - 1000,
        updated_at: now - 10,
    };
    let v1 = compute_adapter_view(&online_adapter, &cfg, now);
    assert_eq!(v1.state, "locked");
    assert!(v1.online);
    assert!(v1.stale);

    // Offline for 400s (> 300s) => state = unknown, stateReportedAt preserved
    let mut offline_adapter = online_adapter.clone();
    offline_adapter.online_status = "offline".into();
    offline_adapter.last_seen_at = Some(now - 400);
    let v2 = compute_adapter_view(&offline_adapter, &cfg, now);
    assert_eq!(v2.state, "unknown");
    assert_eq!(v2.state_reported_at, Some(now - 200));
    assert!(!v2.online);
    assert!(!v2.stale);
}

#[tokio::test]
async fn test_audit_retention_cleanup_default_90_days() {
    let db = temp_db().await;
    let cfg = db.get_system_config().await.unwrap();
    assert_eq!(cfg.audit_retention_days, 90);

    let now = 1_763_164_740;
    let old = AuditLogRow {
        id: "aud_old".into(),
        actor_type: "user".into(),
        actor_id: "usr_1".into(),
        action: "unlock".into(),
        target_type: "lock".into(),
        target_id: "ichuang".into(),
        result: "success".into(),
        detail_json: "{}".into(),
        ip: "127.0.0.1".into(),
        request_id: "req_1".into(),
        created_at: now - 91 * 86_400,
    };
    let fresh = AuditLogRow {
        id: "aud_fresh".into(),
        created_at: now - 10 * 86_400,
        ..old.clone()
    };

    db.insert_audit_log(&old).await.unwrap();
    db.insert_audit_log(&fresh).await.unwrap();

    let deleted = db
        .cleanup_expired_audits(cfg.audit_retention_days, now)
        .await
        .unwrap();
    assert_eq!(deleted, 1);

    let remaining: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM audit_logs")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(remaining.0, 1);
}

#[tokio::test]
async fn test_audit_worker_persists_events() {
    let db = temp_db().await;
    let handle = spawn_audit_worker(db.clone());
    handle.record(AuditEvent {
        actor_type: "admin".into(),
        actor_id: "adm_1".into(),
        action: "approve_adapter".into(),
        target_type: "adapter".into(),
        target_id: "gw_1".into(),
        result: "success".into(),
        detail: serde_json::json!({ "ok": true }),
        ip: "10.0.0.1".into(),
        request_id: "req_abc".into(),
    });

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM audit_logs")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(count.0, 1);
}

#[tokio::test]
async fn test_seed_admin_groups_preserves_custom_override() {
    let db = temp_db().await;
    // Migration default (`updated_at == 0`) tracks env seed
    db.seed_admin_groups_if_default(&["env-admins".into()])
        .await
        .unwrap();
    let cfg1 = db.get_system_config().await.unwrap();
    assert_eq!(cfg1.admin_groups, vec!["env-admins".to_string()]);

    // Admin customization sets `updated_at > 0` and must not be overwritten on restart
    db.set_system_config_key("admin_groups", "[\"custom-admins\"]", 1_700_000_000)
        .await
        .unwrap();
    db.seed_admin_groups_if_default(&["other-admins".into()])
        .await
        .unwrap();
    let cfg2 = db.get_system_config().await.unwrap();
    assert_eq!(cfg2.admin_groups, vec!["custom-admins".to_string()]);
    assert_eq!(cfg2.rate_limits.unlock_user.max, 5);
    assert_eq!(cfg2.rate_limits.adapter_register_id.window_sec, 3600);

    // Rate limit customization persists in system_config
    let mut custom_rl = cfg2.rate_limits.clone();
    custom_rl.unlock_user.max = 25;
    custom_rl.unlock_user.window_sec = 30;
    db.set_system_config_key(
        "rate_limits",
        &serde_json::to_string(&custom_rl).unwrap(),
        1_700_000_010,
    )
    .await
    .unwrap();
    let cfg3 = db.get_system_config().await.unwrap();
    assert_eq!(cfg3.rate_limits.unlock_user.max, 25);
    assert_eq!(cfg3.rate_limits.unlock_user.window_sec, 30);
}

#[tokio::test]
async fn test_sync_existing_user_from_sso_updates_role_groups_and_status() {
    let db = temp_db().await;
    let now = 1_763_164_740;

    let user = db
        .upsert_user_from_sso(
            "sub_carol",
            "Carol",
            &["maker-members".into()],
            &["locker-admins".into()],
            now,
        )
        .await
        .unwrap();
    assert_eq!(user.role, "user");
    assert_eq!(user.status, "active");

    // Promote via SSO group sync & disable account via SSO sync
    let updated = db
        .sync_existing_user_from_sso(
            "sub_carol",
            "Carol Lead",
            &["maker-members".into(), "locker-admins".into()],
            &["locker-admins".into()],
            false,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(updated.display_name, "Carol Lead");
    assert_eq!(updated.role, "admin");
    assert_eq!(updated.status, "disabled");
    assert_eq!(
        updated.groups(),
        vec!["maker-members".to_string(), "locker-admins".to_string()]
    );

    // Re-logging in via sso_exchange must NOT resurrect a disabled user
    let relogin = db
        .upsert_user_from_sso(
            "sub_carol",
            "Carol Lead",
            &["maker-members".into()],
            &["locker-admins".into()],
            now + 100,
        )
        .await;
    assert!(relogin.is_err());
    let persisted = db.find_user_by_subject("sub_carol").await.unwrap().unwrap();
    assert_eq!(persisted.status, "disabled");
}

#[tokio::test]
async fn test_token_rotation_due_ignores_state_updates_and_expires_stale_pending() {
    let db = temp_db().await;
    let audit = spawn_audit_worker(db.clone());
    let now = 1_763_164_740;

    // Adapter has recent updated_at (e.g. periodic state report), but token_rotated_at is 50000s ago
    sqlx::query(
        "INSERT INTO adapters (
            id, name, approval_status, online_status, reported_state, model, fw_version,
            token_hash, token_refresh_interval, approved_at, token_rotated_at, created_at, updated_at
         ) VALUES (
            'gw_due', 'GW Due', 'approved', 'online', 'locked', 'm1', '1.0',
            'hash_1', 43200, ?, ?, ?, ?
         )",
    )
    .bind(now - 50_000)
    .bind(now - 50_000)
    .bind(now - 60_000)
    .bind(now - 5)
    .execute(&db.pool)
    .await
    .unwrap();

    // Adapter with stale pending rotation (> 600s old)
    sqlx::query(
        "INSERT INTO adapters (
            id, name, approval_status, online_status, reported_state, model, fw_version,
            token_hash, pending_token_hash, pending_token_msg_id, pending_token_at,
            token_refresh_interval, approved_at, token_rotated_at, created_at, updated_at
         ) VALUES (
            'gw_stuck', 'GW Stuck', 'approved', 'online', 'locked', 'm1', '1.0',
            'hash_2', 'pending_hash_2', 'rot_stuck', ?,
            43200, ?, ?, ?, ?
         )",
    )
    .bind(now - 601)
    .bind(now - 50_000)
    .bind(now - 50_000)
    .bind(now - 60_000)
    .bind(now - 601)
    .execute(&db.pool)
    .await
    .unwrap();

    let due_before = query_due_rotation_adapters(&db, now).await.unwrap();
    assert_eq!(due_before.len(), 1);
    assert_eq!(due_before[0].id, "gw_due");

    expire_stale_pending_tokens(&db, &audit, now).await;

    let stuck = db.find_adapter_by_id("gw_stuck").await.unwrap().unwrap();
    // Pending token stays valid (device may have persisted it), but is flagged stale once.
    assert_eq!(stuck.pending_token_hash.as_deref(), Some("pending_hash_2"));
    assert!(stuck.pending_token_stale_at.is_some());
    assert!(db
        .expire_stale_pending_tokens(now - 601, now + 1)
        .await
        .unwrap()
        .is_empty());

    // No further rotation while a pending token exists.
    let due_after = query_due_rotation_adapters(&db, now).await.unwrap();
    let ids: Vec<String> = due_after.into_iter().map(|a| a.id).collect();
    assert!(ids.contains(&"gw_due".to_string()));
    assert!(!ids.contains(&"gw_stuck".to_string()));
}

#[tokio::test]
async fn test_get_system_config_fails_closed_on_corrupted_json() {
    let db = temp_db().await;
    db.set_system_config_key("admin_groups", "not-valid-json", 1_763_164_740)
        .await
        .unwrap();
    assert!(db.get_system_config().await.is_err());
}

#[tokio::test]
async fn test_user_authentik_pk_mapping() {
    let db = temp_db().await;
    let now = 1_763_164_740;
    let admin_groups = vec!["locker-admins".to_string()];
    let user = db
        .upsert_user_from_sso("sub-pk-1", "Pk User", &[], &admin_groups, now)
        .await
        .unwrap();
    assert!(user.authentik_pk.is_none());
    assert!(db.find_user_by_authentik_pk("42").await.unwrap().is_none());

    db.set_user_authentik_pk("sub-pk-1", "42").await.unwrap();
    let found = db.find_user_by_authentik_pk("42").await.unwrap().unwrap();
    assert_eq!(found.id, user.id);

    // Re-login must not clear the stored pk.
    let again = db
        .upsert_user_from_sso("sub-pk-1", "Pk User", &[], &admin_groups, now + 1)
        .await
        .unwrap();
    assert_eq!(again.authentik_pk.as_deref(), Some("42"));
}

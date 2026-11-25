use axum::body::Body;
use axum::http::{header, HeaderMap, HeaderValue, Request, StatusCode};
use axum::response::IntoResponse;
use http_body_util::BodyExt;
use locker_backend::auth::{hash_token, issue_access_token, OidcCache};
use locker_backend::config::AppConfig;
use locker_backend::error::{AppError, ErrorCode};
use locker_backend::infra::audit::spawn_audit_worker;
use locker_backend::infra::db::Db;
use locker_backend::infra::mqtt::MqttClient;
use locker_backend::infra::redis::RedisStore;
use locker_backend::routes::{extract_request_id, internal_router, resolve_client_ip, router};
use locker_backend::state::AppState;
use locker_backend::utils::is_valid_identifier;
use serde_json::Value;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::Arc;
use tower::ServiceExt;

fn test_config() -> AppConfig {
    AppConfig {
        http_addr: "127.0.0.1:0".into(),
        internal_http_addr: "127.0.0.1:0".into(),
        cookie_secure: false,
        allow_insecure_oidc_http: true,
        database_url: "sqlite::memory:".into(),
        redis_url: "redis://127.0.0.1:6379".into(),
        jwt_secret: "test-jwt-secret-with-at-least-thirty-two-bytes".into(),
        authentik_issuer: "http://localhost:9000/application/o/locker/".into(),
        authentik_api_base_url: "http://authentik-server:9000".into(),
        authentik_api_token: "test-authentik-api-token".into(),
        authentik_webhook_secret: "test-webhook-secret".into(),
        authentik_client_id: "locker-client-id".into(),
        authentik_client_secret: "locker-client-secret".into(),
        authentik_discovery_url: None,
        authentik_admin_groups: vec!["locker-admins".into()],
        backchannel_logout_allowed_ips: Vec::new(),
        trusted_proxies: Vec::new(),
        mqtt_host: "127.0.0.1".into(),
        mqtt_public_endpoint: None,
        mqtt_port: 8883,
        mqtt_client_id: "locker-backend".into(),
        mqtt_username: "locker-backend".into(),
        mqtt_password: "backend-internal-mqtt-secret".into(),
        mqtt_ca_cert: PathBuf::from("/certs/ca.crt"),
        mqtt_client_cert: PathBuf::from("/certs/backend.crt"),
        mqtt_client_key: PathBuf::from("/certs/backend.key"),
        mqtt_broker_api_url: "http://127.0.0.1:18083/api/v5".into(),
        mqtt_broker_api_key: String::new(),
        mqtt_broker_api_secret: String::new(),
        internal_mqtt_secret: "test-internal-secret-16".into(),
        static_dir: None,
    }
}

async fn test_state() -> AppState {
    test_state_with(test_config()).await
}

async fn test_state_with(config: AppConfig) -> AppState {
    let config = Arc::new(config);
    let db = Db::connect("sqlite::memory:").await.unwrap();
    let redis = RedisStore::new_in_memory();
    let audit = spawn_audit_worker(db.clone());
    let http = reqwest::Client::new();
    let mqtt = MqttClient::new_disconnected(config.clone(), http.clone());
    AppState {
        config,
        db,
        redis,
        mqtt,
        audit,
        http,
        oidc_cache: OidcCache::default(),
    }
}

async fn seed_user_session(
    state: &AppState,
    subject: &str,
    name: &str,
    groups: &[String],
    device_session_id: &str,
    now: i64,
) -> (String, String) {
    let user = state
        .db
        .upsert_user_from_sso(subject, name, groups, &["locker-admins".into()], now)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO user_devices (
            id, user_id, device_id, device_name, sso_sid, sso_refresh_token,
            refresh_token_hash, refresh_family_id, last_ip, status, created_at, last_active_at
         ) VALUES (?, ?, ?, 'Browser', NULL, NULL, ?, ?, '127.0.0.1', 'online', ?, ?)",
    )
    .bind(device_session_id)
    .bind(&user.id)
    .bind(format!("dev_{device_session_id}"))
    .bind(hash_token(&format!("rt_{device_session_id}")))
    .bind(format!("fam_{device_session_id}"))
    .bind(now)
    .bind(now)
    .execute(&state.db.pool)
    .await
    .unwrap();

    let (token, _) = issue_access_token(
        &state.config.jwt_secret,
        &user.id,
        device_session_id,
        user.role,
        now,
    )
    .unwrap();
    (user.id, token)
}

async fn json_body(resp: axum::response::Response) -> Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

#[test]
fn test_error_codes_and_http_status_mapping() {
    let cases = [
        (ErrorCode::InvalidArgument, StatusCode::BAD_REQUEST),
        (ErrorCode::Unauthorized, StatusCode::UNAUTHORIZED),
        (ErrorCode::DeviceKicked, StatusCode::UNAUTHORIZED),
        (ErrorCode::Forbidden, StatusCode::FORBIDDEN),
        (ErrorCode::AdapterForbidden, StatusCode::FORBIDDEN),
        (ErrorCode::LockForbidden, StatusCode::FORBIDDEN),
        (ErrorCode::DevicePending, StatusCode::FORBIDDEN),
        (ErrorCode::DeviceRevoked, StatusCode::FORBIDDEN),
        (ErrorCode::AdapterNotFound, StatusCode::NOT_FOUND),
        (ErrorCode::LockNotFound, StatusCode::NOT_FOUND),
        (ErrorCode::NotFound, StatusCode::NOT_FOUND),
        (ErrorCode::Conflict, StatusCode::CONFLICT),
        (ErrorCode::AdapterBusy, StatusCode::CONFLICT),
        (ErrorCode::LockUnbound, StatusCode::CONFLICT),
        (ErrorCode::DeviceAlreadyRegistered, StatusCode::CONFLICT),
        (ErrorCode::ReplayRejected, StatusCode::CONFLICT),
        (ErrorCode::RateLimited, StatusCode::TOO_MANY_REQUESTS),
        (ErrorCode::Internal, StatusCode::INTERNAL_SERVER_ERROR),
        (ErrorCode::DeviceError, StatusCode::BAD_GATEWAY),
        (ErrorCode::AdapterOffline, StatusCode::SERVICE_UNAVAILABLE),
        (ErrorCode::DeviceTimeout, StatusCode::GATEWAY_TIMEOUT),
    ];

    for (code, expected_status) in cases {
        let err = AppError::new(code, "test").with_request_id("req_test");
        assert_eq!(err.into_response().status(), expected_status);
    }
}

#[test]
fn test_config_defaults_and_jwt_issue() {
    std::env::set_var("ALLOW_DEV_DEFAULTS", "false");
    std::env::set_var("JWT_SECRET", "too-short");
    assert!(AppConfig::from_env().is_err());

    std::env::set_var("ALLOW_DEV_DEFAULTS", "true");
    std::env::set_var("STATIC_DIR", "/app/static");
    let cfg = AppConfig::from_env().unwrap();
    assert_eq!(
        cfg.static_dir.as_deref(),
        Some(std::path::Path::new("/app/static"))
    );
    let now = 1_763_164_740;
    let (tok, exp) = issue_access_token(
        &cfg.jwt_secret,
        "u1",
        "d1",
        locker_backend::domain::UserRole::User,
        now,
    )
    .unwrap();
    assert!(!tok.is_empty());
    assert_eq!(exp, now + 900);

    // Require AUTHENTIK_API_TOKEN (or non-empty AUTHENTIK_BOOTSTRAP_TOKEN) when ALLOW_DEV_DEFAULTS=false
    std::env::set_var("ALLOW_DEV_DEFAULTS", "false");
    std::env::set_var("ALLOW_INSECURE_OIDC_HTTP", "true");
    std::env::set_var(
        "JWT_SECRET",
        "test-jwt-secret-with-at-least-thirty-two-bytes",
    );
    std::env::set_var("AUTHENTIK_CLIENT_SECRET", "test-client-secret");
    std::env::set_var("MQTT_PASSWORD", "test-mqtt-password-16");
    std::env::set_var("INTERNAL_MQTT_SECRET", "test-internal-secret-16");
    std::env::set_var("AUTHENTIK_API_TOKEN", "");
    std::env::set_var("AUTHENTIK_BOOTSTRAP_TOKEN", "");
    assert!(AppConfig::from_env().is_err());

    std::env::set_var("AUTHENTIK_BOOTSTRAP_TOKEN", "bootstrap-token-value");
    let cfg = AppConfig::from_env().unwrap();
    assert_eq!(cfg.authentik_api_token, "bootstrap-token-value");

    std::env::set_var("AUTHENTIK_API_TOKEN", "explicit-api-token");
    let cfg = AppConfig::from_env().unwrap();
    assert_eq!(cfg.authentik_api_token, "explicit-api-token");

    for key in [
        "STATIC_DIR",
        "JWT_SECRET",
        "ALLOW_DEV_DEFAULTS",
        "ALLOW_INSECURE_OIDC_HTTP",
        "AUTHENTIK_CLIENT_SECRET",
        "MQTT_PASSWORD",
        "INTERNAL_MQTT_SECRET",
        "AUTHENTIK_API_TOKEN",
        "AUTHENTIK_BOOTSTRAP_TOKEN",
    ] {
        std::env::remove_var(key);
    }
}

#[test]
fn test_identifier_request_id_and_client_ip_resolution() {
    assert!(is_valid_identifier("adapter-01_A", 1, 64));
    assert!(!is_valid_identifier("bad+topic", 1, 64));
    assert!(!is_valid_identifier("bad/#", 1, 64));
    assert!(!is_valid_identifier("", 1, 64));

    let mut headers = HeaderMap::new();
    headers.insert("x-request-id", HeaderValue::from_static("req bad/chars!"));
    assert!(extract_request_id(&headers).starts_with("req_"));

    headers.insert("x-request-id", HeaderValue::from_static("trace-123_ok"));
    assert_eq!(extract_request_id(&headers), "trace-123_ok");

    let mut ip_headers = HeaderMap::new();
    ip_headers.insert(
        "x-forwarded-for",
        HeaderValue::from_static("203.0.113.9, 10.0.0.5"),
    );
    let untrusted_peer = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)));
    let trusted_proxy = vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))];

    // Spoofed XFF from untrusted peer must be ignored.
    assert_eq!(
        resolve_client_ip(&ip_headers, untrusted_peer, &trusted_proxy),
        "198.51.100.2"
    );
    // Trusted proxy honors right-most untrusted IP in XFF.
    assert_eq!(
        resolve_client_ip(
            &ip_headers,
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))),
            &trusted_proxy
        ),
        "203.0.113.9"
    );
}

#[tokio::test]
async fn test_http_auth_401_403_and_public_internal_isolation() {
    let state = test_state().await;
    let app = router().with_state(state.clone());
    let now = chrono::Utc::now().timestamp();

    // /healthz succeeds
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // /internal/mqtt/auth is NOT exposed on public router
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/internal/mqtt/auth")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // Unauthenticated /api/me -> 401
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/me")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Non-admin on /api/admin/locks -> 403
    let (_, user_tok) = seed_user_session(
        &state,
        "sub_member",
        "Member",
        &["maker-members".into()],
        "ud_member",
        now,
    )
    .await;
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/admin/locks")
                .header(header::AUTHORIZATION, format!("Bearer {user_tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Disabled user -> 403
    state
        .db
        .sync_existing_user_from_sso(
            "sub_member",
            "Member",
            &["maker-members".into()],
            &["locker-admins".into()],
            false,
        )
        .await
        .unwrap();
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/me")
                .header(header::AUTHORIZATION, format!("Bearer {user_tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_http_unlock_replay_mutex_timeout_and_reply_wakeup() {
    let state = test_state().await;
    let now = chrono::Utc::now().timestamp();
    let (_, tok) = seed_user_session(
        &state,
        "sub_alice",
        "Alice",
        &["maker-members".into()],
        "ud_alice",
        now,
    )
    .await;

    sqlx::query(
        "INSERT INTO adapters (
            id, name, approval_status, online_status, reported_state, model, fw_version,
            token_hash, token_refresh_interval, created_at, updated_at
         ) VALUES ('ad_101', '101 GW', 'approved', 'online', 'locked', 'm1', '1.0', 'h', 43200, ?, ?)",
    )
    .bind(now)
    .bind(now)
    .execute(&state.db.pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO locks (id, name, description, adapter_id, created_by, created_at, updated_at)
         VALUES ('lock_101', '101 Door', '', 'ad_101', 'adm', ?, ?)",
    )
    .bind(now)
    .bind(now)
    .execute(&state.db.pool)
    .await
    .unwrap();

    state
        .db
        .replace_lock_groups("lock_101", &["maker-members".into()], "adm", now)
        .await
        .unwrap();

    // Speed up timeout test (minimum enforced by dispatch_unlock_command is 1000ms)
    state
        .db
        .set_system_config_key("command_timeout_ms", "1000", now)
        .await
        .unwrap();

    let app = router().with_state(state.clone());

    // 1) Timestamp outside replay window -> 409 REPLAY_REJECTED
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/unlock")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "lockId": "lock_101",
                        "nonce": "nonce_stale_0001",
                        "ts": now - 600,
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    assert_eq!(json_body(resp).await["code"], "REPLAY_REJECTED");

    // 2) Pre-held adapter mutex -> 409 ADAPTER_BUSY
    assert!(state
        .redis
        .acquire_adapter_mutex("ad_101", "other_msg", 5000)
        .await
        .unwrap());
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/unlock")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "lockId": "lock_101",
                        "nonce": "nonce_busy_00001",
                        "ts": now,
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    assert_eq!(json_body(resp).await["code"], "ADAPTER_BUSY");

    // 3) Duplicate nonce -> 409 REPLAY_REJECTED
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/unlock")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "lockId": "lock_101",
                        "nonce": "nonce_busy_00001",
                        "ts": now,
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    assert_eq!(json_body(resp).await["code"], "REPLAY_REJECTED");

    // Release mutex and verify timeout convergence + mutex cleanup
    state
        .redis
        .release_adapter_mutex("ad_101", "other_msg")
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/unlock")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "lockId": "lock_101",
                        "nonce": "nonce_timeout_01",
                        "ts": now,
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["data"]["status"], "timeout");

    // Mutex must be released after timeout so a subsequent unlock can acquire it
    assert!(state
        .redis
        .acquire_adapter_mutex("ad_101", "verify_free", 1000)
        .await
        .unwrap());
    state
        .redis
        .release_adapter_mutex("ad_101", "verify_free")
        .await
        .unwrap();

    // Verify MQTT v5 publish captured message_expiry_interval == 1s (for 1000ms) & QoS 2
    let msgs = state.mqtt.take_captured_messages();
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].topic, "adapter/ad_101/cmd");
    assert_eq!(msgs[0].message_expiry_interval, Some(1));
    assert!(!msgs[0].retain);

    // 4) Success wakeup via Redis cmd reply
    let state_bg = state.clone();
    tokio::spawn(async move {
        for _ in 0..50 {
            let captured = state_bg.mqtt.take_captured_messages();
            if let Some(msg) = captured.into_iter().next() {
                let env: Value = serde_json::from_slice(&msg.payload).unwrap();
                let msg_id = env["msgId"].as_str().unwrap();
                state_bg
                    .redis
                    .publish_cmd_reply(
                        "ad_101",
                        msg_id,
                        r#"{"ok":true,"code":"OK","message":"door unlocked"}"#,
                    )
                    .await
                    .unwrap();
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    });

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/unlock")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "lockId": "lock_101",
                        "nonce": "nonce_success_01",
                        "ts": now,
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["data"]["status"], "success");
    assert_eq!(body["data"]["deviceCode"], "OK");
}

#[tokio::test]
async fn test_http_internal_mqtt_cn_fail_closed_and_adapter_status_period() {
    let state = test_state().await;
    let now = chrono::Utc::now().timestamp();
    let raw_token = "adapter-secret-token-at-least-thirty-two-chars";
    let token_hash = hash_token(raw_token);

    sqlx::query(
        "INSERT INTO adapters (
            id, name, approval_status, online_status, reported_state, model, fw_version,
            token_hash, token_refresh_interval, created_at, updated_at
         ) VALUES ('ad_mtls', 'mTLS GW', 'approved', 'offline', 'unknown', 'm1', '1.0', ?, 43200, ?, ?)",
    )
    .bind(&token_hash)
    .bind(now)
    .bind(now)
    .execute(&state.db.pool)
    .await
    .unwrap();

    let internal_app = internal_router().with_state(state.clone());

    for bad_cn in [
        Value::Null,
        Value::String("".into()),
        Value::String("undefined".into()),
        Value::String("other-adapter".into()),
    ] {
        let resp = internal_app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/internal/mqtt/auth")
                    .header("x-internal-secret", &state.config.internal_mqtt_secret)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "clientid": "ad_mtls",
                            "username": "ad_mtls",
                            "password": raw_token,
                            "cert_cn": bad_cn,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(json_body(resp).await["result"], "deny");
    }

    let resp = internal_app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/internal/mqtt/auth")
                .header("x-internal-secret", &state.config.internal_mqtt_secret)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "clientid": "ad_mtls",
                        "username": "ad_mtls",
                        "password": raw_token,
                        "cert_cn": "ad_mtls",
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(json_body(resp).await["result"], "allow");

    // Backend ACL must fail closed when username does not match mqtt_username
    let resp = internal_app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/internal/mqtt/acl")
                .header("x-internal-secret", &state.config.internal_mqtt_secret)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "clientid": state.config.mqtt_client_id,
                        "username": "spoofed-username",
                        "topic": "adapter/ad_mtls/cmd",
                        "action": "publish",
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(json_body(resp).await["result"], "deny");

    let resp = internal_app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/internal/mqtt/acl")
                .header("x-internal-secret", &state.config.internal_mqtt_secret)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "clientid": state.config.mqtt_client_id,
                        "username": state.config.mqtt_username,
                        "topic": "adapter/ad_mtls/cmd",
                        "action": "publish",
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(json_body(resp).await["result"], "allow");

    // Verify /api/adapter/status returns stateReportPeriodSec
    let public_app = router().with_state(state.clone());
    let resp = public_app
        .oneshot(
            Request::builder()
                .uri("/api/adapter/status")
                .header(header::AUTHORIZATION, format!("Bearer {raw_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["data"]["adapterId"], "ad_mtls");
    assert_eq!(body["data"]["stateReportPeriodSec"], 60);
}

#[tokio::test]
async fn test_http_webhook_and_refresh_fail_closed() {
    let state = test_state().await;
    let now = chrono::Utc::now().timestamp();
    let app = router().with_state(state.clone());

    let (_, _) = seed_user_session(
        &state,
        "sub_disabled",
        "Disabled User",
        &["maker-members".into()],
        "ud_dis",
        now,
    )
    .await;
    state
        .db
        .sync_existing_user_from_sso(
            "sub_disabled",
            "Disabled User",
            &["maker-members".into()],
            &["locker-admins".into()],
            false,
        )
        .await
        .unwrap();

    // Webhook without pk (cannot verify via Authentik API) and without is_active=false must NOT resurrect disabled user
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/authentik-webhook")
                .header(
                    "x-authentik-webhook-secret",
                    &state.config.authentik_webhook_secret,
                )
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "action": "user_write",
                        "modelName": "user",
                        "uid": "sub_disabled",
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let user_row = state
        .db
        .find_user_by_subject("sub_disabled")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(user_row.status, locker_backend::domain::UserStatus::Disabled);

    // Refresh without CSRF header must fail closed with 403
    let (_, _) = seed_user_session(
        &state,
        "sub_nort",
        "No Refresh Token",
        &["maker-members".into()],
        "ud_nort",
        now,
    )
    .await;
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/refresh")
                .header(header::COOKIE, "user_refresh_token=rt_ud_nort")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Refresh without sso_refresh_token must fail closed with 401
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/refresh")
                .header("x-requested-with", "fetch")
                .header(header::COOKIE, "user_refresh_token=rt_ud_nort")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

fn openssl_sign_register(
    key_path: &std::path::Path,
    adapter_id: &str,
    token: &str,
    ts: i64,
) -> String {
    use base64::Engine as _;
    use std::io::Write;
    let token_hash = hash_token(token);
    let msg = format!("locker-adapter-register:v1:{adapter_id}:{token_hash}:{ts}");
    let mut child = std::process::Command::new("openssl")
        .args(["dgst", "-sha256", "-sign"])
        .arg(key_path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(msg.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    base64::engine::general_purpose::STANDARD.encode(out.stdout)
}

fn gen_test_ca_and_adapter_certs(
    dir: &std::path::Path,
    adapter_ids: &[&str],
) -> std::path::PathBuf {
    let ca_key = dir.join("ca.key");
    let ca_crt = dir.join("ca.crt");
    let status = std::process::Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "30",
            "-sha256",
            "-subj",
            "/CN=Test-Locker-CA",
        ])
        .arg("-keyout")
        .arg(&ca_key)
        .arg("-out")
        .arg(&ca_crt)
        .status()
        .unwrap();
    assert!(status.success());

    let ext_path = dir.join("client.ext");
    std::fs::write(
        &ext_path,
        "basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=clientAuth\n",
    )
    .unwrap();

    for aid in adapter_ids {
        let key = dir.join(format!("{aid}.key"));
        let csr = dir.join(format!("{aid}.csr"));
        let crt = dir.join(format!("{aid}.crt"));
        let s1 = std::process::Command::new("openssl")
            .args(["req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj"])
            .arg(format!("/CN={aid}"))
            .arg("-keyout")
            .arg(&key)
            .arg("-out")
            .arg(&csr)
            .status()
            .unwrap();
        assert!(s1.success());
        let s2 = std::process::Command::new("openssl")
            .args(["x509", "-req", "-CAcreateserial", "-days", "30", "-sha256"])
            .arg("-in")
            .arg(&csr)
            .arg("-CA")
            .arg(&ca_crt)
            .arg("-CAkey")
            .arg(&ca_key)
            .arg("-extfile")
            .arg(&ext_path)
            .arg("-out")
            .arg(&crt)
            .status()
            .unwrap();
        assert!(s2.success());
    }
    ca_crt
}

#[tokio::test]
async fn test_http_adapter_cert_registration_unique_token_and_status_ip_limit() {
    let dir = std::env::temp_dir().join(format!(
        "locker_cert_test_{}",
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let ca_crt = gen_test_ca_and_adapter_certs(&dir, &["ad_cert1", "ad_cert2"]);

    let mut config = test_config();
    config.mqtt_ca_cert = ca_crt;
    let state = test_state_with(config).await;
    let now = chrono::Utc::now().timestamp();
    let (_, admin_tok) = seed_user_session(
        &state,
        "sub_cert_admin",
        "Cert Admin",
        &["locker-admins".into()],
        "ud_cert_admin",
        now,
    )
    .await;

    let app = router().with_state(state.clone());
    let cert1_pem = std::fs::read_to_string(dir.join("ad_cert1.crt")).unwrap();
    let key1_path = dir.join("ad_cert1.key");
    let cert2_pem = std::fs::read_to_string(dir.join("ad_cert2.crt")).unwrap();
    let key2_path = dir.join("ad_cert2.key");

    let tok1 = "adapter-cert-secret-token-1-000001";
    let tok2 = "adapter-cert-secret-token-2-000002";

    // 1) Cert CN mismatch -> 401
    let bad_sig = openssl_sign_register(&key2_path, "ad_cert1", tok1, now);
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/adapter/register")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "adapterId": "ad_cert1",
                        "token": tok1,
                        "certPem": cert2_pem,
                        "ts": now,
                        "signature": bad_sig,
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // 2) Stale ts -> 409 REPLAY_REJECTED
    let stale_sig = openssl_sign_register(&key1_path, "ad_cert1", tok1, now - 600);
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/adapter/register")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "adapterId": "ad_cert1",
                        "token": tok1,
                        "certPem": cert1_pem,
                        "ts": now - 600,
                        "signature": stale_sig,
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);

    // 3) Valid cert + PoP signature -> 200 pending
    let sig1 = openssl_sign_register(&key1_path, "ad_cert1", tok1, now);
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/adapter/register")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "adapterId": "ad_cert1",
                        "token": tok1,
                        "certPem": cert1_pem,
                        "ts": now,
                        "signature": sig1,
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(json_body(resp).await["data"]["approvalStatus"], "pending");

    // 4) Duplicate token_hash across adapters -> 409 DEVICE_ALREADY_REGISTERED
    let sig2_dup = openssl_sign_register(&key2_path, "ad_cert2", tok1, now);
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/adapter/register")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "adapterId": "ad_cert2",
                        "token": tok1,
                        "certPem": cert2_pem,
                        "ts": now,
                        "signature": sig2_dup,
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    assert_eq!(json_body(resp).await["code"], "DEVICE_ALREADY_REGISTERED");

    // 5) Admin reset clears token_hash; old token fails /status; re-register with new token succeeds
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/admin/adapters/ad_cert1/reset")
                .header(header::AUTHORIZATION, format!("Bearer {admin_tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"reason":"reprovision"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/adapter/status")
                .header(header::AUTHORIZATION, format!("Bearer {tok1}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let sig1_new = openssl_sign_register(&key1_path, "ad_cert1", tok2, now);
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/adapter/register")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "adapterId": "ad_cert1",
                        "token": tok2,
                        "certPem": cert1_pem,
                        "ts": now,
                        "signature": sig1_new,
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 6) /api/adapter/status enforces IP rate limit before DB lookup (default max 30/min)
    for _ in 0..29 {
        let _ = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/adapter/status")
                    .header(header::AUTHORIZATION, "Bearer invalid-token-probe")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
    }
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/adapter/status")
                .header(header::AUTHORIZATION, "Bearer invalid-token-probe")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_http_unlock_extreme_ts_admin_group_recompute_and_rotation_conflict() {
    let state = test_state().await;
    let now = chrono::Utc::now().timestamp();
    let (_, admin_tok) = seed_user_session(
        &state,
        "sub_adm_recompute",
        "Admin Recompute",
        &["locker-admins".into()],
        "ud_adm_recompute",
        now,
    )
    .await;

    sqlx::query(
        "INSERT INTO adapters (
            id, name, approval_status, online_status, reported_state, model, fw_version,
            token_hash, pending_token_hash, pending_token_msg_id, pending_token_at,
            token_refresh_interval, created_at, updated_at
         ) VALUES ('ad_rot', 'Rot GW', 'approved', 'online', 'locked', 'm1', '1.0', 'h_rot', 'pend_h', 'pend_msg', ?, 43200, ?, ?)",
    )
    .bind(now)
    .bind(now)
    .bind(now)
    .execute(&state.db.pool)
    .await
    .unwrap();

    let app = router().with_state(state.clone());

    // 1) Extreme i64::MIN ts must return 409 REPLAY_REJECTED without overflow/panic
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/unlock")
                .header(header::AUTHORIZATION, format!("Bearer {admin_tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "lockId": "missing_lock",
                        "nonce": "nonce_min_i64_001",
                        "ts": i64::MIN,
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    assert_eq!(json_body(resp).await["code"], "REPLAY_REJECTED");

    // 2) Concurrent manual token rotation when pending_token_hash != NULL -> 409 CONFLICT
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/admin/adapters/ad_rot/refresh-token")
                .header(header::AUTHORIZATION, format!("Bearer {admin_tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);

    // 3) Updating adminGroups immediately recomputes users.role
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/admin/config")
                .header(header::AUTHORIZATION, format!("Bearer {admin_tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"adminGroups":["super-admins"]}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Former admin is immediately demoted on the very next request
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/admin/locks")
                .header(header::AUTHORIZATION, format!("Bearer {admin_tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_http_old_token_auth_clears_stale_pending_and_schedules_retry() {
    let state = test_state().await;
    let now = chrono::Utc::now().timestamp();
    let old_tok_fresh = "old_adapter_token_fresh_32chars_1";
    let old_hash_fresh = locker_backend::utils::hash_token(old_tok_fresh);
    let old_tok_stale = "old_adapter_token_stale_32chars_2";
    let old_hash_stale = locker_backend::utils::hash_token(old_tok_stale);

    // 1) Fresh pending token (not stale yet): old-token auth succeeds and preserves pending
    sqlx::query(
        "INSERT INTO adapters (
            id, name, approval_status, online_status, reported_state, model, fw_version,
            token_hash, pending_token_hash, pending_token_msg_id, pending_token_at,
            token_refresh_interval, created_at, updated_at
         ) VALUES ('ad_fresh_pend', 'Fresh Pend', 'approved', 'offline', 'locked', 'm1', '1.0',
                   ?, 'pend_h_fresh', 'pend_msg_fresh', ?, 43200, ?, ?)",
    )
    .bind(&old_hash_fresh)
    .bind(now - 60)
    .bind(now - 3600)
    .bind(now - 60)
    .execute(&state.db.pool)
    .await
    .unwrap();

    let internal_app = internal_router().with_state(state.clone());
    let resp = internal_app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/internal/mqtt/auth")
                .header("x-internal-secret", &state.config.internal_mqtt_secret)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "clientid": "ad_fresh_pend",
                        "username": "ad_fresh_pend",
                        "password": old_tok_fresh,
                        "cert_cn": "ad_fresh_pend",
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(json_body(resp).await["result"], "allow");
    let fresh_row = state
        .db
        .find_adapter_by_id("ad_fresh_pend")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        fresh_row.pending_token_hash.as_deref(),
        Some("pend_h_fresh")
    );
    assert!(!state
        .redis
        .take_adapter_rotation_retry("ad_fresh_pend")
        .await
        .unwrap());

    // 2) Stale pending token (> 600s old / flagged stale): old-token auth clears pending & marks retry
    sqlx::query(
        "INSERT INTO adapters (
            id, name, approval_status, online_status, reported_state, model, fw_version,
            token_hash, pending_token_hash, pending_token_msg_id, pending_token_at,
            pending_token_stale_at, token_refresh_interval, created_at, updated_at
         ) VALUES ('ad_stale_pend', 'Stale Pend', 'approved', 'offline', 'locked', 'm1', '1.0',
                   ?, 'pend_h_stale', 'pend_msg_stale', ?, ?, 43200, ?, ?)",
    )
    .bind(&old_hash_stale)
    .bind(now - 700)
    .bind(now - 100)
    .bind(now - 3600)
    .bind(now - 100)
    .execute(&state.db.pool)
    .await
    .unwrap();

    let resp = internal_app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/internal/mqtt/auth")
                .header("x-internal-secret", &state.config.internal_mqtt_secret)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "clientid": "ad_stale_pend",
                        "username": "ad_stale_pend",
                        "password": old_tok_stale,
                        "cert_cn": "ad_stale_pend",
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(json_body(resp).await["result"], "allow");

    let stale_row = state
        .db
        .find_adapter_by_id("ad_stale_pend")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stale_row.token_hash, old_hash_stale);
    assert!(stale_row.pending_token_hash.is_none());
    assert!(stale_row.pending_token_msg_id.is_none());
    assert!(stale_row.pending_token_at.is_none());
    assert!(stale_row.pending_token_stale_at.is_none());

    // Retry flag was scheduled in Redis and is consumed atomically on presence online
    assert!(state
        .redis
        .take_adapter_rotation_retry("ad_stale_pend")
        .await
        .unwrap());
    assert!(!state
        .redis
        .take_adapter_rotation_retry("ad_stale_pend")
        .await
        .unwrap());
}

#[tokio::test]
async fn static_assets_support_gzip_compression_and_cache_headers() {
    let state = test_state().await;
    let temp_dir = std::env::temp_dir().join(format!("locker_static_test_{}", uuid::Uuid::new_v4()));
    let assets_dir = temp_dir.join("assets");
    std::fs::create_dir_all(&assets_dir).unwrap();
    std::fs::write(
        temp_dir.join("index.html"),
        "<!doctype html><html><body>Locker Console</body></html>",
    )
    .unwrap();
    let js_body = "console.log('locker-frontend-bundle-payload-for-gzip-compression-test');\n".repeat(4);
    std::fs::write(assets_dir.join("app.js"), &js_body).unwrap();
    // Minimal pre-compressed .gz sibling served by ServeDir::precompressed_gzip()
    let gz_body: Vec<u8> = vec![0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03];
    std::fs::write(assets_dir.join("app.js.gz"), &gz_body).unwrap();

    let app = locker_backend::routes::router_with_static(Some(&temp_dir)).with_state(state);

    let gzip_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/assets/app.js")
                .header(header::ACCEPT_ENCODING, "gzip")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(gzip_resp.status(), StatusCode::OK);
    assert_eq!(
        gzip_resp.headers().get(header::CONTENT_ENCODING).unwrap(),
        "gzip"
    );
    assert_eq!(
        gzip_resp.headers().get(header::CACHE_CONTROL).unwrap(),
        "public, max-age=604800, immutable"
    );
    assert_eq!(
        gzip_resp
            .headers()
            .get(header::X_CONTENT_TYPE_OPTIONS)
            .unwrap(),
        "nosniff"
    );

    let raw_resp = app
        .oneshot(
            Request::builder()
                .uri("/assets/app.js")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(raw_resp.status(), StatusCode::OK);
    assert!(raw_resp.headers().get(header::CONTENT_ENCODING).is_none());
    let raw_bytes = raw_resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(raw_bytes.as_ref(), js_body.as_bytes());

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_http_admin_users_status_split_and_pagination() {
    let state = test_state().await;
    let now = chrono::Utc::now().timestamp();
    let (_, admin_tok) = seed_user_session(
        &state,
        "sub_admin_users",
        "Admin",
        &["locker-admins".into()],
        "ud_admin_users",
        now,
    )
    .await;

    for i in 0..3 {
        let u = state
            .db
            .upsert_user_from_sso(
                &format!("sub_act_{i}"),
                &format!("Active {i}"),
                &["maker-members".into()],
                &["locker-admins".into()],
                now + i as i64 + 1,
            )
            .await
            .unwrap();
        if i == 2 {
            state
                .db
                .sync_existing_user_from_sso(
                    &u.sso_subject,
                    "Disabled User",
                    &["maker-members".into()],
                    &["locker-admins".into()],
                    false,
                )
                .await
                .unwrap();
        }
    }

    let app = router().with_state(state);

    // Missing status / pageSize must be rejected
    let missing = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/admin/users")
                .header(header::AUTHORIZATION, format!("Bearer {admin_tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::BAD_REQUEST);

    // pageSize > 50 must be rejected
    let over_limit = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/admin/users?status=active&pageSize=51")
                .header(header::AUTHORIZATION, format!("Bearer {admin_tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(over_limit.status(), StatusCode::BAD_REQUEST);

    // Active users page 1 (pageSize=2 -> 2 of 3 total active users)
    let act_p1 = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/admin/users?status=active&page=1&pageSize=2")
                .header(header::AUTHORIZATION, format!("Bearer {admin_tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(act_p1.status(), StatusCode::OK);
    let act_body = json_body(act_p1).await;
    assert_eq!(act_body["data"]["status"], "active");
    assert_eq!(act_body["data"]["total"], 3);
    assert_eq!(act_body["data"]["items"].as_array().unwrap().len(), 2);

    // Disabled users strictly separated
    let dis_p1 = app
        .oneshot(
            Request::builder()
                .uri("/api/admin/users?status=disabled&page=1&pageSize=50")
                .header(header::AUTHORIZATION, format!("Bearer {admin_tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(dis_p1.status(), StatusCode::OK);
    let dis_body = json_body(dis_p1).await;
    assert_eq!(dis_body["data"]["status"], "disabled");
    assert_eq!(dis_body["data"]["total"], 1);
    assert_eq!(dis_body["data"]["items"].as_array().unwrap().len(), 1);
    assert_eq!(dis_body["data"]["items"][0]["status"], "disabled");
}

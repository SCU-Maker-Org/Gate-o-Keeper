use axum::body::Body;
use axum::http::{header, HeaderMap, HeaderValue, Request, StatusCode};
use axum::response::IntoResponse;
use http_body_util::BodyExt;
use locker_backend::audit::spawn_audit_worker;
use locker_backend::auth::{hash_token, issue_access_token, OidcCache};
use locker_backend::config::AppConfig;
use locker_backend::db::Db;
use locker_backend::error::{AppError, ErrorCode};
use locker_backend::mqtt::MqttClient;
use locker_backend::redis_store::RedisStore;
use locker_backend::routes::{
    extract_request_id, internal_router, is_valid_identifier, resolve_client_ip, router,
};
use locker_backend::state::AppState;
use serde_json::Value;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
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
    let config = test_config();
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
        &user.role,
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
    let (tok, exp) = issue_access_token(&cfg.jwt_secret, "u1", "d1", "user", now).unwrap();
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
        "VITE_AUTHENTIK_AUTHORIZE_URL",
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
        .oneshot(Request::builder().uri("/healthz").body(Body::empty()).unwrap())
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
        .oneshot(Request::builder().uri("/api/me").body(Body::empty()).unwrap())
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
                .header("x-authentik-webhook-secret", &state.config.authentik_webhook_secret)
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
    assert_eq!(user_row.status, "disabled");

    // Refresh without sso_refresh_token must fail closed with 401
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
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::IntoResponse;
use locker_backend::auth::issue_access_token;
use locker_backend::config::AppConfig;
use locker_backend::error::{AppError, ErrorCode};
use locker_backend::routes::{extract_request_id, is_valid_identifier, resolve_client_ip};
use std::net::{IpAddr, Ipv4Addr};

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
    std::env::set_var("VITE_AUTHENTIK_AUTHORIZE_URL", "https://auth.example.com/application/o/authorize/");
    std::env::set_var("STATIC_DIR", "/app/static");
    let cfg = AppConfig::from_env().unwrap();
    assert_eq!(
        cfg.authentik_authorize_url,
        "https://auth.example.com/application/o/authorize/"
    );
    assert_eq!(
        cfg.static_dir.as_deref(),
        Some(std::path::Path::new("/app/static"))
    );
    let now = 1_763_164_740;
    let (tok, exp) = issue_access_token(&cfg.jwt_secret, "u1", "d1", "user", now).unwrap();
    assert!(!tok.is_empty());
    assert_eq!(exp, now + 900);
    std::env::remove_var("STATIC_DIR");
    std::env::remove_var("VITE_AUTHENTIK_AUTHORIZE_URL");
    std::env::remove_var("JWT_SECRET");
    std::env::remove_var("ALLOW_DEV_DEFAULTS");
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

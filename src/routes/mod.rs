//! Web API Layer: Axum routing, HTTP extractors (`ClientIp`, `AuthContext`, `AdminContext`),
//! security headers, and request/response serialization.

pub mod adapter;
pub mod admin;
pub mod auth;
pub mod extractors;
pub mod internal_mqtt;
pub mod user;

use crate::error::{with_request_id_scope, AppError};
use crate::state::AppState;
use axum::body::Body;
use axum::http::{header, HeaderValue, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{any, get, post};
use axum::Router;
use std::path::Path;
use tower_http::services::{ServeDir, ServeFile};
use tower_http::trace::TraceLayer;

pub use crate::services::{
    compute_adapter_view, compute_lock_view, is_valid_identifier, target_ref, AdapterStatusView,
    LockStatusView,
};
pub use extractors::{
    extract_request_id, require_admin, resolve_client_ip, AdminContext, AuthContext, BearerToken,
    ClientIp, RequestId,
};

pub fn router() -> Router<AppState> {
    router_with_static(None)
}

async fn api_not_found(RequestId(req_id): RequestId) -> AppError {
    AppError::not_found("endpoint not found").with_request_id(&req_id)
}

async fn request_id_middleware(mut req: Request<Body>, next: Next) -> Response {
    let req_id = extract_request_id(req.headers());
    req.extensions_mut().insert(RequestId(req_id.clone()));
    let mut resp = with_request_id_scope(req_id.clone(), next.run(req)).await;
    if let Ok(val) = HeaderValue::from_str(&req_id) {
        resp.headers_mut().insert("x-request-id", val);
    }
    resp
}

async fn static_and_security_headers(req: Request<Body>, next: Next) -> Response {
    let is_immutable_asset =
        req.method() == axum::http::Method::GET && req.uri().path().starts_with("/assets/");
    let mut resp = next.run(req).await;
    let is_ok = resp.status() == StatusCode::OK;
    let headers = resp.headers_mut();
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::X_FRAME_OPTIONS,
        HeaderValue::from_static("SAMEORIGIN"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'self'; base-uri 'self'; form-action 'self'",
        ),
    );
    if is_immutable_asset && is_ok {
        headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("public, max-age=604800, immutable"),
        );
    }
    resp
}

pub fn router_with_static(static_dir: Option<&Path>) -> Router<AppState> {
    let mut app = Router::new()
        .route("/healthz", get(user::healthz))
        // Auth & Authentik OIDC
        .route("/api/auth/sso-exchange", post(auth::sso_exchange))
        .route("/api/auth/refresh", post(auth::refresh))
        .route("/api/auth/logout", post(auth::logout))
        .route(
            "/api/auth/backchannel-logout",
            post(auth::backchannel_logout),
        )
        .route("/api/auth/authentik-webhook", post(auth::authentik_webhook))
        // User & Unlock
        .route("/api/me", get(user::me))
        .route("/api/locks/:id/status", get(user::lock_status))
        .route("/api/unlock", post(user::unlock))
        // Adapter bootstrap
        .route("/api/adapter/register", post(adapter::register))
        .route("/api/adapter/status", get(adapter::status))
        // Admin - Locks
        .route(
            "/api/admin/locks",
            get(admin::list_locks).post(admin::create_lock),
        )
        .route("/api/admin/locks/:id/update", post(admin::update_lock))
        .route("/api/admin/locks/:id/bind", post(admin::bind_lock))
        .route("/api/admin/locks/:id/delete", post(admin::delete_lock))
        .route(
            "/api/admin/locks/:id/groups",
            get(admin::get_lock_groups).post(admin::set_lock_groups),
        )
        .route(
            "/api/admin/locks/:id/unlock",
            post(admin::admin_unlock_lock),
        )
        .route(
            "/api/admin/locks/:id/refresh-state",
            post(admin::refresh_lock_state),
        )
        // Admin - Adapters
        .route("/api/admin/adapters", get(admin::list_adapters))
        .route(
            "/api/admin/adapters/:id/approve",
            post(admin::approve_adapter),
        )
        .route(
            "/api/admin/adapters/:id/reject",
            post(admin::reject_adapter),
        )
        .route(
            "/api/admin/adapters/:id/revoke",
            post(admin::revoke_adapter),
        )
        .route("/api/admin/adapters/:id/reset", post(admin::reset_adapter))
        .route(
            "/api/admin/adapters/:id/delete",
            post(admin::delete_adapter),
        )
        .route(
            "/api/admin/adapters/:id/refresh-token",
            post(admin::refresh_adapter_token),
        )
        .route(
            "/api/admin/adapters/:id/update",
            post(admin::update_adapter),
        )
        .route("/api/admin/adapters/:id/unlock", post(admin::admin_unlock))
        .route(
            "/api/admin/adapters/:id/refresh-state",
            post(admin::refresh_adapter_state),
        )
        .route("/api/admin/users", get(admin::list_users))
        .route("/api/admin/users/:id/kick", post(admin::kick_user))
        .route("/api/admin/audit-logs", get(admin::list_audit_logs))
        .route(
            "/api/admin/config",
            get(admin::get_config).post(admin::update_config),
        );

    if let Some(dir) = static_dir.filter(|d| d.is_dir()) {
        let index_file = dir.join("index.html");
        let spa = ServeDir::new(dir)
            .precompressed_gzip()
            .fallback(ServeFile::new(index_file).precompressed_gzip());
        app = app
            .route("/api/*rest", any(api_not_found))
            .route("/internal/*rest", any(api_not_found))
            .fallback_service(spa);
    }

    app.layer(middleware::from_fn(static_and_security_headers))
        .layer(middleware::from_fn(request_id_middleware))
        .layer(TraceLayer::new_for_http())
}

pub fn internal_router() -> Router<AppState> {
    Router::new()
        .route("/internal/mqtt/auth", post(internal_mqtt::mqtt_auth))
        .route("/internal/mqtt/acl", post(internal_mqtt::mqtt_acl))
        .fallback(any(api_not_found))
        .layer(middleware::from_fn(request_id_middleware))
        .layer(TraceLayer::new_for_http())
}

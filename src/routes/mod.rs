//! Web API Layer: Axum routing, HTTP extractors (`ClientIp`, `AdminContext`),
//! security headers, and request/response serialization.

pub mod adapter;
pub mod admin;
pub mod auth;
pub mod internal_mqtt;
pub mod user;

use crate::auth::{authenticate_request, AuthUser};
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use axum::body::Body;
use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::request::Parts;
use axum::http::{header, HeaderMap, HeaderValue, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{any, get, post};
use axum::Router;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use tower_http::services::{ServeDir, ServeFile};
use tower_http::trace::TraceLayer;

pub use crate::services::{
    compute_adapter_view, compute_lock_view, is_valid_identifier, target_ref, AdapterStatusView,
    LockStatusView,
};

pub fn router() -> Router<AppState> {
    router_with_static(None)
}

async fn api_not_found(headers: HeaderMap) -> AppError {
    let req_id = extract_request_id(&headers);
    AppError::not_found("endpoint not found").with_request_id(&req_id)
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
        let spa = ServeDir::new(dir).fallback(ServeFile::new(index_file));
        app = app
            .route("/api/*rest", any(api_not_found))
            .route("/internal/*rest", any(api_not_found))
            .fallback_service(spa);
    }

    app.layer(middleware::from_fn(static_and_security_headers))
        .layer(TraceLayer::new_for_http())
}

pub fn internal_router() -> Router<AppState> {
    Router::new()
        .route("/internal/mqtt/auth", post(internal_mqtt::mqtt_auth))
        .route("/internal/mqtt/acl", post(internal_mqtt::mqtt_acl))
        .fallback(any(api_not_found))
        .layer(TraceLayer::new_for_http())
}

pub fn extract_request_id(headers: &HeaderMap) -> String {
    headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| is_valid_identifier(s, 1, 64))
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| format!("req_{}", uuid::Uuid::new_v4().simple()))
}

#[derive(Clone, Debug)]
pub struct ClientIp(pub String);

#[axum::async_trait]
impl FromRequestParts<AppState> for ClientIp {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let peer_ip = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ConnectInfo(addr)| addr.ip());
        Ok(Self(resolve_client_ip(
            &parts.headers,
            peer_ip,
            &state.config.trusted_proxies,
        )))
    }
}

pub fn resolve_client_ip(
    headers: &HeaderMap,
    peer_ip: Option<IpAddr>,
    trusted_proxies: &[IpAddr],
) -> String {
    let Some(peer) = peer_ip else {
        return "unknown".to_string();
    };

    if trusted_proxies.contains(&peer) {
        if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            let parsed: Vec<IpAddr> = xff
                .split(',')
                .filter_map(|part| part.trim().parse::<IpAddr>().ok())
                .collect();
            if let Some(client) = parsed
                .into_iter()
                .rev()
                .find(|ip| !trusted_proxies.contains(ip))
            {
                return client.to_string();
            }
        }
        if let Some(real_ip) = headers
            .get("x-real-ip")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse::<IpAddr>().ok())
        {
            return real_ip.to_string();
        }
    }

    peer.to_string()
}

pub fn require_admin(auth: &AuthUser, req_id: &str) -> AppResult<()> {
    if auth.user.role != "admin" {
        return Err(AppError::forbidden("admin role required").with_request_id(req_id));
    }
    Ok(())
}

/// Request extractor that resolves `requestId`, authenticates the bearer JWT,
/// and enforces the `admin` role in one place for all `/api/admin/*` routes.
#[derive(Clone, Debug)]
pub struct AdminContext {
    pub auth: AuthUser,
    pub req_id: String,
}

#[axum::async_trait]
impl FromRequestParts<AppState> for AdminContext {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let req_id = extract_request_id(&parts.headers);
        let auth = authenticate_request(state, &parts.headers)
            .await
            .map_err(|e| e.with_request_id(&req_id))?;
        require_admin(&auth, &req_id)?;
        Ok(Self { auth, req_id })
    }
}

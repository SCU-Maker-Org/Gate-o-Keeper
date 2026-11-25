use crate::auth::{authenticate_request, bearer_token, AuthUser};
use crate::domain::UserRole;
use crate::error::{AppError, AppResult};
use crate::services::is_valid_identifier;
use crate::state::AppState;
use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::request::Parts;
use axum::http::HeaderMap;
use std::net::{IpAddr, SocketAddr};

pub fn extract_request_id(headers: &HeaderMap) -> String {
    headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| is_valid_identifier(s, 1, 64))
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| format!("req_{}", uuid::Uuid::new_v4().simple()))
}

/// Request extractor that resolves `requestId` from `x-request-id` (reusing the middleware value if present).
#[derive(Clone, Debug)]
pub struct RequestId(pub String);

#[axum::async_trait]
impl<S> FromRequestParts<S> for RequestId
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        if let Some(id) = parts.extensions.get::<RequestId>() {
            return Ok(id.clone());
        }
        Ok(Self(extract_request_id(&parts.headers)))
    }
}

/// Request extractor that parses the `Authorization: Bearer <token>` header.
#[derive(Clone, Debug)]
pub struct BearerToken(pub String);

#[axum::async_trait]
impl<S> FromRequestParts<S> for BearerToken
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let token = bearer_token(&parts.headers)?;
        Ok(Self(token.to_string()))
    }
}

/// Request extractor that resolves the client IP address from peer info and trusted proxy headers.
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

/// Request extractor that resolves `requestId` and authenticates the bearer JWT.
#[derive(Clone, Debug)]
pub struct AuthContext {
    pub auth: AuthUser,
    pub req_id: String,
}

#[axum::async_trait]
impl FromRequestParts<AppState> for AuthContext {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let RequestId(req_id) = RequestId::from_request_parts(parts, state)
            .await
            .expect("infallible");
        let auth = authenticate_request(state, &parts.headers)
            .await
            .map_err(|e| e.with_request_id(&req_id))?;
        Ok(Self { auth, req_id })
    }
}

pub fn require_admin(auth: &AuthUser, req_id: &str) -> AppResult<()> {
    if auth.user.role != UserRole::Admin {
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
        let AuthContext { auth, req_id } = AuthContext::from_request_parts(parts, state).await?;
        require_admin(&auth, &req_id)?;
        Ok(Self { auth, req_id })
    }
}

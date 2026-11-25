//! Authentication primitives: token hashing, adapter cert verification,
//! JWT access tokens, OIDC code exchange, and back-channel logout validation.

mod adapter_cert;
mod authentik_api;
mod jwt;
mod oidc;

use serde::Deserialize;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

pub use crate::utils::{compute_user_role, constant_time_eq, generate_random_token, hash_token};

pub use adapter_cert::verify_adapter_registration_cert;
pub use authentik_api::{
    fetch_authentik_user_by_pk, fetch_authentik_users_list, AuthentikApiUser, AuthentikGroupSummary,
};
pub use jwt::{
    authenticate_request, bearer_token, issue_access_token, verify_access_token,
    AccessTokenClaims, AuthUser,
};
pub use oidc::{
    refresh_authentik_oidc_profile, verify_authentik_code_and_get_profile,
    verify_backchannel_logout_token, BackChannelLogoutClaims, OidcRefreshFailure, OidcUserProfile,
};

/// Lifetime of a user access token, in seconds.
pub const ACCESS_TOKEN_TTL_SEC: i64 = 900;
/// Lifetime of a user refresh token, in seconds.
pub const REFRESH_TOKEN_TTL_SEC: i64 = 7 * 86_400;
/// Minimum interval between `user_devices.last_active_at` writes.
pub(super) const DEVICE_ACTIVITY_UPDATE_SEC: i64 = 30;
/// Clock skew allowed while validating OIDC tokens.
pub(super) const OIDC_LEEWAY_SEC: u64 = 30;
/// Cache lifetime for OIDC discovery documents and JWKS keys.
pub(super) const OIDC_CACHE_TTL: Duration = Duration::from_secs(300);

#[derive(Clone, Default)]
pub struct OidcCache {
    pub(super) inner: Arc<RwLock<Option<CachedOidc>>>,
}

#[derive(Clone)]
pub(super) struct CachedOidc {
    pub(super) discovery: OidcDiscovery,
    pub(super) jwks: jsonwebtoken::jwk::JwkSet,
    pub(super) fetched_at: Instant,
}

#[derive(Clone, Debug, Deserialize)]
pub(super) struct OidcDiscovery {
    pub(super) issuer: String,
    pub(super) token_endpoint: String,
    pub(super) jwks_uri: String,
    #[serde(default)]
    pub(super) userinfo_endpoint: Option<String>,
}

pub(super) fn unix_now() -> i64 {
    chrono::Utc::now().timestamp()
}

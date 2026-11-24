//! Authentication primitives: token hashing, adapter cert verification,
//! JWT access tokens, OIDC code exchange, back-channel logout validation,
//! and refresh-token rotation.

mod adapter_cert;
mod authentik_api;
mod jwt;
mod oidc;
mod sessions;

use rand::RngCore;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;
use tokio::sync::RwLock;

pub use adapter_cert::verify_adapter_registration_cert;
pub use authentik_api::{
    fetch_authentik_user_by_pk, fetch_authentik_users_list, AuthentikApiUser,
    AuthentikGroupSummary,
};
pub use jwt::{authenticate_request, issue_access_token, verify_access_token, AccessTokenClaims, AuthUser};
pub use oidc::{
    verify_authentik_code_and_get_profile, verify_backchannel_logout_token,
    BackChannelLogoutClaims, OidcUserProfile,
};
pub use sessions::{evict_excess_devices_for_user, login_or_reuse_device, rotate_refresh_token};

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

/// Returns the lowercase hex-encoded SHA-256 digest of `token`.
pub fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// Generates a 256-bit cryptographically random hex-encoded token.
pub fn generate_random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Constant-time string equality comparison for secret/hash checks.
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

/// Computes local user role (`"admin"` or `"user"`) from group membership.
pub fn compute_user_role(groups: &[String], admin_groups: &[String]) -> &'static str {
    if groups.iter().any(|g| admin_groups.iter().any(|ag| ag == g)) {
        "admin"
    } else {
        "user"
    }
}

pub(super) fn unix_now() -> i64 {
    chrono::Utc::now().timestamp()
}

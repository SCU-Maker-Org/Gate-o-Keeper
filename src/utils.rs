//! Pure stateless primitives shared across layers (hashing, tokens, validation, role mapping).

use crate::domain::UserRole;
use rand::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

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

/// Computes local user role (`UserRole::Admin` or `UserRole::User`) from group membership.
pub fn compute_user_role(groups: &[String], admin_groups: &[String]) -> UserRole {
    if groups.iter().any(|g| admin_groups.iter().any(|ag| ag == g)) {
        UserRole::Admin
    } else {
        UserRole::User
    }
}

/// Validates identifier length and `[A-Za-z0-9_-]` charset.
pub fn is_valid_identifier(s: &str, min_len: usize, max_len: usize) -> bool {
    let len = s.len();
    len >= min_len
        && len <= max_len
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

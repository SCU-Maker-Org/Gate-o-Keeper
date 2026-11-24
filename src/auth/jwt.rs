use super::{unix_now, ACCESS_TOKEN_TTL_SEC, DEVICE_ACTIVITY_UPDATE_SEC, OIDC_LEEWAY_SEC};
use crate::error::{AppError, AppResult, ErrorCode};
use crate::infra::db::UserRow;
use crate::infra::redis::JwtRevocationStatus;
use crate::state::AppState;
use axum::http::{header, HeaderMap};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct AccessTokenClaims {
    pub sub: String,
    pub jti: String,
    pub device_session_id: String,
    pub role: String,
    pub iat: i64,
    pub exp: i64,
}

#[derive(Clone, Debug)]
pub struct AuthUser {
    pub user: UserRow,
    pub device_session_id: String,
    pub claims: AccessTokenClaims,
}

/// Signs a short-lived HS256 access token.
///
/// Returns the compact JWT and its `exp` timestamp.
pub fn issue_access_token(
    jwt_secret: &str,
    user_id: &str,
    device_session_id: &str,
    role: &str,
    now: i64,
) -> AppResult<(String, i64)> {
    let exp = now + ACCESS_TOKEN_TTL_SEC;
    let claims = AccessTokenClaims {
        sub: user_id.to_owned(),
        jti: format!("jti_{}", uuid::Uuid::new_v4().simple()),
        device_session_id: device_session_id.to_owned(),
        role: role.to_owned(),
        iat: now,
        exp,
    };

    let token = jsonwebtoken::encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(jwt_secret.as_bytes()),
    )
    .map_err(|err| {
        tracing::error!(error = %err, "failed to sign access token");
        AppError::internal("failed to sign access token")
    })?;

    Ok((token, exp))
}

/// Verifies an HS256 access token and returns its claims.
pub fn verify_access_token(jwt_secret: &str, token: &str) -> AppResult<AccessTokenClaims> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.required_spec_claims = ["exp", "sub", "jti"]
        .into_iter()
        .map(String::from)
        .collect();
    validation.validate_exp = true;
    validation.validate_aud = false;
    validation.leeway = OIDC_LEEWAY_SEC;

    jsonwebtoken::decode::<AccessTokenClaims>(
        token,
        &DecodingKey::from_secret(jwt_secret.as_bytes()),
        &validation,
    )
    .map(|data| data.claims)
    .map_err(|err| {
        tracing::debug!(error = %err, "access token verification failed");
        AppError::unauthorized("invalid or expired access token")
    })
}

/// Authenticates an HTTP request from its `Authorization: Bearer` header.
pub async fn authenticate_request(state: &AppState, headers: &HeaderMap) -> AppResult<AuthUser> {
    let token = bearer_token(headers)?;
    let claims = verify_access_token(&state.config.jwt_secret, token)?;

    match state
        .redis
        .check_jwt_revocation(
            &claims.device_session_id,
            &claims.sub,
            &claims.jti,
            claims.iat,
        )
        .await?
    {
        JwtRevocationStatus::Active => {}
        JwtRevocationStatus::DeviceKicked => {
            return Err(AppError::new(ErrorCode::DeviceKicked, "device kicked"));
        }
        JwtRevocationStatus::Revoked => {
            return Err(AppError::unauthorized("token revoked"));
        }
    }

    let device = state
        .db
        .find_device_by_id(&claims.device_session_id)
        .await?
        .ok_or_else(|| AppError::unauthorized("device session not found"))?;
    if device.user_id != claims.sub {
        return Err(AppError::unauthorized("device session mismatch"));
    }
    match device.status.as_str() {
        "online" => {}
        "kicked" => return Err(AppError::new(ErrorCode::DeviceKicked, "device kicked")),
        _ => return Err(AppError::unauthorized("token revoked")),
    }

    let user = state
        .db
        .find_user_by_id(&claims.sub)
        .await?
        .ok_or_else(|| AppError::unauthorized("user not found"))?;

    if user.status != "active" {
        return Err(AppError::forbidden("account is disabled"));
    }

    touch_device_activity(state, &claims.device_session_id).await;

    Ok(AuthUser {
        user,
        device_session_id: claims.device_session_id.clone(),
        claims,
    })
}

fn bearer_token(headers: &HeaderMap) -> AppResult<&str> {
    let value = headers
        .get(header::AUTHORIZATION)
        .ok_or_else(|| AppError::unauthorized("missing authorization header"))?
        .to_str()
        .map_err(|_| AppError::unauthorized("invalid authorization header"))?;

    let mut parts = value.split_whitespace();
    let scheme = parts
        .next()
        .ok_or_else(|| AppError::unauthorized("invalid authorization header"))?;
    let token = parts
        .next()
        .ok_or_else(|| AppError::unauthorized("invalid authorization header"))?;

    if !scheme.eq_ignore_ascii_case("bearer") || token.is_empty() || parts.next().is_some() {
        return Err(AppError::unauthorized("invalid authorization header"));
    }

    Ok(token)
}

async fn touch_device_activity(state: &AppState, device_session_id: &str) {
    let now = unix_now();
    let cutoff = now - DEVICE_ACTIVITY_UPDATE_SEC;

    if let Err(err) = state
        .db
        .touch_device_activity(device_session_id, now, cutoff)
        .await
    {
        tracing::warn!(
            error = %err.message,
            device_session_id,
            "failed to update device activity"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::hash_token;

    #[test]
    fn hash_token_matches_known_sha256_vectors() {
        assert_eq!(
            hash_token("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hash_token(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(hash_token("locker").len(), 64);
    }

    #[test]
    fn access_token_round_trip_preserves_claims() {
        let now = unix_now();
        let (token, exp) = issue_access_token("test-secret", "usr_1", "ud_1", "admin", now)
            .expect("access token should be issued");

        assert_eq!(exp, now + ACCESS_TOKEN_TTL_SEC);

        let claims =
            verify_access_token("test-secret", &token).expect("access token should verify");

        assert_eq!(claims.sub, "usr_1");
        assert_eq!(claims.device_session_id, "ud_1");
        assert_eq!(claims.role, "admin");
        assert_eq!(claims.iat, now);
        assert_eq!(claims.exp, exp);
        assert!(!claims.jti.is_empty());
    }

    #[test]
    fn access_token_rejects_wrong_secret_and_tampering() {
        let (token, _) = issue_access_token("test-secret", "usr_1", "ud_1", "user", unix_now())
            .expect("access token should be issued");

        let wrong_secret =
            verify_access_token("other-secret", &token).expect_err("wrong secret must be rejected");
        assert_eq!(wrong_secret.code, ErrorCode::Unauthorized);

        let tampered = format!("{token}extra");
        let tampered_err = verify_access_token("test-secret", &tampered)
            .expect_err("tampered token must be rejected");
        assert_eq!(tampered_err.code, ErrorCode::Unauthorized);
    }

    #[test]
    fn access_token_rejects_expired_tokens() {
        let now = unix_now();
        let expired_claims = AccessTokenClaims {
            sub: "usr_1".to_owned(),
            jti: "jti_expired".to_owned(),
            device_session_id: "ud_1".to_owned(),
            role: "user".to_owned(),
            iat: now - 2_000,
            exp: now - 1_000,
        };

        let token = jsonwebtoken::encode(
            &Header::new(Algorithm::HS256),
            &expired_claims,
            &EncodingKey::from_secret(b"test-secret"),
        )
        .expect("expired token should still encode");

        let err =
            verify_access_token("test-secret", &token).expect_err("expired token must be rejected");
        assert_eq!(err.code, ErrorCode::Unauthorized);
    }
}

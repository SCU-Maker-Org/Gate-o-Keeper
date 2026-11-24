use super::{CachedOidc, OidcDiscovery, OIDC_CACHE_TTL, OIDC_LEEWAY_SEC};
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use std::time::Instant;

const BACKCHANNEL_LOGOUT_EVENT: &str = "http://schemas.openid.net/event/backchannel-logout";

#[derive(Clone, Debug)]
pub struct OidcUserProfile {
    pub sub: String,
    pub display_name: String,
    pub sid: Option<String>,
    pub groups: Vec<String>,
    pub is_active: Option<bool>,
    pub refresh_token: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackChannelLogoutClaims {
    pub sub: Option<String>,
    pub sid: Option<String>,
    pub jti: String,
    pub exp: i64,
}

#[derive(Debug, Deserialize)]
pub(super) struct TokenEndpointResponse {
    #[serde(default)]
    pub(super) access_token: Option<String>,
    #[serde(default)]
    pub(super) id_token: Option<String>,
    #[serde(default)]
    pub(super) refresh_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct IdTokenClaims {
    sub: String,
    #[serde(default)]
    sid: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    preferred_username: Option<String>,
    #[serde(default)]
    groups: Option<Vec<String>>,
    #[serde(default)]
    is_active: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct UserInfoClaims {
    #[serde(default)]
    sub: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    preferred_username: Option<String>,
    #[serde(default)]
    groups: Option<Vec<String>>,
    #[serde(default)]
    is_active: Option<bool>,
}

/// Exchanges an Authentik authorization code for an ID token and returns the
/// identity and group information needed to upsert the local user.
pub async fn verify_authentik_code_and_get_profile(
    state: &AppState,
    code: &str,
    code_verifier: &str,
    redirect_uri: &str,
) -> AppResult<OidcUserProfile> {
    let cached = fetch_oidc_cached(state, false).await?;
    let discovery = &cached.discovery;

    let form = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("code_verifier", code_verifier),
        ("redirect_uri", redirect_uri),
        ("client_id", state.config.authentik_client_id.as_str()),
        (
            "client_secret",
            state.config.authentik_client_secret.as_str(),
        ),
    ];

    let response = state
        .http
        .post(&discovery.token_endpoint)
        .form(&form)
        .send()
        .await
        .map_err(|err| {
            tracing::error!(error = %err, "OIDC token endpoint request failed");
            AppError::internal("failed to exchange authorization code")
        })?;

    if !response.status().is_success() {
        tracing::warn!(
            status = %response.status(),
            "OIDC token endpoint rejected the code exchange"
        );
        return Err(AppError::unauthorized("authorization code exchange failed"));
    }

    let token_response: TokenEndpointResponse = response.json().await.map_err(|err| {
        tracing::error!(error = %err, "failed to parse OIDC token response");
        AppError::internal("invalid OIDC token response")
    })?;

    extract_profile_from_token_response(state, discovery, token_response, None).await
}

pub(super) async fn extract_profile_from_token_response(
    state: &AppState,
    discovery: &OidcDiscovery,
    token_response: TokenEndpointResponse,
    expected_sub: Option<&str>,
) -> AppResult<OidcUserProfile> {
    let TokenEndpointResponse {
        access_token,
        id_token,
        refresh_token,
    } = token_response;

    let (mut sub, sid, mut display_name, mut groups, mut is_active, needs_userinfo) =
        match id_token.as_deref() {
            Some(raw_id_token) => {
                let claims: IdTokenClaims = verify_oidc_token(
                    state,
                    discovery,
                    raw_id_token,
                    &["exp", "iss", "aud", "sub"],
                )
                .await?;
                if let Some(exp_sub) = expected_sub {
                    if claims.sub != exp_sub {
                        return Err(AppError::unauthorized("OIDC subject mismatch"));
                    }
                }
                let needs_ui = claims.groups.is_none();
                (
                    Some(claims.sub),
                    claims.sid,
                    claims.name.or(claims.preferred_username),
                    claims.groups.into_iter().flatten().collect::<Vec<String>>(),
                    claims.is_active,
                    needs_ui,
                )
            }
            None => {
                if expected_sub.is_none() {
                    return Err(AppError::unauthorized(
                        "OIDC token response missing id_token",
                    ));
                }
                (
                    expected_sub.map(ToOwned::to_owned),
                    None,
                    None,
                    Vec::new(),
                    None,
                    true,
                )
            }
        };

    if needs_userinfo {
        if let Some(userinfo_endpoint) = discovery.userinfo_endpoint.as_deref() {
            let access_token = access_token.as_deref().ok_or_else(|| {
                AppError::unauthorized("OIDC token response missing access_token")
            })?;

            let response = state
                .http
                .get(userinfo_endpoint)
                .bearer_auth(access_token)
                .send()
                .await
                .map_err(|err| {
                    tracing::error!(error = %err, "OIDC userinfo request failed");
                    AppError::internal("failed to fetch userinfo")
                })?;

            if !response.status().is_success() {
                tracing::warn!(
                    status = %response.status(),
                    "OIDC userinfo endpoint returned an error"
                );
                return Err(AppError::internal("failed to fetch userinfo"));
            }

            let userinfo: UserInfoClaims = response.json().await.map_err(|err| {
                tracing::error!(error = %err, "failed to parse OIDC userinfo response");
                AppError::internal("invalid OIDC userinfo response")
            })?;

            if let Some(userinfo_sub) = userinfo.sub.as_deref() {
                if let Some(cur_sub) = sub.as_deref() {
                    if userinfo_sub != cur_sub {
                        tracing::warn!("OIDC userinfo subject does not match id_token subject");
                        return Err(AppError::unauthorized("userinfo subject mismatch"));
                    }
                } else {
                    sub = Some(userinfo_sub.to_string());
                }
            }

            if let Some(userinfo_groups) = userinfo.groups {
                groups = userinfo_groups;
            }
            if is_active.is_none() {
                is_active = userinfo.is_active;
            }
            if display_name.is_none() {
                display_name = userinfo.name.or(userinfo.preferred_username);
            }
        }
    }

    let sub = sub.ok_or_else(|| AppError::unauthorized("missing OIDC subject"))?;
    let display_name = match display_name {
        Some(display_name) => display_name,
        None => sub.clone(),
    };

    Ok(OidcUserProfile {
        display_name,
        sub,
        sid,
        groups,
        is_active,
        refresh_token,
    })
}

pub enum OidcRefreshFailure {
    ClientRejected(reqwest::StatusCode),
    Other(AppError),
}

/// Exchanges an upstream Authentik `refresh_token` for an updated OIDC user profile.
pub async fn refresh_authentik_oidc_profile(
    state: &AppState,
    sso_refresh_token: &str,
    expected_sub: &str,
) -> Result<OidcUserProfile, OidcRefreshFailure> {
    let cached = fetch_oidc_cached(state, false)
        .await
        .map_err(OidcRefreshFailure::Other)?;
    let discovery = &cached.discovery;

    let form = [
        ("grant_type", "refresh_token"),
        ("refresh_token", sso_refresh_token),
        ("client_id", state.config.authentik_client_id.as_str()),
        (
            "client_secret",
            state.config.authentik_client_secret.as_str(),
        ),
    ];

    let response = state
        .http
        .post(&discovery.token_endpoint)
        .form(&form)
        .send()
        .await
        .map_err(|err| {
            OidcRefreshFailure::Other(AppError::internal(format!(
                "OIDC refresh request failed: {err}"
            )))
        })?;

    let status = response.status();
    if status.is_client_error() {
        return Err(OidcRefreshFailure::ClientRejected(status));
    }
    if !status.is_success() {
        return Err(OidcRefreshFailure::Other(AppError::internal(format!(
            "OIDC refresh endpoint returned status {status}"
        ))));
    }

    let token_response: TokenEndpointResponse = response.json().await.map_err(|err| {
        OidcRefreshFailure::Other(AppError::internal(format!(
            "invalid OIDC refresh response: {err}"
        )))
    })?;

    extract_profile_from_token_response(state, discovery, token_response, Some(expected_sub))
        .await
        .map_err(OidcRefreshFailure::Other)
}

/// Verifies an OIDC Back-Channel Logout token and validates its claims.
pub async fn verify_backchannel_logout_token(
    state: &AppState,
    logout_token: &str,
) -> AppResult<BackChannelLogoutClaims> {
    let cached = fetch_oidc_cached(state, false).await?;
    let claims: serde_json::Value = verify_oidc_token(
        state,
        &cached.discovery,
        logout_token,
        &["exp", "iat", "iss", "aud"],
    )
    .await?;
    validate_backchannel_logout_claims(&claims)
}

pub(super) async fn fetch_oidc_cached(
    state: &AppState,
    force_refresh: bool,
) -> AppResult<CachedOidc> {
    if !force_refresh {
        let guard = state.oidc_cache.inner.read().await;
        if let Some(ref cached) = *guard {
            if cached.fetched_at.elapsed() < OIDC_CACHE_TTL {
                return Ok(cached.clone());
            }
        }
    }

    let discovery = fetch_discovery(state).await?;
    let jwks = fetch_jwks(state, &discovery.jwks_uri).await?;
    let cached = CachedOidc {
        discovery,
        jwks,
        fetched_at: Instant::now(),
    };

    let mut guard = state.oidc_cache.inner.write().await;
    *guard = Some(cached.clone());
    Ok(cached)
}

async fn fetch_discovery(state: &AppState) -> AppResult<OidcDiscovery> {
    let url = match state.config.authentik_discovery_url.as_deref() {
        Some(url) => url.to_owned(),
        None => format!(
            "{}/.well-known/openid-configuration",
            state.config.authentik_issuer.trim_end_matches('/')
        ),
    };
    validate_oidc_url_scheme(state, &url)?;

    let response = state.http.get(&url).send().await.map_err(|err| {
        tracing::error!(error = %err, "failed to fetch OIDC discovery document");
        AppError::internal("failed to fetch OIDC discovery document")
    })?;

    if !response.status().is_success() {
        tracing::error!(
            status = %response.status(),
            "OIDC discovery endpoint returned an error"
        );
        return Err(AppError::internal("OIDC discovery failed"));
    }

    let mut discovery = response.json::<OidcDiscovery>().await.map_err(|err| {
        tracing::error!(error = %err, "failed to parse OIDC discovery document");
        AppError::internal("invalid OIDC discovery document")
    })?;

    if !state.config.authentik_issuer.is_empty() {
        let internal_issuer =
            state
                .config
                .authentik_discovery_url
                .as_deref()
                .and_then(|internal_url| {
                    let pub_origin = url_origin(&state.config.authentik_issuer)?;
                    let int_origin = url_origin(internal_url)?;
                    state
                        .config
                        .authentik_issuer
                        .strip_prefix(pub_origin)
                        .map(|rest| format!("{int_origin}{rest}"))
                });

        let issuer_matches = discovery.issuer == state.config.authentik_issuer
            || internal_issuer
                .as_deref()
                .is_some_and(|int_iss| discovery.issuer == int_iss);

        if !issuer_matches {
            tracing::error!(
                discovered = %discovery.issuer,
                expected = %state.config.authentik_issuer,
                "OIDC discovery issuer mismatch"
            );
            return Err(AppError::internal("OIDC discovery issuer mismatch"));
        }
    }

    // Rewrite public origin to internal discovery origin for backend-to-backend requests.
    if let Some(internal_url) = state.config.authentik_discovery_url.as_deref() {
        if let (Some(pub_origin), Some(int_origin)) = (
            url_origin(&state.config.authentik_issuer),
            url_origin(internal_url),
        ) {
            if pub_origin != int_origin {
                let rewrite = |u: &mut String| {
                    if let Some(rest) = u.strip_prefix(pub_origin) {
                        *u = format!("{int_origin}{rest}");
                    }
                };
                rewrite(&mut discovery.token_endpoint);
                rewrite(&mut discovery.jwks_uri);
                if let Some(ref mut ui) = discovery.userinfo_endpoint {
                    rewrite(ui);
                }
            }
        }
    }

    validate_oidc_endpoint(state, &discovery.token_endpoint)?;
    validate_oidc_endpoint(state, &discovery.jwks_uri)?;
    if let Some(ref ui) = discovery.userinfo_endpoint {
        validate_oidc_endpoint(state, ui)?;
    }

    Ok(discovery)
}

fn validate_oidc_url_scheme(state: &AppState, url: &str) -> AppResult<()> {
    if url.starts_with("https://") {
        return Ok(());
    }
    if state.config.allow_insecure_oidc_http && url.starts_with("http://") {
        return Ok(());
    }
    Err(AppError::internal("OIDC endpoint must use HTTPS"))
}

fn validate_oidc_endpoint(state: &AppState, url: &str) -> AppResult<()> {
    validate_oidc_url_scheme(state, url)?;
    let origin = url_origin(url).ok_or_else(|| AppError::internal("invalid OIDC endpoint URL"))?;
    let issuer_origin = url_origin(&state.config.authentik_issuer);
    let discovery_origin = state
        .config
        .authentik_discovery_url
        .as_deref()
        .and_then(url_origin);

    if Some(origin) != issuer_origin && Some(origin) != discovery_origin {
        tracing::error!(endpoint = %url, "OIDC discovery endpoint origin mismatch");
        return Err(AppError::internal("OIDC endpoint origin mismatch"));
    }
    Ok(())
}

fn url_origin(url: &str) -> Option<&str> {
    let scheme_end = url.find("://")? + 3;
    let rest = &url[scheme_end..];
    match rest.find('/') {
        Some(idx) => Some(&url[..scheme_end + idx]),
        None => Some(url),
    }
}

async fn fetch_jwks(state: &AppState, jwks_uri: &str) -> AppResult<JwkSet> {
    let response = state.http.get(jwks_uri).send().await.map_err(|err| {
        tracing::error!(error = %err, "failed to fetch OIDC JWKS");
        AppError::internal("failed to fetch OIDC JWKS")
    })?;

    if !response.status().is_success() {
        tracing::error!(
            status = %response.status(),
            "OIDC JWKS endpoint returned an error"
        );
        return Err(AppError::internal("failed to fetch OIDC JWKS"));
    }

    response.json::<JwkSet>().await.map_err(|err| {
        tracing::error!(error = %err, "failed to parse OIDC JWKS");
        AppError::internal("invalid OIDC JWKS")
    })
}

async fn verify_oidc_token<T: DeserializeOwned>(
    state: &AppState,
    discovery: &OidcDiscovery,
    token: &str,
    required_claims: &[&str],
) -> AppResult<T> {
    let header = jsonwebtoken::decode_header(token).map_err(|err| {
        tracing::warn!(error = %err, "failed to decode OIDC token header");
        AppError::unauthorized("invalid token header")
    })?;

    let alg = asymmetric_algorithm(header.alg)?;
    let kid = header
        .kid
        .as_deref()
        .ok_or_else(|| AppError::unauthorized("token missing key id"))?;

    let mut cached = fetch_oidc_cached(state, false).await?;
    let jwk = match cached.jwks.find(kid) {
        Some(jwk) => jwk,
        None => {
            cached = fetch_oidc_cached(state, true).await?;
            cached
                .jwks
                .find(kid)
                .ok_or_else(|| AppError::unauthorized("unknown signing key"))?
        }
    };

    let key = DecodingKey::from_jwk(jwk).map_err(|err| {
        tracing::warn!(error = %err, "failed to build OIDC decoding key");
        AppError::unauthorized("invalid signing key")
    })?;

    let mut validation = Validation::new(alg);
    if state.config.authentik_issuer == discovery.issuer {
        validation.set_issuer(&[discovery.issuer.as_str()]);
    } else {
        validation.set_issuer(&[
            state.config.authentik_issuer.as_str(),
            discovery.issuer.as_str(),
        ]);
    }
    validation.set_audience(&[state.config.authentik_client_id.as_str()]);
    validation.validate_exp = true;
    validation.leeway = OIDC_LEEWAY_SEC;
    validation.set_required_spec_claims(required_claims);

    jsonwebtoken::decode::<T>(token, &key, &validation)
        .map(|data| data.claims)
        .map_err(|err| {
            tracing::warn!(error = %err, "OIDC token verification failed");
            AppError::unauthorized("invalid token")
        })
}

fn asymmetric_algorithm(alg: Algorithm) -> AppResult<Algorithm> {
    match alg {
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::ES256
        | Algorithm::ES384
        | Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::PS512 => Ok(alg),
        _ => Err(AppError::unauthorized("unsupported token algorithm")),
    }
}

fn validate_backchannel_logout_claims(
    claims: &serde_json::Value,
) -> AppResult<BackChannelLogoutClaims> {
    if claims.get("nonce").is_some() {
        return Err(AppError::invalid("logout token must not contain nonce"));
    }

    let events = claims
        .get("events")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| AppError::invalid("logout token missing events"))?;

    if !events.contains_key(BACKCHANNEL_LOGOUT_EVENT) {
        return Err(AppError::invalid(
            "logout token missing backchannel-logout event",
        ));
    }

    let sub = claims
        .get("sub")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);

    let jti = claims
        .get("jti")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::invalid("logout token missing jti"))?
        .to_owned();

    let sid = claims
        .get("sid")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);

    if sub.is_none() && sid.is_none() {
        return Err(AppError::invalid(
            "logout token must contain at least sub or sid",
        ));
    }

    let exp = claims
        .get("exp")
        .and_then(serde_json::Value::as_i64)
        .ok_or_else(|| AppError::invalid("logout token missing exp"))?;

    Ok(BackChannelLogoutClaims { sub, sid, jti, exp })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorCode;

    #[test]
    fn backchannel_logout_accepts_valid_claims() {
        let claims = serde_json::json!({
            "sub": "user-1",
            "sid": "session-1",
            "jti": "logout-1",
            "exp": 2_000_000_000i64,
            "events": {
                "http://schemas.openid.net/event/backchannel-logout": {}
            }
        });

        let parsed = validate_backchannel_logout_claims(&claims)
            .expect("valid logout claims should be accepted");

        assert_eq!(parsed.sub.as_deref(), Some("user-1"));
        assert_eq!(parsed.sid.as_deref(), Some("session-1"));
        assert_eq!(parsed.jti, "logout-1");
        assert_eq!(parsed.exp, 2_000_000_000);
    }

    #[test]
    fn backchannel_logout_accepts_sid_without_sub() {
        let claims = serde_json::json!({
            "sid": "session-only",
            "jti": "logout-sid",
            "exp": 2_000_000_000i64,
            "events": {
                "http://schemas.openid.net/event/backchannel-logout": {}
            }
        });

        let parsed = validate_backchannel_logout_claims(&claims)
            .expect("sid-only logout claims should be accepted");
        assert!(parsed.sub.is_none());
        assert_eq!(parsed.sid.as_deref(), Some("session-only"));
    }

    #[test]
    fn backchannel_logout_rejects_missing_sub_and_sid() {
        let claims = serde_json::json!({
            "jti": "logout-1",
            "exp": 2_000_000_000i64,
            "events": {
                "http://schemas.openid.net/event/backchannel-logout": {}
            }
        });

        let err = validate_backchannel_logout_claims(&claims)
            .expect_err("missing both sub and sid must be rejected");
        assert_eq!(err.code, ErrorCode::InvalidArgument);
    }

    #[test]
    fn backchannel_logout_rejects_missing_exp() {
        let claims = serde_json::json!({
            "sub": "user-1",
            "jti": "logout-1",
            "events": {
                "http://schemas.openid.net/event/backchannel-logout": {}
            }
        });

        let err =
            validate_backchannel_logout_claims(&claims).expect_err("missing exp must be rejected");
        assert_eq!(err.code, ErrorCode::InvalidArgument);
    }

    #[test]
    fn backchannel_logout_rejects_nonce() {
        let claims = serde_json::json!({
            "sub": "user-1",
            "jti": "logout-1",
            "exp": 2_000_000_000i64,
            "nonce": "must-not-be-here",
            "events": {
                "http://schemas.openid.net/event/backchannel-logout": {}
            }
        });

        let err = validate_backchannel_logout_claims(&claims).expect_err("nonce must be rejected");
        assert_eq!(err.code, ErrorCode::InvalidArgument);
    }

    #[test]
    fn backchannel_logout_requires_events_key() {
        let missing_events = serde_json::json!({
            "sub": "user-1",
            "jti": "logout-1",
            "exp": 2_000_000_000i64
        });

        let err = validate_backchannel_logout_claims(&missing_events)
            .expect_err("missing events must be rejected");
        assert_eq!(err.code, ErrorCode::InvalidArgument);

        let wrong_event = serde_json::json!({
            "sub": "user-1",
            "jti": "logout-1",
            "exp": 2_000_000_000i64,
            "events": {}
        });

        let err = validate_backchannel_logout_claims(&wrong_event)
            .expect_err("missing backchannel-logout event must be rejected");
        assert_eq!(err.code, ErrorCode::InvalidArgument);
    }

    #[test]
    fn backchannel_logout_requires_jti() {
        let claims = serde_json::json!({
            "sub": "user-1",
            "exp": 2_000_000_000i64,
            "events": {
                "http://schemas.openid.net/event/backchannel-logout": {}
            }
        });

        let err =
            validate_backchannel_logout_claims(&claims).expect_err("missing jti must be rejected");
        assert_eq!(err.code, ErrorCode::InvalidArgument);
    }
}

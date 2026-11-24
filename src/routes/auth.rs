use crate::auth::{authenticate_request, REFRESH_TOKEN_TTL_SEC};
use crate::error::{ApiEnvelope, AppError, AppResult};
use crate::routes::{extract_request_id, ClientIp};
use crate::services::auth::{
    self as auth_svc, AuthSessionTokens, AuthentikWebhookInput, BackchannelLogoutOutcome,
    SsoExchangeInput,
};
use crate::state::AppState;
use crate::utils::constant_time_eq;
use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use axum_extra::extract::cookie::{Cookie, SameSite};
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use time::Duration as CookieDuration;

const REFRESH_COOKIE_NAME: &str = "user_refresh_token";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SsoExchangeRequest {
    pub code: String,
    pub code_verifier: String,
    pub redirect_uri: String,
    pub device_id: String,
    #[serde(default)]
    pub device_name: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthTokenResponse {
    pub access_token: String,
    pub expires_in: i64,
    pub device_session_id: String,
}

fn build_refresh_cookie(token: String, secure: bool, max_age_secs: i64) -> Cookie<'static> {
    Cookie::build((REFRESH_COOKIE_NAME, token))
        .http_only(true)
        .secure(secure)
        .same_site(SameSite::Strict)
        .path("/api/auth")
        .max_age(CookieDuration::seconds(max_age_secs))
        .build()
}

fn attach_no_store(mut resp: Response) -> Response {
    let headers = resp.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    resp
}

fn token_response(tokens: AuthSessionTokens, cookie_secure: bool, req_id: String) -> Response {
    let cookie = build_refresh_cookie(tokens.raw_refresh_token, cookie_secure, REFRESH_TOKEN_TTL_SEC);
    let jar = CookieJar::new().add(cookie);

    attach_no_store(
        (
            jar,
            ApiEnvelope::ok(
                AuthTokenResponse {
                    access_token: tokens.access_token,
                    expires_in: tokens.expires_in,
                    device_session_id: tokens.device_session_id,
                },
                req_id,
            ),
        )
            .into_response(),
    )
}

pub async fn sso_exchange(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Json(body): Json<SsoExchangeRequest>,
) -> AppResult<Response> {
    let req_id = extract_request_id(&headers);
    let tokens = auth_svc::sso_exchange(
        &state,
        &ip,
        &req_id,
        SsoExchangeInput {
            code: &body.code,
            code_verifier: &body.code_verifier,
            redirect_uri: &body.redirect_uri,
            device_id: &body.device_id,
            device_name: &body.device_name,
        },
    )
    .await?;

    Ok(token_response(tokens, state.config.cookie_secure, req_id))
}

pub async fn refresh(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    jar: CookieJar,
) -> AppResult<Response> {
    let req_id = extract_request_id(&headers);

    let has_custom_header = headers
        .get("x-requested-with")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| !v.trim().is_empty());
    let fetch_site_ok = headers
        .get("sec-fetch-site")
        .and_then(|v| v.to_str().ok())
        .is_none_or(|v| v == "same-origin" || v == "none");
    if !has_custom_header || !fetch_site_ok {
        return Err(
            AppError::forbidden("missing CSRF header or cross-site refresh rejected")
                .with_request_id(&req_id),
        );
    }

    let raw_refresh = jar
        .get(REFRESH_COOKIE_NAME)
        .map(|c| c.value().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::unauthorized("missing refresh cookie").with_request_id(&req_id))?;

    let tokens = auth_svc::refresh_session(&state, &ip, &req_id, &raw_refresh).await?;
    Ok(token_response(tokens, state.config.cookie_secure, req_id))
}

pub async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Response> {
    let req_id = extract_request_id(&headers);
    let auth = authenticate_request(&state, &headers)
        .await
        .map_err(|e| e.with_request_id(&req_id))?;

    auth_svc::logout_session(&state, &auth.device_session_id, &req_id).await?;

    let clear_cookie = build_refresh_cookie(String::new(), state.config.cookie_secure, 0);
    let jar = CookieJar::new().add(clear_cookie);

    Ok((
        jar,
        ApiEnvelope::ok(serde_json::json!({ "loggedOut": true }), req_id),
    )
        .into_response())
}

#[derive(Deserialize)]
pub struct BackChannelLogoutForm {
    pub logout_token: String,
}

fn is_ip_allowed(allowed_ips: &[IpAddr], ip: &str) -> bool {
    if allowed_ips.is_empty() {
        return true;
    }
    ip.parse::<IpAddr>()
        .ok()
        .is_some_and(|addr| allowed_ips.contains(&addr))
}

pub async fn backchannel_logout(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    axum::Form(form): axum::Form<BackChannelLogoutForm>,
) -> Response {
    let req_id = extract_request_id(&headers);
    if !is_ip_allowed(&state.config.backchannel_logout_allowed_ips, &ip) {
        return StatusCode::FORBIDDEN.into_response();
    }

    match auth_svc::process_backchannel_logout(&state, &ip, &req_id, &form.logout_token).await {
        BackchannelLogoutOutcome::Ok => attach_no_store(StatusCode::OK.into_response()),
        BackchannelLogoutOutcome::BadRequest => StatusCode::BAD_REQUEST.into_response(),
        BackchannelLogoutOutcome::TooManyRequests => StatusCode::TOO_MANY_REQUESTS.into_response(),
        BackchannelLogoutOutcome::InternalError => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthentikWebhookPayload {
    #[serde(default)]
    pub action: String,
    #[serde(default, alias = "model_name")]
    pub model_name: String,
    #[serde(default)]
    pub pk: Option<serde_json::Value>,
    #[serde(default)]
    pub uid: Option<String>,
    #[serde(default, alias = "is_active")]
    pub is_active: Option<bool>,
    #[serde(default)]
    pub changes: Option<serde_json::Value>,
}

fn verify_webhook_secret(headers: &HeaderMap, expected: &str) -> bool {
    let candidate = headers
        .get("x-authentik-webhook-secret")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .or_else(|| {
            headers
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.strip_prefix("Bearer "))
                .map(str::trim)
        });
    let Some(got) = candidate else {
        return false;
    };
    constant_time_eq(got, expected)
}

pub async fn authentik_webhook(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Json(body): Json<AuthentikWebhookPayload>,
) -> AppResult<Json<ApiEnvelope<serde_json::Value>>> {
    let req_id = extract_request_id(&headers);

    if !verify_webhook_secret(&headers, &state.config.authentik_webhook_secret) {
        return Err(AppError::unauthorized("invalid webhook secret").with_request_id(&req_id));
    }

    if !is_ip_allowed(&state.config.backchannel_logout_allowed_ips, &ip) {
        return Err(AppError::forbidden("webhook IP not allowed").with_request_id(&req_id));
    }

    let synced = auth_svc::process_authentik_webhook(
        &state,
        &ip,
        &req_id,
        AuthentikWebhookInput {
            action: body.action,
            model_name: body.model_name,
            pk: body.pk,
            uid: body.uid,
            is_active: body.is_active,
            changes: body.changes,
        },
    )
    .await?;

    Ok(ApiEnvelope::ok(
        serde_json::json!({
            "handled": true,
            "syncedUsers": synced,
        }),
        req_id,
    ))
}

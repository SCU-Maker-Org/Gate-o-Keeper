use crate::auth::{constant_time_eq, hash_token, verify_adapter_registration_cert};
use crate::db::AdapterRow;
use crate::error::{ApiEnvelope, AppError, AppResult, ErrorCode};
use crate::routes::{extract_request_id, is_valid_identifier, ClientIp};
use crate::state::AppState;
use axum::extract::State;
use axum::http::{header, HeaderMap};
use axum::Json;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterAdapterRequest {
    pub adapter_id: String,
    pub token: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub fw_version: String,
    pub cert_pem: String,
    pub ts: i64,
    pub signature: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterAdapterResponse {
    pub adapter_id: String,
    pub approval_status: String,
}

async fn handle_existing_adapter_register(
    state: &AppState,
    existing: &AdapterRow,
    token_hash: &str,
    body: &RegisterAdapterRequest,
    now: i64,
    req_id: &str,
) -> AppResult<Json<ApiEnvelope<RegisterAdapterResponse>>> {
    let display_name = if body.name.trim().is_empty() {
        existing.id.as_str()
    } else {
        body.name.trim()
    };
    let model = body.model.trim();
    let fw_version = body.fw_version.trim();
    match existing.approval_status.as_str() {
        "revoked" => Err(
            AppError::new(ErrorCode::DeviceRevoked, "adapter has been revoked")
                .with_request_id(req_id),
        ),
        "rejected" => Err(AppError::new(
            ErrorCode::DeviceRevoked,
            "adapter registration was rejected; reset required",
        )
        .with_request_id(req_id)),
        "approved" => {
            let matches = constant_time_eq(&existing.token_hash, token_hash)
                || existing
                    .pending_token_hash
                    .as_deref()
                    .is_some_and(|p| constant_time_eq(p, token_hash));
            if matches {
                return Ok(ApiEnvelope::ok(
                    RegisterAdapterResponse {
                        adapter_id: existing.id.clone(),
                        approval_status: existing.approval_status.clone(),
                    },
                    req_id.to_owned(),
                ));
            }
            Err(AppError::new(
                ErrorCode::DeviceAlreadyRegistered,
                "adapter already approved with another credential",
            )
            .with_request_id(req_id))
        }
        _ if existing.token_hash.is_empty() => {
            let update_res = sqlx::query(
                "UPDATE adapters
                 SET name = ?, model = ?, fw_version = ?, token_hash = ?, updated_at = ?
                 WHERE id = ? AND approval_status = 'pending' AND token_hash = ''",
            )
            .bind(display_name)
            .bind(model)
            .bind(fw_version)
            .bind(token_hash)
            .bind(now)
            .bind(&existing.id)
            .execute(&state.db.pool)
            .await;

            match update_res {
                Ok(r) if r.rows_affected() > 0 => Ok(ApiEnvelope::ok(
                    RegisterAdapterResponse {
                        adapter_id: existing.id.clone(),
                        approval_status: "pending".to_string(),
                    },
                    req_id.to_owned(),
                )),
                Ok(_) => Err(AppError::new(
                    ErrorCode::DeviceAlreadyRegistered,
                    "adapter state changed during registration",
                )
                .with_request_id(req_id)),
                Err(sqlx::Error::Database(ref db_err)) if db_err.is_unique_violation() => {
                    Err(AppError::new(
                        ErrorCode::DeviceAlreadyRegistered,
                        "adapter credential already in use",
                    )
                    .with_request_id(req_id))
                }
                Err(err) => Err(AppError::from(err).with_request_id(req_id)),
            }
        }
        _ if constant_time_eq(&existing.token_hash, token_hash) => Ok(ApiEnvelope::ok(
            RegisterAdapterResponse {
                adapter_id: existing.id.clone(),
                approval_status: existing.approval_status.clone(),
            },
            req_id.to_owned(),
        )),
        _ => Err(AppError::new(
            ErrorCode::DeviceAlreadyRegistered,
            "adapter already pending with another credential",
        )
        .with_request_id(req_id)),
    }
}

pub async fn register(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Json(body): Json<RegisterAdapterRequest>,
) -> AppResult<Json<ApiEnvelope<RegisterAdapterResponse>>> {
    let req_id = extract_request_id(&headers);
    let adapter_id = body.adapter_id.trim();

    if !is_valid_identifier(adapter_id, 1, 64) || adapter_id == state.config.mqtt_client_id {
        return Err(
            AppError::invalid("adapterId must match [A-Za-z0-9_-]{1,64} and not be reserved")
                .with_request_id(&req_id),
        );
    }

    let distinct_bytes = body.token.as_bytes().iter().collect::<HashSet<_>>().len();
    if body.token.len() < 32
        || body.token.trim() != body.token
        || distinct_bytes < 8
        || body.name.trim().len() > 128
        || body.model.trim().len() > 128
        || body.fw_version.trim().len() > 128
    {
        return Err(AppError::invalid(
            "token must be >= 32 non-trivial chars and name/model/fwVersion <= 128 chars",
        )
        .with_request_id(&req_id));
    }

    let cfg = state.db.get_system_config().await?;
    if !state
        .redis
        .check_rate_limit(
            &format!("adapter:reg:ip:{ip}"),
            cfg.rate_limits.adapter_register_ip.max,
            cfg.rate_limits.adapter_register_ip.window_sec,
        )
        .await?
    {
        return Err(
            AppError::new(ErrorCode::RateLimited, "rate limit exceeded").with_request_id(&req_id)
        );
    }

    let token_hash = hash_token(&body.token);
    let now = chrono::Utc::now().timestamp();

    verify_adapter_registration_cert(
        &state.config.mqtt_ca_cert,
        adapter_id,
        &token_hash,
        &body.cert_pem,
        body.ts,
        &body.signature,
        now,
    )
    .map_err(|e| e.with_request_id(&req_id))?;

    if !state
        .redis
        .check_rate_limit(
            &format!("adapter:reg:id:{adapter_id}"),
            cfg.rate_limits.adapter_register_id.max,
            cfg.rate_limits.adapter_register_id.window_sec,
        )
        .await?
    {
        return Err(
            AppError::new(ErrorCode::RateLimited, "rate limit exceeded").with_request_id(&req_id)
        );
    }

    if let Some(existing) = state.db.find_adapter_by_id(adapter_id).await? {
        return handle_existing_adapter_register(&state, &existing, &token_hash, &body, now, &req_id)
            .await;
    }

    let display_name = if body.name.trim().is_empty() {
        adapter_id
    } else {
        body.name.trim()
    };

    let insert_res = sqlx::query(
        "INSERT INTO adapters (id, name, approval_status, online_status, reported_state, model, fw_version, token_hash, token_refresh_interval, created_at, updated_at)
         VALUES (?, ?, 'pending', 'offline', 'unknown', ?, ?, ?, 43200, ?, ?)",
    )
    .bind(adapter_id)
    .bind(display_name)
    .bind(body.model.trim())
    .bind(body.fw_version.trim())
    .bind(&token_hash)
    .bind(now)
    .bind(now)
    .execute(&state.db.pool)
    .await;

    if let Err(err) = insert_res {
        if let sqlx::Error::Database(ref db_err) = err {
            if db_err.is_unique_violation() {
                return Err(AppError::new(
                    ErrorCode::DeviceAlreadyRegistered,
                    "adapter already registered",
                )
                .with_request_id(&req_id));
            }
        }
        return Err(AppError::from(err).with_request_id(&req_id));
    }

    Ok(ApiEnvelope::ok(
        RegisterAdapterResponse {
            adapter_id: adapter_id.to_string(),
            approval_status: "pending".to_string(),
        },
        req_id,
    ))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdapterStatusResponse {
    pub adapter_id: String,
    pub approval_status: String,
    pub mqtt_endpoint: String,
    pub state_report_period_sec: i64,
}

pub async fn status(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
) -> AppResult<Json<ApiEnvelope<AdapterStatusResponse>>> {
    let req_id = extract_request_id(&headers);
    let cfg = state.db.get_system_config().await?;
    if !state
        .redis
        .check_rate_limit(
            &format!("adapter:status:ip:{ip}"),
            cfg.rate_limits.adapter_status_ip.max,
            cfg.rate_limits.adapter_status_ip.window_sec,
        )
        .await?
    {
        return Err(
            AppError::new(ErrorCode::RateLimited, "rate limit exceeded").with_request_id(&req_id)
        );
    }

    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|raw| {
            let mut parts = raw.split_whitespace();
            let scheme = parts.next()?;
            let token = parts.next()?;
            if scheme.eq_ignore_ascii_case("bearer") && !token.is_empty() && parts.next().is_none()
            {
                Some(token)
            } else {
                None
            }
        })
        .ok_or_else(|| {
            AppError::unauthorized("missing adapter bearer token").with_request_id(&req_id)
        })?;

    let token_hash = hash_token(bearer);
    let adapter: Option<crate::db::AdapterRow> = sqlx::query_as(
        "SELECT * FROM adapters WHERE token_hash = ? OR pending_token_hash = ? LIMIT 1",
    )
    .bind(&token_hash)
    .bind(&token_hash)
    .fetch_optional(&state.db.pool)
    .await?;

    let adapter = adapter
        .ok_or_else(|| AppError::unauthorized("invalid adapter token").with_request_id(&req_id))?;

    if !state
        .redis
        .check_rate_limit(
            &format!("adapter:status:{}", adapter.id),
            cfg.rate_limits.adapter_status_id.max,
            cfg.rate_limits.adapter_status_id.window_sec,
        )
        .await?
    {
        return Err(
            AppError::new(ErrorCode::RateLimited, "rate limit exceeded").with_request_id(&req_id)
        );
    }

    let endpoint = format!("mqtts://{}:{}", state.config.mqtt_host, state.config.mqtt_port);
    Ok(ApiEnvelope::ok(
        AdapterStatusResponse {
            adapter_id: adapter.id,
            approval_status: adapter.approval_status,
            mqtt_endpoint: endpoint,
            state_report_period_sec: cfg.state_report_period_sec,
        },
        req_id,
    ))
}

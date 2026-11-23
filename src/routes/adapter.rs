use crate::auth::hash_token;
use crate::error::{AppError, AppResult, ApiEnvelope, ErrorCode};
use crate::routes::{extract_request_id, is_valid_identifier, ClientIp};
use crate::state::AppState;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use serde::{Deserialize, Serialize};

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
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterAdapterResponse {
    pub adapter_id: String,
    pub approval_status: String,
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

    if body.token.len() < 32
        || body.name.trim().len() > 128
        || body.model.trim().len() > 128
        || body.fw_version.trim().len() > 128
    {
        return Err(
            AppError::invalid("token must be >= 32 chars and name/model/fwVersion <= 128 chars")
                .with_request_id(&req_id),
        );
    }

    let cfg = state.db.get_system_config().await?;
    if !state
        .redis
        .check_rate_limit(
            &format!("adapter:reg:id:{adapter_id}"),
            cfg.rate_limits.adapter_register_id.max,
            cfg.rate_limits.adapter_register_id.window_sec,
        )
        .await?
        || !state
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

    if let Some(existing) = state.db.find_adapter_by_id(adapter_id).await? {
        match existing.approval_status.as_str() {
            "revoked" => {
                return Err(
                    AppError::new(ErrorCode::DeviceRevoked, "adapter has been revoked")
                        .with_request_id(&req_id),
                );
            }
            "rejected" => {
                return Err(AppError::new(
                    ErrorCode::DeviceRevoked,
                    "adapter registration was rejected; reset required",
                )
                .with_request_id(&req_id));
            }
            "approved" => {
                if existing.token_hash == token_hash
                    || existing.pending_token_hash.as_deref() == Some(token_hash.as_str())
                {
                    return Ok(ApiEnvelope::ok(
                        RegisterAdapterResponse {
                            adapter_id: existing.id,
                            approval_status: existing.approval_status,
                        },
                        req_id,
                    ));
                }
                return Err(AppError::new(
                    ErrorCode::DeviceAlreadyRegistered,
                    "adapter already approved with another credential",
                )
                .with_request_id(&req_id));
            }
            // pending -> idempotent ONLY with matching credential to prevent TOFU hijack
            _ => {
                if existing.token_hash == token_hash {
                    return Ok(ApiEnvelope::ok(
                        RegisterAdapterResponse {
                            adapter_id: existing.id,
                            approval_status: existing.approval_status,
                        },
                        req_id,
                    ));
                }
                return Err(AppError::new(
                    ErrorCode::DeviceAlreadyRegistered,
                    "adapter already pending with another credential",
                )
                .with_request_id(&req_id));
            }
        }
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
}

pub async fn status(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<ApiEnvelope<AdapterStatusResponse>>> {
    let req_id = extract_request_id(&headers);
    let bearer = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::unauthorized("missing adapter bearer token").with_request_id(&req_id))?;

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

    let cfg = state.db.get_system_config().await?;
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
        },
        req_id,
    ))
}

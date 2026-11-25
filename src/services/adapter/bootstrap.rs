use super::{AdapterStatusResponse, RegisterAdapterInput, RegisterAdapterResponse};
use crate::auth::verify_adapter_registration_cert;
use crate::domain::ApprovalStatus;
use crate::error::{AppError, AppResult, ErrorCode};
use crate::infra::db::AdapterRow;
use crate::state::AppState;
use crate::utils::{constant_time_eq, hash_token, is_valid_identifier};
use std::collections::HashSet;

fn handle_existing_approved_or_claimed(
    existing: &AdapterRow,
    token_hash: &str,
) -> AppResult<Option<RegisterAdapterResponse>> {
    match existing.approval_status {
        ApprovalStatus::Revoked => Err(AppError::new(
            ErrorCode::DeviceRevoked,
            "adapter has been revoked",
        )),
        ApprovalStatus::Rejected => Err(AppError::new(
            ErrorCode::DeviceRevoked,
            "adapter registration was rejected; reset required",
        )),
        ApprovalStatus::Approved => {
            let matches = constant_time_eq(&existing.token_hash, token_hash)
                || existing
                    .pending_token_hash
                    .as_deref()
                    .is_some_and(|p| constant_time_eq(p, token_hash));
            if matches {
                Ok(Some(RegisterAdapterResponse {
                    adapter_id: existing.id.clone(),
                    approval_status: existing.approval_status,
                }))
            } else {
                Err(AppError::new(
                    ErrorCode::DeviceAlreadyRegistered,
                    "adapter already approved with another credential",
                ))
            }
        }
        ApprovalStatus::Pending if existing.token_hash.is_empty() => Ok(None),
        ApprovalStatus::Pending if constant_time_eq(&existing.token_hash, token_hash) => {
            Ok(Some(RegisterAdapterResponse {
                adapter_id: existing.id.clone(),
                approval_status: existing.approval_status,
            }))
        }
        ApprovalStatus::Pending => Err(AppError::new(
            ErrorCode::DeviceAlreadyRegistered,
            "adapter already pending with another credential",
        )),
    }
}

/// Validates mTLS client cert signature + rate limits and registers or re-claims an adapter.
pub async fn register_adapter(
    state: &AppState,
    ip: &str,
    _req_id: &str,
    input: RegisterAdapterInput<'_>,
) -> AppResult<RegisterAdapterResponse> {
    let adapter_id = input.adapter_id.trim();

    if !is_valid_identifier(adapter_id, 1, 64) || adapter_id == state.config.mqtt_client_id {
        return Err(AppError::invalid(
            "adapterId must match [A-Za-z0-9_-]{1,64} and not be reserved",
        ));
    }

    let distinct_bytes = input.token.as_bytes().iter().collect::<HashSet<_>>().len();
    if input.token.len() < 32
        || input.token.trim() != input.token
        || distinct_bytes < 8
        || input.name.trim().len() > 128
        || input.model.trim().len() > 128
        || input.fw_version.trim().len() > 128
    {
        return Err(AppError::invalid(
            "token must be >= 32 non-trivial chars and name/model/fwVersion <= 128 chars",
        ));
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
        return Err(AppError::new(ErrorCode::RateLimited, "rate limit exceeded"));
    }

    let token_hash = hash_token(input.token);
    let now = chrono::Utc::now().timestamp();

    verify_adapter_registration_cert(
        &state.config.mqtt_ca_cert,
        adapter_id,
        &token_hash,
        input.cert_pem,
        input.ts,
        input.signature,
        now,
    )?;

    if !state
        .redis
        .check_rate_limit(
            &format!("adapter:reg:id:{adapter_id}"),
            cfg.rate_limits.adapter_register_id.max,
            cfg.rate_limits.adapter_register_id.window_sec,
        )
        .await?
    {
        return Err(AppError::new(ErrorCode::RateLimited, "rate limit exceeded"));
    }

    let display_name = if input.name.trim().is_empty() {
        adapter_id
    } else {
        input.name.trim()
    };
    let model = input.model.trim();
    let fw_version = input.fw_version.trim();

    if let Some(existing) = state.db.find_adapter_by_id(adapter_id).await? {
        if let Some(resp) = handle_existing_approved_or_claimed(&existing, &token_hash)? {
            return Ok(resp);
        }
        state
            .db
            .claim_reset_pending_adapter(
                &existing.id,
                display_name,
                model,
                fw_version,
                &token_hash,
                now,
            )
            .await?;
        return Ok(RegisterAdapterResponse {
            adapter_id: existing.id,
            approval_status: ApprovalStatus::Pending,
        });
    }

    state
        .db
        .insert_pending_adapter(
            adapter_id,
            display_name,
            model,
            fw_version,
            &token_hash,
            now,
        )
        .await?;

    Ok(RegisterAdapterResponse {
        adapter_id: adapter_id.to_string(),
        approval_status: ApprovalStatus::Pending,
    })
}

/// Polls adapter approval status and broker config for a bearer device token.
pub async fn get_adapter_status(
    state: &AppState,
    ip: &str,
    _req_id: &str,
    bearer_token: &str,
) -> AppResult<AdapterStatusResponse> {
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
        return Err(AppError::new(ErrorCode::RateLimited, "rate limit exceeded"));
    }

    let token_hash = hash_token(bearer_token);
    let adapter = state
        .db
        .find_adapter_by_any_token_hash(&token_hash)
        .await?
        .ok_or_else(|| AppError::unauthorized("invalid adapter token"))?;

    if !state
        .redis
        .check_rate_limit(
            &format!("adapter:status:{}", adapter.id),
            cfg.rate_limits.adapter_status_id.max,
            cfg.rate_limits.adapter_status_id.window_sec,
        )
        .await?
    {
        return Err(AppError::new(ErrorCode::RateLimited, "rate limit exceeded"));
    }

    let endpoint = state
        .config
        .mqtt_public_endpoint
        .clone()
        .unwrap_or_else(|| {
            format!(
                "mqtts://{}:{}",
                state.config.mqtt_host, state.config.mqtt_port
            )
        });
    Ok(AdapterStatusResponse {
        adapter_id: adapter.id,
        approval_status: adapter.approval_status,
        mqtt_endpoint: endpoint,
        state_report_period_sec: cfg.state_report_period_sec,
    })
}

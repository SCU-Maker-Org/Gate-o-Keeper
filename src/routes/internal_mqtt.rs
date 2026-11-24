use crate::auth::{constant_time_eq, hash_token};
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct EmqxAuthRequest {
    pub clientid: String,
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub cert_cn: Option<String>,
}

#[derive(Serialize)]
pub struct EmqxAuthResponse {
    pub result: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_superuser: Option<bool>,
}

#[derive(Deserialize)]
pub struct EmqxAclRequest {
    pub clientid: String,
    pub username: String,
    pub topic: String,
    pub action: String,
}

#[derive(Serialize)]
pub struct EmqxAclResponse {
    pub result: &'static str,
}

fn check_internal_secret(state: &AppState, headers: &HeaderMap) -> AppResult<()> {
    let provided = headers
        .get("x-internal-secret")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let matched = constant_time_eq(provided, &state.config.internal_mqtt_secret);
    if !matched {
        return Err(AppError::unauthorized("invalid internal mqtt secret"));
    }
    Ok(())
}

fn cert_cn_matches_clientid(cert_cn: Option<&str>, clientid: &str) -> bool {
    match cert_cn.map(str::trim).filter(|s| !s.is_empty() && *s != "undefined") {
        Some(cn) => cn == clientid,
        None => false,
    }
}

pub async fn mqtt_auth(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<EmqxAuthRequest>,
) -> AppResult<Json<EmqxAuthResponse>> {
    check_internal_secret(&state, &headers)?;

    if !cert_cn_matches_clientid(body.cert_cn.as_deref(), &body.clientid) {
        tracing::warn!(
            clientid = %body.clientid,
            cert_cn = ?body.cert_cn,
            "mTLS certificate CN does not match MQTT clientid"
        );
        return Ok(Json(EmqxAuthResponse {
            result: "deny",
            is_superuser: None,
        }));
    }

    // Allow backend service account itself
    let backend_pw_ok = constant_time_eq(&body.password, &state.config.mqtt_password);
    if body.clientid == state.config.mqtt_client_id
        && body.username == state.config.mqtt_username
        && backend_pw_ok
    {
        return Ok(Json(EmqxAuthResponse {
            result: "allow",
            is_superuser: Some(true),
        }));
    }

    if body.clientid.is_empty() || body.clientid != body.username {
        return Ok(Json(EmqxAuthResponse {
            result: "deny",
            is_superuser: None,
        }));
    }

    let cfg = state.db.get_system_config().await?;
    if !state
        .redis
        .check_rate_limit(
            &format!("mqtt:conn:{}", body.clientid),
            cfg.rate_limits.mqtt_conn_client.max,
            cfg.rate_limits.mqtt_conn_client.window_sec,
        )
        .await?
    {
        return Ok(Json(EmqxAuthResponse {
            result: "deny",
            is_superuser: None,
        }));
    }

    let Some(adapter) = state.db.find_adapter_by_id(&body.clientid).await? else {
        return Ok(Json(EmqxAuthResponse {
            result: "deny",
            is_superuser: None,
        }));
    };

    if adapter.approval_status != "approved" {
        return Ok(Json(EmqxAuthResponse {
            result: "deny",
            is_superuser: None,
        }));
    }

    let incoming_hash = hash_token(&body.password);
    if constant_time_eq(&adapter.token_hash, &incoming_hash) {
        return Ok(Json(EmqxAuthResponse {
            result: "allow",
            is_superuser: Some(false),
        }));
    }

    let pending_ok = adapter
        .pending_token_hash
        .as_deref()
        .is_some_and(|pending| constant_time_eq(pending, &incoming_hash));
    if pending_ok {
        // Atomically promote rotated token on reconnect
        let now = chrono::Utc::now().timestamp();
        let res = sqlx::query(
            "UPDATE adapters
             SET token_hash = ?, pending_token_hash = NULL, pending_token_msg_id = NULL,
                 pending_token_at = NULL, token_rotated_at = ?, updated_at = ?
             WHERE id = ? AND pending_token_hash = ? AND approval_status = 'approved'",
        )
        .bind(&incoming_hash)
        .bind(now)
        .bind(now)
        .bind(&adapter.id)
        .bind(&incoming_hash)
        .execute(&state.db.pool)
        .await?;

        if res.rows_affected() > 0 {
            return Ok(Json(EmqxAuthResponse {
                result: "allow",
                is_superuser: Some(false),
            }));
        }
    }

    Ok(Json(EmqxAuthResponse {
        result: "deny",
        is_superuser: None,
    }))
}

pub async fn mqtt_acl(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<EmqxAclRequest>,
) -> AppResult<Json<EmqxAclResponse>> {
    check_internal_secret(&state, &headers)?;

    if body.clientid == state.config.mqtt_client_id && body.username == state.config.mqtt_username
    {
        return Ok(Json(EmqxAclResponse { result: "allow" }));
    }

    if body.clientid.is_empty() || body.clientid != body.username {
        return Ok(Json(EmqxAclResponse { result: "deny" }));
    }

    let Some(adapter) = state.db.find_adapter_by_id(&body.clientid).await? else {
        return Ok(Json(EmqxAclResponse { result: "deny" }));
    };

    if adapter.approval_status != "approved" {
        return Ok(Json(EmqxAclResponse { result: "deny" }));
    }

    let id = &body.clientid;
    let allowed = match body.action.as_str() {
        "subscribe" => body.topic == format!("adapter/{id}/cmd"),
        "publish" => {
            body.topic == format!("adapter/{id}/ack")
                || body.topic == format!("adapter/{id}/result")
                || body.topic == format!("adapter/{id}/state")
                || body.topic == format!("adapter/{id}/presence")
                || body.topic == format!("adapter/{id}/error")
        }
        _ => false,
    };

    Ok(Json(EmqxAclResponse {
        result: if allowed { "allow" } else { "deny" },
    }))
}

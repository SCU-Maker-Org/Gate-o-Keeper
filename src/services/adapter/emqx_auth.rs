use super::MqttAuthDecision;
use crate::domain::{ApprovalStatus, AuditActorType, AuditResult};
use crate::error::AppResult;
use crate::state::AppState;
use crate::utils::{constant_time_eq, hash_token};

fn cert_cn_matches_clientid(cert_cn: Option<&str>, clientid: &str) -> bool {
    match cert_cn
        .map(str::trim)
        .filter(|s| !s.is_empty() && *s != "undefined")
    {
        Some(cn) => cn == clientid,
        None => false,
    }
}

/// Authenticates an EMQX MQTT client connection (mTLS CN + service account or approved adapter token).
pub async fn authenticate_mqtt(
    state: &AppState,
    clientid: &str,
    username: &str,
    password: &str,
    cert_cn: Option<&str>,
) -> AppResult<MqttAuthDecision> {
    let deny = MqttAuthDecision {
        allow: false,
        is_superuser: None,
    };

    if !cert_cn_matches_clientid(cert_cn, clientid) {
        tracing::warn!(
            clientid,
            cert_cn = ?cert_cn,
            "mTLS certificate CN does not match MQTT clientid"
        );
        return Ok(deny);
    }

    let backend_pw_ok = constant_time_eq(password, &state.config.mqtt_password);
    if clientid == state.config.mqtt_client_id
        && username == state.config.mqtt_username
        && backend_pw_ok
    {
        return Ok(MqttAuthDecision {
            allow: true,
            is_superuser: Some(true),
        });
    }

    if clientid.is_empty() || clientid != username {
        return Ok(deny);
    }

    let cfg = state.db.get_system_config().await?;
    if !state
        .redis
        .check_rate_limit(
            &format!("mqtt:conn:{clientid}"),
            cfg.rate_limits.mqtt_conn_client.max,
            cfg.rate_limits.mqtt_conn_client.window_sec,
        )
        .await?
    {
        return Ok(deny);
    }

    let Some(adapter) = state.db.find_adapter_by_id(clientid).await? else {
        return Ok(deny);
    };
    if adapter.approval_status != ApprovalStatus::Approved {
        return Ok(deny);
    }

    let incoming_hash = hash_token(password);
    if constant_time_eq(&adapter.token_hash, &incoming_hash) {
        if adapter.pending_token_hash.is_some() {
            let now = chrono::Utc::now().timestamp();
            let cutoff = now - super::PENDING_TOKEN_TTL_SEC;
            let is_stale = adapter.pending_token_stale_at.is_some()
                || adapter.pending_token_at.unwrap_or(adapter.updated_at) <= cutoff;
            if is_stale
                && state
                    .db
                    .clear_stale_pending_token_on_old_auth(
                        &adapter.id,
                        &adapter.token_hash,
                        cutoff,
                        now,
                    )
                    .await?
            {
                tracing::info!(
                    adapter_id = %adapter.id,
                    msg_id = ?adapter.pending_token_msg_id,
                    "cleared stale pending token on old-token auth; scheduling rotation retry"
                );
                let req_id = adapter.pending_token_msg_id.clone().unwrap_or_default();
                state.audit.record_event(
                    AuditActorType::System,
                    "emqx_auth",
                    "clear_stale_pending_token",
                    "adapter",
                    &adapter.id,
                    AuditResult::Success,
                    serde_json::json!({
                        "msgId": adapter.pending_token_msg_id,
                        "pendingTokenAt": adapter.pending_token_at,
                        "pendingTokenStaleAt": adapter.pending_token_stale_at,
                    }),
                    "",
                    &req_id,
                );
                if let Err(err) = state
                    .redis
                    .mark_adapter_rotation_retry(&adapter.id, super::PENDING_TOKEN_TTL_SEC as u64)
                    .await
                {
                    tracing::warn!(
                        adapter_id = %adapter.id,
                        error = %err.message,
                        "failed to mark adapter rotation retry in redis"
                    );
                }
            }
        }
        return Ok(MqttAuthDecision {
            allow: true,
            is_superuser: Some(false),
        });
    }

    let pending_ok = adapter
        .pending_token_hash
        .as_deref()
        .is_some_and(|pending| constant_time_eq(pending, &incoming_hash));
    if pending_ok {
        let now = chrono::Utc::now().timestamp();
        if state
            .db
            .promote_pending_token_on_auth(&adapter.id, &incoming_hash, now)
            .await?
        {
            return Ok(MqttAuthDecision {
                allow: true,
                is_superuser: Some(false),
            });
        }
    }

    Ok(deny)
}

/// Authorizes an EMQX MQTT pub/sub ACL check.
pub async fn authorize_mqtt_acl(
    state: &AppState,
    clientid: &str,
    username: &str,
    topic: &str,
    action: &str,
) -> AppResult<bool> {
    if clientid == state.config.mqtt_client_id && username == state.config.mqtt_username {
        return Ok(true);
    }
    if clientid.is_empty() || clientid != username {
        return Ok(false);
    }
    let Some(adapter) = state.db.find_adapter_by_id(clientid).await? else {
        return Ok(false);
    };
    if adapter.approval_status != ApprovalStatus::Approved {
        return Ok(false);
    }

    let allowed = match action {
        "subscribe" => topic == format!("adapter/{clientid}/cmd"),
        "publish" => {
            topic == format!("adapter/{clientid}/ack")
                || topic == format!("adapter/{clientid}/result")
                || topic == format!("adapter/{clientid}/state")
                || topic == format!("adapter/{clientid}/presence")
                || topic == format!("adapter/{clientid}/error")
        }
        _ => false,
    };
    Ok(allowed)
}

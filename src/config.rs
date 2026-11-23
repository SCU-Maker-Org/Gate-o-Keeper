use serde::{Deserialize, Serialize};
use std::env;
use std::net::IpAddr;
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct AppConfig {
    pub http_addr: String,
    pub cookie_secure: bool,
    pub allow_insecure_oidc_http: bool,
    pub database_url: String,
    pub redis_url: String,
    pub jwt_secret: String,
    pub authentik_issuer: String,
    pub authentik_authorize_url: String,
    pub authentik_admin_url: String,
    pub authentik_api_base_url: String,
    pub authentik_api_token: Option<String>,
    pub authentik_webhook_secret: String,
    pub authentik_client_id: String,
    pub authentik_client_secret: String,
    pub authentik_discovery_url: Option<String>,
    pub authentik_admin_groups: Vec<String>,
    pub backchannel_logout_allowed_ips: Vec<IpAddr>,
    pub trusted_proxies: Vec<IpAddr>,
    pub mqtt_host: String,
    pub mqtt_port: u16,
    pub mqtt_client_id: String,
    pub mqtt_username: String,
    pub mqtt_password: String,
    pub mqtt_ca_cert: PathBuf,
    pub mqtt_client_cert: PathBuf,
    pub mqtt_client_key: PathBuf,
    pub mqtt_broker_api_url: String,
    pub mqtt_broker_api_key: String,
    pub mqtt_broker_api_secret: String,
    pub internal_mqtt_secret: String,
    pub static_dir: Option<PathBuf>,
}

fn derive_authorize_url(issuer: &str) -> String {
    if let Ok(parsed) = reqwest::Url::parse(issuer) {
        let scheme = parsed.scheme();
        if let Some(host) = parsed.host_str() {
            let port_part = parsed.port().map(|p| format!(":{p}")).unwrap_or_default();
            return format!("{scheme}://{host}{port_part}/application/o/authorize/");
        }
    }
    "http://localhost:9000/application/o/authorize/".to_string()
}

fn derive_origin_url(raw_url: &str, fallback: &str) -> String {
    if let Ok(parsed) = reqwest::Url::parse(raw_url) {
        let scheme = parsed.scheme();
        if let Some(host) = parsed.host_str() {
            let port_part = parsed.port().map(|p| format!(":{p}")).unwrap_or_default();
            return format!("{scheme}://{host}{port_part}");
        }
    }
    fallback.to_string()
}

impl AppConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        let _ = dotenvy::dotenv();

        let parse_csv = |key: &str| -> Vec<String> {
            env::var(key)
                .unwrap_or_default()
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(ToOwned::to_owned)
                .collect()
        };

        let parse_ips = |key: &str| -> anyhow::Result<Vec<IpAddr>> {
            let mut ips = Vec::new();
            for item in parse_csv(key) {
                let ip: IpAddr = item
                    .parse()
                    .map_err(|e| anyhow::anyhow!("invalid IP in {key} ('{item}'): {e}"))?;
                ips.push(ip);
            }
            Ok(ips)
        };

        let allow_dev_defaults = env::var("ALLOW_DEV_DEFAULTS")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);

        let require_secret = |key: &str, min_len: usize, dev_fallback: &str| -> anyhow::Result<String> {
            match env::var(key) {
                Ok(v) if !v.trim().is_empty() => {
                    let trimmed = v.trim().to_string();
                    if !allow_dev_defaults && trimmed.len() < min_len {
                        anyhow::bail!("{key} must be at least {min_len} characters");
                    }
                    Ok(trimmed)
                }
                _ if allow_dev_defaults => Ok(dev_fallback.to_string()),
                _ => anyhow::bail!("{key} environment variable is required"),
            }
        };

        let discovery = env::var("AUTHENTIK_DISCOVERY_URL")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        let allow_insecure_oidc_http = env::var("ALLOW_INSECURE_OIDC_HTTP")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);

        let authentik_issuer = env::var("AUTHENTIK_ISSUER")
            .map(|s| s.trim().to_string())
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "https://id.example.com/application/o/locker/".into());

        if !allow_insecure_oidc_http && !allow_dev_defaults {
            if !authentik_issuer.starts_with("https://") {
                anyhow::bail!("AUTHENTIK_ISSUER must use https:// unless ALLOW_INSECURE_OIDC_HTTP=true");
            }
            if let Some(ref d) = discovery {
                if !d.starts_with("https://") {
                    anyhow::bail!("AUTHENTIK_DISCOVERY_URL must use https:// unless ALLOW_INSECURE_OIDC_HTTP=true");
                }
            }
        }

        let authentik_authorize_url = env::var("VITE_AUTHENTIK_AUTHORIZE_URL")
            .ok()
            .or_else(|| env::var("AUTHENTIK_AUTHORIZE_URL").ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| derive_authorize_url(&authentik_issuer));

        let authentik_admin_url = env::var("AUTHENTIK_ADMIN_URL")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| {
                let origin = derive_origin_url(&authentik_authorize_url, "http://localhost:9000");
                format!("{origin}/if/admin/#/identity/users")
            });

        let authentik_api_base_url = env::var("AUTHENTIK_API_BASE_URL")
            .ok()
            .map(|s| s.trim().trim_end_matches('/').to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| {
                let source = discovery.as_deref().unwrap_or(&authentik_issuer);
                derive_origin_url(source, "http://authentik-server:9000")
            });

        let authentik_api_token = env::var("AUTHENTIK_API_TOKEN")
            .ok()
            .or_else(|| env::var("AUTHENTIK_BOOTSTRAP_TOKEN").ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        let internal_mqtt_secret = require_secret(
            "INTERNAL_MQTT_SECRET",
            16,
            "dev-internal-mqtt-secret",
        )?;

        let authentik_webhook_secret = env::var("AUTHENTIK_WEBHOOK_SECRET")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| internal_mqtt_secret.clone());

        let authentik_client_id = env::var("AUTHENTIK_CLIENT_ID")
            .ok()
            .or_else(|| env::var("VITE_AUTHENTIK_CLIENT_ID").ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "locker-client-id".into());

        let static_dir = env::var("STATIC_DIR")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .map(PathBuf::from);

        let admin_groups = {
            let g = parse_csv("AUTHENTIK_ADMIN_GROUPS");
            if g.is_empty() {
                vec!["locker-admins".to_string()]
            } else {
                g
            }
        };

        Ok(Self {
            http_addr: env::var("HTTP_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".into()),
            cookie_secure: env::var("COOKIE_SECURE")
                .map(|v| v != "false" && v != "0")
                .unwrap_or(true),
            allow_insecure_oidc_http,
            database_url: env::var("DATABASE_URL")
                .unwrap_or_else(|_| "sqlite:///data/locker.db?mode=rwc".into()),
            redis_url: env::var("REDIS_URL")
                .unwrap_or_else(|_| "redis://127.0.0.1:6379".into()),
            jwt_secret: require_secret(
                "JWT_SECRET",
                32,
                "dev-only-jwt-secret-change-me-in-production-64-bytes",
            )?,
            authentik_issuer,
            authentik_authorize_url,
            authentik_admin_url,
            authentik_api_base_url,
            authentik_api_token,
            authentik_webhook_secret,
            authentik_client_id,
            authentik_client_secret: require_secret(
                "AUTHENTIK_CLIENT_SECRET",
                12,
                "locker-client-secret",
            )?,
            authentik_discovery_url: discovery,
            authentik_admin_groups: admin_groups,
            backchannel_logout_allowed_ips: parse_ips("BACKCHANNEL_LOGOUT_ALLOWED_IPS")?,
            trusted_proxies: parse_ips("TRUSTED_PROXIES")?,
            mqtt_host: env::var("MQTT_HOST").unwrap_or_else(|_| "broker".into()),
            mqtt_port: env::var("MQTT_PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(8883),
            mqtt_client_id: env::var("MQTT_CLIENT_ID")
                .unwrap_or_else(|_| "locker-backend".into()),
            mqtt_username: env::var("MQTT_USERNAME")
                .unwrap_or_else(|_| "locker-backend".into()),
            mqtt_password: require_secret(
                "MQTT_PASSWORD",
                16,
                "backend-internal-mqtt-secret",
            )?,
            mqtt_ca_cert: PathBuf::from(
                env::var("MQTT_CA_CERT").unwrap_or_else(|_| "/certs/ca.crt".into()),
            ),
            mqtt_client_cert: PathBuf::from(
                env::var("MQTT_CLIENT_CERT").unwrap_or_else(|_| "/certs/backend.crt".into()),
            ),
            mqtt_client_key: PathBuf::from(
                env::var("MQTT_CLIENT_KEY").unwrap_or_else(|_| "/certs/backend.key".into()),
            ),
            mqtt_broker_api_url: env::var("MQTT_BROKER_API_URL")
                .unwrap_or_else(|_| "http://broker:18083/api/v5".into()),
            mqtt_broker_api_key: env::var("MQTT_BROKER_API_KEY").unwrap_or_default(),
            mqtt_broker_api_secret: env::var("MQTT_BROKER_API_SECRET").unwrap_or_default(),
            internal_mqtt_secret,
            static_dir,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RateLimitRule {
    pub max: i64,
    pub window_sec: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RateLimitConfig {
    pub unlock_user: RateLimitRule,
    pub unlock_ip: RateLimitRule,
    pub sso_exchange_ip: RateLimitRule,
    pub adapter_register_id: RateLimitRule,
    pub adapter_register_ip: RateLimitRule,
    pub adapter_status_id: RateLimitRule,
    pub mqtt_conn_client: RateLimitRule,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            unlock_user: RateLimitRule {
                max: 5,
                window_sec: 60,
            },
            unlock_ip: RateLimitRule {
                max: 20,
                window_sec: 60,
            },
            sso_exchange_ip: RateLimitRule {
                max: 10,
                window_sec: 60,
            },
            adapter_register_id: RateLimitRule {
                max: 3,
                window_sec: 3600,
            },
            adapter_register_ip: RateLimitRule {
                max: 10,
                window_sec: 60,
            },
            adapter_status_id: RateLimitRule {
                max: 12,
                window_sec: 60,
            },
            mqtt_conn_client: RateLimitRule {
                max: 10,
                window_sec: 60,
            },
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemConfig {
    pub unlock_replay_window_sec: i64,
    pub command_timeout_ms: u64,
    pub max_devices_per_user: i64,
    pub audit_retention_days: i64,
    pub offline_unknown_sec: i64,
    pub state_report_period_sec: i64,
    pub admin_groups: Vec<String>,
    #[serde(default)]
    pub rate_limits: RateLimitConfig,
}

impl Default for SystemConfig {
    fn default() -> Self {
        Self {
            unlock_replay_window_sec: 60,
            command_timeout_ms: 10_000,
            max_devices_per_user: 3,
            audit_retention_days: 90,
            offline_unknown_sec: 300,
            state_report_period_sec: 60,
            admin_groups: vec!["locker-admins".to_string()],
            rate_limits: RateLimitConfig::default(),
        }
    }
}

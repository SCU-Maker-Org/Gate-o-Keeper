use crate::config::AppConfig;
use crate::infra::audit::AuditHandle;
use crate::infra::db::Db;
use crate::infra::mqtt::MqttClient;
use crate::infra::redis::RedisStore;
use crate::auth::OidcCache;

#[derive(Clone)]
pub struct AppState {
    pub config: AppConfig,
    pub db: Db,
    pub redis: RedisStore,
    pub mqtt: MqttClient,
    pub audit: AuditHandle,
    pub http: reqwest::Client,
    pub oidc_cache: OidcCache,
}

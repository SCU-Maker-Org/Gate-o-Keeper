use crate::audit::AuditHandle;
use crate::auth::OidcCache;
use crate::config::AppConfig;
use crate::db::Db;
use crate::mqtt::MqttClient;
use crate::redis_store::RedisStore;

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

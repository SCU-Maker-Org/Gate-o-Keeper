use locker_backend::audit::spawn_audit_worker_with_control;
use locker_backend::auth::OidcCache;
use locker_backend::config::AppConfig;
use locker_backend::db::Db;
use locker_backend::mqtt::connect_and_spawn;
use locker_backend::redis_store::RedisStore;
use locker_backend::routes;
use locker_backend::state::AppState;
use std::net::SocketAddr;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,locker_backend=debug")),
        )
        .json()
        .init();

    let config = AppConfig::from_env()?;
    let db = Db::connect(&config.database_url).await?;
    db.seed_admin_groups_if_default(&config.authentik_admin_groups)
        .await?;
    let redis = RedisStore::connect(&config.redis_url).await?;
    let (audit, audit_ctrl) = spawn_audit_worker_with_control(db.clone());
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    let mqtt = connect_and_spawn(
        config.clone(),
        db.clone(),
        redis.clone(),
        audit.clone(),
        http.clone(),
    )?;

    let state = AppState {
        config: config.clone(),
        db,
        redis,
        mqtt,
        audit,
        http,
        oidc_cache: OidcCache::default(),
    };

    let static_dir = state.config.static_dir.clone();
    let app = routes::router_with_static(static_dir.as_deref()).with_state(state);
    let listener = tokio::net::TcpListener::bind(&config.http_addr).await?;
    tracing::info!(
        addr = %config.http_addr,
        static_dir = ?static_dir,
        "locker-backend listening"
    );
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    tracing::info!("shutting down; draining audit logs");
    audit_ctrl.shutdown().await;
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sig.recv().await;
        } else {
            std::future::pending::<()>().await;
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
}

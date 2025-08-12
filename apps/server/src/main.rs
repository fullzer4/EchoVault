pub mod config;
pub mod telemetry;
pub mod db;
pub mod api;
pub mod auth;

use std::net::SocketAddr;

use tracing_subscriber::{fmt, EnvFilter};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt().with_env_filter(filter).init();

    let cfg = config::Config::from_env()?;
    let pool = db::init_pool(&cfg.database_url).await?;
    db::run_migrations(&pool).await?;

    let app = api::router(pool.clone(), cfg.clone());

    let addr: SocketAddr = cfg.listen.parse()?;
    tracing::info!(%addr, "listening");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

mod app;
mod auth;
mod blossom;
mod config;
mod db;
mod entitlements;
mod safety_hq;

use anyhow::Context;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,tubestr_backend=debug")),
        )
        .init();

    let config = config::AppConfig::from_env()?;
    let state = app::build_state(config).await?;
    let router = app::build_router(state.clone());

    state
        .safety_hq
        .start()
        .await
        .with_context(|| "failed to start Safety HQ runtime")?;

    let listener = tokio::net::TcpListener::bind((state.config.host.as_str(), state.config.port))
        .await
        .with_context(|| "failed to bind TCP listener")?;

    tracing::info!(
        host = state.config.host,
        port = state.config.port,
        "listening"
    );

    axum::serve(listener, router)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("shutdown signal received");
        })
        .await
        .with_context(|| "server exited with error")?;

    Ok(())
}

use std::path::PathBuf;
use tokio::sync::broadcast;
use tracing::{error, info};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use vine::config::Config;
use vine::proxy::ProxyServer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,vine=debug")),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config_path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("vine.toml"));

    info!("Loading configuration from '{}'...", config_path.display());
    let config = match Config::load_or_create(&config_path) {
        Ok(cfg) => cfg,
        Err(e) => {
            error!(
                "Failed to load configuration file '{}': {}",
                config_path.display(),
                e
            );
            std::process::exit(1);
        }
    };

    let server = ProxyServer::new(config)?;

    let (shutdown_tx, shutdown_rx) = broadcast::channel(1);

    tokio::spawn(async move {
        // Ctrl+C, or SIGTERM from `docker stop` and the like.
        #[cfg(unix)]
        let terminate = async {
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(mut signal) => {
                    signal.recv().await;
                }
                Err(err) => {
                    error!("Failed to listen for SIGTERM: {}", err);
                    std::future::pending::<()>().await;
                }
            }
        };
        #[cfg(not(unix))]
        let terminate = std::future::pending::<()>();
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                if let Err(err) = result {
                    error!("Failed to listen for shutdown signal: {}", err);
                    return;
                }
                info!("Received shutdown signal (Ctrl+C). Initiating graceful shutdown...");
            }
            () = terminate => {
                info!("Received SIGTERM. Initiating graceful shutdown...");
            }
        }
        let _ = shutdown_tx.send(());
    });

    if let Err(e) = server.run(shutdown_rx).await {
        error!("Fatal proxy error: {}", e);
        std::process::exit(1);
    }

    info!("Vine proxy shut down successfully.");
    std::process::exit(0);
}

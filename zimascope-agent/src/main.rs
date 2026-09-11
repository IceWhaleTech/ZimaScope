use std::path::PathBuf;

use zimascope_agent::{
    Collector, CollectorConfig,
    api::{self, ApiConfig, ApiState},
};

const DEFAULT_SOCKET: &str = "/run/zimascope/agent.sock";
const SOCKET_ENV: &str = "ZIMASCOPE_API_SOCKET";

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let socket_path = std::env::var_os(SOCKET_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET));

    let state = ApiState::new(ApiConfig {
        database: std::env::var_os("ZIMASCOPE_DATABASE").map(PathBuf::from),
        ..ApiConfig::default()
    });
    let server = match api::bind_unix(&socket_path) {
        Ok(listener) => {
            let state = state.clone();
            Some(tokio::spawn(async move {
                if let Err(error) = api::serve_unix(listener, state).await {
                    eprintln!("zimascope-agent: api server stopped: {error}");
                }
            }))
        }
        Err(error) => {
            eprintln!(
                "zimascope-agent: cannot serve API on {}: {error}",
                socket_path.display()
            );
            None
        }
    };

    let (collector, mut batches) = match Collector::start(CollectorConfig::default()).await {
        Ok(worker) => worker,
        Err(error) => {
            // Keep the local API alive so the UI can explain why collection is
            // unavailable instead of crash-looping (PRD 8.1).
            state.set_collector_error(format!("{error:#}"));
            eprintln!("zimascope-agent: collection unavailable: {error:#}");
            wait_for_shutdown().await;
            shutdown_server(server, &socket_path).await;
            return;
        }
    };

    loop {
        tokio::select! {
            batch = batches.recv() => match batch {
                Some(batch) => state.ingest_batch(batch),
                None => break,
            },
            result = tokio::signal::ctrl_c() => {
                if let Err(error) = result {
                    eprintln!("zimascope-agent: wait for shutdown signal: {error}");
                }
                break;
            }
        }
    }

    if let Err(error) = collector.shutdown().await {
        eprintln!("zimascope-agent: shutdown failed: {error:#}");
    }
    shutdown_server(server, &socket_path).await;
}

async fn wait_for_shutdown() {
    if let Err(error) = tokio::signal::ctrl_c().await {
        eprintln!("zimascope-agent: wait for shutdown signal: {error}");
    }
}

async fn shutdown_server(
    server: Option<tokio::task::JoinHandle<()>>,
    socket_path: &std::path::Path,
) {
    if let Some(server) = server {
        server.abort();
    }
    let _ = std::fs::remove_file(socket_path);
}

use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, RwLock},
};

use zimascope_agent::{
    Collector, CollectorConfig, FingerprintLibrary,
    api::{self, ApiConfig, ApiState},
};

const DEFAULT_SOCKET: &str = "/run/zimascope/agent.sock";
const SOCKET_ENV: &str = "ZIMASCOPE_API_SOCKET";
/// Optional local TCP listener for development (e.g. `127.0.0.1:8787`) so a
/// browser or Vite proxy can reach the Unix-socket API. Never set in
/// production: the daemon is meant to be reached through ZimaOS only.
const TCP_ENV: &str = "ZIMASCOPE_API_TCP";
/// Production HTTP listener (e.g. `0.0.0.0:8080`). When set, the full `/v1`
/// API and, if [`UI_ENV`] points at a built frontend, the SPA are served on
/// this address.
const HTTP_ENV: &str = "ZIMASCOPE_HTTP_LISTEN";
/// Directory of the built frontend (`dist/`) served by [`HTTP_ENV`].
const UI_ENV: &str = "ZIMASCOPE_UI_DIR";
/// One `.mmdb` file or a directory of them (country and ASN databases are
/// merged per lookup). Missing or invalid files degrade to scope-only
/// profiles instead of failing startup.
const GEOIP_ENV: &str = "ZIMASCOPE_GEOIP_DATABASE";
/// Custom fingerprint library JSON. Defaults to `fingerprints.json` next to
/// the database; uploads through the API are persisted here.
const FINGERPRINTS_ENV: &str = "ZIMASCOPE_FINGERPRINTS";

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let socket_path = std::env::var_os(SOCKET_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET));

    let database = std::env::var_os("ZIMASCOPE_DATABASE").map(PathBuf::from);
    let fingerprints_path = std::env::var_os(FINGERPRINTS_ENV)
        .map(PathBuf::from)
        .or_else(|| {
            database
                .as_ref()
                .and_then(|path| path.parent())
                .map(|directory| directory.join("fingerprints.json"))
        });
    let fingerprints = Arc::new(RwLock::new(match &fingerprints_path {
        Some(path) => FingerprintLibrary::load_or_default(path),
        None => FingerprintLibrary::default_library(),
    }));

    let state = ApiState::new(ApiConfig {
        database,
        geoip_database: std::env::var_os(GEOIP_ENV).map(PathBuf::from),
        fingerprints: Arc::clone(&fingerprints),
        fingerprints_path,
        ..ApiConfig::default()
    });

    let mut servers = Vec::new();
    match api::bind_unix(&socket_path) {
        Ok(listener) => {
            let state = state.clone();
            servers.push(tokio::spawn(async move {
                if let Err(error) = api::serve_unix(listener, state).await {
                    eprintln!("zimascope-agent: api server stopped: {error}");
                }
            }));
        }
        Err(error) => eprintln!(
            "zimascope-agent: cannot serve API on {}: {error}",
            socket_path.display()
        ),
    }

    if let Some(address) = tcp_address() {
        match tokio::net::TcpListener::bind(address).await {
            Ok(listener) => {
                let state = state.clone();
                eprintln!("zimascope-agent: dev API listening on http://{address}");
                servers.push(tokio::spawn(async move {
                    if let Err(error) = axum::serve(listener, api::router(state)).await {
                        eprintln!("zimascope-agent: dev API server stopped: {error}");
                    }
                }));
            }
            Err(error) => eprintln!("zimascope-agent: cannot serve dev API on {address}: {error}"),
        }
    }

    if let Some(address) = http_address() {
        match tokio::net::TcpListener::bind(address).await {
            Ok(listener) => {
                let router = match std::env::var_os(UI_ENV).map(PathBuf::from) {
                    Some(ui_dir) if ui_dir.is_dir() => {
                        eprintln!("zimascope-agent: serving UI from {}", ui_dir.display());
                        api::router_with_ui(state.clone(), &ui_dir)
                    }
                    Some(ui_dir) => {
                        eprintln!(
                            "zimascope-agent: UI directory {} is missing; serving API only",
                            ui_dir.display()
                        );
                        api::router(state.clone())
                    }
                    None => api::router(state.clone()),
                };
                eprintln!("zimascope-agent: http server listening on http://{address}");
                servers.push(tokio::spawn(async move {
                    if let Err(error) = axum::serve(listener, router).await {
                        eprintln!("zimascope-agent: http server stopped: {error}");
                    }
                }));
            }
            Err(error) => eprintln!("zimascope-agent: cannot serve http on {address}: {error}"),
        }
    }

    let (collector, mut batches) = match Collector::start(CollectorConfig {
        fingerprints,
        ..CollectorConfig::default()
    })
    .await
    {
        Ok(worker) => worker,
        Err(error) => {
            // Keep the local API alive so the UI can explain why collection is
            // unavailable instead of crash-looping (PRD 8.1).
            state.set_collector_error(format!("{error:#}"));
            eprintln!("zimascope-agent: collection unavailable: {error:#}");
            wait_for_shutdown().await;
            shutdown_servers(servers, &socket_path);
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
    shutdown_servers(servers, &socket_path);
}

fn tcp_address() -> Option<SocketAddr> {
    env_address(TCP_ENV)
}

fn http_address() -> Option<SocketAddr> {
    env_address(HTTP_ENV)
}

fn env_address(name: &str) -> Option<SocketAddr> {
    let value = std::env::var(name).ok()?;
    match value.parse() {
        Ok(address) => Some(address),
        Err(error) => {
            eprintln!("zimascope-agent: invalid {name} {value:?}: {error}");
            None
        }
    }
}

async fn wait_for_shutdown() {
    if let Err(error) = tokio::signal::ctrl_c().await {
        eprintln!("zimascope-agent: wait for shutdown signal: {error}");
    }
}

fn shutdown_servers(servers: Vec<tokio::task::JoinHandle<()>>, socket_path: &std::path::Path) {
    for server in servers {
        server.abort();
    }
    let _ = std::fs::remove_file(socket_path);
}

use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, RwLock},
};

use zimascoped::{
    Collector, CollectorConfig, FingerprintLibrary, InterfaceSelector,
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

    let mut servers = tokio::task::JoinSet::new();
    match api::bind_unix(&socket_path) {
        Ok(listener) => {
            let state = state.clone();
            servers.spawn(async move {
                if let Err(error) = api::serve_unix(listener, state).await {
                    eprintln!("zimascoped: api server stopped: {error}");
                }
            });
        }
        Err(error) => eprintln!(
            "zimascoped: cannot serve API on {}: {error}",
            socket_path.display()
        ),
    }

    if let Some(address) = tcp_address() {
        match tokio::net::TcpListener::bind(address).await {
            Ok(listener) => {
                let state = state.clone();
                eprintln!("zimascoped: dev API listening on http://{address}");
                servers.spawn(async move {
                    if let Err(error) = axum::serve(listener, api::router(state)).await {
                        eprintln!("zimascoped: dev API server stopped: {error}");
                    }
                });
            }
            Err(error) => eprintln!("zimascoped: cannot serve dev API on {address}: {error}"),
        }
    }

    if let Some(address) = http_address() {
        match tokio::net::TcpListener::bind(address).await {
            Ok(listener) => {
                let router = match std::env::var_os(UI_ENV).map(PathBuf::from) {
                    Some(ui_dir) if ui_dir.is_dir() => {
                        eprintln!("zimascoped: serving UI from {}", ui_dir.display());
                        api::router_with_ui(state.clone(), &ui_dir)
                    }
                    Some(ui_dir) => {
                        if api::has_embedded_ui() {
                            eprintln!(
                                "zimascoped: UI directory {} is missing; serving the embedded frontend",
                                ui_dir.display()
                            );
                            api::router_with_embedded_ui(state.clone())
                        } else {
                            eprintln!(
                                "zimascoped: UI directory {} is missing; serving API only",
                                ui_dir.display()
                            );
                            api::router(state.clone())
                        }
                    }
                    None => {
                        if api::has_embedded_ui() {
                            eprintln!("zimascoped: serving the embedded frontend");
                            api::router_with_embedded_ui(state.clone())
                        } else {
                            eprintln!("zimascoped: no frontend bundle; serving API only");
                            api::router(state.clone())
                        }
                    }
                };
                eprintln!("zimascoped: http server listening on http://{address}");
                servers.spawn(async move {
                    if let Err(error) = axum::serve(listener, router).await {
                        eprintln!("zimascoped: http server stopped: {error}");
                    }
                });
            }
            Err(error) => eprintln!("zimascoped: cannot serve http on {address}: {error}"),
        }
    }

    // The persisted Device Boundary decides where hooks attach; an empty list
    // keeps the safe default of following the default route.
    let interfaces = InterfaceSelector::from_names(&state.boundary_interfaces());
    let (collector, mut batches) = match Collector::start(CollectorConfig {
        interfaces,
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
            eprintln!("zimascoped: collection unavailable: {error:#}");
            shutdown_signal().await;
            shutdown_servers(servers, &socket_path);
            return;
        }
    };

    state.set_policy_handle(collector.policy_handle());
    if let Err(error) = state.apply_policy().await {
        eprintln!("zimascoped: traffic rule enforcement unavailable: {error:#}");
    }
    // Re-apply the boundary in case settings changed between the startup read
    // and the collector becoming available.
    state.refresh_boundary().await;

    loop {
        tokio::select! {
            batch = batches.recv() => match batch {
                Some(batch) => state.ingest_batch(batch),
                None => break,
            },
            () = shutdown_signal() => break,
        }
    }

    if let Err(error) = collector.shutdown().await {
        eprintln!("zimascoped: shutdown failed: {error:#}");
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
            eprintln!("zimascoped: invalid {name} {value:?}: {error}");
            None
        }
    }
}

async fn shutdown_signal() {
    if let Err(error) = tokio::signal::ctrl_c().await {
        eprintln!("zimascoped: wait for shutdown signal: {error}");
    }
}

fn shutdown_servers(mut servers: tokio::task::JoinSet<()>, socket_path: &std::path::Path) {
    servers.abort_all();
    let _ = std::fs::remove_file(socket_path);
}

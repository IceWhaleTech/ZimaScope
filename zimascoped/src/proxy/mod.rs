//! mihomo/Clash external-controller integration.
//!
//! A background poller reads `GET /connections` from the proxy control API
//! and maps fake-IP client sockets back to the address the proxy actually
//! dialed (origin server when known, egress node otherwise). The resolver is
//! read at ingest time so fake-IP Flows carry real GeoIP attribution; nothing
//! else depends on the proxy being up.

mod http;
mod wire;

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use http::Target;

/// How often the controller is polled.
const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// One proxy connection resolved to a real destination.
#[derive(Clone, Debug, Default)]
pub struct ProxyResolution {
    pub host: Option<String>,
    /// Origin server when the proxy knew it, otherwise the egress node.
    pub real_address: Option<IpAddr>,
    /// Country codes the proxy itself attributed to the destination.
    pub country: Option<String>,
    pub asn: Option<u32>,
    pub chains: Vec<String>,
}

/// Client socket identity used to match an observed Flow to a proxy
/// connection. Fake-IP connections carry no usable destination address in
/// the controller response, so the tuple is `(client, client port, service
/// port)` — unique per socket.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProxyKey {
    pub client: IpAddr,
    pub client_port: u16,
    pub destination_port: u16,
}

impl ProxyKey {
    /// Builds a key for a Flow whose remote side is a fake address.
    pub fn for_fake_flow(
        client: IpAddr,
        client_port: Option<u16>,
        destination_port: Option<u16>,
    ) -> Option<Self> {
        let (Some(client_port), Some(destination_port)) = (client_port, destination_port) else {
            return None;
        };
        Some(Self {
            client,
            client_port,
            destination_port,
        })
    }
}

/// Integration state surfaced through `/v1/status`.
#[derive(Clone, Debug, Default)]
pub struct ProxyStatus {
    pub enabled: bool,
    pub reachable: bool,
    pub mapped: usize,
    pub last_error: Option<String>,
}

struct Shared {
    target: Option<Target>,
    resolutions: HashMap<ProxyKey, ProxyResolution>,
    status: ProxyStatus,
}

/// Shared, cheap-to-clone resolver handle.
#[derive(Clone)]
pub struct ProxyResolver {
    shared: Arc<Mutex<Shared>>,
}

impl ProxyResolver {
    /// Starts the background poller thread.
    pub fn start() -> Self {
        let resolver = Self {
            shared: Arc::new(Mutex::new(Shared {
                target: None,
                resolutions: HashMap::new(),
                status: ProxyStatus::default(),
            })),
        };
        let worker = resolver.clone();
        thread::Builder::new()
            .name("zimascope-proxy".to_owned())
            .spawn(move || worker.run())
            .expect("spawn proxy poller thread");
        resolver
    }

    /// Applies the current settings; disabling clears all mappings.
    pub fn configure(&self, enabled: bool, controller_url: &str, secret: &str) {
        let mut shared = self.lock();
        shared.status.enabled = enabled;
        if !enabled || controller_url.is_empty() {
            shared.target = None;
            shared.resolutions.clear();
            shared.status.reachable = false;
            shared.status.mapped = 0;
            shared.status.last_error = None;
            return;
        }
        shared.target = Some(Target {
            url: controller_url.to_owned(),
            secret: secret.to_owned(),
        });
    }

    pub fn status(&self) -> ProxyStatus {
        self.lock().status.clone()
    }

    /// Resolves a fake-IP flow by client socket.
    pub fn lookup(&self, key: &ProxyKey) -> Option<ProxyResolution> {
        self.lock().resolutions.get(key).cloned()
    }

    /// Test-only injection of a mapping.
    #[cfg(test)]
    pub(crate) fn insert_resolution(&self, key: ProxyKey, resolution: ProxyResolution) {
        let mut shared = self.lock();
        shared.resolutions.insert(key, resolution);
        shared.status.mapped = shared.resolutions.len();
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Shared> {
        self.shared
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }

    fn run(self) {
        loop {
            thread::sleep(POLL_INTERVAL);
            let target = match &self.lock().target {
                Some(target) => Target {
                    url: target.url.clone(),
                    secret: target.secret.clone(),
                },
                None => continue,
            };
            match http::fetch_body(&target).and_then(|body| wire::parse_connections(&body)) {
                Ok(resolutions) => {
                    let mut shared = self.lock();
                    shared.status.reachable = true;
                    shared.status.last_error = None;
                    shared.status.mapped = resolutions.len();
                    shared.resolutions = resolutions;
                }
                Err(error) => {
                    let mut shared = self.lock();
                    shared.status.reachable = false;
                    shared.status.last_error = Some(error);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_requires_both_ports() {
        let client = "192.168.100.7".parse().unwrap();
        let key = ProxyKey::for_fake_flow(client, Some(54_036), Some(443)).expect("key");
        assert_eq!(key.client, client);
        assert_eq!(key.client_port, 54_036);
        assert_eq!(key.destination_port, 443);
        assert!(ProxyKey::for_fake_flow(client, None, Some(443)).is_none());
        assert!(ProxyKey::for_fake_flow(client, Some(54_036), None).is_none());
    }

    #[test]
    fn lookup_matches_client_socket_exactly() {
        let resolver = ProxyResolver::start();
        let key = ProxyKey {
            client: "10.0.0.2".parse().unwrap(),
            client_port: 54_036,
            destination_port: 443,
        };
        resolver.insert_resolution(
            key,
            ProxyResolution {
                real_address: Some("140.82.112.3".parse().unwrap()),
                ..ProxyResolution::default()
            },
        );

        assert_eq!(
            resolver
                .lookup(&key)
                .and_then(|resolution| resolution.real_address),
            Some("140.82.112.3".parse().unwrap())
        );
        assert!(
            resolver
                .lookup(&ProxyKey {
                    client_port: 54_037,
                    ..key
                })
                .is_none()
        );
        assert!(
            resolver
                .lookup(&ProxyKey {
                    destination_port: 80,
                    ..key
                })
                .is_none()
        );
    }
}

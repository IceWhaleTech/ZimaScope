//! Wire format of `GET /connections` and its mapping into resolutions.

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
};

use serde::Deserialize;

use super::{ProxyKey, ProxyResolution};

#[derive(Deserialize)]
struct WireResponse {
    #[serde(default)]
    connections: Vec<WireConnection>,
}

#[derive(Deserialize)]
struct WireConnection {
    metadata: WireMetadata,
    #[serde(default)]
    chains: Vec<String>,
}

#[derive(Deserialize)]
struct WireMetadata {
    #[serde(rename = "sourceIP")]
    source_ip: Option<String>,
    #[serde(rename = "sourcePort")]
    source_port: Option<String>,
    /// Empty in fake-IP mode: the client connected to a synthetic address.
    #[serde(rename = "destinationIP")]
    destination_ip: Option<String>,
    #[serde(rename = "destinationPort")]
    destination_port: Option<String>,
    host: Option<String>,
    /// The address the proxy actually dialed: the origin server when known,
    /// otherwise the egress proxy node.
    #[serde(rename = "remoteDestination")]
    remote_destination: Option<String>,
    #[serde(rename = "destinationGeoIP")]
    destination_geoip: Option<Vec<String>>,
    #[serde(rename = "destinationIPASN")]
    destination_ip_asn: Option<String>,
}

/// Parses a controller response body into per-socket resolutions.
pub(super) fn parse_connections(body: &[u8]) -> Result<HashMap<ProxyKey, ProxyResolution>, String> {
    let response: WireResponse =
        serde_json::from_slice(body).map_err(|error| format!("parse /connections: {error}"))?;
    Ok(map_connections(response))
}

fn map_connections(response: WireResponse) -> HashMap<ProxyKey, ProxyResolution> {
    let mut resolutions = HashMap::new();
    for connection in response.connections {
        let metadata = connection.metadata;
        let Some(client) = parse_ip(metadata.source_ip.as_deref()) else {
            continue;
        };
        let (Some(client_port), Some(destination_port)) = (
            parse_port(metadata.source_port.as_deref()),
            parse_port(metadata.destination_port.as_deref()),
        ) else {
            continue;
        };
        let origin = parse_ip(metadata.destination_ip.as_deref());
        let egress = metadata
            .remote_destination
            .as_deref()
            .and_then(parse_remote_address);
        // Fake-IP connections have no origin address; the address the proxy
        // dialed is the only real destination.
        let real_address = origin.or(egress);
        let country = metadata
            .destination_geoip
            .as_ref()
            .and_then(|codes| codes.first())
            .map(|code| code.to_uppercase());
        let asn = metadata
            .destination_ip_asn
            .as_deref()
            .and_then(|value| value.trim_start_matches("AS").parse::<u32>().ok());
        let host = metadata
            .host
            .filter(|host| !host.is_empty())
            .map(|host| host.trim_end_matches('.').to_ascii_lowercase());
        resolutions.insert(
            ProxyKey {
                client,
                client_port,
                destination_port,
            },
            ProxyResolution {
                host,
                real_address,
                country,
                asn,
                chains: connection.chains,
            },
        );
    }
    resolutions
}

fn parse_port(value: Option<&str>) -> Option<u16> {
    value?.trim().parse().ok()
}

fn parse_ip(value: Option<&str>) -> Option<IpAddr> {
    let value = value?.trim();
    if value.is_empty() {
        return None;
    }
    value.parse().ok()
}

/// `remoteDestination` is usually `IP:port`; accept bare addresses too.
fn parse_remote_address(value: &str) -> Option<IpAddr> {
    let value = value.trim();
    if let Ok(address) = value.parse::<IpAddr>() {
        return Some(address);
    }
    value.parse::<SocketAddr>().ok().map(|address| address.ip())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Trimmed from a live mihomo capture: fake-IP connections carry an
    /// empty `destinationIP` and expose only the egress node.
    const MIHOMO_SAMPLE: &str = r#"{
        "downloadTotal": 104470029,
        "uploadTotal": 1443447,
        "connections": [
            {
                "id": "8d0893cb-6901-455b-a292-d9fce6cc2943",
                "metadata": {
                    "network": "tcp",
                    "type": "Redir",
                    "sourceIP": "192.168.100.9",
                    "sourcePort": "50123",
                    "destinationIP": "",
                    "destinationPort": "443",
                    "host": "dns.google",
                    "dnsMode": "fake-ip",
                    "remoteDestination": "103.195.188.111:443",
                    "destinationGeoIP": null,
                    "destinationIPASN": ""
                },
                "chains": ["新加坡[2.5x]-豪华1", "赛博云"]
            },
            {
                "id": "abc",
                "metadata": {
                    "network": "tcp",
                    "sourceIP": "192.168.100.111",
                    "sourcePort": "55401",
                    "destinationIP": "172.66.149.158",
                    "destinationPort": "443",
                    "host": "config.immersivetranslate.com",
                    "dnsMode": "normal",
                    "remoteDestination": "103.195.188.111:443",
                    "destinationGeoIP": ["US"],
                    "destinationIPASN": "AS36459"
                },
                "chains": ["新加坡[2.5x]-豪华1"]
            }
        ]
    }"#;

    #[test]
    fn maps_fake_ip_connection_to_egress_node() {
        let resolutions = parse_connections(MIHOMO_SAMPLE.as_bytes()).expect("parse");
        assert_eq!(resolutions.len(), 2);

        let key = ProxyKey {
            client: "192.168.100.9".parse().unwrap(),
            client_port: 50_123,
            destination_port: 443,
        };
        let fake = resolutions.get(&key).expect("fake-ip connection");
        assert_eq!(fake.real_address, Some("103.195.188.111".parse().unwrap()));
        assert_eq!(fake.host.as_deref(), Some("dns.google"));
        assert_eq!(fake.country, None);
        assert_eq!(fake.asn, None);
        assert_eq!(fake.chains.len(), 2);
    }

    #[test]
    fn prefers_origin_address_and_proxy_geoip() {
        let resolutions = parse_connections(MIHOMO_SAMPLE.as_bytes()).expect("parse");
        let key = ProxyKey {
            client: "192.168.100.111".parse().unwrap(),
            client_port: 55_401,
            destination_port: 443,
        };
        let normal = resolutions.get(&key).expect("normal connection");
        assert_eq!(normal.real_address, Some("172.66.149.158".parse().unwrap()));
        assert_eq!(normal.country.as_deref(), Some("US"));
        assert_eq!(normal.asn, Some(36459));
    }

    #[test]
    fn rejects_unparseable_bodies() {
        assert!(parse_connections(b"{\"connections\": [").is_err());
    }
}

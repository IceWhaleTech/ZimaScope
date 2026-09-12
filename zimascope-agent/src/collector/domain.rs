//! User-space parsing, validation and deduplication of domain evidence.
//!
//! The eBPF program only copies bounded payload samples; DNS answers, TLS SNI
//! and HTTP Host are parsed here, where loops and string handling are free of
//! verifier constraints.

use std::{
    net::{IpAddr, Ipv4Addr},
    time::{Duration, Instant},
};

use hashbrown::HashMap;
use zimascope_common::{
    kernel_abi::{self, DOMAIN_SAMPLE_MAX, Direction, IpFamily, SampleKind, TransportProtocol},
    model::{AssociationConfidence, DomainEvidence, DomainObservation},
};
use zimascope_ebpf::{
    domain::{extract_http_host, extract_tls_sni, parse_dns_response},
    parse::MemoryCursor,
};

use super::tracker::MonoClock;

pub(crate) const DOMAIN_MAX_LEN: usize = kernel_abi::DOMAIN_MAX_LEN;
pub(crate) const DOMAIN_LABEL_MAX_LEN: usize = 63;

const MIN_DNS_TTL: Duration = Duration::from_secs(10);
const MAX_DNS_TTL: Duration = Duration::from_secs(3600);
const DIRECT_EVIDENCE_TTL: Duration = Duration::from_secs(300);

#[derive(Eq, Hash, PartialEq)]
struct DomainDedupeKey {
    domain: Box<str>,
    address: IpAddr,
    evidence: DomainEvidence,
    client_context: u64,
}

/// Parses kernel payload samples and suppresses duplicates until expiry.
#[derive(Default)]
pub(crate) struct DomainDecoder {
    dedupe: HashMap<DomainDedupeKey, Instant>,
}

impl DomainDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Parses one sample, appending every distinct observation it yields.
    pub fn decode(
        &mut self,
        sample: &kernel_abi::DomainSample,
        clock: &mut MonoClock,
        now: Instant,
        observations: &mut Vec<DomainObservation>,
    ) {
        if IpFamily::from_abi(sample.ip_family) != Some(IpFamily::V4)
            || Direction::from_abi(sample.direction).is_none()
            || TransportProtocol::from_abi(sample.transport).is_none()
        {
            return;
        }
        let Some(kind) = SampleKind::from_abi(sample.kind) else {
            return;
        };
        let length = sample.payload_len as usize;
        if length == 0 || length > DOMAIN_SAMPLE_MAX {
            return;
        }

        let cursor = MemoryCursor::new(&sample.payload[..length]);
        let peer = ipv4_from_abi(sample.address);

        clock.anchor_if_needed(sample.observed_mono_ns, now);
        let observed_at = clock.to_instant(sample.observed_mono_ns);

        match kind {
            SampleKind::Dns => {
                let offset = if sample.transport == TransportProtocol::Tcp as u8 {
                    2
                } else {
                    0
                };
                if offset >= length {
                    return;
                }
                let mut buffer = [0u8; DOMAIN_MAX_LEN];
                parse_dns_response(
                    &cursor,
                    offset,
                    length,
                    &mut buffer,
                    |domain, len, answer| {
                        let Some(domain) = domain_from_buffer(domain, len) else {
                            return;
                        };
                        let address = ipv4_from_abi(answer.address);
                        let expires_at = observed_at + clamp_dns_ttl(answer.ttl_secs);
                        self.push(
                            domain,
                            address,
                            DomainEvidence::Dns,
                            observed_at,
                            expires_at,
                            now,
                            observations,
                        );
                    },
                );
            }
            SampleKind::TlsClientHello => {
                let mut buffer = [0u8; DOMAIN_MAX_LEN];
                if let Some(len) = extract_tls_sni(&cursor, 0, length, &mut buffer) {
                    if let Some(domain) = domain_from_buffer(&buffer, len) {
                        self.push(
                            domain,
                            peer,
                            DomainEvidence::TlsSni,
                            observed_at,
                            observed_at + DIRECT_EVIDENCE_TTL,
                            now,
                            observations,
                        );
                    }
                }
            }
            SampleKind::HttpRequest => {
                let mut buffer = [0u8; DOMAIN_MAX_LEN];
                if let Some(len) = extract_http_host(&cursor, 0, length, &mut buffer) {
                    if let Some(domain) = domain_from_buffer(&buffer, len) {
                        self.push(
                            domain,
                            peer,
                            DomainEvidence::HttpHost,
                            observed_at,
                            observed_at + DIRECT_EVIDENCE_TTL,
                            now,
                            observations,
                        );
                    }
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn push(
        &mut self,
        domain: Box<str>,
        address: IpAddr,
        evidence: DomainEvidence,
        observed_at: Instant,
        expires_at: Instant,
        now: Instant,
        observations: &mut Vec<DomainObservation>,
    ) {
        let key = DomainDedupeKey {
            domain: domain.clone(),
            address,
            evidence,
            client_context: 0,
        };
        if let Some(existing_expiry) = self.dedupe.get(&key) {
            if *existing_expiry > now {
                return;
            }
        }
        self.dedupe.insert(key, expires_at);

        observations.push(DomainObservation {
            domain,
            address,
            evidence,
            confidence: confidence_for(evidence),
            client_context: 0,
            observed_at,
            expires_at,
        });
    }

    pub fn purge_expired(&mut self, now: Instant) {
        self.dedupe.retain(|_, expiry| *expiry > now);
    }

    #[cfg(test)]
    pub fn tracked(&self) -> usize {
        self.dedupe.len()
    }
}

fn confidence_for(evidence: DomainEvidence) -> AssociationConfidence {
    match evidence {
        DomainEvidence::Dns => AssociationConfidence::Inferred,
        DomainEvidence::TlsSni | DomainEvidence::HttpHost => AssociationConfidence::Direct,
    }
}

fn clamp_dns_ttl(ttl_secs: u32) -> Duration {
    Duration::from_secs(u64::from(ttl_secs)).clamp(MIN_DNS_TTL, MAX_DNS_TTL)
}

fn ipv4_from_abi(raw: [u8; 16]) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(raw[12], raw[13], raw[14], raw[15]))
}

fn domain_from_buffer(buffer: &[u8; DOMAIN_MAX_LEN], len: usize) -> Option<Box<str>> {
    if len == 0 || len > DOMAIN_MAX_LEN {
        return None;
    }
    let raw = std::str::from_utf8(&buffer[..len]).ok()?;
    normalize_domain(raw)
}

/// Normalizes a domain: lowercase ASCII, one trailing root dot removed, empty
/// labels and oversized names rejected. Internationalized names keep their
/// display form.
pub(crate) fn normalize_domain(raw: &str) -> Option<Box<str>> {
    let trimmed = raw.strip_suffix('.').unwrap_or(raw);
    if trimmed.is_empty() || trimmed.len() > DOMAIN_MAX_LEN {
        return None;
    }

    for label in trimmed.split('.') {
        if label.is_empty() || label.len() > DOMAIN_LABEL_MAX_LEN {
            return None;
        }
    }

    if trimmed
        .chars()
        .any(|character| character.is_control() || character == ' ' || character == '/')
    {
        return None;
    }

    Some(trimmed.to_ascii_lowercase().into_boxed_str())
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use zimascope_common::kernel_abi::{DomainSample, SampleKind};

    use super::*;
    use crate::collector::tracker::MonoClock;

    fn dns_response(question: &str, answers: &[(u32, [u8; 4])]) -> Vec<u8> {
        let mut message = Vec::new();
        message.extend_from_slice(&0x1234u16.to_be_bytes());
        message.extend_from_slice(&0x8180u16.to_be_bytes());
        message.extend_from_slice(&1u16.to_be_bytes());
        message.extend_from_slice(&(answers.len() as u16).to_be_bytes());
        message.extend_from_slice(&0u16.to_be_bytes());
        message.extend_from_slice(&0u16.to_be_bytes());
        for label in question.split('.') {
            message.push(label.len() as u8);
            message.extend_from_slice(label.as_bytes());
        }
        message.push(0);
        message.extend_from_slice(&1u16.to_be_bytes());
        message.extend_from_slice(&1u16.to_be_bytes());
        for (ttl, address) in answers {
            message.push(0xC0);
            message.push(0x0C);
            message.extend_from_slice(&1u16.to_be_bytes());
            message.extend_from_slice(&1u16.to_be_bytes());
            message.extend_from_slice(&ttl.to_be_bytes());
            message.extend_from_slice(&4u16.to_be_bytes());
            message.extend_from_slice(address);
        }
        message
    }

    fn client_hello(sni: &str) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(1);
        body.push(0);

        let entry_len = 1 + 2 + sni.len();
        let mut server_name = Vec::new();
        server_name.extend_from_slice(&(entry_len as u16).to_be_bytes());
        server_name.push(0);
        server_name.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        server_name.extend_from_slice(sni.as_bytes());

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0u16.to_be_bytes());
        extensions.extend_from_slice(&(server_name.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&server_name);

        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = Vec::new();
        handshake.push(0x01);
        handshake.extend_from_slice(&[
            (body.len() >> 16) as u8,
            (body.len() >> 8) as u8,
            body.len() as u8,
        ]);
        handshake.extend_from_slice(&body);

        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    fn sample(kind: SampleKind, transport: u8, address: [u8; 4], payload: &[u8]) -> DomainSample {
        let mut sample = DomainSample {
            observed_mono_ns: 1_000,
            ifindex: 7,
            payload_len: payload.len().min(DOMAIN_SAMPLE_MAX) as u16,
            kind: kind as u8,
            transport,
            ip_family: IpFamily::V4 as u8,
            direction: Direction::Outbound as u8,
            reserved: [0; 6],
            address: [0; 16],
            payload: [0; DOMAIN_SAMPLE_MAX],
        };
        sample.address[12..].copy_from_slice(&address);
        sample.payload[..sample.payload_len as usize].copy_from_slice(payload);
        sample
    }

    #[test]
    fn normalizes_ascii_domains() {
        assert_eq!(
            normalize_domain("Example.COM.").as_deref(),
            Some("example.com")
        );
        assert_eq!(normalize_domain("a.b.c").as_deref(), Some("a.b.c"));
    }

    #[test]
    fn preserves_unicode_display_form() {
        assert_eq!(
            normalize_domain("Bücher.Example").as_deref(),
            Some("bücher.example")
        );
    }

    #[test]
    fn rejects_invalid_domains() {
        assert_eq!(normalize_domain(""), None);
        assert_eq!(normalize_domain("."), None);
        assert_eq!(normalize_domain("a..b"), None);
        assert_eq!(normalize_domain("bad domain.example"), None);
        assert_eq!(normalize_domain("path/segment"), None);
        assert_eq!(normalize_domain(&"a".repeat(254)), None);
        let long_label = format!("{}.example", "a".repeat(64));
        assert_eq!(normalize_domain(&long_label), None);
    }

    #[test]
    fn dns_samples_become_inferred_observations_and_deduplicate() {
        let mut decoder = DomainDecoder::new();
        let mut clock = MonoClock::default();
        let base = Instant::now();
        let message = dns_response("Example.COM", &[(300, [93, 184, 216, 34])]);
        let sample = sample(
            SampleKind::Dns,
            TransportProtocol::Udp as u8,
            [8, 8, 8, 8],
            &message,
        );

        let mut observations = Vec::new();
        decoder.decode(&sample, &mut clock, base, &mut observations);
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].domain.as_ref(), "example.com");
        assert_eq!(observations[0].address.to_string(), "93.184.216.34");
        assert_eq!(observations[0].confidence, AssociationConfidence::Inferred);
        assert_eq!(decoder.tracked(), 1);

        let mut duplicates = Vec::new();
        decoder.decode(&sample, &mut clock, base, &mut duplicates);
        assert!(duplicates.is_empty());

        decoder.purge_expired(base + Duration::from_secs(400));
        assert_eq!(decoder.tracked(), 0);
    }

    #[test]
    fn tls_and_http_samples_are_direct_evidence() {
        let mut decoder = DomainDecoder::new();
        let mut clock = MonoClock::default();
        let base = Instant::now();

        let hello = client_hello("cdn.example.com");
        let mut observations = Vec::new();
        decoder.decode(
            &sample(
                SampleKind::TlsClientHello,
                TransportProtocol::Tcp as u8,
                [203, 0, 113, 9],
                &hello,
            ),
            &mut clock,
            base,
            &mut observations,
        );
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].domain.as_ref(), "cdn.example.com");
        assert_eq!(observations[0].address.to_string(), "203.0.113.9");
        assert_eq!(observations[0].confidence, AssociationConfidence::Direct);

        let request = b"GET / HTTP/1.1\r\nHost: Example.COM\r\n\r\n";
        let mut observations = Vec::new();
        decoder.decode(
            &sample(
                SampleKind::HttpRequest,
                TransportProtocol::Tcp as u8,
                [203, 0, 113, 10],
                request,
            ),
            &mut clock,
            base,
            &mut observations,
        );
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].domain.as_ref(), "example.com");
        assert_eq!(observations[0].evidence, DomainEvidence::HttpHost);
    }

    #[test]
    fn invalid_samples_are_dropped() {
        let mut decoder = DomainDecoder::new();
        let mut clock = MonoClock::default();
        let base = Instant::now();
        let message = dns_response("example.com", &[(60, [192, 0, 2, 1])]);

        let mut invalid = sample(
            SampleKind::Dns,
            TransportProtocol::Udp as u8,
            [8, 8, 8, 8],
            &message,
        );
        invalid.kind = 9;
        let mut observations = Vec::new();
        decoder.decode(&invalid, &mut clock, base, &mut observations);
        assert!(observations.is_empty());

        let mut invalid = sample(
            SampleKind::Dns,
            TransportProtocol::Udp as u8,
            [8, 8, 8, 8],
            &message,
        );
        invalid.ip_family = 6;
        decoder.decode(&invalid, &mut clock, base, &mut observations);
        assert!(observations.is_empty());

        let mut invalid = sample(
            SampleKind::Dns,
            TransportProtocol::Udp as u8,
            [8, 8, 8, 8],
            &message,
        );
        invalid.payload_len = 0;
        decoder.decode(&invalid, &mut clock, base, &mut observations);
        assert!(observations.is_empty());

        let mut invalid = sample(
            SampleKind::Dns,
            TransportProtocol::Udp as u8,
            [8, 8, 8, 8],
            &message,
        );
        invalid.transport = 1;
        decoder.decode(&invalid, &mut clock, base, &mut observations);
        assert!(observations.is_empty());
    }

    #[test]
    fn shared_addresses_yield_multiple_candidates() {
        let mut decoder = DomainDecoder::new();
        let mut clock = MonoClock::default();
        let base = Instant::now();
        let mut observations = Vec::new();

        for domain in ["one.example", "two.example"] {
            let message = dns_response(domain, &[(60, [203, 0, 113, 9])]);
            decoder.decode(
                &sample(
                    SampleKind::Dns,
                    TransportProtocol::Udp as u8,
                    [8, 8, 8, 8],
                    &message,
                ),
                &mut clock,
                base,
                &mut observations,
            );
        }

        assert_eq!(observations.len(), 2);
        assert_eq!(observations[0].address, observations[1].address);
    }
}

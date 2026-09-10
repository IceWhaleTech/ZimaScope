//! Validation, normalization and deduplication of domain evidence.

use std::{net::IpAddr, time::Instant};

use hashbrown::HashMap;
use zimascope_common::{
    kernel_abi,
    model::{AssociationConfidence, DomainEvidence, DomainObservation},
};

use super::tracker::MonoClock;

pub(crate) const DOMAIN_MAX_LEN: usize = kernel_abi::DOMAIN_MAX_LEN;
pub(crate) const DOMAIN_LABEL_MAX_LEN: usize = 63;

#[derive(Eq, Hash, PartialEq)]
struct DomainDedupeKey {
    domain: Box<str>,
    address: IpAddr,
    evidence: DomainEvidence,
    client_context: u64,
}

/// Validates kernel domain events and suppresses duplicates until expiry.
#[derive(Default)]
pub(crate) struct DomainDecoder {
    dedupe: HashMap<DomainDedupeKey, Instant>,
}

impl DomainDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn decode(
        &mut self,
        event: &kernel_abi::DomainEvent,
        clock: &mut MonoClock,
        now: Instant,
    ) -> Option<DomainObservation> {
        let evidence = DomainEvidence::from_abi(event.evidence)?;
        if event.ip_family != 4 {
            return None;
        }

        let length = event.domain_len as usize;
        if length == 0 || length > DOMAIN_MAX_LEN {
            return None;
        }

        let raw = std::str::from_utf8(&event.domain[..length]).ok()?;
        let domain = normalize_domain(raw)?;

        let address = IpAddr::V4(std::net::Ipv4Addr::new(
            event.address[12],
            event.address[13],
            event.address[14],
            event.address[15],
        ));

        clock.anchor_if_needed(event.observed_mono_ns, now);
        let observed_at = clock.to_instant(event.observed_mono_ns);
        let expires_at = clock.to_instant(event.expires_mono_ns);

        let key = DomainDedupeKey {
            domain: domain.clone(),
            address,
            evidence,
            client_context: event.client_context,
        };
        if let Some(existing_expiry) = self.dedupe.get(&key) {
            if *existing_expiry > now {
                return None;
            }
        }
        self.dedupe.insert(key, expires_at);

        Some(DomainObservation {
            domain,
            address,
            evidence,
            confidence: confidence_for(evidence),
            client_context: event.client_context,
            observed_at,
            expires_at,
        })
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

    use zimascope_common::kernel_abi::DomainEvidenceKind;

    use super::*;
    use crate::collector::{test_source::abi_domain_event, tracker::MonoClock};

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
    fn dedupes_until_expiry_and_purges() {
        let mut decoder = DomainDecoder::new();
        let mut clock = MonoClock::default();
        let base = Instant::now();
        let event = abi_domain_event(
            DomainEvidenceKind::Dns as u8,
            "example.com",
            [93, 184, 216, 34],
            1_000,
            2_000,
            5,
        );

        let first = decoder
            .decode(&event, &mut clock, base)
            .expect("first observation");
        assert_eq!(first.confidence, AssociationConfidence::Inferred);
        assert_eq!(decoder.tracked(), 1);

        assert!(decoder.decode(&event, &mut clock, base).is_none());

        let after_expiry = base + Duration::from_micros(10);
        assert!(decoder.decode(&event, &mut clock, after_expiry).is_some());
        decoder.purge_expired(after_expiry + Duration::from_secs(1));
        assert_eq!(decoder.tracked(), 0);
    }

    #[test]
    fn direct_evidence_maps_to_direct_confidence() {
        let mut decoder = DomainDecoder::new();
        let mut clock = MonoClock::default();
        let base = Instant::now();

        for kind in [DomainEvidenceKind::TlsSni, DomainEvidenceKind::HttpHost] {
            let event = abi_domain_event(
                kind as u8,
                "cdn.example.com",
                [93, 184, 216, 34],
                1_000,
                2_000,
                7,
            );
            let observation = decoder
                .decode(&event, &mut clock, base)
                .expect("valid event");
            assert_eq!(observation.confidence, AssociationConfidence::Direct);
        }
    }
}

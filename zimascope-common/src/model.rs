//! User-space domain values.
//!
//! These types never cross the kernel boundary and may use normal Rust types.

use std::{
    net::{IpAddr, Ipv4Addr},
    num::NonZeroU32,
    time::{Duration, Instant, SystemTime},
};

use crate::kernel_abi;

/// Identity of one direction of a Flow in user space.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct FlowKey {
    pub source: Endpoint,
    pub destination: Endpoint,
    pub interface_index: NonZeroU32,
    pub protocol: Protocol,
    pub direction: FlowDirection,
}

/// A network peer identified by IP address and, when available, port.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Endpoint {
    pub address: IpAddr,
    pub port: Option<u16>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum Protocol {
    Tcp,
    Udp,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum FlowDirection {
    Inbound,
    Outbound,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TrafficCounters {
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowState {
    Active,
    Ended(EndReason),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum EndReason {
    IdleTimeout,
    TcpFin,
    TcpReset,
    EvictedOrUnknown,
}

/// One Flow as observed across a single collection interval.
///
/// `delta` is the traffic observed since the previous successful poll. `total`
/// is the cumulative value currently represented by the kernel map.
#[derive(Clone, Debug)]
pub struct FlowUpdate {
    pub key: FlowKey,
    pub delta: TrafficCounters,
    pub total: TrafficCounters,
    pub first_seen: Instant,
    pub last_seen: Instant,
    pub state: FlowState,
    /// Fingerprint library match for this Flow, once a sample is classified.
    pub service: Option<Box<str>>,
    /// Application Identity resolved from socket ownership, when observed.
    pub application: Option<ApplicationRef>,
}

/// The process observed to own a Flow, before user-space enrichment.
///
/// `tgid` is the process (thread group) id in the host PID namespace; `comm`
/// was captured in the kernel so a process that exits before the next poll is
/// still identified. Name, executable path and container attribution are
/// resolved downstream where the filesystem is available.
#[derive(Clone, Debug)]
pub struct ApplicationRef {
    pub tgid: u32,
    pub uid: u32,
    pub cgroup_id: u64,
    pub comm: Box<str>,
}

/// Zero-extended 16-byte storage for an IPv4 address, matching the kernel ABI.
pub fn ipv4_storage(address: Ipv4Addr) -> [u8; 16] {
    let mut storage = [0u8; 16];
    storage[12..].copy_from_slice(&address.octets());
    storage
}

/// Reads the IPv4 address from its zero-extended 16-byte kernel storage.
pub fn ipv4_from_abi(storage: [u8; 16]) -> Ipv4Addr {
    Ipv4Addr::new(storage[12], storage[13], storage[14], storage[15])
}

/// Encodes an address and its family the way the kernel ABI stores them.
pub fn ip_storage(address: IpAddr) -> ([u8; 16], kernel_abi::IpFamily) {
    match address {
        IpAddr::V4(address) => (ipv4_storage(address), kernel_abi::IpFamily::V4),
        IpAddr::V6(address) => (address.octets(), kernel_abi::IpFamily::V6),
    }
}

/// Encodes a process name the way `bpf_get_current_comm` does: at most 15
/// bytes plus a NUL terminator.
pub fn comm_bytes(comm: &str) -> [u8; 16] {
    let mut storage = [0u8; 16];
    let length = comm.len().min(15);
    storage[..length].copy_from_slice(&comm.as_bytes()[..length]);
    storage
}

/// Decodes a kernel `comm` value back into text.
pub fn comm_text(raw: &[u8; 16]) -> Box<str> {
    let end = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
    let text = std::str::from_utf8(&raw[..end]).unwrap_or_default();
    text.trim().into()
}

/// An Association between a domain and an Endpoint.
#[derive(Clone, Debug)]
pub struct DomainObservation {
    pub domain: Box<str>,
    pub address: IpAddr,
    pub evidence: DomainEvidence,
    pub confidence: AssociationConfidence,
    pub client_context: u64,
    pub observed_at: Instant,
    pub expires_at: Instant,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum DomainEvidence {
    Dns,
    TlsSni,
    HttpHost,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum AssociationConfidence {
    Direct,
    Inferred,
}

/// Classification of an address relative to the public internet. Only
/// [`AddressScope::Public`] addresses are enriched with geographic data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum AddressScope {
    Public,
    Private,
    Shared,
    FakeIp,
    Loopback,
    LinkLocal,
    UniqueLocal,
    Multicast,
    Broadcast,
    Documentation,
    Reserved,
    Unspecified,
}

/// Locally enriched information about an IP address (PRD 8.5 / 10.3).
#[derive(Clone, Debug)]
pub struct IpProfile {
    pub address: IpAddr,
    pub scope: AddressScope,
    pub country: Option<Box<str>>,
    pub region: Option<Box<str>>,
    pub city_approximate: Option<Box<str>>,
    pub asn: Option<u32>,
    pub organization: Option<Box<str>>,
    pub database_version: Option<Box<str>>,
    pub enriched_at: SystemTime,
}

/// The complete result of one logical collection interval.
#[derive(Clone, Debug)]
pub struct CollectionBatch {
    pub sequence: u64,
    pub collected_at: SystemTime,
    pub interval: Duration,
    pub flows: Vec<FlowUpdate>,
    pub domains: Vec<DomainObservation>,
    pub health: CollectorHealth,
}

#[derive(Clone, Debug)]
pub struct CollectorHealth {
    pub state: CollectorState,
    pub attached_interfaces: Vec<InterfaceHealth>,
    pub map_entries: usize,
    pub map_capacity: usize,
    pub kernel: KernelCounters,
    pub gaps: Vec<ObservationGap>,
    /// Whether Application Identity capture is attached. Attribution is
    /// advisory: collection runs with or without it.
    pub application: ApplicationHealth,
}

#[derive(Clone, Debug, Default)]
pub struct ApplicationHealth {
    /// TCP connect/listen ownership capture is attached.
    pub attached: bool,
    /// UDP send ownership capture is attached.
    pub udp_attached: bool,
    pub last_error: Option<Box<str>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum CollectorState {
    Running,
    Degraded,
    Stopped,
}

#[derive(Clone, Debug)]
pub struct InterfaceHealth {
    pub ifindex: NonZeroU32,
    pub name: Box<str>,
    pub ingress_attached: bool,
    pub egress_attached: bool,
    pub last_error: Option<Box<str>>,
}

/// Kernel counters converted to the interval since the previous poll.
///
/// The field list is defined once and shared by the ABI conversion and the
/// delta arithmetic, so a new kernel counter cannot be half-wired.
macro_rules! kernel_counters {
    ($($field:ident),+ $(,)?) => {
        #[derive(Clone, Copy, Debug, Default)]
        pub struct KernelCounters {
            $(pub $field: u64,)+
        }

        impl From<kernel_abi::KernelStats> for KernelCounters {
            fn from(stats: kernel_abi::KernelStats) -> Self {
                Self { $($field: stats.$field,)+ }
            }
        }

        impl KernelCounters {
            /// Whether every counter is at least its previous value. A
            /// decrease means the kernel object was reloaded.
            pub fn is_monotonic_from(&self, previous: &Self) -> bool {
                true $(&& self.$field >= previous.$field)+
            }

            /// Field-wise delta; callers must check
            /// [`Self::is_monotonic_from`] first.
            pub fn delta_from(&self, previous: &Self) -> Self {
                Self { $($field: self.$field - previous.$field,)+ }
            }
        }
    };
}

kernel_counters! {
    packets_seen,
    packets_parsed,
    parse_failures,
    map_update_failures,
    flow_evictions,
    domain_events_emitted,
    domain_events_dropped,
    service_events_emitted,
    service_events_dropped,
    owner_events_inserted,
    owner_events_dropped,
    policy_dropped_packets,
    policy_dropped_bytes,
    policy_missing_state,
}

/// A known interval in which ZimaScope could not observe complete metadata.
#[derive(Clone, Debug)]
pub struct ObservationGap {
    pub started_at: SystemTime,
    pub ended_at: Option<SystemTime>,
    pub reason: GapReason,
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum GapReason {
    InterfaceDetached { ifindex: u32 },
    MapReadFailed,
}

impl Protocol {
    /// Converts a validated kernel ABI discriminant.
    pub const fn from_abi(value: u8) -> Option<Self> {
        match kernel_abi::TransportProtocol::from_abi(value) {
            Some(kernel_abi::TransportProtocol::Tcp) => Some(Self::Tcp),
            Some(kernel_abi::TransportProtocol::Udp) => Some(Self::Udp),
            None => None,
        }
    }
}

impl FlowDirection {
    /// Converts a validated kernel ABI discriminant.
    pub const fn from_abi(value: u8) -> Option<Self> {
        match kernel_abi::Direction::from_abi(value) {
            Some(kernel_abi::Direction::Inbound) => Some(Self::Inbound),
            Some(kernel_abi::Direction::Outbound) => Some(Self::Outbound),
            None => None,
        }
    }
}

impl AddressScope {
    /// Classifies an address without any external database.
    pub fn classify(address: IpAddr) -> Self {
        match address {
            IpAddr::V4(address) => Self::classify_v4(address),
            IpAddr::V6(address) => Self::classify_v6(address),
        }
    }

    fn classify_v4(address: std::net::Ipv4Addr) -> Self {
        let octets = address.octets();
        let value = u32::from_be_bytes(octets);

        if address.is_broadcast() {
            return Self::Broadcast;
        }
        if address.is_loopback() {
            return Self::Loopback;
        }
        if address.is_private() {
            return Self::Private;
        }
        if address.is_link_local() {
            return Self::LinkLocal;
        }
        if address.is_multicast() {
            return Self::Multicast;
        }
        if address.is_documentation() {
            return Self::Documentation;
        }
        if address.is_unspecified() {
            return Self::Unspecified;
        }
        if value & 0xFFC0_0000 == 0x6440_0000 {
            // 100.64.0.0/10, RFC 6598 carrier-grade NAT.
            return Self::Shared;
        }
        if value & 0xFFFE_0000 == 0xC612_0000 {
            // 198.18.0.0/15, RFC 2544 benchmarking. Local proxies commonly
            // hand these out in fake-IP mode; the true destination never
            // appears at the device boundary.
            return Self::FakeIp;
        }
        if value & 0xFFFFFF00 == 0xC000_0000
            || value & 0xF000_0000 == 0xF000_0000
            || value & 0xFF00_0000 == 0x0000_0000
        {
            // 192.0.0.0/24, 240.0.0.0/4, 0.0.0.0/8.
            return Self::Reserved;
        }

        Self::Public
    }

    fn classify_v6(address: std::net::Ipv6Addr) -> Self {
        if address.is_loopback() {
            return Self::Loopback;
        }
        if address.is_unspecified() {
            return Self::Unspecified;
        }
        if address.is_unique_local() {
            return Self::UniqueLocal;
        }
        if address.is_unicast_link_local() {
            return Self::LinkLocal;
        }
        if address.is_multicast() {
            return Self::Multicast;
        }
        if address.segments()[0] == 0x2001 && address.segments()[1] == 0x0db8 {
            return Self::Documentation;
        }

        Self::Public
    }

    pub const fn is_public(self) -> bool {
        matches!(self, Self::Public)
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::AddressScope;

    fn classify(address: &str) -> AddressScope {
        AddressScope::classify(address.parse::<IpAddr>().expect("valid address"))
    }

    #[test]
    fn classifies_ipv4_scopes() {
        assert_eq!(classify("8.8.8.8"), AddressScope::Public);
        assert_eq!(classify("1.1.1.1"), AddressScope::Public);
        assert_eq!(classify("10.0.0.1"), AddressScope::Private);
        assert_eq!(classify("172.16.0.1"), AddressScope::Private);
        assert_eq!(classify("172.31.255.255"), AddressScope::Private);
        assert_eq!(classify("172.32.0.1"), AddressScope::Public);
        assert_eq!(classify("172.15.255.255"), AddressScope::Public);
        assert_eq!(classify("192.168.1.1"), AddressScope::Private);
        assert_eq!(classify("127.0.0.1"), AddressScope::Loopback);
        assert_eq!(classify("169.254.1.1"), AddressScope::LinkLocal);
        assert_eq!(classify("100.64.0.1"), AddressScope::Shared);
        assert_eq!(classify("100.63.255.255"), AddressScope::Public);
        assert_eq!(classify("100.128.0.1"), AddressScope::Public);
        assert_eq!(classify("224.0.0.1"), AddressScope::Multicast);
        assert_eq!(classify("255.255.255.255"), AddressScope::Broadcast);
        assert_eq!(classify("192.0.2.10"), AddressScope::Documentation);
        assert_eq!(classify("198.51.100.10"), AddressScope::Documentation);
        assert_eq!(classify("203.0.113.10"), AddressScope::Documentation);
        assert_eq!(classify("198.18.0.1"), AddressScope::FakeIp);
        assert_eq!(classify("198.19.255.255"), AddressScope::FakeIp);
        assert_eq!(classify("198.20.0.1"), AddressScope::Public);
        assert_eq!(classify("240.0.0.1"), AddressScope::Reserved);
        assert_eq!(classify("0.0.0.0"), AddressScope::Unspecified);
        assert_eq!(classify("0.1.2.3"), AddressScope::Reserved);
    }

    #[test]
    fn classifies_ipv6_scopes() {
        assert_eq!(classify("2606:4700:4700::1111"), AddressScope::Public);
        assert_eq!(classify("::1"), AddressScope::Loopback);
        assert_eq!(classify("::"), AddressScope::Unspecified);
        assert_eq!(classify("fd00::1"), AddressScope::UniqueLocal);
        assert_eq!(classify("fe80::1"), AddressScope::LinkLocal);
        assert_eq!(classify("ff02::1"), AddressScope::Multicast);
        assert_eq!(classify("2001:db8::1"), AddressScope::Documentation);
    }

    #[test]
    fn only_public_is_enriched() {
        assert!(classify("8.8.8.8").is_public());
        assert!(!classify("192.168.1.1").is_public());
        assert!(!classify("100.64.0.1").is_public());
    }
}

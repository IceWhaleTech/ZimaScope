//! Fixed-size types shared with the eBPF programs.
//!
//! Every type in this module is `#[repr(C)]`, contains no pointers, no
//! platform-sized integers and no types with a destructor, so it can be copied
//! across the kernel/user-space boundary byte for byte. Multi-byte network
//! fields keep network byte order and carry a `_be` suffix.

/// Version of the kernel/user-space contract. Bump this whenever the layout of
/// any type in this module changes.
pub const ABI_VERSION: u16 = 4;

/// Maximum normalized domain length. A DNS name is at most 253 characters.
pub const DOMAIN_MAX_LEN: usize = 253;

/// Maximum L4 payload bytes copied for one domain sample. DNS, TLS SNI and
/// HTTP Host evidence all live near the start of the payload.
pub const DOMAIN_SAMPLE_MAX: usize = 512;

/// Maximum L4 payload bytes copied for one service-fingerprint sample. Every
/// supported signature lives in the first few dozen bytes.
pub const SERVICE_SAMPLE_MAX: usize = 64;

/// `FlowValue::service_flags`: the first payload of this direction has been
/// sampled for protocol fingerprinting.
pub const SERVICE_SAMPLED_FLAG: u16 = 1 << 0;

/// Default number of Flow entries the eBPF map is compiled with.
///
/// The capacity is baked into the eBPF object, so the daemon must refuse to run
/// when [`crate::model`]-side configuration asks for a different value.
pub const DEFAULT_FLOW_CAPACITY: u32 = 65_536;

/// Default number of owning-socket entries the eBPF map is compiled with.
pub const DEFAULT_OWNER_CAPACITY: u32 = 65_536;

/// Default number of listening-port entries the eBPF map is compiled with.
pub const DEFAULT_LISTENER_CAPACITY: u32 = 4_096;

/// Default number of Traffic Rules the match maps are compiled with. Every
/// match map and the rule-state map are sized from this bound.
pub const DEFAULT_TRAFFIC_RULE_CAPACITY: u32 = 64;

/// Program names include the ABI version so a stale object is rejected at
/// lookup instead of running with mismatched struct layouts.
pub const TC_INGRESS_PROGRAM: &str = "tc_ingress_v1";
pub const TC_EGRESS_PROGRAM: &str = "tc_egress_v1";
pub const SOCK_OWNER_PROGRAM: &str = "sock_owner_v1";
pub const UDP_OWNER_PROGRAM: &str = "udp_owner_v1";

pub const ABI_METADATA_MAP: &str = "abi_metadata";
pub const FLOW_MAP: &str = "flow_map";
pub const KERNEL_STATS_MAP: &str = "kernel_stats";
pub const DOMAIN_EVENTS_MAP: &str = "domain_events";
pub const SERVICE_EVENTS_MAP: &str = "service_events";
pub const OWNER_MAP: &str = "owner_map";
pub const LISTENER_MAP: &str = "listener_map";
pub const POLICY_CONFIG_MAP: &str = "policy_config";
pub const RULE_STATES_MAP: &str = "rule_states";
pub const APP_CGROUP_INGRESS_MAP: &str = "app_cgroup_ingress";
pub const APP_CGROUP_EGRESS_MAP: &str = "app_cgroup_egress";
pub const APP_COMM_INGRESS_MAP: &str = "app_comm_ingress";
pub const APP_COMM_EGRESS_MAP: &str = "app_comm_egress";
pub const ENDPOINT_EXACT_INGRESS_MAP: &str = "endpoint_exact_ingress";
pub const ENDPOINT_EXACT_EGRESS_MAP: &str = "endpoint_exact_egress";
pub const ENDPOINT_CIDR_INGRESS_MAP: &str = "endpoint_cidr_ingress";
pub const ENDPOINT_CIDR_EGRESS_MAP: &str = "endpoint_cidr_egress";

/// Compile-time description of the ABI layout, stored in the eBPF object so a
/// version mismatch can be rejected before any collection starts.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct AbiMetadata {
    pub version: u16,
    pub flow_key_size: u16,
    pub flow_value_size: u16,
    pub domain_sample_size: u16,
    pub kernel_stats_size: u16,
    pub service_sample_size: u16,
    pub owner_key_size: u16,
    pub owner_value_size: u16,
    pub rule_state_size: u16,
    pub policy_config_size: u16,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpFamily {
    V4 = 4,
    V6 = 6,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    Inbound = 1,
    Outbound = 2,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportProtocol {
    Tcp = 6,
    Udp = 17,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SampleKind {
    Dns = 1,
    TlsClientHello = 2,
    HttpRequest = 3,
}

/// Whether an [`OwnerKey`] identifies a connected socket or a listening port.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnerKind {
    Socket = 1,
    Listener = 2,
}

impl AbiMetadata {
    /// Metadata describing the current build.
    pub const CURRENT: Self = Self {
        version: ABI_VERSION,
        flow_key_size: core::mem::size_of::<FlowKey>() as u16,
        flow_value_size: core::mem::size_of::<FlowValue>() as u16,
        domain_sample_size: core::mem::size_of::<DomainSample>() as u16,
        kernel_stats_size: core::mem::size_of::<KernelStats>() as u16,
        service_sample_size: core::mem::size_of::<ServiceSample>() as u16,
        owner_key_size: core::mem::size_of::<OwnerKey>() as u16,
        owner_value_size: core::mem::size_of::<OwnerValue>() as u16,
        rule_state_size: core::mem::size_of::<RuleState>() as u16,
        policy_config_size: core::mem::size_of::<PolicyConfig>() as u16,
    };
}

impl IpFamily {
    /// Validates a raw ABI discriminant.
    pub const fn from_abi(value: u8) -> Option<Self> {
        match value {
            4 => Some(Self::V4),
            6 => Some(Self::V6),
            _ => None,
        }
    }
}

impl Direction {
    /// Validates a raw ABI discriminant.
    pub const fn from_abi(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Inbound),
            2 => Some(Self::Outbound),
            _ => None,
        }
    }
}

impl TransportProtocol {
    /// Validates a raw ABI discriminant.
    pub const fn from_abi(value: u8) -> Option<Self> {
        match value {
            6 => Some(Self::Tcp),
            17 => Some(Self::Udp),
            _ => None,
        }
    }
}

impl SampleKind {
    /// Validates a raw ABI discriminant.
    pub const fn from_abi(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Dns),
            2 => Some(Self::TlsClientHello),
            3 => Some(Self::HttpRequest),
            _ => None,
        }
    }
}

impl OwnerKind {
    /// Validates a raw ABI discriminant.
    pub const fn from_abi(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Socket),
            2 => Some(Self::Listener),
            _ => None,
        }
    }
}

/// Action a matched Traffic Rule applies to a packet.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuleAction {
    Limit = 1,
    Block = 2,
}

impl RuleAction {
    /// Validates a raw ABI discriminant.
    pub const fn from_abi(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Limit),
            2 => Some(Self::Block),
            _ => None,
        }
    }
}

/// Identity of one direction of a Flow as observed at the Device Boundary.
///
/// IPv4 addresses occupy the final four bytes of the 16-byte storage and are
/// zero-extended, so the layout does not change when IPv6 is added.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FlowKey {
    pub src_addr: [u8; 16],
    pub dst_addr: [u8; 16],
    pub src_port_be: u16,
    pub dst_port_be: u16,
    pub ifindex: u32,
    pub protocol: u8,
    pub direction: u8,
    pub ip_family: u8,
    pub reserved: u8,
}

/// Cumulative counters for one Flow.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct FlowValue {
    pub packets: u64,
    pub bytes: u64,
    pub first_seen_mono_ns: u64,
    pub last_seen_mono_ns: u64,
    pub tcp_flags: u16,
    pub parse_flags: u16,
    /// Collection-side flags such as [`SERVICE_SAMPLED_FLAG`].
    pub service_flags: u16,
    pub reserved: u16,
}

/// Identity of a socket owner as captured in process context.
///
/// The local address is deliberately excluded so a port-preserving SNAT (for
/// example Docker `MASQUERADE`) still joins a container socket to its Flow at
/// the Device Boundary. `kind = Listener` entries carry the local port only.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct OwnerKey {
    pub remote_addr: [u8; 16],
    pub remote_port_be: u16,
    pub local_port_be: u16,
    pub protocol: u8,
    pub kind: u8,
    pub ip_family: u8,
    pub reserved: u8,
}

/// The process that owns a socket, captured at connect or listen time.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct OwnerValue {
    /// Thread-group id: the process that called connect/listen.
    pub tgid: u32,
    /// Thread id that produced the observation.
    pub pid: u32,
    pub uid: u32,
    pub reserved: u32,
    pub cgroup_id: u64,
    /// `bpf_get_current_comm` at observation time, NUL padded.
    pub comm: [u8; 16],
    pub observed_mono_ns: u64,
}

/// Value stored in every Traffic Rule match map.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct RuleRef {
    pub rule_id: u32,
    pub action: u8,
    pub reserved: [u8; 3],
}

/// Key of one rule-direction rule state entry.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BucketKey {
    pub rule_id: u32,
    pub direction: u8,
    pub reserved: [u8; 3],
}

/// ABI placeholder for the kernel's `struct bpf_spin_lock`.
///
/// The kernel locates the lock in a map value by its exact BTF name, so this
/// type keeps that name; the eBPF side casts a pointer to it into the aya
/// binding of the same layout when calling the spin-lock helpers.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
#[allow(non_camel_case_types)]
pub struct bpf_spin_lock {
    pub val: u32,
}

/// Runtime state of one rule in one direction: a token bucket for `limit`
/// rules and counters for every rule. User space reads and updates it with
/// `BPF_F_LOCK`; the packet path holds `lock` around every read-modify-write.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct RuleState {
    pub lock: bpf_spin_lock,
    pub reserved: u32,
    pub rate_bytes_per_s: u64,
    pub burst_bytes: u64,
    pub tokens: u64,
    pub last_refill_mono_ns: u64,
    pub matched_packets: u64,
    pub matched_bytes: u64,
    pub dropped_packets: u64,
    pub dropped_bytes: u64,
}

/// Exact Endpoint match key. IPv4 addresses are zero-extended; a `port_be` of
/// zero matches every port.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct EndpointMatchKey {
    pub addr: [u8; 16],
    pub port_be: u16,
    pub reserved: [u8; 6],
}

/// Single-entry policy fast path. `app_rules` and `endpoint_rules` let the
/// packet path skip whole tiers that hold no rules.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct PolicyConfig {
    pub enabled: u8,
    pub app_rules: u8,
    pub endpoint_rules: u8,
    pub reserved: u8,
    pub revision: u32,
}

/// One bounded payload sample emitted from the packet path.
///
/// User space parses DNS responses, TLS ClientHellos and HTTP requests out of
/// `payload`; the kernel never assembles domain names. `direction`, `address`
/// and `ifindex` refer to the observed Flow, where `address` is the
/// direction-relative peer.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DomainSample {
    pub observed_mono_ns: u64,
    pub ifindex: u32,
    pub payload_len: u16,
    pub kind: u8,
    pub transport: u8,
    pub ip_family: u8,
    pub direction: u8,
    pub reserved: [u8; 6],
    pub address: [u8; 16],
    pub payload: [u8; DOMAIN_SAMPLE_MAX],
}

/// One bounded first-payload sample emitted once per Flow direction.
///
/// User space matches protocol signatures (SSH banners, database handshakes,
/// TLS records, …) out of `payload`; the kernel never decides what the
/// protocol is and raw bytes are discarded after classification.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ServiceSample {
    pub observed_mono_ns: u64,
    pub key: FlowKey,
    pub payload_len: u16,
    pub reserved: [u8; 6],
    pub payload: [u8; SERVICE_SAMPLE_MAX],
}

/// Cumulative kernel-side counters. One value is kept per CPU and summed by
/// user space.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct KernelStats {
    pub packets_seen: u64,
    pub packets_parsed: u64,
    pub parse_failures: u64,
    pub map_update_failures: u64,
    pub flow_evictions: u64,
    pub domain_events_emitted: u64,
    pub domain_events_dropped: u64,
    pub service_events_emitted: u64,
    pub service_events_dropped: u64,
    pub owner_events_inserted: u64,
    pub owner_events_dropped: u64,
    pub policy_dropped_packets: u64,
    pub policy_dropped_bytes: u64,
    pub policy_missing_state: u64,
}

const _: () = {
    assert!(core::mem::size_of::<AbiMetadata>() == 20);
    assert!(core::mem::align_of::<AbiMetadata>() == 2);

    assert!(core::mem::size_of::<FlowKey>() == 44);
    assert!(core::mem::align_of::<FlowKey>() == 4);

    assert!(core::mem::size_of::<FlowValue>() == 40);
    assert!(core::mem::align_of::<FlowValue>() == 8);

    assert!(core::mem::size_of::<OwnerKey>() == 24);
    assert!(core::mem::align_of::<OwnerKey>() == 2);

    assert!(core::mem::size_of::<OwnerValue>() == 48);
    assert!(core::mem::align_of::<OwnerValue>() == 8);

    assert!(core::mem::size_of::<RuleRef>() == 8);
    assert!(core::mem::align_of::<RuleRef>() == 4);

    assert!(core::mem::size_of::<BucketKey>() == 8);
    assert!(core::mem::align_of::<BucketKey>() == 4);

    assert!(core::mem::size_of::<bpf_spin_lock>() == 4);
    assert!(core::mem::align_of::<bpf_spin_lock>() == 4);

    assert!(core::mem::size_of::<RuleState>() == 72);
    assert!(core::mem::align_of::<RuleState>() == 8);

    assert!(core::mem::size_of::<EndpointMatchKey>() == 24);
    assert!(core::mem::align_of::<EndpointMatchKey>() == 2);

    assert!(core::mem::size_of::<PolicyConfig>() == 8);
    assert!(core::mem::align_of::<PolicyConfig>() == 4);

    assert!(core::mem::size_of::<DomainSample>() == 552);
    assert!(core::mem::align_of::<DomainSample>() == 8);

    assert!(core::mem::size_of::<ServiceSample>() == 128);
    assert!(core::mem::align_of::<ServiceSample>() == 8);

    assert!(core::mem::size_of::<KernelStats>() == 112);
    assert!(core::mem::align_of::<KernelStats>() == 8);

    assert!(core::mem::offset_of!(FlowKey, src_addr) == 0);
    assert!(core::mem::offset_of!(FlowKey, dst_addr) == 16);
    assert!(core::mem::offset_of!(FlowKey, src_port_be) == 32);
    assert!(core::mem::offset_of!(FlowKey, dst_port_be) == 34);
    assert!(core::mem::offset_of!(FlowKey, ifindex) == 36);
    assert!(core::mem::offset_of!(FlowKey, protocol) == 40);
    assert!(core::mem::offset_of!(FlowKey, direction) == 41);
    assert!(core::mem::offset_of!(FlowKey, ip_family) == 42);
    assert!(core::mem::offset_of!(FlowKey, reserved) == 43);

    assert!(core::mem::offset_of!(OwnerKey, remote_addr) == 0);
    assert!(core::mem::offset_of!(OwnerKey, remote_port_be) == 16);
    assert!(core::mem::offset_of!(OwnerKey, local_port_be) == 18);
    assert!(core::mem::offset_of!(OwnerKey, protocol) == 20);
    assert!(core::mem::offset_of!(OwnerKey, kind) == 21);
    assert!(core::mem::offset_of!(OwnerKey, ip_family) == 22);

    assert!(core::mem::offset_of!(OwnerValue, cgroup_id) == 16);
    assert!(core::mem::offset_of!(OwnerValue, comm) == 24);
    assert!(core::mem::offset_of!(OwnerValue, observed_mono_ns) == 40);

    assert!(core::mem::offset_of!(DomainSample, address) == 24);
    assert!(core::mem::offset_of!(DomainSample, payload) == 40);

    assert!(core::mem::offset_of!(ServiceSample, key) == 8);
    assert!(core::mem::offset_of!(ServiceSample, payload_len) == 52);
    assert!(core::mem::offset_of!(ServiceSample, payload) == 60);

    assert!(core::mem::offset_of!(FlowValue, tcp_flags) == 32);
    assert!(core::mem::offset_of!(FlowValue, parse_flags) == 34);
    assert!(core::mem::offset_of!(FlowValue, service_flags) == 36);

    assert!(core::mem::offset_of!(RuleRef, rule_id) == 0);
    assert!(core::mem::offset_of!(RuleRef, action) == 4);

    assert!(core::mem::offset_of!(BucketKey, rule_id) == 0);
    assert!(core::mem::offset_of!(BucketKey, direction) == 4);

    assert!(core::mem::offset_of!(RuleState, lock) == 0);
    assert!(core::mem::offset_of!(RuleState, reserved) == 4);
    assert!(core::mem::offset_of!(RuleState, rate_bytes_per_s) == 8);
    assert!(core::mem::offset_of!(RuleState, tokens) == 24);
    assert!(core::mem::offset_of!(RuleState, last_refill_mono_ns) == 32);
    assert!(core::mem::offset_of!(RuleState, matched_packets) == 40);
    assert!(core::mem::offset_of!(RuleState, dropped_bytes) == 64);

    assert!(core::mem::offset_of!(EndpointMatchKey, addr) == 0);
    assert!(core::mem::offset_of!(EndpointMatchKey, port_be) == 16);

    assert!(core::mem::offset_of!(PolicyConfig, enabled) == 0);
    assert!(core::mem::offset_of!(PolicyConfig, revision) == 4);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_describes_current_layout() {
        let metadata = AbiMetadata::CURRENT;
        assert_eq!(metadata.version, ABI_VERSION);
        assert_eq!(metadata.flow_key_size as usize, size_of::<FlowKey>());
        assert_eq!(metadata.flow_value_size as usize, size_of::<FlowValue>());
        assert_eq!(
            metadata.domain_sample_size as usize,
            size_of::<DomainSample>()
        );
        assert_eq!(
            metadata.service_sample_size as usize,
            size_of::<ServiceSample>()
        );
        assert_eq!(
            metadata.kernel_stats_size as usize,
            size_of::<KernelStats>()
        );
        assert_eq!(metadata.owner_key_size as usize, size_of::<OwnerKey>());
        assert_eq!(metadata.owner_value_size as usize, size_of::<OwnerValue>());
        assert_eq!(metadata.rule_state_size as usize, size_of::<RuleState>());
        assert_eq!(
            metadata.policy_config_size as usize,
            size_of::<PolicyConfig>()
        );
    }

    #[test]
    fn discriminants_round_trip() {
        assert_eq!(IpFamily::from_abi(4), Some(IpFamily::V4));
        assert_eq!(IpFamily::from_abi(6), Some(IpFamily::V6));
        assert_eq!(IpFamily::from_abi(0), None);

        assert_eq!(Direction::from_abi(1), Some(Direction::Inbound));
        assert_eq!(Direction::from_abi(2), Some(Direction::Outbound));
        assert_eq!(Direction::from_abi(3), None);

        assert_eq!(TransportProtocol::from_abi(6), Some(TransportProtocol::Tcp));
        assert_eq!(
            TransportProtocol::from_abi(17),
            Some(TransportProtocol::Udp)
        );
        assert_eq!(TransportProtocol::from_abi(1), None);

        assert_eq!(SampleKind::from_abi(1), Some(SampleKind::Dns));
        assert_eq!(SampleKind::from_abi(2), Some(SampleKind::TlsClientHello));
        assert_eq!(SampleKind::from_abi(3), Some(SampleKind::HttpRequest));
        assert_eq!(SampleKind::from_abi(4), None);

        assert_eq!(OwnerKind::from_abi(1), Some(OwnerKind::Socket));
        assert_eq!(OwnerKind::from_abi(2), Some(OwnerKind::Listener));
        assert_eq!(OwnerKind::from_abi(3), None);

        assert_eq!(RuleAction::from_abi(1), Some(RuleAction::Limit));
        assert_eq!(RuleAction::from_abi(2), Some(RuleAction::Block));
        assert_eq!(RuleAction::from_abi(3), None);
    }

    #[test]
    fn ipv4_storage_is_zero_extended() {
        fn ipv4(addr: [u8; 4]) -> [u8; 16] {
            let mut storage = [0u8; 16];
            storage[12..].copy_from_slice(&addr);
            storage
        }

        let key = FlowKey {
            src_addr: ipv4([192, 168, 1, 10]),
            dst_addr: ipv4([1, 1, 1, 1]),
            src_port_be: 443u16.to_be(),
            dst_port_be: 52_340u16.to_be(),
            ifindex: 2,
            protocol: TransportProtocol::Tcp as u8,
            direction: Direction::Outbound as u8,
            ip_family: IpFamily::V4 as u8,
            reserved: 0,
        };

        assert_eq!(&key.src_addr[..12], &[0u8; 12]);
        assert_eq!(&key.src_addr[12..], &[192, 168, 1, 10]);
        assert_eq!(u16::from_be(key.dst_port_be), 52_340);
    }
}

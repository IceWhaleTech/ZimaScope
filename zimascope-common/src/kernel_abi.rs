//! Fixed-size types shared with the eBPF programs.
//!
//! Every type in this module is `#[repr(C)]`, contains no pointers, no
//! platform-sized integers and no types with a destructor, so it can be copied
//! across the kernel/user-space boundary byte for byte. Multi-byte network
//! fields keep network byte order and carry a `_be` suffix.

/// Version of the kernel/user-space contract. Bump this whenever the layout of
/// any type in this module changes.
pub const ABI_VERSION: u16 = 1;

/// Maximum normalized domain length. A DNS name is at most 253 characters.
pub const DOMAIN_MAX_LEN: usize = 253;

/// Default number of Flow entries the eBPF map is compiled with.
///
/// The capacity is baked into the eBPF object, so the daemon must refuse to run
/// when [`crate::model`]-side configuration asks for a different value.
pub const DEFAULT_FLOW_CAPACITY: u32 = 65_536;

/// Program names include the ABI version so a stale object is rejected at
/// lookup instead of running with mismatched struct layouts.
pub const TC_INGRESS_PROGRAM: &str = "tc_ingress_v1";
pub const TC_EGRESS_PROGRAM: &str = "tc_egress_v1";

pub const ABI_METADATA_MAP: &str = "abi_metadata";
pub const FLOW_MAP: &str = "flow_map";
pub const KERNEL_STATS_MAP: &str = "kernel_stats";
pub const DOMAIN_EVENTS_MAP: &str = "domain_events";

/// Compile-time description of the ABI layout, stored in the eBPF object so a
/// version mismatch can be rejected before any collection starts.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct AbiMetadata {
    pub version: u16,
    pub flow_key_size: u16,
    pub flow_value_size: u16,
    pub domain_event_size: u16,
    pub kernel_stats_size: u16,
    pub reserved: [u8; 6],
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
pub enum DomainEvidenceKind {
    Dns = 1,
    TlsSni = 2,
    HttpHost = 3,
}

impl AbiMetadata {
    /// Metadata describing the current build.
    pub const CURRENT: Self = Self {
        version: ABI_VERSION,
        flow_key_size: core::mem::size_of::<FlowKey>() as u16,
        flow_value_size: core::mem::size_of::<FlowValue>() as u16,
        domain_event_size: core::mem::size_of::<DomainEvent>() as u16,
        kernel_stats_size: core::mem::size_of::<KernelStats>() as u16,
        reserved: [0; 6],
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

impl DomainEvidenceKind {
    /// Validates a raw ABI discriminant.
    pub const fn from_abi(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Dns),
            2 => Some(Self::TlsSni),
            3 => Some(Self::HttpHost),
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
    pub reserved: u32,
}

/// One bounded domain-evidence event emitted from the packet path.
///
/// `direction`, `address` and `ifindex` refer to the observed Flow so user
/// space can associate the domain with an Endpoint. DNS events carry the
/// resolved address; TLS SNI and HTTP Host events carry the peer address.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DomainEvent {
    pub observed_mono_ns: u64,
    pub expires_mono_ns: u64,
    pub client_context: u64,
    pub address: [u8; 16],
    pub ifindex: u32,
    pub domain_len: u16,
    pub evidence: u8,
    pub ip_family: u8,
    pub direction: u8,
    pub reserved: u8,
    pub domain: [u8; DOMAIN_MAX_LEN],
    pub padding: u8,
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
}

const _: () = {
    assert!(core::mem::size_of::<AbiMetadata>() == 16);
    assert!(core::mem::align_of::<AbiMetadata>() == 2);

    assert!(core::mem::size_of::<FlowKey>() == 44);
    assert!(core::mem::align_of::<FlowKey>() == 4);

    assert!(core::mem::size_of::<FlowValue>() == 40);
    assert!(core::mem::align_of::<FlowValue>() == 8);

    assert!(core::mem::size_of::<DomainEvent>() == 304);
    assert!(core::mem::align_of::<DomainEvent>() == 8);

    assert!(core::mem::size_of::<KernelStats>() == 56);
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

    assert!(core::mem::offset_of!(DomainEvent, domain) == 50);
    assert!(core::mem::offset_of!(DomainEvent, padding) == 303);

    assert!(core::mem::offset_of!(FlowValue, tcp_flags) == 32);
    assert!(core::mem::offset_of!(FlowValue, parse_flags) == 34);
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
            metadata.domain_event_size as usize,
            size_of::<DomainEvent>()
        );
        assert_eq!(
            metadata.kernel_stats_size as usize,
            size_of::<KernelStats>()
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

        assert_eq!(
            DomainEvidenceKind::from_abi(1),
            Some(DomainEvidenceKind::Dns)
        );
        assert_eq!(
            DomainEvidenceKind::from_abi(2),
            Some(DomainEvidenceKind::TlsSni)
        );
        assert_eq!(
            DomainEvidenceKind::from_abi(3),
            Some(DomainEvidenceKind::HttpHost)
        );
        assert_eq!(DomainEvidenceKind::from_abi(4), None);
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

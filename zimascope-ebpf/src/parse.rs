//! Bounded Ethernet/VLAN/IPv4/TCP/UDP parsing.
//!
//! Parsing is generic over a [`PacketCursor`] so the exact same code runs in
//! the eBPF program against verified packet pointers and in host unit tests
//! against a byte slice. Every field access is bounds checked; a packet that
//! cannot be fully parsed never changes traffic and is reported as
//! [`ParseResult::Truncated`] or [`ParseResult::Invalid`].

use core::mem::offset_of;

use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
    vlan::VlanHdr,
};
use zimascope_common::kernel_abi::IpFamily;

const TCP_DATA_OFFSET_AND_FLAGS_OFFSET: usize = 12;

#[inline(always)]
const fn ether_type_host(value: EtherType) -> u16 {
    // EtherType discriminants are stored in network byte order by network-types.
    (value as u16).to_be()
}

/// Bits recorded in [`zimascope_common::kernel_abi::FlowValue::parse_flags`].
pub const PARSE_FLAG_VLAN_TAGGED: u16 = 1 << 0;
pub const PARSE_FLAG_IP_OPTIONS: u16 = 1 << 1;
pub const PARSE_FLAG_IP_FRAGMENTED: u16 = 1 << 2;

/// Result of parsing one captured packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseResult {
    /// The packet is an IPv4 TCP/UDP Flow observation.
    Flow(ParsedFlow),
    /// The packet is well-formed but outside V1 scope: another L3 protocol,
    /// another L4 protocol, or a non-initial IP fragment.
    Skipped,
    /// Captured bytes ended before a required header was complete.
    Truncated,
    /// A header contained values that cannot describe a valid packet.
    Invalid,
}

/// The Flow-relevant fields extracted from one packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParsedFlow {
    pub src_addr: [u8; 16],
    pub dst_addr: [u8; 16],
    pub src_port_be: u16,
    pub dst_port_be: u16,
    pub protocol: u8,
    pub ip_family: u8,
    pub tcp_flags: u16,
    pub parse_flags: u16,
    pub payload_offset: usize,
    pub payload_end: usize,
}

impl ParseResult {
    pub const fn is_flow(&self) -> bool {
        matches!(self, Self::Flow(_))
    }

    /// Whether the packet was in scope but malformed or incomplete.
    pub const fn is_failure(&self) -> bool {
        matches!(self, Self::Truncated | Self::Invalid)
    }
}

/// Bounded byte access. Implementations must never read outside the captured
/// packet; returning `None` is the only failure mode.
pub trait PacketCursor {
    fn read_u8(&self, offset: usize) -> Option<u8>;
    fn read_u16_be(&self, offset: usize) -> Option<u16>;
    fn read_u32_be(&self, offset: usize) -> Option<u32>;

    /// Copies `len` bytes at `offset` into `destination`. Returns `false` when
    /// any byte is outside the captured packet.
    ///
    /// Implementations should override this with a bulk copy; the default
    /// exists for in-memory cursors.
    fn read_bytes(&self, offset: usize, destination: &mut [u8]) -> bool {
        for (index, byte) in destination.iter_mut().enumerate() {
            match self.read_u8(offset + index) {
                Some(value) => *byte = value,
                None => return false,
            }
        }
        true
    }

    /// Whether `len` bytes at `offset` are present in the captured packet.
    fn has(&self, offset: usize, len: usize) -> bool {
        len == 0 || self.read_u8(offset + len - 1).is_some()
    }
}

/// Packet cursor over a captured byte slice.
///
/// Used by user space to parse the bounded payload samples emitted by the
/// kernel, and by the host unit tests.
pub struct MemoryCursor<'a> {
    data: &'a [u8],
}

impl<'a> MemoryCursor<'a> {
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    pub const fn len(&self) -> usize {
        self.data.len()
    }

    pub const fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl PacketCursor for MemoryCursor<'_> {
    #[inline(always)]
    fn read_u8(&self, offset: usize) -> Option<u8> {
        self.data.get(offset).copied()
    }

    #[inline(always)]
    fn read_u16_be(&self, offset: usize) -> Option<u16> {
        let bytes = self.data.get(offset..offset + 2)?;
        Some(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    #[inline(always)]
    fn read_u32_be(&self, offset: usize) -> Option<u32> {
        let bytes = self.data.get(offset..offset + 4)?;
        Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    #[inline(always)]
    fn read_bytes(&self, offset: usize, destination: &mut [u8]) -> bool {
        match self.data.get(offset..offset + destination.len()) {
            Some(bytes) => {
                destination.copy_from_slice(bytes);
                true
            }
            None => false,
        }
    }
}

/// Parses one captured packet into a Flow observation.
#[inline(always)]
pub fn parse<C: PacketCursor + ?Sized>(cursor: &C) -> ParseResult {
    let (ethertype, l3_offset) = match cursor.read_u16_be(offset_of!(EthHdr, ether_type)) {
        Some(value)
            if value == ether_type_host(EtherType::Ieee8021q)
                || value == ether_type_host(EtherType::Ieee8021ad) =>
        {
            match cursor.read_u16_be(EthHdr::LEN + offset_of!(VlanHdr, ether_type)) {
                Some(inner) => (inner, EthHdr::LEN + VlanHdr::LEN),
                None => return ParseResult::Truncated,
            }
        }
        Some(ethertype) => (ethertype, EthHdr::LEN),
        None => return ParseResult::Truncated,
    };

    if ethertype != ether_type_host(EtherType::Ipv4) {
        return ParseResult::Skipped;
    }

    parse_ipv4(cursor, l3_offset)
}

#[inline(always)]
fn parse_ipv4<C: PacketCursor + ?Sized>(cursor: &C, l3_offset: usize) -> ParseResult {
    let version_ihl = match cursor.read_u8(l3_offset + offset_of!(Ipv4Hdr, vihl)) {
        Some(value) => value,
        None => return ParseResult::Truncated,
    };
    if version_ihl >> 4 != 4 {
        return ParseResult::Invalid;
    }

    let ihl_words = (version_ihl & 0x0F) as usize;
    if ihl_words < Ipv4Hdr::LEN / 4 {
        return ParseResult::Invalid;
    }
    let ip_header_len = ihl_words * 4;

    let total_length = match cursor.read_u16_be(l3_offset + offset_of!(Ipv4Hdr, tot_len)) {
        Some(value) => value as usize,
        None => return ParseResult::Truncated,
    };
    if total_length < ip_header_len {
        return ParseResult::Invalid;
    }

    let fragment = match cursor.read_u16_be(l3_offset + offset_of!(Ipv4Hdr, frags)) {
        Some(value) => value,
        None => return ParseResult::Truncated,
    };
    if fragment & 0x1FFF != 0 {
        // Later fragments do not carry a TCP/UDP header.
        return ParseResult::Skipped;
    }

    let protocol = match cursor.read_u8(l3_offset + offset_of!(Ipv4Hdr, proto)) {
        Some(value) => value,
        None => return ParseResult::Truncated,
    };

    let src_word = match cursor.read_u32_be(l3_offset + offset_of!(Ipv4Hdr, src_addr)) {
        Some(value) => value,
        None => return ParseResult::Truncated,
    };
    let dst_word = match cursor.read_u32_be(l3_offset + offset_of!(Ipv4Hdr, dst_addr)) {
        Some(value) => value,
        None => return ParseResult::Truncated,
    };

    let l4_offset = l3_offset + ip_header_len;
    let declared_end = l3_offset + total_length;

    let mut parse_flags = 0u16;
    if ihl_words > Ipv4Hdr::LEN / 4 {
        parse_flags |= PARSE_FLAG_IP_OPTIONS;
    }
    if fragment & (1 << 13) != 0 {
        parse_flags |= PARSE_FLAG_IP_FRAGMENTED;
    }

    match protocol {
        value if value == IpProto::Tcp as u8 => {
            if l4_offset + TcpHdr::LEN > declared_end || !cursor.has(l4_offset, TcpHdr::LEN) {
                return ParseResult::Truncated;
            }
        }
        value if value == IpProto::Udp as u8 => {
            if l4_offset + UdpHdr::LEN > declared_end || !cursor.has(l4_offset, UdpHdr::LEN) {
                return ParseResult::Truncated;
            }
        }
        _ => return ParseResult::Skipped,
    }

    let (src_port_offset, dst_port_offset) = if protocol == IpProto::Tcp as u8 {
        (offset_of!(TcpHdr, source), offset_of!(TcpHdr, dest))
    } else {
        (offset_of!(UdpHdr, src), offset_of!(UdpHdr, dst))
    };
    let src_port_be = match cursor.read_u16_be(l4_offset + src_port_offset) {
        Some(value) => value,
        None => return ParseResult::Truncated,
    };
    let dst_port_be = match cursor.read_u16_be(l4_offset + dst_port_offset) {
        Some(value) => value,
        None => return ParseResult::Truncated,
    };

    let (tcp_flags, l4_header_len) = if protocol == IpProto::Tcp as u8 {
        let offset_flags = match cursor.read_u16_be(l4_offset + TCP_DATA_OFFSET_AND_FLAGS_OFFSET) {
            Some(value) => value,
            None => return ParseResult::Truncated,
        };
        let data_offset_words = (offset_flags >> 12) as usize;
        if data_offset_words < TcpHdr::LEN / 4 {
            return ParseResult::Invalid;
        }
        if l4_offset + data_offset_words * 4 > declared_end
            || !cursor.has(l4_offset, data_offset_words * 4)
        {
            return ParseResult::Truncated;
        }
        (offset_flags & 0x01FF, data_offset_words * 4)
    } else {
        (0, UdpHdr::LEN)
    };

    ParseResult::Flow(ParsedFlow {
        src_addr: ipv4_storage(src_word),
        dst_addr: ipv4_storage(dst_word),
        src_port_be: src_port_be.to_be(),
        dst_port_be: dst_port_be.to_be(),
        protocol,
        ip_family: IpFamily::V4 as u8,
        tcp_flags,
        parse_flags,
        payload_offset: l4_offset + l4_header_len,
        payload_end: declared_end,
    })
}

#[inline(always)]
fn ipv4_storage(word_be: u32) -> [u8; 16] {
    let mut storage = [0u8; 16];
    storage[12..].copy_from_slice(&word_be.to_be_bytes());
    storage
}

#[cfg(test)]
impl PacketCursor for [u8] {
    #[inline(always)]
    fn read_u8(&self, offset: usize) -> Option<u8> {
        self.get(offset).copied()
    }

    #[inline(always)]
    fn read_u16_be(&self, offset: usize) -> Option<u16> {
        let bytes = self.get(offset..offset + 2)?;
        Some(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    #[inline(always)]
    fn read_u32_be(&self, offset: usize) -> Option<u32> {
        let bytes = self.get(offset..offset + 4)?;
        Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::vec::Vec;

    use super::*;

    const SRC: [u8; 4] = [192, 168, 1, 10];
    const DST: [u8; 4] = [93, 184, 216, 34];

    struct PacketBuilder {
        bytes: Vec<u8>,
    }

    impl PacketBuilder {
        fn ethernet(ethertype: u16) -> Self {
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&[0xAA; 6]);
            bytes.extend_from_slice(&[0xBB; 6]);
            bytes.extend_from_slice(&ethertype.to_be_bytes());
            Self { bytes }
        }

        fn vlan(mut self, inner: u16) -> Self {
            self.bytes.extend_from_slice(&[0x00, 0x64]);
            self.bytes.extend_from_slice(&inner.to_be_bytes());
            self
        }

        fn ipv4(self, protocol: u8, fragment: u16, ihl_words: u8, payload_len: usize) -> Self {
            self.ipv4_from(SRC, DST, protocol, fragment, ihl_words, payload_len)
        }

        fn ipv4_from(
            mut self,
            src: [u8; 4],
            dst: [u8; 4],
            protocol: u8,
            fragment: u16,
            ihl_words: u8,
            payload_len: usize,
        ) -> Self {
            let header_len = ihl_words as usize * 4;
            let total_length = header_len + payload_len;
            self.bytes.push((4 << 4) | (ihl_words & 0x0F));
            self.bytes.push(0);
            self.bytes
                .extend_from_slice(&(total_length as u16).to_be_bytes());
            self.bytes.extend_from_slice(&[0x12, 0x34]);
            self.bytes.extend_from_slice(&fragment.to_be_bytes());
            self.bytes.push(64);
            self.bytes.push(protocol);
            self.bytes.extend_from_slice(&[0, 0]);
            self.bytes.extend_from_slice(&src);
            self.bytes.extend_from_slice(&dst);
            while self.bytes.len() < EthHdr::LEN + header_len {
                self.bytes.push(0xEE);
            }
            self
        }

        fn payload(mut self, payload: &[u8]) -> Self {
            self.bytes.extend_from_slice(payload);
            self
        }

        fn build(self) -> Vec<u8> {
            self.bytes
        }
    }

    fn tcp_segment(src_port: u16, dst_port: u16, data_offset_words: u8, flags: u16) -> Vec<u8> {
        let mut segment = Vec::new();
        segment.extend_from_slice(&src_port.to_be_bytes());
        segment.extend_from_slice(&dst_port.to_be_bytes());
        segment.extend_from_slice(&1u32.to_be_bytes());
        segment.extend_from_slice(&2u32.to_be_bytes());
        segment.push(data_offset_words << 4);
        segment.push((flags & 0xFF) as u8);
        segment.extend_from_slice(&1024u16.to_be_bytes());
        segment.extend_from_slice(&[0, 0, 0, 0]);
        while segment.len() < data_offset_words as usize * 4 {
            segment.push(0x11);
        }
        segment
    }

    fn udp_segment(src_port: u16, dst_port: u16, payload_len: usize) -> Vec<u8> {
        let mut segment = Vec::new();
        segment.extend_from_slice(&src_port.to_be_bytes());
        segment.extend_from_slice(&dst_port.to_be_bytes());
        segment.extend_from_slice(&((UdpHdr::LEN + payload_len) as u16).to_be_bytes());
        segment.extend_from_slice(&[0, 0]);
        segment.resize(UdpHdr::LEN + payload_len, 0x22);
        segment
    }

    fn assert_flow(result: ParseResult) -> ParsedFlow {
        match result {
            ParseResult::Flow(flow) => flow,
            other => panic!("expected a parsed flow, got {other:?}"),
        }
    }

    #[test]
    fn parses_ipv4_tcp() {
        let segment = tcp_segment(52_340, 443, 5, 0x02);
        let payload_len = segment.len();
        let packet = PacketBuilder::ethernet(ether_type_host(EtherType::Ipv4))
            .ipv4(IpProto::Tcp as u8, 0, 5, payload_len)
            .payload(&segment)
            .build();

        let flow = assert_flow(parse(&packet[..]));
        assert_eq!(&flow.src_addr[12..], &SRC);
        assert_eq!(&flow.dst_addr[12..], &DST);
        assert_eq!(&flow.src_addr[..12], &[0u8; 12]);
        assert_eq!(u16::from_be(flow.src_port_be), 52_340);
        assert_eq!(u16::from_be(flow.dst_port_be), 443);
        assert_eq!(flow.protocol, 6);
        assert_eq!(flow.ip_family, 4);
        assert_eq!(flow.tcp_flags & 0x02, 0x02);
        assert_eq!(flow.parse_flags, 0);
    }

    #[test]
    fn parses_single_vlan_tag() {
        let segment = tcp_segment(1_024, 80, 5, 0x10);
        let payload_len = segment.len();
        let packet = PacketBuilder::ethernet(ether_type_host(EtherType::Ieee8021q))
            .vlan(ether_type_host(EtherType::Ipv4))
            .ipv4(IpProto::Tcp as u8, 0, 5, payload_len)
            .payload(&segment)
            .build();

        let flow = assert_flow(parse(&packet[..]));
        assert_eq!(u16::from_be(flow.dst_port_be), 80);
        assert_eq!(u16::from_be(flow.src_port_be), 1_024);
    }

    #[test]
    fn parses_ipv4_udp() {
        let segment = udp_segment(53, 40_000, 16);
        let payload_len = segment.len();
        let packet = PacketBuilder::ethernet(ether_type_host(EtherType::Ipv4))
            .ipv4(IpProto::Udp as u8, 0, 5, payload_len)
            .payload(&segment)
            .build();

        let flow = assert_flow(parse(&packet[..]));
        assert_eq!(u16::from_be(flow.src_port_be), 53);
        assert_eq!(u16::from_be(flow.dst_port_be), 40_000);
        assert_eq!(flow.protocol, 17);
        assert_eq!(flow.tcp_flags, 0);
    }

    #[test]
    fn ipv4_options_shift_the_l4_offset() {
        let segment = tcp_segment(443, 50_000, 5, 0x12);
        let payload_len = segment.len();
        let packet = PacketBuilder::ethernet(ether_type_host(EtherType::Ipv4))
            .ipv4(IpProto::Tcp as u8, 0, 6, payload_len)
            .payload(&segment)
            .build();

        let flow = assert_flow(parse(&packet[..]));
        assert_eq!(u16::from_be(flow.src_port_be), 443);
        assert_eq!(
            flow.parse_flags & PARSE_FLAG_IP_OPTIONS,
            PARSE_FLAG_IP_OPTIONS
        );
    }

    #[test]
    fn first_fragment_with_mf_is_parsed() {
        let segment = tcp_segment(443, 50_000, 5, 0x10);
        let payload_len = segment.len();
        let packet = PacketBuilder::ethernet(ether_type_host(EtherType::Ipv4))
            .ipv4(IpProto::Tcp as u8, 1 << 13, 5, payload_len)
            .payload(&segment)
            .build();

        let flow = assert_flow(parse(&packet[..]));
        assert_eq!(
            flow.parse_flags & PARSE_FLAG_IP_FRAGMENTED,
            PARSE_FLAG_IP_FRAGMENTED
        );
    }

    #[test]
    fn non_initial_fragment_is_skipped() {
        let packet = PacketBuilder::ethernet(ether_type_host(EtherType::Ipv4))
            .ipv4(IpProto::Tcp as u8, 0x0100, 5, UdpHdr::LEN)
            .payload(&[0u8; 8])
            .build();

        assert_eq!(parse(&packet[..]), ParseResult::Skipped);
    }

    #[test]
    fn non_ipv4_ethertypes_are_skipped() {
        let arp = PacketBuilder::ethernet(0x0806).build();
        assert_eq!(parse(&arp[..]), ParseResult::Skipped);

        let ipv6 = PacketBuilder::ethernet(ether_type_host(EtherType::Ipv6)).build();
        assert_eq!(parse(&ipv6[..]), ParseResult::Skipped);
    }

    #[test]
    fn unsupported_l4_protocol_is_skipped() {
        let packet = PacketBuilder::ethernet(ether_type_host(EtherType::Ipv4))
            .ipv4(1, 0, 5, 8)
            .payload(&[0u8; 8])
            .build();

        assert_eq!(parse(&packet[..]), ParseResult::Skipped);
    }

    #[test]
    fn only_malformed_or_incomplete_packets_are_failures() {
        assert!(!ParseResult::Skipped.is_failure());
        assert!(ParseResult::Truncated.is_failure());
        assert!(ParseResult::Invalid.is_failure());
    }

    #[test]
    fn truncated_frames_never_parse() {
        let segment = tcp_segment(443, 50_000, 5, 0x10);
        let payload_len = segment.len();
        let packet = PacketBuilder::ethernet(ether_type_host(EtherType::Ipv4))
            .ipv4(IpProto::Tcp as u8, 0, 5, payload_len)
            .payload(&segment)
            .build();

        let complete_header_len = EthHdr::LEN + Ipv4Hdr::LEN + TcpHdr::LEN;
        for len in 0..complete_header_len {
            let result = parse(&packet[..len]);
            assert!(
                !result.is_flow(),
                "a frame truncated to {len} bytes must not parse"
            );
        }
        assert!(parse(&packet[..complete_header_len]).is_flow());
        assert!(parse(&packet[..]).is_flow());
    }

    #[test]
    fn invalid_ipv4_lengths_are_rejected() {
        let mut packet = PacketBuilder::ethernet(ether_type_host(EtherType::Ipv4))
            .ipv4(IpProto::Tcp as u8, 0, 5, TcpHdr::LEN)
            .payload(&tcp_segment(1, 2, 5, 0))
            .build();
        let total_length = EthHdr::LEN + offset_of!(Ipv4Hdr, tot_len);
        packet[total_length..total_length + 2].copy_from_slice(&10u16.to_be_bytes());
        assert_eq!(parse(&packet[..]), ParseResult::Invalid);
    }

    #[test]
    fn invalid_ihl_is_rejected() {
        let mut packet = PacketBuilder::ethernet(ether_type_host(EtherType::Ipv4))
            .ipv4(IpProto::Tcp as u8, 0, 5, TcpHdr::LEN)
            .payload(&tcp_segment(1, 2, 5, 0))
            .build();
        packet[EthHdr::LEN + offset_of!(Ipv4Hdr, vihl)] = (4 << 4) | 4;
        assert_eq!(parse(&packet[..]), ParseResult::Invalid);
    }

    #[test]
    fn invalid_tcp_data_offset_is_rejected() {
        let segment = tcp_segment(443, 50_000, 4, 0x10);
        let payload_len = segment.len();
        let packet = PacketBuilder::ethernet(ether_type_host(EtherType::Ipv4))
            .ipv4(IpProto::Tcp as u8, 0, 5, payload_len)
            .payload(&segment)
            .build();

        assert_eq!(parse(&packet[..]), ParseResult::Invalid);
    }
}

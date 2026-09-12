//! TC ingress and egress entry points.
//!
//! Every path returns `TC_ACT_UNSPEC`: ZimaScope observes traffic and never
//! drops, delays or modifies a packet. Under tcx multiprog a program that
//! returns `TC_ACT_OK` also stops the chain, so `TC_ACT_UNSPEC` is what lets
//! other classifiers attached to the same interface still run; when ZimaScope
//! is last the kernel treats it as pass.
//!
//! The packet path never parses domain evidence. For candidate packets it
//! peeks at constant offsets and copies a bounded L4 payload sample into a
//! ring buffer; DNS, TLS SNI and HTTP Host are parsed in user space.

use aya_ebpf::{
    bindings::{BPF_ANY, TC_ACT_UNSPEC},
    cty::c_void,
    helpers::{bpf_ktime_get_ns, bpf_skb_load_bytes},
    macros::classifier,
    programs::TcContext,
};
use zimascope_common::kernel_abi::{
    DOMAIN_SAMPLE_MAX, Direction, DomainSample, FlowKey, FlowValue, IpFamily, SERVICE_SAMPLE_MAX,
    SERVICE_SAMPLED_FLAG, SampleKind, ServiceSample, TransportProtocol,
};
use zimascope_ebpf::{
    domain::{DNS_PORT, HTTP_PORT, TLS_PORT},
    parse::{PacketCursor, ParseResult, ParsedFlow, parse},
};

use crate::maps::{DOMAIN_EVENTS, FLOW_MAP, KERNEL_STATS, SERVICE_EVENTS};

#[classifier]
pub fn tc_ingress_v1(ctx: TcContext) -> i32 {
    process(&ctx, Direction::Inbound as u8)
}

#[classifier]
pub fn tc_egress_v1(ctx: TcContext) -> i32 {
    process(&ctx, Direction::Outbound as u8)
}

#[inline(always)]
fn process(ctx: &TcContext, direction: u8) -> i32 {
    let cursor = BpfCursor {
        data: ctx.data() as *const u8,
        data_end: ctx.data_end() as *const u8,
    };

    match parse(&cursor) {
        ParseResult::Flow(flow) => {
            let observed_mono_ns = unsafe { bpf_ktime_get_ns() };
            let packet_len = ctx.len() as u64;
            let ifindex = unsafe { (*ctx.skb.skb).ifindex };
            let key = flow_key(&flow, direction, ifindex);
            let recorded = update_flow(&ctx, &key, &flow, observed_mono_ns, packet_len);

            if recorded {
                sample_domains(ctx, &flow, direction, ifindex, observed_mono_ns);
            }

            if let Some(stats) = KERNEL_STATS.get_ptr_mut(0) {
                let stats = unsafe { &mut *stats };
                stats.packets_seen = stats.packets_seen.saturating_add(1);
                stats.packets_parsed = stats.packets_parsed.saturating_add(1);
                if !recorded {
                    stats.map_update_failures = stats.map_update_failures.saturating_add(1);
                }
            }
        }
        result @ (ParseResult::Skipped | ParseResult::Truncated | ParseResult::Invalid) => {
            if let Some(stats) = KERNEL_STATS.get_ptr_mut(0) {
                let stats = unsafe { &mut *stats };
                stats.packets_seen = stats.packets_seen.saturating_add(1);
                if result.is_failure() {
                    stats.parse_failures = stats.parse_failures.saturating_add(1);
                }
            }
        }
    }

    TC_ACT_UNSPEC as i32
}

#[inline(always)]
fn flow_key(flow: &ParsedFlow, direction: u8, ifindex: u32) -> FlowKey {
    FlowKey {
        src_addr: flow.src_addr,
        dst_addr: flow.dst_addr,
        src_port_be: flow.src_port_be,
        dst_port_be: flow.dst_port_be,
        ifindex,
        protocol: flow.protocol,
        direction,
        ip_family: flow.ip_family,
        reserved: 0,
    }
}

/// Updates the Flow entry for one packet and, on the first payload of each
/// direction, emits one bounded sample for protocol fingerprinting.
#[inline(always)]
fn update_flow(
    ctx: &TcContext,
    key: &FlowKey,
    flow: &ParsedFlow,
    observed_mono_ns: u64,
    packet_len: u64,
) -> bool {
    if let Some(ptr) = FLOW_MAP.get_ptr_mut(key) {
        let value = unsafe { &mut *ptr };
        record(value, flow, observed_mono_ns, packet_len);
        sample_service(ctx, key, flow, value, observed_mono_ns);
        return true;
    }

    let mut value = FlowValue::default();
    record(&mut value, flow, observed_mono_ns, packet_len);
    sample_service(ctx, key, flow, &mut value, observed_mono_ns);
    FLOW_MAP.insert(key, &value, BPF_ANY as u64).is_ok()
}

/// Copies the first L4 payload of this direction into the service ring buffer,
/// once per Flow direction. The flag is set even when the ring buffer is full
/// so a busy flow cannot retry on every packet.
#[inline(always)]
fn sample_service(
    ctx: &TcContext,
    key: &FlowKey,
    flow: &ParsedFlow,
    value: &mut FlowValue,
    observed_mono_ns: u64,
) {
    if value.service_flags & SERVICE_SAMPLED_FLAG != 0 {
        return;
    }
    if flow.protocol != TransportProtocol::Tcp as u8
        && flow.protocol != TransportProtocol::Udp as u8
    {
        return;
    }
    let available = flow.payload_end.saturating_sub(flow.payload_offset);
    if available == 0 {
        return;
    }
    value.service_flags |= SERVICE_SAMPLED_FLAG;

    // `min`/`max` selects do not always carry a nonzero minimum through the
    // verifier; deriving the length with arithmetic keeps `len >= 1` visible.
    let len = (available - 1).min(SERVICE_SAMPLE_MAX - 1) + 1;

    let Some(mut entry) = SERVICE_EVENTS.reserve::<ServiceSample>(0) else {
        record_service_dropped();
        return;
    };

    unsafe {
        let sample = entry.as_mut_ptr();
        (*sample).observed_mono_ns = observed_mono_ns;
        (*sample).key = *key;
        (*sample).payload_len = len as u16;
        (*sample).reserved = [0; 6];

        let destination = core::slice::from_raw_parts_mut((*sample).payload.as_mut_ptr(), len);
        let result = bpf_skb_load_bytes(
            ctx.skb.skb.cast::<c_void>(),
            flow.payload_offset as u32,
            destination.as_mut_ptr().cast::<c_void>(),
            len as u32,
        );
        if result != 0 {
            entry.discard(0);
            record_service_dropped();
            return;
        }
    }

    entry.submit(0);
    record_service_emitted();
}

#[inline(always)]
fn record(value: &mut FlowValue, flow: &ParsedFlow, now: u64, packet_len: u64) {
    if value.packets == 0 {
        value.first_seen_mono_ns = now;
    }
    value.packets = value.packets.saturating_add(1);
    value.bytes = value.bytes.saturating_add(packet_len);
    value.last_seen_mono_ns = now;
    value.tcp_flags |= flow.tcp_flags;
    value.parse_flags |= flow.parse_flags;
}

/// Selects candidate packets and copies a bounded payload sample for user
/// space to parse.
///
/// Egress GSO packets keep only headers in the linear skb area, so payload
/// peeks go through `bpf_skb_load_bytes` instead of direct packet pointers.
#[inline(always)]
fn sample_domains(
    ctx: &TcContext,
    flow: &ParsedFlow,
    direction: u8,
    ifindex: u32,
    observed_mono_ns: u64,
) {
    let is_tcp = flow.protocol == TransportProtocol::Tcp as u8;
    let is_udp = flow.protocol == TransportProtocol::Udp as u8;
    let outbound = direction == Direction::Outbound as u8;

    let is_dns = (is_tcp || is_udp)
        && (flow.src_port_be == DNS_PORT.to_be() || flow.dst_port_be == DNS_PORT.to_be());
    let is_tls = outbound && is_tcp && flow.dst_port_be == TLS_PORT.to_be();
    let is_http = outbound && is_tcp && flow.dst_port_be == HTTP_PORT.to_be();
    if !is_dns && !is_tls && !is_http {
        return;
    }

    let mut peek = [0u8; PEEK_LEN];
    if !peek_payload(ctx, flow.payload_offset, &mut peek) {
        return;
    }

    let kind = if is_dns {
        // Two constant loads instead of indexing with a computed base: LLVM
        // otherwise folds the base into pointer arithmetic and the verifier
        // rejects the pointer OR.
        let flags = if is_tcp { peek[4] } else { peek[2] };
        if flags & 0x80 == 0 {
            return;
        }
        SampleKind::Dns as u8
    } else if is_tls {
        if peek[0] != 0x16 || peek[5] != 0x01 {
            return;
        }
        SampleKind::TlsClientHello as u8
    } else {
        if !matches!(peek[0], b'G' | b'P' | b'H' | b'D') {
            return;
        }
        SampleKind::HttpRequest as u8
    };

    let address = if outbound {
        flow.dst_addr
    } else {
        flow.src_addr
    };
    emit_domain_sample(
        ctx,
        flow,
        kind,
        address,
        ifindex,
        direction,
        observed_mono_ns,
    );
}

const PEEK_LEN: usize = 8;

#[inline(always)]
fn peek_payload(ctx: &TcContext, offset: usize, buffer: &mut [u8; PEEK_LEN]) -> bool {
    unsafe {
        bpf_skb_load_bytes(
            ctx.skb.skb.cast::<c_void>(),
            offset as u32,
            buffer.as_mut_ptr().cast::<c_void>(),
            PEEK_LEN as u32,
        ) == 0
    }
}

#[inline(always)]
fn emit_domain_sample(
    ctx: &TcContext,
    flow: &ParsedFlow,
    kind: u8,
    address: [u8; 16],
    ifindex: u32,
    direction: u8,
    observed_mono_ns: u64,
) {
    let available = flow.payload_end.saturating_sub(flow.payload_offset);
    if available == 0 {
        return;
    }
    // `min`/`max` selects do not always carry a nonzero minimum through the
    // verifier; deriving the length with arithmetic keeps `len >= 1` visible
    // for the helper, which rejects zero-sized reads.
    let len = (available - 1).min(DOMAIN_SAMPLE_MAX - 1) + 1;

    let Some(mut entry) = DOMAIN_EVENTS.reserve::<DomainSample>(0) else {
        record_dropped();
        return;
    };

    unsafe {
        let sample = entry.as_mut_ptr();
        (*sample).observed_mono_ns = observed_mono_ns;
        (*sample).ifindex = ifindex;
        (*sample).payload_len = len as u16;
        (*sample).kind = kind;
        (*sample).transport = flow.protocol;
        (*sample).ip_family = IpFamily::V4 as u8;
        (*sample).direction = direction;
        (*sample).reserved = [0; 6];
        (*sample).address = address;

        let destination = core::slice::from_raw_parts_mut((*sample).payload.as_mut_ptr(), len);
        let result = bpf_skb_load_bytes(
            ctx.skb.skb.cast::<c_void>(),
            flow.payload_offset as u32,
            destination.as_mut_ptr().cast::<c_void>(),
            len as u32,
        );
        if result != 0 {
            entry.discard(0);
            record_dropped();
            return;
        }
    }

    entry.submit(0);
    record_emitted();
}

#[inline(always)]
fn record_dropped() {
    if let Some(stats) = KERNEL_STATS.get_ptr_mut(0) {
        let stats = unsafe { &mut *stats };
        stats.domain_events_dropped = stats.domain_events_dropped.saturating_add(1);
    }
}

#[inline(always)]
fn record_emitted() {
    if let Some(stats) = KERNEL_STATS.get_ptr_mut(0) {
        let stats = unsafe { &mut *stats };
        stats.domain_events_emitted = stats.domain_events_emitted.saturating_add(1);
    }
}

#[inline(always)]
fn record_service_emitted() {
    if let Some(stats) = KERNEL_STATS.get_ptr_mut(0) {
        let stats = unsafe { &mut *stats };
        stats.service_events_emitted = stats.service_events_emitted.saturating_add(1);
    }
}

#[inline(always)]
fn record_service_dropped() {
    if let Some(stats) = KERNEL_STATS.get_ptr_mut(0) {
        let stats = unsafe { &mut *stats };
        stats.service_events_dropped = stats.service_events_dropped.saturating_add(1);
    }
}

/// Bounded packet access backed by verified TC pointers.
struct BpfCursor {
    data: *const u8,
    data_end: *const u8,
}

/// Largest packet offset the header parser may touch, absolute from the frame
/// start. Keeping this far below the verifier's `MAX_PACKET_OFF` (0xffff)
/// leaves headroom for any constant offsets the compiler folds into pointers.
const MAX_PACKET_OFF: usize = 0x3fff;

impl BpfCursor {
    #[inline(always)]
    fn slice_at(&self, offset: usize, len: usize) -> Option<*const u8> {
        // Keep the offset bounded by the verifier's maximum packet offset so
        // it can derive a range for the access. Keep the addition and bound
        // check as separate pointer operations as well: integer arithmetic
        // lets LLVM fold `start + len > data_end` into `start >= data_end`,
        // which the verifier cannot use to infer a packet range.
        if offset.checked_add(len)? > MAX_PACKET_OFF {
            return None;
        }
        let start = self.data.wrapping_add(offset);
        let end = start.wrapping_add(len);
        if end < start || end > self.data_end {
            return None;
        }
        Some(start)
    }
}

impl PacketCursor for BpfCursor {
    #[inline(always)]
    fn read_u8(&self, offset: usize) -> Option<u8> {
        let addr = self.slice_at(offset, 1)?;
        Some(unsafe { core::ptr::read_unaligned(addr) })
    }

    #[inline(always)]
    fn read_u16_be(&self, offset: usize) -> Option<u16> {
        let addr = self.slice_at(offset, 2)?;
        let bytes = unsafe { core::ptr::read_unaligned(addr.cast::<[u8; 2]>()) };
        Some(u16::from_be_bytes(bytes))
    }

    #[inline(always)]
    fn read_u32_be(&self, offset: usize) -> Option<u32> {
        let addr = self.slice_at(offset, 4)?;
        let bytes = unsafe { core::ptr::read_unaligned(addr.cast::<[u8; 4]>()) };
        Some(u32::from_be_bytes(bytes))
    }
}

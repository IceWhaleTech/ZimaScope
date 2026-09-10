//! TC ingress and egress entry points.
//!
//! Every path returns `TC_ACT_OK`: ZimaScope V1 observes traffic and never
//! drops, delays or modifies a packet.

use aya_ebpf::{
    bindings::{BPF_ANY, TC_ACT_OK},
    helpers::bpf_ktime_get_ns,
    macros::classifier,
    programs::TcContext,
};
use zimascope_common::kernel_abi::{
    DOMAIN_MAX_LEN, Direction, DomainEvent, DomainEvidenceKind, FlowKey, FlowValue, IpFamily,
};
use zimascope_ebpf::{
    domain::{
        DNS_PORT, HTTP_PORT, TLS_PORT, extract_http_host, extract_tls_sni, parse_dns_response,
    },
    parse::{PacketCursor, ParseResult, ParsedFlow, parse},
};

use crate::maps::{DOMAIN_EVENTS, FLOW_MAP, KERNEL_STATS};

const MIN_DNS_TTL_NS: u64 = 10 * 1_000_000_000;
const MAX_DNS_TTL_NS: u64 = 3_600 * 1_000_000_000;
const DIRECT_EVIDENCE_TTL_NS: u64 = 300 * 1_000_000_000;

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
        data: ctx.data(),
        data_end: ctx.data_end(),
    };

    match parse(&cursor) {
        ParseResult::Flow(flow) => {
            let observed_mono_ns = unsafe { bpf_ktime_get_ns() };
            let packet_len = ctx.len() as u64;
            let ifindex = unsafe { (*ctx.skb.skb).ifindex };
            let key = flow_key(&flow, direction, ifindex);
            let recorded = update_flow(&key, &flow, observed_mono_ns, packet_len);

            if recorded {
                inspect_domains(&cursor, &flow, direction, ifindex, observed_mono_ns);
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

    TC_ACT_OK as i32
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

/// Updates the Flow entry for one packet.
#[inline(always)]
fn update_flow(key: &FlowKey, flow: &ParsedFlow, observed_mono_ns: u64, packet_len: u64) -> bool {
    if let Some(ptr) = FLOW_MAP.get_ptr_mut(key) {
        let value = unsafe { &mut *ptr };
        record(value, flow, observed_mono_ns, packet_len);
        return true;
    }

    let mut value = FlowValue::default();
    record(&mut value, flow, observed_mono_ns, packet_len);
    FLOW_MAP.insert(key, &value, BPF_ANY as u64).is_ok()
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

/// Extracts domain evidence from candidate packets.
#[inline(always)]
fn inspect_domains(
    cursor: &BpfCursor,
    flow: &ParsedFlow,
    direction: u8,
    ifindex: u32,
    observed_mono_ns: u64,
) {
    let mut domain_buffer = [0u8; DOMAIN_MAX_LEN];
    let is_tcp = flow.protocol == zimascope_common::kernel_abi::TransportProtocol::Tcp as u8;
    let is_udp = flow.protocol == zimascope_common::kernel_abi::TransportProtocol::Udp as u8;

    let dns_candidate = (is_tcp || is_udp)
        && (flow.src_port_be == DNS_PORT.to_be() || flow.dst_port_be == DNS_PORT.to_be());
    if dns_candidate {
        let payload_offset = if is_tcp {
            flow.payload_offset + 2
        } else {
            flow.payload_offset
        };
        parse_dns_response(
            cursor,
            payload_offset,
            flow.payload_end,
            &mut domain_buffer,
            |domain, len, answer| {
                let expires_mono_ns =
                    observed_mono_ns.saturating_add(clamp_dns_ttl_ns(u64::from(answer.ttl_secs)));
                emit_domain_event(
                    observed_mono_ns,
                    expires_mono_ns,
                    answer.address,
                    ifindex,
                    DomainEvidenceKind::Dns as u8,
                    direction,
                    domain,
                    len,
                );
            },
        );
    }

    if direction != Direction::Outbound as u8 || !is_tcp {
        return;
    }

    if flow.dst_port_be == TLS_PORT.to_be() {
        if let Some(len) = extract_tls_sni(
            cursor,
            flow.payload_offset,
            flow.payload_end,
            &mut domain_buffer,
        ) {
            emit_domain_event(
                observed_mono_ns,
                observed_mono_ns.saturating_add(DIRECT_EVIDENCE_TTL_NS),
                flow.dst_addr,
                ifindex,
                DomainEvidenceKind::TlsSni as u8,
                direction,
                &domain_buffer,
                len,
            );
        }
    }

    if flow.dst_port_be == HTTP_PORT.to_be() {
        if let Some(len) = extract_http_host(
            cursor,
            flow.payload_offset,
            flow.payload_end,
            &mut domain_buffer,
        ) {
            emit_domain_event(
                observed_mono_ns,
                observed_mono_ns.saturating_add(DIRECT_EVIDENCE_TTL_NS),
                flow.dst_addr,
                ifindex,
                DomainEvidenceKind::HttpHost as u8,
                direction,
                &domain_buffer,
                len,
            );
        }
    }
}

fn clamp_dns_ttl_ns(ttl_secs: u64) -> u64 {
    ttl_secs
        .saturating_mul(1_000_000_000)
        .clamp(MIN_DNS_TTL_NS, MAX_DNS_TTL_NS)
}

#[inline(always)]
fn emit_domain_event(
    observed_mono_ns: u64,
    expires_mono_ns: u64,
    address: [u8; 16],
    ifindex: u32,
    evidence: u8,
    direction: u8,
    domain: &[u8; DOMAIN_MAX_LEN],
    domain_len: usize,
) {
    let Some(mut entry) = DOMAIN_EVENTS.reserve::<DomainEvent>(0) else {
        if let Some(stats) = KERNEL_STATS.get_ptr_mut(0) {
            let stats = unsafe { &mut *stats };
            stats.domain_events_dropped = stats.domain_events_dropped.saturating_add(1);
        }
        return;
    };

    let len = if domain_len > DOMAIN_MAX_LEN {
        DOMAIN_MAX_LEN
    } else {
        domain_len
    };

    unsafe {
        let event = entry.as_mut_ptr();
        core::ptr::write_bytes(event.cast::<u8>(), 0, core::mem::size_of::<DomainEvent>());
        (*event).observed_mono_ns = observed_mono_ns;
        (*event).expires_mono_ns = expires_mono_ns;
        (*event).client_context = 0;
        (*event).address = address;
        (*event).ifindex = ifindex;
        (*event).domain_len = len as u16;
        (*event).evidence = evidence;
        (*event).ip_family = IpFamily::V4 as u8;
        (*event).direction = direction;
        for index in 0..DOMAIN_MAX_LEN {
            if index >= len {
                break;
            }
            (*event).domain[index] = domain[index];
        }
    }

    entry.submit(0);

    if let Some(stats) = KERNEL_STATS.get_ptr_mut(0) {
        let stats = unsafe { &mut *stats };
        stats.domain_events_emitted = stats.domain_events_emitted.saturating_add(1);
    }
}

/// Bounded packet access backed by verified TC pointers.
struct BpfCursor {
    data: usize,
    data_end: usize,
}

impl BpfCursor {
    #[inline(always)]
    fn slice_at(&self, offset: usize, len: usize) -> Option<usize> {
        let start = self.data.checked_add(offset)?;
        let end = start.checked_add(len)?;
        if end > self.data_end {
            return None;
        }
        Some(start)
    }
}

impl PacketCursor for BpfCursor {
    #[inline(always)]
    fn read_u8(&self, offset: usize) -> Option<u8> {
        let addr = self.slice_at(offset, 1)?;
        Some(unsafe { core::ptr::read_unaligned(addr as *const u8) })
    }

    #[inline(always)]
    fn read_u16_be(&self, offset: usize) -> Option<u16> {
        let addr = self.slice_at(offset, 2)? as *const u8;
        let bytes = unsafe { core::ptr::read_unaligned(addr as *const [u8; 2]) };
        Some(u16::from_be_bytes(bytes))
    }

    #[inline(always)]
    fn read_u32_be(&self, offset: usize) -> Option<u32> {
        let addr = self.slice_at(offset, 4)? as *const u8;
        let bytes = unsafe { core::ptr::read_unaligned(addr as *const [u8; 4]) };
        Some(u32::from_be_bytes(bytes))
    }
}

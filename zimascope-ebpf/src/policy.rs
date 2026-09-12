//! Traffic Rule evaluation in the packet path.
//!
//! Every path is fail-open: a packet passes unless an enabled rule matches it
//! and the rule's action drops it. Evaluation order is Application Identity,
//! exact Endpoint, then CIDR; the first tier with a match wins. A `block` wins
//! over a `limit` when both match inside the application tier.

use aya_ebpf::{
    bindings::bpf_spin_lock as AyaSpinLock,
    helpers::{bpf_ktime_get_ns, bpf_spin_lock, bpf_spin_unlock},
    maps::lpm_trie::Key as LpmKey,
};
use zimascope_common::kernel_abi::{
    BucketKey, Direction, EndpointMatchKey, IpFamily, OwnerKey, OwnerKind, OwnerValue, RuleAction,
    RuleRef, RuleState, TransportProtocol,
};
use zimascope_ebpf::parse::ParsedFlow;

use crate::maps::{
    APP_CGROUP_EGRESS, APP_CGROUP_INGRESS, APP_COMM_EGRESS, APP_COMM_INGRESS, ENDPOINT_CIDR_EGRESS,
    ENDPOINT_CIDR_INGRESS, ENDPOINT_EXACT_EGRESS, ENDPOINT_EXACT_INGRESS, KERNEL_STATS,
    LISTENER_MAP, OWNER_MAP, POLICY_CONFIG, RULE_STATES,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Verdict {
    Pass,
    Drop,
}

const NS_PER_SECOND: u64 = 1_000_000_000;
const REFILL_CAP_NS: u64 = NS_PER_SECOND;

/// Evaluates the Traffic Rules against one parsed Flow packet.
#[inline(always)]
pub fn evaluate(flow: &ParsedFlow, direction: u8, packet_len: u64) -> Verdict {
    let Some(config) = POLICY_CONFIG.get(0) else {
        return Verdict::Pass;
    };
    if config.enabled == 0 {
        return Verdict::Pass;
    }

    let outbound = direction == Direction::Outbound as u8;
    if config.app_rules != 0 {
        if let Some(rule) = app_rule(flow, outbound) {
            return enforce(rule, direction, packet_len);
        }
    }
    if config.endpoint_rules != 0 {
        if let Some(rule) = endpoint_rule(flow, outbound) {
            return enforce(rule, direction, packet_len);
        }
    }
    Verdict::Pass
}

#[inline(always)]
fn app_rule(flow: &ParsedFlow, outbound: bool) -> Option<RuleRef> {
    let owner = lookup_owner(flow, outbound)?;
    let (cgroup, comm) = if outbound {
        (unsafe { APP_CGROUP_EGRESS.get(&owner.cgroup_id) }, unsafe {
            APP_COMM_EGRESS.get(&owner.comm)
        })
    } else {
        (
            unsafe { APP_CGROUP_INGRESS.get(&owner.cgroup_id) },
            unsafe { APP_COMM_INGRESS.get(&owner.comm) },
        )
    };

    match (cgroup, comm) {
        (Some(container), Some(process)) => Some(prefer(container, process)),
        (Some(container), None) => Some(*container),
        (None, Some(process)) => Some(*process),
        (None, None) => None,
    }
}

#[inline(always)]
fn prefer(container: &RuleRef, process: &RuleRef) -> RuleRef {
    if container.action == RuleAction::Block as u8 {
        *container
    } else if process.action == RuleAction::Block as u8 {
        *process
    } else {
        *container
    }
}

#[inline(always)]
fn lookup_owner(flow: &ParsedFlow, outbound: bool) -> Option<OwnerValue> {
    let (remote_addr, remote_port_be, local_port_be) = if outbound {
        (flow.dst_addr, flow.dst_port_be, flow.src_port_be)
    } else {
        (flow.src_addr, flow.src_port_be, flow.dst_port_be)
    };
    let is_udp = flow.protocol == TransportProtocol::Udp as u8;

    let key = OwnerKey {
        remote_addr,
        remote_port_be,
        local_port_be: if is_udp { 0 } else { local_port_be },
        protocol: flow.protocol,
        kind: OwnerKind::Socket as u8,
        ip_family: flow.ip_family,
        reserved: 0,
    };
    if let Some(owner) = unsafe { OWNER_MAP.get(&key) } {
        return Some(*owner);
    }
    if is_udp {
        return None;
    }

    let listener = OwnerKey {
        remote_addr: [0; 16],
        remote_port_be: 0,
        local_port_be,
        protocol: flow.protocol,
        kind: OwnerKind::Listener as u8,
        ip_family: flow.ip_family,
        reserved: 0,
    };
    unsafe { LISTENER_MAP.get(&listener) }.copied()
}

#[inline(always)]
fn endpoint_rule(flow: &ParsedFlow, outbound: bool) -> Option<RuleRef> {
    let (addr, port_be) = if outbound {
        (flow.dst_addr, flow.dst_port_be)
    } else {
        (flow.src_addr, flow.src_port_be)
    };
    let exact = EndpointMatchKey {
        addr,
        port_be,
        reserved: [0; 6],
    };
    let (exact_map, cidr_map) = if outbound {
        (&ENDPOINT_EXACT_EGRESS, &ENDPOINT_CIDR_EGRESS)
    } else {
        (&ENDPOINT_EXACT_INGRESS, &ENDPOINT_CIDR_INGRESS)
    };

    if let Some(rule) = unsafe { exact_map.get(&exact) } {
        return Some(*rule);
    }
    let wildcard = EndpointMatchKey {
        port_be: 0,
        ..exact
    };
    if let Some(rule) = unsafe { exact_map.get(&wildcard) } {
        return Some(*rule);
    }
    if flow.ip_family != IpFamily::V4 as u8 {
        return None;
    }

    let mut octets = [0u8; 4];
    octets.copy_from_slice(&addr[12..]);
    cidr_map.get(&LpmKey::new(32, octets)).copied()
}

#[inline(always)]
fn enforce(rule: RuleRef, direction: u8, packet_len: u64) -> Verdict {
    let key = BucketKey {
        rule_id: rule.rule_id,
        direction,
        reserved: [0; 3],
    };
    let Some(state) = RULE_STATES.get_ptr_mut(&key) else {
        record_missing_state();
        return Verdict::Pass;
    };

    // The lock is the first field of the value, so the value pointer is the
    // lock pointer; this avoids forming a reference to the lock field.
    let lock = state.cast::<AyaSpinLock>();
    let now = unsafe { bpf_ktime_get_ns() };

    unsafe { bpf_spin_lock(lock) };
    let state = unsafe { &mut *state };
    refill(state, now);
    state.matched_packets = state.matched_packets.saturating_add(1);
    state.matched_bytes = state.matched_bytes.saturating_add(packet_len);

    let verdict = if rule.action == RuleAction::Block as u8 {
        drop_packet(state, packet_len);
        Verdict::Drop
    } else if state.tokens >= packet_len {
        state.tokens -= packet_len;
        Verdict::Pass
    } else {
        drop_packet(state, packet_len);
        Verdict::Drop
    };
    unsafe { bpf_spin_unlock(lock) };

    verdict
}

#[inline(always)]
fn refill(state: &mut RuleState, now: u64) {
    let elapsed = now
        .saturating_sub(state.last_refill_mono_ns)
        .min(REFILL_CAP_NS);
    let add = elapsed * state.rate_bytes_per_s / NS_PER_SECOND;
    if add > 0 {
        state.tokens = state.tokens.saturating_add(add).min(state.burst_bytes);
        state.last_refill_mono_ns = now;
    }
}

#[inline(always)]
fn drop_packet(state: &mut RuleState, packet_len: u64) {
    state.dropped_packets = state.dropped_packets.saturating_add(1);
    state.dropped_bytes = state.dropped_bytes.saturating_add(packet_len);
}

#[inline(always)]
fn record_missing_state() {
    if let Some(stats) = KERNEL_STATS.get_ptr_mut(0) {
        let stats = unsafe { &mut *stats };
        stats.policy_missing_state = stats.policy_missing_state.saturating_add(1);
    }
}

//! Socket-owner capture for Application Identity.
//!
//! A cgroup `sock_ops` program records which process owns an outbound TCP
//! socket (at connect) and which process owns a listening port (at listen).
//! The packet path is untouched: user space joins these observations to Flow
//! snapshots, so bytes stay owned by TC at the Device Boundary.
//!
//! The key omits the local address on purpose: a container socket carries the
//! container address here, while the same Flow at the boundary carries the
//! host address after SNAT. Port-preserving NAT keeps the join working.

use aya_ebpf::{
    bindings::{BPF_ANY, BPF_SOCK_OPS_TCP_CONNECT_CB, BPF_SOCK_OPS_TCP_LISTEN_CB},
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid,
        bpf_get_current_uid_gid, bpf_ktime_get_ns,
    },
    macros::sock_ops,
    maps::LruHashMap,
    programs::SockOpsContext,
};
use zimascope_common::kernel_abi::{IpFamily, OwnerKey, OwnerKind, OwnerValue, TransportProtocol};

use crate::maps::{KERNEL_STATS, LISTENER_MAP, OWNER_MAP};

/// `AF_INET`, the only family this phase attributes.
const AF_INET: u32 = 2;

/// Socket-ops programs must return 1 to stay transparent.
const SOCK_OPS_CONTINUE: u32 = 1;

#[sock_ops]
pub fn sock_owner_v1(ctx: SockOpsContext) -> u32 {
    let op = ctx.op();
    if ctx.family() != AF_INET {
        return SOCK_OPS_CONTINUE;
    }

    if op == BPF_SOCK_OPS_TCP_CONNECT_CB as u32 {
        let key = owner_key(&ctx, OwnerKind::Socket, false);
        insert_owner(&OWNER_MAP, &key, &owner_value());
    } else if op == BPF_SOCK_OPS_TCP_LISTEN_CB as u32 {
        let key = owner_key(&ctx, OwnerKind::Listener, true);
        insert_owner(&LISTENER_MAP, &key, &owner_value());
    }

    SOCK_OPS_CONTINUE
}

#[inline(always)]
fn owner_key(ctx: &SockOpsContext, kind: OwnerKind, listener: bool) -> OwnerKey {
    let (remote_addr, remote_port_be) = if listener {
        ([0u8; 16], 0)
    } else {
        (
            ipv4_storage(ctx.remote_ip4()),
            // The kernel exposes `remote_port` as the network-order port
            // shifted into bits 16..32 on little-endian targets; the high half
            // is already the `_be` value this ABI stores.
            (ctx.remote_port() >> 16) as u16,
        )
    };

    OwnerKey {
        remote_addr,
        remote_port_be,
        // `local_port` is the host-order `skc_num`; the ABI stores network
        // order, matching every other `_be` field.
        local_port_be: (ctx.local_port() as u16).to_be(),
        protocol: TransportProtocol::Tcp as u8,
        kind: kind as u8,
        ip_family: IpFamily::V4 as u8,
        reserved: 0,
    }
}

#[inline(always)]
pub(crate) fn owner_value() -> OwnerValue {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);

    OwnerValue {
        tgid: (pid_tgid >> 32) as u32,
        pid: pid_tgid as u32,
        uid: uid_gid as u32,
        reserved: 0,
        // Safety: only valid from process context, which every owner capture
        // callback runs in.
        cgroup_id: unsafe { bpf_get_current_cgroup_id() },
        comm,
        observed_mono_ns: unsafe { bpf_ktime_get_ns() },
    }
}

/// Encodes the network-order IPv4 value into the zero-extended storage used
/// by every address in the kernel ABI.
#[inline(always)]
pub(crate) fn ipv4_storage(value: u32) -> [u8; 16] {
    let octets = u32::from_be(value).to_be_bytes();
    let mut storage = [0u8; 16];
    storage[12] = octets[0];
    storage[13] = octets[1];
    storage[14] = octets[2];
    storage[15] = octets[3];
    storage
}

#[inline(always)]
pub(crate) fn insert_owner(
    map: &LruHashMap<OwnerKey, OwnerValue>,
    key: &OwnerKey,
    value: &OwnerValue,
) {
    let inserted = map.insert(key, value, BPF_ANY as u64).is_ok();
    if let Some(stats) = KERNEL_STATS.get_ptr_mut(0) {
        let stats = unsafe { &mut *stats };
        if inserted {
            stats.owner_events_inserted = stats.owner_events_inserted.saturating_add(1);
        } else {
            stats.owner_events_dropped = stats.owner_events_dropped.saturating_add(1);
        }
    }
}

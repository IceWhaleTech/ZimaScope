//! UDP socket-owner capture for Application Identity.
//!
//! `cgroup/sendmsg4` fires in the sending process's context for every UDP
//! send, connected or not. This hook does not expose a stable local port, so
//! the owner key carries the remote endpoint only; user space joins UDP Flows
//! by `(protocol, remote)`. Multiple local sockets talking to one remote are
//! therefore ambiguous and resolve to the most recent sender.

use aya_ebpf::{macros::cgroup_sock_addr, programs::SockAddrContext};
use zimascope_common::kernel_abi::{IpFamily, OwnerKey, OwnerKind, TransportProtocol};

use crate::{
    maps::OWNER_MAP,
    owner::{insert_owner, ipv4_storage, owner_value},
};

/// Socket-addr programs return 1 to allow the operation.
const SOCK_ADDR_ALLOW: i32 = 1;

#[cgroup_sock_addr(sendmsg4)]
pub fn udp_owner_v1(ctx: SockAddrContext) -> i32 {
    let (remote_ip4, remote_port) = unsafe {
        let addr = ctx.sock_addr;
        ((*addr).user_ip4, (*addr).user_port)
    };

    let key = OwnerKey {
        remote_addr: ipv4_storage(remote_ip4),
        // `user_port` is the network-order `sin_port` zero-extended; the low
        // 16 bits are already the `_be` value this ABI stores.
        remote_port_be: (remote_port & 0xffff) as u16,
        local_port_be: 0,
        protocol: TransportProtocol::Udp as u8,
        kind: OwnerKind::Socket as u8,
        ip_family: IpFamily::V4 as u8,
        reserved: 0,
    };
    insert_owner(&OWNER_MAP, &key, &owner_value());

    SOCK_ADDR_ALLOW
}

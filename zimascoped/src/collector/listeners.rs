//! Startup seeding of pre-existing listeners.
//!
//! `TCP_LISTEN_CB` only fires for sockets that start listening after the
//! agent attached, and UDP ownership is only captured when the host sends
//! (`cgroup/sendmsg4`). Long-lived services (sshd, systemd-resolved, the OS
//! web UI, media servers) already bind at boot, so inbound Flows to them
//! would never be attributed. One `/proc` sweep at startup — refreshed
//! periodically because owner entries expire — seeds the tracker's listener
//! cache with the processes that currently own a bound TCP or UDP port.

use std::{collections::HashMap, fs, os::unix::fs::MetadataExt, time::Instant};

use zimascope_common::kernel_abi::{IpFamily, OwnerKey, OwnerKind, OwnerValue, TransportProtocol};

use super::tracker::FlowTracker;

/// Seeds listener ownership once. Missing `/proc` (non-Linux development)
/// simply yields nothing.
pub(crate) fn seed(tracker: &mut FlowTracker, now: Instant) {
    for (key, value) in scan() {
        tracker.record_owner(&key, &value, now);
    }
}

/// Scans the `/proc` socket tables for bound ports and their owning processes.
fn scan() -> Vec<(OwnerKey, OwnerValue)> {
    let mut bound: Vec<(u8, u16, u64)> = Vec::new();
    if let Ok(table) = fs::read_to_string("/proc/net/tcp") {
        bound.extend(
            parse_listen_ports(&table)
                .into_iter()
                .map(|(port, inode)| (TransportProtocol::Tcp as u8, port, inode)),
        );
    }
    for path in ["/proc/net/udp", "/proc/net/udp6"] {
        if let Ok(table) = fs::read_to_string(path) {
            bound.extend(
                parse_bound_ports(&table)
                    .into_iter()
                    .map(|(port, inode)| (TransportProtocol::Udp as u8, port, inode)),
            );
        }
    }
    if bound.is_empty() {
        return Vec::new();
    }

    let inodes: Vec<u64> = bound.iter().map(|(_, _, inode)| *inode).collect();
    let owners = find_owner_pids(&inodes);

    let mut seeded = Vec::with_capacity(bound.len());
    for (protocol, port, inode) in bound {
        let Some(pid) = owners.get(&inode) else {
            continue;
        };
        let Some(value) = owner_value(*pid) else {
            continue;
        };
        seeded.push((listener_key(protocol, port), value));
    }
    seeded
}

/// Parses `local_port`/`inode` pairs of LISTEN entries from `/proc/net/tcp`.
fn parse_listen_ports(table: &str) -> Vec<(u16, u64)> {
    let mut listeners = Vec::new();
    for line in table.lines().skip(1) {
        let mut fields = line.split_whitespace();
        let Some(_slot) = fields.next() else { continue };
        let Some(local) = fields.next() else { continue };
        let Some(_remote) = fields.next() else {
            continue;
        };
        let Some(state) = fields.next() else { continue };
        if state != "0A" {
            continue;
        }
        let Some(port) = local_port(local) else {
            continue;
        };
        // Columns after state: tx/rx queue, timer, retransmits, uid, timeout,
        // then inode.
        let inode = fields.nth(5).and_then(|value| value.parse::<u64>().ok());
        if let Some(inode) = inode {
            listeners.push((port, inode));
        }
    }
    listeners
}

/// Parses `local_port`/`inode` pairs of bound entries from `/proc/net/udp`.
///
/// Connected and unconnected sockets are both seeded: an inbound datagram for
/// the port is owned by that process either way.
fn parse_bound_ports(table: &str) -> Vec<(u16, u64)> {
    let mut sockets = Vec::new();
    for line in table.lines().skip(1) {
        let mut fields = line.split_whitespace();
        let Some(_slot) = fields.next() else { continue };
        let Some(local) = fields.next() else { continue };
        let Some(_remote) = fields.next() else {
            continue;
        };
        let Some(_state) = fields.next() else {
            continue;
        };
        let Some(port) = local_port(local) else {
            continue;
        };
        let inode = fields.nth(5).and_then(|value| value.parse::<u64>().ok());
        if let Some(inode) = inode {
            sockets.push((port, inode));
        }
    }
    sockets
}

/// Extracts the port from a `/proc/net` `address:port` field; port zero means
/// the socket is not bound and cannot own an inbound datagram.
fn local_port(local: &str) -> Option<u16> {
    let (_, port) = local.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    (port != 0).then_some(port)
}

/// Finds the process owning each socket inode by scanning `/proc/<pid>/fd`.
fn find_owner_pids(inodes: &[u64]) -> HashMap<u64, u32> {
    let wanted: std::collections::HashSet<u64> = inodes.iter().copied().collect();
    let mut owners = HashMap::new();
    let Ok(processes) = fs::read_dir("/proc") else {
        return owners;
    };

    for process in processes.flatten() {
        if owners.len() == wanted.len() {
            break;
        }
        let Some(pid) = process
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(entries) = fs::read_dir(process.path().join("fd")) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(target) = fs::read_link(entry.path()) else {
                continue;
            };
            let Some(target) = target.to_str() else {
                continue;
            };
            let Some(inode) = parse_socket_inode(target) else {
                continue;
            };
            if wanted.contains(&inode) {
                owners.entry(inode).or_insert(pid);
            }
        }
    }
    owners
}

/// Parses a `/proc/<pid>/fd` symlink target such as `socket:[12345]`.
fn parse_socket_inode(target: &str) -> Option<u64> {
    target
        .strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

fn owner_value(pid: u32) -> Option<OwnerValue> {
    let comm = fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|comm| comm.trim().to_owned())?;
    let uid = fs::metadata(format!("/proc/{pid}"))
        .ok()
        .map(|meta| meta.uid());

    Some(OwnerValue {
        tgid: pid,
        pid,
        uid: uid.unwrap_or(0),
        reserved: 0,
        cgroup_id: 0,
        comm: zimascope_common::model::comm_bytes(&comm),
        observed_mono_ns: 0,
    })
}

fn listener_key(protocol: u8, port: u16) -> OwnerKey {
    OwnerKey {
        remote_addr: [0u8; 16],
        remote_port_be: 0,
        local_port_be: port.to_be(),
        protocol,
        kind: OwnerKind::Listener as u8,
        ip_family: IpFamily::V4 as u8,
        reserved: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TABLE: &str = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000 100 0 0 10 0
   1: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 54321 1 0000 100 0 0 10 0
   2: 0100007F:9C40 0100007F:1F90 01 00000000:00000000 00:00000000 00000000     0        0 99999 1 0000 100 0 0 10 0
   3: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 11111 1 0000 100 0 0 10 0
";

    const UDP_TABLE: &str = "\
   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  0: 0100007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   102        0 22222 2 0000000000000000 0
  1: 00000000:14E9 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 33333 2 0000000000000000 0
  2: 0100007F:C350 0100007F:0035 01 00000000:00000000 00:00000000 00000000  1000        0 44444 2 0000000000000000 0
  3: 00000000:0000 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 55555 2 0000000000000000 0
";

    #[test]
    fn parses_only_listening_sockets() {
        let listeners = parse_listen_ports(TABLE);
        assert_eq!(listeners, vec![(8080, 12345), (80, 54321), (22, 11111)]);
    }

    #[test]
    fn parses_bound_udp_sockets_and_skips_unbound() {
        let sockets = parse_bound_ports(UDP_TABLE);
        assert_eq!(sockets, vec![(53, 22222), (5353, 33333), (50000, 44444)]);
    }

    #[test]
    fn parses_socket_inode_symlinks() {
        assert_eq!(parse_socket_inode("socket:[4242]"), Some(4242));
        assert_eq!(parse_socket_inode("pipe:[4242]"), None);
        assert_eq!(parse_socket_inode("socket:[oops]"), None);
    }

    #[test]
    fn builds_network_order_listener_keys() {
        let key = listener_key(TransportProtocol::Udp as u8, 5353);
        assert_eq!(u16::from_be(key.local_port_be), 5353);
        assert_eq!(key.protocol, TransportProtocol::Udp as u8);
        assert_eq!(key.kind, OwnerKind::Listener as u8);
        assert_eq!(key.remote_addr, [0u8; 16]);
        assert_eq!(key.remote_port_be, 0);
    }
}

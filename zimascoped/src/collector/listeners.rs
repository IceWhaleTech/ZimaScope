//! Startup seeding of pre-existing TCP listeners.
//!
//! `TCP_LISTEN_CB` only fires for sockets that start listening after the
//! agent attached. Long-lived services (sshd, the OS web UI, media servers)
//! already listen at boot, so their inbound Flows would never be attributed.
//! One `/proc` sweep at startup seeds the tracker's listener cache with the
//! processes that currently own a listening port; live `sock_ops` events keep
//! the cache up to date from then on.

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

/// Scans `/proc/net/tcp` and the file descriptor tables for listening
/// sockets and their owning processes.
fn scan() -> Vec<(OwnerKey, OwnerValue)> {
    let Ok(table) = fs::read_to_string("/proc/net/tcp") else {
        return Vec::new();
    };
    let listeners = parse_listen_ports(&table);
    if listeners.is_empty() {
        return Vec::new();
    }

    let inodes: Vec<u64> = listeners.iter().map(|(_, inode)| *inode).collect();
    let owners = find_owner_pids(&inodes);

    let mut seeded = Vec::with_capacity(listeners.len());
    for (port, inode) in listeners {
        let Some(pid) = owners.get(&inode) else {
            continue;
        };
        let Some(value) = owner_value(*pid) else {
            continue;
        };
        seeded.push((listener_key(port), value));
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
        // `0100007F:1F90` — address:port, both hex.
        let Some((_, port)) = local.split_once(':') else {
            continue;
        };
        let Ok(port) = u16::from_str_radix(port, 16) else {
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

    let mut raw = [0u8; 16];
    let bytes = comm.as_bytes();
    let length = bytes.len().min(raw.len());
    raw[..length].copy_from_slice(&bytes[..length]);

    Some(OwnerValue {
        tgid: pid,
        pid,
        uid: uid.unwrap_or(0),
        reserved: 0,
        cgroup_id: 0,
        comm: raw,
        observed_mono_ns: 0,
    })
}

fn listener_key(port: u16) -> OwnerKey {
    OwnerKey {
        remote_addr: [0u8; 16],
        remote_port_be: 0,
        local_port_be: port.to_be(),
        protocol: TransportProtocol::Tcp as u8,
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

    #[test]
    fn parses_only_listening_sockets() {
        let listeners = parse_listen_ports(TABLE);
        assert_eq!(listeners, vec![(8080, 12345), (80, 54321), (22, 11111)]);
    }

    #[test]
    fn parses_socket_inode_symlinks() {
        assert_eq!(parse_socket_inode("socket:[4242]"), Some(4242));
        assert_eq!(parse_socket_inode("pipe:[4242]"), None);
        assert_eq!(parse_socket_inode("socket:[oops]"), None);
    }

    #[test]
    fn builds_network_order_listener_keys() {
        let key = listener_key(8080);
        assert_eq!(u16::from_be(key.local_port_be), 8080);
        assert_eq!(key.kind, OwnerKind::Listener as u8);
        assert_eq!(key.remote_addr, [0u8; 16]);
        assert_eq!(key.remote_port_be, 0);
    }
}

//! Application Identity resolution for the Traffic Rule compiler.
//!
//! `cont:` identities resolve through the cgroup tree; `proc:comm:` identities
//! carry the kernel `comm` directly. An executable-path identity needs the
//! `applications` table's `comm` column, so the API normalizes it before
//! compilation and this resolver reports it as unresolved otherwise.

use std::{collections::HashMap, path::Path, time::Instant};

use super::{AppKey, ApplicationKeys};
use crate::cgroup;

/// Resolves `cont:` and `proc:comm:` identities on this host.
#[derive(Default)]
pub struct SystemApplicationKeys {
    containers: HashMap<String, Vec<u64>>,
    refreshed_at: Option<Instant>,
}

impl SystemApplicationKeys {
    pub fn new() -> Self {
        Self::default()
    }

    fn cgroups_for(&mut self, container_id: &str) -> Vec<u64> {
        let stale = self
            .refreshed_at
            .map(|at| at.elapsed() >= cgroup::INDEX_REFRESH)
            .unwrap_or(true);
        if stale {
            self.refresh();
        }
        self.containers
            .get(container_id)
            .cloned()
            .unwrap_or_default()
    }

    fn refresh(&mut self) {
        let mut index = HashMap::new();
        cgroup::walk_tree(Path::new("/sys/fs/cgroup"), &mut index);

        let mut containers: HashMap<String, Vec<u64>> = HashMap::new();
        for (inode, container) in index {
            if let Some(container) = container {
                containers
                    .entry(container.into_string())
                    .or_default()
                    .push(inode);
            }
        }
        self.containers = containers;
        self.refreshed_at = Some(Instant::now());
    }

    #[cfg(test)]
    fn with_containers(containers: HashMap<String, Vec<u64>>) -> Self {
        Self {
            containers,
            refreshed_at: Some(Instant::now()),
        }
    }
}

impl ApplicationKeys for SystemApplicationKeys {
    fn keys(&mut self, identity: &str) -> Result<Vec<AppKey>, String> {
        if let Some(comm) = identity.strip_prefix("proc:comm:") {
            return Ok(vec![AppKey::Comm(comm_bytes(comm)?)]);
        }
        if let Some(container_id) = identity.strip_prefix("cont:") {
            let cgroups = self.cgroups_for(container_id);
            if cgroups.is_empty() {
                return Err(format!("container {container_id} has no cgroup directory"));
            }
            return Ok(cgroups.into_iter().map(AppKey::Cgroup).collect());
        }
        Err(format!(
            "application identity {identity:?} needs an executable-to-comm resolution"
        ))
    }
}

/// Encodes a process name the way `bpf_get_current_comm` does: at most 15
/// bytes plus a NUL terminator.
fn comm_bytes(comm: &str) -> Result<[u8; 16], String> {
    if comm.is_empty() {
        return Err("process name is empty".to_owned());
    }
    let mut storage = [0u8; 16];
    let length = comm.len().min(15);
    storage[..length].copy_from_slice(&comm.as_bytes()[..length]);
    Ok(storage)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comm_identity_matches_the_kernel_encoding() {
        let mut keys = SystemApplicationKeys::default();
        let resolved = keys.keys("proc:comm:qbittorrent-nox").expect("comm key");

        let mut expected = [0u8; 16];
        expected[..15].copy_from_slice(b"qbittorrent-nox");
        assert_eq!(resolved, vec![AppKey::Comm(expected)]);
    }

    #[test]
    fn long_process_names_are_truncated_like_the_kernel() {
        let mut keys = SystemApplicationKeys::default();
        let resolved = keys
            .keys("proc:comm:a-very-long-process-name")
            .expect("comm key");
        let AppKey::Comm(comm) = resolved[0] else {
            panic!("comm key expected");
        };
        assert_eq!(&comm[..15], b"a-very-long-pro");
        assert_eq!(comm[15], 0);
    }

    #[test]
    fn container_identity_resolves_to_cgroup_ids() {
        let mut containers = HashMap::new();
        containers.insert("abc123".to_owned(), vec![41, 42]);
        let mut keys = SystemApplicationKeys::with_containers(containers);

        assert_eq!(
            keys.keys("cont:abc123").expect("container keys"),
            vec![AppKey::Cgroup(41), AppKey::Cgroup(42)]
        );
    }

    #[test]
    fn missing_container_and_executable_identities_are_unresolved() {
        let mut keys = SystemApplicationKeys::default();
        assert!(keys.keys("cont:missing").is_err());
        assert!(keys.keys("proc:/usr/bin/curl").is_err());
        assert!(keys.keys("mystery:1").is_err());
    }
}

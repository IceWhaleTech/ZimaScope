//! Application Identity resolution for the Traffic Rule compiler.
//!
//! `cont:` identities resolve through the cgroup tree; `proc:comm:` identities
//! carry the kernel `comm` directly. An executable-path identity needs the
//! `applications` table's `comm` column, so the API normalizes it before
//! compilation and this resolver reports it as unresolved otherwise.

use super::{AppKey, ApplicationKeys};
use crate::cgroup::CgroupIndex;

/// Resolves `cont:` and `proc:comm:` identities on this host.
#[derive(Default)]
pub struct SystemApplicationKeys {
    cgroups: CgroupIndex,
}

impl SystemApplicationKeys {
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(test)]
    fn with_containers(containers: std::collections::HashMap<String, Vec<u64>>) -> Self {
        Self {
            cgroups: CgroupIndex::with_containers(containers),
        }
    }
}

impl ApplicationKeys for SystemApplicationKeys {
    fn keys(&mut self, identity: &str) -> Result<Vec<AppKey>, String> {
        if let Some(comm) = identity.strip_prefix("proc:comm:") {
            if comm.is_empty() {
                return Err("process name is empty".to_owned());
            }
            return Ok(vec![AppKey::Comm(zimascope_common::model::comm_bytes(
                comm,
            ))]);
        }
        if let Some(container_id) = identity.strip_prefix("cont:") {
            let cgroups = self.cgroups.inodes_for_container(container_id);
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

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

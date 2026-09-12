//! Shared cgroup v2 helpers.
//!
//! Container ids are parsed from cgroup paths and directory inodes are walked
//! once per refresh window. Both the Application Identity resolver and the
//! Traffic Rule compiler need the same view of the cgroup tree.

use std::{
    collections::HashMap,
    fs,
    os::unix::fs::MetadataExt,
    path::Path,
    time::{Duration, Instant},
};

/// Mount point of the cgroup v2 hierarchy on ZimaOS.
pub(crate) const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// Minimum age of a cgroup-id index before a miss walks the tree again.
pub(crate) const INDEX_REFRESH: Duration = Duration::from_secs(5);

/// Bound on the cgroup tree walk, so a symlink loop cannot recurse forever.
pub(crate) const WALK_DEPTH: usize = 12;

/// Cached view of the cgroup tree.
///
/// One walk builds both directions: inode to container (used to resolve
/// short-lived processes) and container to inodes (used to compile
/// application-identity Traffic Rules).
#[derive(Default)]
pub(crate) struct CgroupIndex {
    by_inode: HashMap<u64, Option<Box<str>>>,
    by_container: HashMap<String, Vec<u64>>,
    refreshed_at: Option<Instant>,
}

impl CgroupIndex {
    /// Rebuilds the snapshot when it is older than [`INDEX_REFRESH`].
    pub(crate) fn refresh_if_stale(&mut self) {
        let stale = self
            .refreshed_at
            .map(|at| at.elapsed() >= INDEX_REFRESH)
            .unwrap_or(true);
        if stale {
            self.refresh();
        }
    }

    /// Returns the container owning a cgroup inode.
    ///
    /// A cached hit is returned without walking the tree; a miss refreshes a
    /// stale snapshot so containers started later are still found.
    pub(crate) fn container_for_inode(&mut self, inode: u64) -> Option<&str> {
        if !self.by_inode.contains_key(&inode) {
            self.refresh_if_stale();
        }
        self.by_inode
            .get(&inode)
            .and_then(|container| container.as_deref())
    }

    /// Every cgroup inode that belongs to `container`.
    pub(crate) fn inodes_for_container(&mut self, container: &str) -> Vec<u64> {
        self.refresh_if_stale();
        self.by_container
            .get(container)
            .cloned()
            .unwrap_or_default()
    }

    fn refresh(&mut self) {
        let mut by_inode = HashMap::new();
        walk_tree(Path::new(CGROUP_ROOT), &mut by_inode);

        let mut by_container: HashMap<String, Vec<u64>> = HashMap::new();
        for (inode, container) in &by_inode {
            if let Some(container) = container {
                by_container
                    .entry(container.to_string())
                    .or_default()
                    .push(*inode);
            }
        }
        self.by_inode = by_inode;
        self.by_container = by_container;
        self.refreshed_at = Some(Instant::now());
    }

    #[cfg(test)]
    pub(crate) fn with_containers(containers: HashMap<String, Vec<u64>>) -> Self {
        Self {
            by_inode: HashMap::new(),
            by_container: containers,
            refreshed_at: Some(Instant::now()),
        }
    }
}

/// Walks a cgroup tree and records every directory inode.
///
/// A directory without a container pattern inherits the nearest ancestor's
/// container id, so processes in nested cgroups still resolve to the container
/// that owns them.
pub(crate) fn walk_tree(root: &Path, index: &mut HashMap<u64, Option<Box<str>>>) {
    walk(root, 0, None, index);
}

fn walk(
    directory: &Path,
    depth: usize,
    inherited: Option<&str>,
    index: &mut HashMap<u64, Option<Box<str>>>,
) {
    if depth >= WALK_DEPTH {
        return;
    }
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        if !metadata.is_dir() {
            continue;
        }
        let path = entry.path();
        let own = path.to_str().and_then(container_id);
        let container = own.as_deref().or(inherited);
        index.insert(metadata.ino(), container.map(Into::into));
        walk(&path, depth + 1, container, index);
    }
}

/// Extracts a container id from a `/proc/<pid>/cgroup` document or a cgroup
/// directory path.
///
/// Handles the cgroup v2 and v1 path conventions used by Docker (systemd
/// scopes and the cgroupfs driver), containerd, CRI-O and Podman.
pub(crate) fn container_id(contents: &str) -> Option<String> {
    for line in contents.lines() {
        let Some(path) = line.rsplit(':').next() else {
            continue;
        };
        let Some(component) = path.rsplit('/').next() else {
            continue;
        };

        for (prefix, suffix) in [
            ("docker-", ".scope"),
            ("cri-containerd-", ".scope"),
            ("crio-", ".scope"),
            ("libpod-", ".scope"),
        ] {
            if let Some(id) = component
                .strip_prefix(prefix)
                .and_then(|rest| rest.strip_suffix(suffix))
                .filter(|id| !id.is_empty())
            {
                return Some(id.to_owned());
            }
        }

        // cgroupfs driver: `.../docker/<id>` (Docker and ZimaOS images).
        let mut components = path.split('/').rev();
        if let Some(id) = components.next() {
            if is_container_hex(id) && components.next() == Some("docker") {
                return Some(id.to_owned());
            }
        }
    }
    None
}

/// Container runtime ids are hex; requiring hex avoids latching onto an
/// arbitrary directory called `docker`.
fn is_container_hex(value: &str) -> bool {
    value.len() >= 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cgroup_v2_docker_scope() {
        let contents = "0::/system.slice/docker-3f2a9c1d4b5e6f708a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5.scope";
        assert_eq!(
            container_id(contents).as_deref(),
            Some("3f2a9c1d4b5e6f708a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5")
        );
    }

    #[test]
    fn parses_cgroup_v1_containerd_scope() {
        let contents = "11:memory:/kubepods.slice/cri-containerd-abcdef0123456789.scope\n\
             10:cpu:/kubepods.slice/cri-containerd-abcdef0123456789.scope";
        assert_eq!(container_id(contents).as_deref(), Some("abcdef0123456789"));
    }

    #[test]
    fn parses_cgroupfs_docker_id() {
        let id = "3f2a9c1d4b5e6f708a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5";
        let contents = format!("0::/docker/{id}");
        assert_eq!(container_id(&contents).as_deref(), Some(id));

        let contents = format!("11:memory:/docker/{id}\n10:cpu:/docker/{id}");
        assert_eq!(container_id(&contents).as_deref(), Some(id));
    }

    #[test]
    fn parses_libpod_scope() {
        assert_eq!(
            container_id("0::/machine.slice/libpod-abcdef0123456789.scope").as_deref(),
            Some("abcdef0123456789")
        );
    }

    #[test]
    fn short_lookalike_directories_are_not_containers() {
        assert_eq!(container_id("0::/docker/not-an-id"), None);
    }

    #[test]
    fn host_processes_have_no_container_id() {
        assert_eq!(container_id("0::/init.scope"), None);
        assert_eq!(container_id("0::/user.slice/user-1000.slice"), None);
    }

    #[test]
    fn walk_inherits_the_container_for_nested_directories() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("zs-cgroup-{}-{unique}", std::process::id()));
        let id = "3f2a9c1d4b5e6f708a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5";
        let container = root.join("system.slice").join(format!("docker-{id}.scope"));
        let nested = container.join("nested");
        let host = root.join("user.slice");
        std::fs::create_dir_all(&nested).expect("create nested cgroup");
        std::fs::create_dir_all(&host).expect("create host cgroup");

        let mut index = HashMap::new();
        walk_tree(&root, &mut index);

        let container_inode = std::fs::metadata(&container)
            .expect("container metadata")
            .ino();
        assert_eq!(
            index
                .get(&container_inode)
                .and_then(|value| value.as_deref()),
            Some(id)
        );
        let nested_inode = std::fs::metadata(&nested).expect("nested metadata").ino();
        assert_eq!(
            index.get(&nested_inode).and_then(|value| value.as_deref()),
            Some(id)
        );
        let host_inode = std::fs::metadata(&host).expect("host metadata").ino();
        assert!(index.get(&host_inode).is_some_and(|value| value.is_none()));

        let _ = std::fs::remove_dir_all(&root);
    }
}

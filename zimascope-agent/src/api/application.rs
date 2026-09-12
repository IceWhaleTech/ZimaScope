//! Resolves kernel socket-owner observations into stable Application identities.
//!
//! The kernel captures `tgid`, `uid`, `cgroup_id` and `comm` in process
//! context. This module adds what only user space can read: the executable
//! path and the container that the process belongs to. Resolution is
//! best-effort and cached; a process that exited in the meantime still keeps
//! its `comm` from the kernel observation.

use std::{collections::HashMap, fs};

use zimascope_common::model::ApplicationRef;

/// How many `(tgid, comm)` resolutions are cached before the cache is dropped.
const RESOLUTION_CACHE_CAPACITY: usize = 4_096;

/// A stable Application record ready for storage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedApplication {
    /// Stable identity key: `cont:<container id>` or `proc:<executable>`.
    pub id: String,
    pub kind: &'static str,
    pub name: String,
    pub exe: Option<String>,
    pub comm: String,
    pub uid: u32,
    pub container_id: Option<String>,
}

/// Cached resolver for Application Identities.
#[derive(Default)]
pub(crate) struct ApplicationResolver {
    cache: HashMap<(u32, String), ProcessFacts>,
}

#[derive(Clone, Debug, Default)]
struct ProcessFacts {
    exe: Option<String>,
    container_id: Option<String>,
}

impl ApplicationResolver {
    /// Resolves one kernel observation, or `None` when no identity evidence
    /// exists at all.
    pub(crate) fn resolve(
        &mut self,
        application: Option<&ApplicationRef>,
    ) -> Option<ResolvedApplication> {
        let application = application?;
        let comm: String = application.comm.to_string();
        let facts = self.facts(application.tgid, &comm);

        let (id, kind, name) = if let Some(container_id) = &facts.container_id {
            let name = if comm.is_empty() {
                container_id.chars().take(12).collect()
            } else {
                comm.clone()
            };
            (format!("cont:{container_id}"), "container", name)
        } else if let Some(exe) = &facts.exe {
            let name = exe
                .rsplit('/')
                .next()
                .filter(|name| !name.is_empty())
                .unwrap_or(exe)
                .to_owned();
            (format!("proc:{exe}"), "process", name)
        } else if !comm.is_empty() {
            let id = format!("proc:comm:{comm}");
            (id, "process", comm.clone())
        } else {
            return None;
        };

        Some(ResolvedApplication {
            id,
            kind,
            name,
            exe: facts.exe,
            comm,
            uid: application.uid,
            container_id: facts.container_id,
        })
    }

    fn facts(&mut self, tgid: u32, comm: &str) -> ProcessFacts {
        let key = (tgid, comm.to_owned());
        if let Some(facts) = self.cache.get(&key) {
            return facts.clone();
        }
        if self.cache.len() >= RESOLUTION_CACHE_CAPACITY {
            self.cache.clear();
        }
        let facts = read_process_facts(tgid);
        self.cache.insert(key, facts.clone());
        facts
    }
}

fn read_process_facts(tgid: u32) -> ProcessFacts {
    let exe = fs::read_link(format!("/proc/{tgid}/exe"))
        .ok()
        .and_then(|path| path.to_str().and_then(normalize_exe));
    let container_id = fs::read_to_string(format!("/proc/{tgid}/cgroup"))
        .ok()
        .as_deref()
        .and_then(container_id_from_cgroup);

    ProcessFacts { exe, container_id }
}

fn normalize_exe(path: &str) -> Option<String> {
    let path = path.trim_end_matches(" (deleted)");
    if path.is_empty() {
        None
    } else {
        Some(path.to_owned())
    }
}

/// Extracts a container id from a `/proc/<pid>/cgroup` document.
///
/// Handles the cgroup v2 and v1 path conventions used by Docker (systemd
/// scopes and the cgroupfs driver), containerd, CRI-O and Podman.
fn container_id_from_cgroup(contents: &str) -> Option<String> {
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
            container_id_from_cgroup(contents).as_deref(),
            Some("3f2a9c1d4b5e6f708a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5")
        );
    }
    #[test]
    fn parses_cgroup_v1_containerd_scope() {
        let contents = "11:memory:/kubepods.slice/cri-containerd-abcdef0123456789.scope\n\
             10:cpu:/kubepods.slice/cri-containerd-abcdef0123456789.scope";
        assert_eq!(
            container_id_from_cgroup(contents).as_deref(),
            Some("abcdef0123456789")
        );
    }

    #[test]
    fn parses_cgroupfs_docker_id() {
        let id = "3f2a9c1d4b5e6f708a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5";
        let contents = format!("0::/docker/{id}");
        assert_eq!(container_id_from_cgroup(&contents).as_deref(), Some(id));

        let contents = format!("11:memory:/docker/{id}\n10:cpu:/docker/{id}");
        assert_eq!(container_id_from_cgroup(&contents).as_deref(), Some(id));
    }

    #[test]
    fn parses_libpod_scope() {
        assert_eq!(
            container_id_from_cgroup("0::/machine.slice/libpod-abcdef0123456789.scope").as_deref(),
            Some("abcdef0123456789")
        );
    }

    #[test]
    fn short_lookalike_directories_are_not_containers() {
        assert_eq!(container_id_from_cgroup("0::/docker/not-an-id"), None);
    }

    #[test]
    fn host_processes_have_no_container_id() {
        assert_eq!(container_id_from_cgroup("0::/init.scope"), None);
        assert_eq!(
            container_id_from_cgroup("0::/user.slice/user-1000.slice"),
            None
        );
    }

    #[test]
    fn resolves_comm_identity_when_the_process_is_gone() {
        let mut resolver = ApplicationResolver::default();
        let application = ApplicationRef {
            tgid: 999_999,
            uid: 1000,
            cgroup_id: 0,
            comm: "curl".into(),
        };

        let resolved = resolver.resolve(Some(&application)).expect("identity");
        assert_eq!(resolved.id, "proc:comm:curl");
        assert_eq!(resolved.kind, "process");
        assert_eq!(resolved.name, "curl");
        assert_eq!(resolved.uid, 1000);
    }

    #[test]
    fn no_observation_resolves_to_nothing() {
        let mut resolver = ApplicationResolver::default();
        assert!(resolver.resolve(None).is_none());
    }
}

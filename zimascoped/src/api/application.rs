//! Resolves kernel socket-owner observations into stable Application identities.
//!
//! The kernel captures `tgid`, `uid`, `cgroup_id` and `comm` in process
//! context. This module adds what only user space can read: the executable
//! path and the container that the process belongs to. Resolution is
//! best-effort and cached; a process that exited in the meantime still keeps
//! its `comm` from the kernel observation.

use std::{collections::HashMap, fs, time::Instant};

use zimascope_common::model::ApplicationRef;

use crate::cgroup;

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
    /// cgroup directory inode (`cgroup_id`) to container id.
    cgroup_index: HashMap<u64, Option<Box<str>>>,
    cgroup_index_at: Option<Instant>,
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
        let facts = self.facts(application.tgid, &comm, application.cgroup_id);

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

    fn facts(&mut self, tgid: u32, comm: &str, cgroup_id: u64) -> ProcessFacts {
        let key = (tgid, comm.to_owned());
        if let Some(facts) = self.cache.get(&key) {
            return facts.clone();
        }
        if self.cache.len() >= RESOLUTION_CACHE_CAPACITY {
            self.cache.clear();
        }
        let mut facts = read_process_facts(tgid);
        // Short-lived processes exit before the poll; the kernel's cgroup id
        // still identifies the container they ran in.
        if facts.container_id.is_none() {
            facts.container_id = self.container_for_cgroup(cgroup_id);
        }
        self.cache.insert(key, facts.clone());
        facts
    }

    /// Maps a kernel `cgroup_id` to the container that owns that cgroup.
    ///
    /// cgroup v2 ids are the inode of the cgroup directory, so the index is
    /// built by walking `/sys/fs/cgroup`; an unknown id re-walks the tree at
    /// most once per [`CGROUP_INDEX_REFRESH`] so containers started later are
    /// still found.
    fn container_for_cgroup(&mut self, cgroup_id: u64) -> Option<String> {
        if cgroup_id == 0 {
            return None;
        }
        if let Some(found) = self.cgroup_index.get(&cgroup_id) {
            return found.as_deref().map(ToOwned::to_owned);
        }

        let due = self
            .cgroup_index_at
            .map(|at| at.elapsed() >= cgroup::INDEX_REFRESH)
            .unwrap_or(true);
        if due {
            self.cgroup_index = index_cgroups();
            self.cgroup_index_at = Some(Instant::now());
            if let Some(found) = self.cgroup_index.get(&cgroup_id) {
                return found.as_deref().map(ToOwned::to_owned);
            }
        }
        None
    }
}

fn read_process_facts(tgid: u32) -> ProcessFacts {
    let exe = fs::read_link(format!("/proc/{tgid}/exe"))
        .ok()
        .and_then(|path| path.to_str().and_then(normalize_exe));
    let container_id = fs::read_to_string(format!("/proc/{tgid}/cgroup"))
        .ok()
        .as_deref()
        .and_then(cgroup::container_id);

    ProcessFacts { exe, container_id }
}

/// Walks the cgroup v2 tree and records every directory inode.
fn index_cgroups() -> HashMap<u64, Option<Box<str>>> {
    let mut index = HashMap::new();
    cgroup::walk_tree(std::path::Path::new("/sys/fs/cgroup"), &mut index);
    index
}

fn normalize_exe(path: &str) -> Option<String> {
    let path = path.trim_end_matches(" (deleted)");
    if path.is_empty() {
        None
    } else {
        Some(path.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

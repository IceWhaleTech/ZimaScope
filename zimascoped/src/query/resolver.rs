//! Resolution of a [`Selector`] into bounded, kernel-matchable targets.
//!
//! The resolver owns selector -> target conversion; the policy compiler owns
//! targets plus action -> kernel program; feature code owns neither and never
//! queries storage directly (ADR-0005).

use std::{
    net::{IpAddr, Ipv4Addr},
    time::SystemTime,
};

use zimascope_common::model;

use super::selector::Selector;
use crate::cgroup::CgroupIndex;

/// Stored process names backing `proc:<exe>` identities.
pub(crate) trait ApplicationComms {
    /// The kernel `comm` recorded for an executable-path identity.
    fn comm(&self, id: &str) -> Option<String>;
}

/// One selector -> target conversion.
pub trait EvidenceResolver {
    fn resolve(
        &mut self,
        selector: &Selector,
        context: &ResolveContext,
    ) -> Result<Resolution, ResolveError>;
}

/// Inputs a resolver may use; `now` bounds evidence freshness.
#[derive(Clone, Copy, Debug)]
pub struct ResolveContext {
    pub now: SystemTime,
}

/// The bounded resource set a selector locates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Resolution {
    pub targets: Vec<MatchTarget>,
    pub coverage: Coverage,
    pub expires_at: Option<SystemTime>,
}

/// One kernel-matchable target.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum MatchTarget {
    Endpoint {
        address: Ipv4Addr,
        port: Option<u16>,
    },
    Cidr {
        address: Ipv4Addr,
        prefix_len: u8,
    },
    AppCgroup {
        cgroup_id: u64,
    },
    AppComm {
        comm: [u8; 16],
    },
}

/// Whether a resolution is usable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Coverage {
    Complete,
    /// The rule persists but installs no match entries.
    Unresolved {
        reason: String,
    },
}

/// The resolver itself failed; retried on the next refresh trigger.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResolveError {
    Unavailable { reason: String },
}

/// Resolves selectors against the host's evidence sources.
pub(crate) struct SystemEvidenceResolver<'a> {
    cgroups: &'a mut CgroupIndex,
    comms: &'a dyn ApplicationComms,
}

impl<'a> SystemEvidenceResolver<'a> {
    pub fn new(cgroups: &'a mut CgroupIndex, comms: &'a dyn ApplicationComms) -> Self {
        Self { cgroups, comms }
    }

    fn complete(mut targets: Vec<MatchTarget>) -> Resolution {
        targets.sort_unstable();
        targets.dedup();
        Resolution {
            targets,
            coverage: Coverage::Complete,
            expires_at: None,
        }
    }

    fn unresolved(reason: String) -> Resolution {
        Resolution {
            targets: Vec::new(),
            coverage: Coverage::Unresolved { reason },
            expires_at: None,
        }
    }

    fn application(&mut self, id: &str) -> Resolution {
        if let Some(comm) = id.strip_prefix("proc:comm:") {
            if comm.is_empty() {
                return Self::unresolved("process name is empty".to_owned());
            }
            return Self::complete(vec![MatchTarget::AppComm {
                comm: model::comm_bytes(comm),
            }]);
        }
        if let Some(container) = id.strip_prefix("cont:") {
            let inodes = self.cgroups.inodes_for_container(container);
            if inodes.is_empty() {
                return Self::unresolved(format!("container {container} has no cgroup directory"));
            }
            return Self::complete(
                inodes
                    .into_iter()
                    .map(|cgroup_id| MatchTarget::AppCgroup { cgroup_id })
                    .collect(),
            );
        }
        if id.starts_with("proc:") {
            let Some(comm) = self.comms.comm(id) else {
                return Self::unresolved(format!("no stored process name for {id}"));
            };
            return Self::complete(vec![MatchTarget::AppComm {
                comm: model::comm_bytes(&comm),
            }]);
        }
        Self::unresolved(format!("application identity {id:?} has no known prefix"))
    }
}

impl EvidenceResolver for SystemEvidenceResolver<'_> {
    fn resolve(
        &mut self,
        selector: &Selector,
        _context: &ResolveContext,
    ) -> Result<Resolution, ResolveError> {
        let resolution = match selector {
            Selector::Endpoint { address, port } => {
                let IpAddr::V4(address) = address else {
                    return Ok(Self::unresolved(
                        "IPv6 matching is a later phase".to_owned(),
                    ));
                };
                Self::complete(vec![MatchTarget::Endpoint {
                    address: *address,
                    port: *port,
                }])
            }
            Selector::Cidr {
                address,
                prefix_len,
            } => {
                let IpAddr::V4(address) = address else {
                    return Ok(Self::unresolved(
                        "IPv6 matching is a later phase".to_owned(),
                    ));
                };
                Self::complete(vec![MatchTarget::Cidr {
                    address: *address,
                    prefix_len: *prefix_len,
                }])
            }
            Selector::Application { id } => self.application(id),
        };
        Ok(resolution)
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, time::Duration};

    use super::*;

    struct FakeComms {
        comms: HashMap<String, String>,
    }

    impl ApplicationComms for FakeComms {
        fn comm(&self, id: &str) -> Option<String> {
            self.comms.get(id).cloned()
        }
    }

    fn context() -> ResolveContext {
        ResolveContext {
            now: SystemTime::UNIX_EPOCH + Duration::from_secs(1),
        }
    }

    fn resolve(cgroups: &mut CgroupIndex, comms: &FakeComms, selector: &Selector) -> Resolution {
        SystemEvidenceResolver::new(cgroups, comms)
            .resolve(selector, &context())
            .expect("resolution succeeds")
    }

    #[test]
    fn endpoints_and_cidrs_need_no_evidence() {
        let mut cgroups = CgroupIndex::default();
        let comms = FakeComms {
            comms: HashMap::new(),
        };
        let resolution = resolve(
            &mut cgroups,
            &comms,
            &Selector::Endpoint {
                address: "203.0.113.9".parse().expect("address"),
                port: Some(443),
            },
        );
        assert_eq!(
            resolution.targets,
            vec![MatchTarget::Endpoint {
                address: "203.0.113.9".parse().expect("address"),
                port: Some(443),
            }]
        );
        assert_eq!(resolution.coverage, Coverage::Complete);
        assert_eq!(resolution.expires_at, None);

        let resolution = resolve(
            &mut cgroups,
            &comms,
            &Selector::Cidr {
                address: "192.0.2.0".parse().expect("address"),
                prefix_len: 24,
            },
        );
        assert_eq!(
            resolution.targets,
            vec![MatchTarget::Cidr {
                address: "192.0.2.0".parse().expect("address"),
                prefix_len: 24,
            }]
        );
    }

    #[test]
    fn comm_identity_matches_the_kernel_encoding() {
        let mut cgroups = CgroupIndex::default();
        let comms = FakeComms {
            comms: HashMap::new(),
        };
        let resolution = resolve(
            &mut cgroups,
            &comms,
            &Selector::Application {
                id: "proc:comm:qbittorrent-nox".to_owned(),
            },
        );

        let mut expected = [0u8; 16];
        expected[..15].copy_from_slice(b"qbittorrent-nox");
        assert_eq!(
            resolution.targets,
            vec![MatchTarget::AppComm { comm: expected }]
        );
    }

    #[test]
    fn container_identity_resolves_to_sorted_deduplicated_cgroups() {
        let mut containers = HashMap::new();
        containers.insert("abc123".to_owned(), vec![42, 41, 42]);
        let mut cgroups = CgroupIndex::with_containers(containers);
        let comms = FakeComms {
            comms: HashMap::new(),
        };

        let resolution = resolve(
            &mut cgroups,
            &comms,
            &Selector::Application {
                id: "cont:abc123".to_owned(),
            },
        );
        assert_eq!(
            resolution.targets,
            vec![
                MatchTarget::AppCgroup { cgroup_id: 41 },
                MatchTarget::AppCgroup { cgroup_id: 42 },
            ]
        );
    }

    #[test]
    fn executable_identity_resolves_through_the_applications_table() {
        let mut cgroups = CgroupIndex::default();
        let mut comms = HashMap::new();
        comms.insert("proc:/usr/bin/curl".to_owned(), "curl".to_owned());
        let comms = FakeComms { comms };

        let resolution = resolve(
            &mut cgroups,
            &comms,
            &Selector::Application {
                id: "proc:/usr/bin/curl".to_owned(),
            },
        );

        let mut expected = [0u8; 16];
        expected[..4].copy_from_slice(b"curl");
        assert_eq!(
            resolution.targets,
            vec![MatchTarget::AppComm { comm: expected }]
        );
    }

    #[test]
    fn missing_evidence_is_unresolved_never_an_error() {
        let mut cgroups = CgroupIndex::with_containers(HashMap::new());
        let comms = FakeComms {
            comms: HashMap::new(),
        };

        for selector in [
            Selector::Application {
                id: "cont:missing".to_owned(),
            },
            Selector::Application {
                id: "proc:/usr/bin/curl".to_owned(),
            },
            Selector::Application {
                id: "mystery:1".to_owned(),
            },
        ] {
            let resolution = resolve(&mut cgroups, &comms, &selector);
            assert!(resolution.targets.is_empty());
            assert!(matches!(resolution.coverage, Coverage::Unresolved { .. }));
        }
    }
}

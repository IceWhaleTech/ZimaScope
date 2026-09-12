//! Compiled Traffic Rule model and kernel reconciliation.
//!
//! User space never touches eBPF objects directly: the API compiles rules into
//! a [`CompiledPolicy`], the collector diffs it against the previously applied
//! program and applies the resulting [`PolicyOp`] sequence through its private
//! `KernelSource` seam. The diff order keeps every intermediate state
//! fail-open (ADR-0004).

use zimascope_common::kernel_abi::{
    BucketKey, Direction, EndpointMatchKey, PolicyConfig, RuleAction, RuleRef,
};

/// One compiled match entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MatchEntry {
    AppCgroup {
        direction: Direction,
        cgroup_id: u64,
    },
    AppComm {
        direction: Direction,
        comm: [u8; 16],
    },
    EndpointExact {
        direction: Direction,
        key: EndpointMatchKey,
    },
    EndpointCidr {
        direction: Direction,
        prefix_len: u32,
        addr: [u8; 4],
    },
}

/// Token bucket parameters for one rule-direction pair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompiledState {
    pub key: BucketKey,
    pub rate_bytes_per_s: u64,
    pub burst_bytes: u64,
}

/// One rule in the shape the kernel maps accept.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledRule {
    pub id: u32,
    pub action: RuleAction,
    pub matches: Vec<MatchEntry>,
    pub states: Vec<CompiledState>,
}

/// Complete desired kernel policy state.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CompiledPolicy {
    pub revision: u64,
    pub enabled: bool,
    pub rules: Vec<CompiledRule>,
}

impl CompiledPolicy {
    fn rule(&self, id: u32) -> Option<&CompiledRule> {
        self.rules.iter().find(|rule| rule.id == id)
    }

    fn has_app_rules(&self) -> bool {
        self.rules.iter().any(|rule| {
            rule.matches.iter().any(|entry| {
                matches!(
                    entry,
                    MatchEntry::AppCgroup { .. } | MatchEntry::AppComm { .. }
                )
            })
        })
    }

    fn has_endpoint_rules(&self) -> bool {
        self.rules.iter().any(|rule| {
            rule.matches.iter().any(|entry| {
                matches!(
                    entry,
                    MatchEntry::EndpointExact { .. } | MatchEntry::EndpointCidr { .. }
                )
            })
        })
    }

    fn config_op(&self, enabled: bool) -> PolicyOp {
        PolicyOp::SetEnabled {
            enabled,
            app_rules: self.has_app_rules(),
            endpoint_rules: self.has_endpoint_rules(),
            revision: self.revision.min(u32::MAX as u64) as u32,
        }
    }
}

/// One ordered kernel-map operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyOp {
    SetEnabled {
        enabled: bool,
        app_rules: bool,
        endpoint_rules: bool,
        revision: u32,
    },
    UpsertState {
        key: BucketKey,
        rate_bytes_per_s: u64,
        burst_bytes: u64,
    },
    RemoveState {
        key: BucketKey,
    },
    UpsertMatch {
        entry: MatchEntry,
        rule: RuleRef,
    },
    RemoveMatch {
        entry: MatchEntry,
    },
}

/// Summary returned after a successful apply.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ApplySummary {
    pub revision: u64,
    pub operations: usize,
    pub rules: usize,
}

/// Builds the ordered operation list between two programs.
///
/// Invariants: disabling writes the config first; removals delete match
/// entries before their state; additions insert state before the match entry
/// that references it; enabling writes the config last.
pub(crate) fn diff(previous: &CompiledPolicy, next: &CompiledPolicy) -> Vec<PolicyOp> {
    let mut operations = Vec::new();
    let disabling = previous.enabled && !next.enabled;
    if disabling {
        operations.push(next.config_op(false));
    }

    for rule in previous
        .rules
        .iter()
        .filter(|rule| next.rule(rule.id).is_none())
    {
        for entry in &rule.matches {
            operations.push(PolicyOp::RemoveMatch { entry: *entry });
        }
        for state in &rule.states {
            operations.push(PolicyOp::RemoveState { key: state.key });
        }
    }

    for rule in &next.rules {
        let before = previous.rule(rule.id);
        for state in &rule.states {
            let unchanged = before
                .and_then(|previous| {
                    previous
                        .states
                        .iter()
                        .find(|previous| previous.key == state.key)
                })
                .is_some_and(|previous| {
                    previous.rate_bytes_per_s == state.rate_bytes_per_s
                        && previous.burst_bytes == state.burst_bytes
                });
            if !unchanged {
                operations.push(PolicyOp::UpsertState {
                    key: state.key,
                    rate_bytes_per_s: state.rate_bytes_per_s,
                    burst_bytes: state.burst_bytes,
                });
            }
        }
        for entry in &rule.matches {
            let unchanged = before.is_some_and(|previous| {
                previous.action == rule.action && previous.matches.contains(entry)
            });
            if !unchanged {
                operations.push(PolicyOp::UpsertMatch {
                    entry: *entry,
                    rule: RuleRef {
                        rule_id: rule.id,
                        action: rule.action as u8,
                        reserved: [0; 3],
                    },
                });
            }
        }
        if let Some(before) = before {
            for entry in &before.matches {
                if !rule.matches.contains(entry) {
                    operations.push(PolicyOp::RemoveMatch { entry: *entry });
                }
            }
        }
    }

    if next.enabled || !disabling {
        operations.push(next.config_op(next.enabled));
    }

    operations
}

/// The configuration entry the kernel fast path reads.
pub(crate) fn config_value(
    enabled: bool,
    app_rules: bool,
    endpoint_rules: bool,
    revision: u32,
) -> PolicyConfig {
    PolicyConfig {
        enabled: u8::from(enabled),
        app_rules: u8::from(app_rules),
        endpoint_rules: u8::from(endpoint_rules),
        reserved: 0,
        revision,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zimascope_common::kernel_abi::RuleAction;

    fn state(rule_id: u32, direction: Direction, rate: u64) -> CompiledState {
        CompiledState {
            key: BucketKey {
                rule_id,
                direction: direction as u8,
                reserved: [0; 3],
            },
            rate_bytes_per_s: rate,
            burst_bytes: rate,
        }
    }

    fn exact(port: u16) -> MatchEntry {
        MatchEntry::EndpointExact {
            direction: Direction::Outbound,
            key: EndpointMatchKey {
                addr: [0; 16],
                port_be: port.to_be(),
                reserved: [0; 6],
            },
        }
    }

    fn rule(id: u32, port: u16, rate: u64) -> CompiledRule {
        CompiledRule {
            id,
            action: RuleAction::Limit,
            matches: vec![exact(port)],
            states: vec![state(id, Direction::Outbound, rate)],
        }
    }

    fn policy(revision: u64, enabled: bool, rules: Vec<CompiledRule>) -> CompiledPolicy {
        CompiledPolicy {
            revision,
            enabled,
            rules,
        }
    }

    #[test]
    fn adding_a_rule_inserts_state_before_match_and_config_last() {
        let next = policy(1, true, vec![rule(1, 443, 1000)]);
        let operations = diff(&CompiledPolicy::default(), &next);

        assert_eq!(
            operations,
            vec![
                PolicyOp::UpsertState {
                    key: state(1, Direction::Outbound, 1000).key,
                    rate_bytes_per_s: 1000,
                    burst_bytes: 1000,
                },
                PolicyOp::UpsertMatch {
                    entry: exact(443),
                    rule: RuleRef {
                        rule_id: 1,
                        action: RuleAction::Limit as u8,
                        reserved: [0; 3],
                    },
                },
                PolicyOp::SetEnabled {
                    enabled: true,
                    app_rules: false,
                    endpoint_rules: true,
                    revision: 1,
                },
            ]
        );
    }

    #[test]
    fn removing_a_rule_deletes_match_before_state() {
        let previous = policy(1, true, vec![rule(1, 443, 1000)]);
        let next = policy(2, true, vec![]);
        let operations = diff(&previous, &next);

        assert_eq!(
            operations,
            vec![
                PolicyOp::RemoveMatch { entry: exact(443) },
                PolicyOp::RemoveState {
                    key: state(1, Direction::Outbound, 1000).key,
                },
                PolicyOp::SetEnabled {
                    enabled: true,
                    app_rules: false,
                    endpoint_rules: false,
                    revision: 2,
                },
            ]
        );
    }

    #[test]
    fn disabling_writes_the_config_first_and_keeps_the_program() {
        let previous = policy(1, true, vec![rule(1, 443, 1000)]);
        let next = policy(2, false, vec![rule(1, 443, 1000)]);
        let operations = diff(&previous, &next);

        assert_eq!(
            operations,
            vec![PolicyOp::SetEnabled {
                enabled: false,
                app_rules: false,
                endpoint_rules: true,
                revision: 2,
            }]
        );
    }

    #[test]
    fn reenabling_writes_the_config_last() {
        let previous = policy(1, false, vec![rule(1, 443, 1000)]);
        let next = policy(2, true, vec![rule(1, 443, 1000)]);
        let operations = diff(&previous, &next);

        assert_eq!(
            operations,
            vec![PolicyOp::SetEnabled {
                enabled: true,
                app_rules: false,
                endpoint_rules: true,
                revision: 2,
            }]
        );
    }

    #[test]
    fn rate_changes_upsert_state_without_touching_matches() {
        let previous = policy(1, true, vec![rule(1, 443, 1000)]);
        let next = policy(2, true, vec![rule(1, 443, 500)]);
        let operations = diff(&previous, &next);

        assert_eq!(
            operations,
            vec![
                PolicyOp::UpsertState {
                    key: state(1, Direction::Outbound, 500).key,
                    rate_bytes_per_s: 500,
                    burst_bytes: 500,
                },
                PolicyOp::SetEnabled {
                    enabled: true,
                    app_rules: false,
                    endpoint_rules: true,
                    revision: 2,
                },
            ]
        );
    }

    #[test]
    fn match_changes_upsert_new_before_removing_stale() {
        let previous = policy(1, true, vec![rule(1, 443, 1000)]);
        let next = policy(2, true, vec![rule(1, 8443, 1000)]);
        let operations = diff(&previous, &next);

        assert_eq!(
            operations,
            vec![
                PolicyOp::UpsertMatch {
                    entry: exact(8443),
                    rule: RuleRef {
                        rule_id: 1,
                        action: RuleAction::Limit as u8,
                        reserved: [0; 3],
                    },
                },
                PolicyOp::RemoveMatch { entry: exact(443) },
                PolicyOp::SetEnabled {
                    enabled: true,
                    app_rules: false,
                    endpoint_rules: true,
                    revision: 2,
                },
            ]
        );
    }

    #[test]
    fn action_changes_reupsert_the_match_values() {
        let previous = policy(1, true, vec![rule(1, 443, 1000)]);
        let mut blocked = rule(1, 443, 1000);
        blocked.action = RuleAction::Block;
        let next = policy(2, true, vec![blocked]);
        let operations = diff(&previous, &next);

        assert_eq!(
            operations,
            vec![
                PolicyOp::UpsertMatch {
                    entry: exact(443),
                    rule: RuleRef {
                        rule_id: 1,
                        action: RuleAction::Block as u8,
                        reserved: [0; 3],
                    },
                },
                PolicyOp::SetEnabled {
                    enabled: true,
                    app_rules: false,
                    endpoint_rules: true,
                    revision: 2,
                },
            ]
        );
    }

    #[test]
    fn application_matches_set_the_app_flag() {
        let next = policy(
            1,
            true,
            vec![CompiledRule {
                id: 1,
                action: RuleAction::Block,
                matches: vec![MatchEntry::AppComm {
                    direction: Direction::Inbound,
                    comm: *b"qbittorrent\0\0\0\0\0",
                }],
                states: vec![],
            }],
        );
        let operations = diff(&CompiledPolicy::default(), &next);
        assert!(matches!(
            operations.last(),
            Some(PolicyOp::SetEnabled {
                app_rules: true,
                endpoint_rules: false,
                ..
            })
        ));
    }
}

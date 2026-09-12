//! Compiled Traffic Rule model and kernel reconciliation.
//!
//! User space never touches eBPF objects directly: the API compiles rules into
//! a [`CompiledPolicy`], the collector diffs it against the previously applied
//! program and applies the resulting [`PolicyOp`] sequence through its private
//! `KernelSource` seam. The diff order keeps every intermediate state
//! fail-open (ADR-0004).

use std::net::Ipv4Addr;

use zimascope_common::kernel_abi::{
    BucketKey, Direction, EndpointMatchKey, PolicyConfig, RuleAction, RuleRef,
};

mod resolve;

pub use resolve::SystemApplicationKeys;

/// Number of rules the kernel maps are compiled with.
pub const MAX_TRAFFIC_RULES: usize =
    zimascope_common::kernel_abi::DEFAULT_TRAFFIC_RULE_CAPACITY as usize;

/// Accepted `limit` rates.
pub const MIN_RATE_BYTES_PER_S: u64 = 4_096;
pub const MAX_RATE_BYTES_PER_S: u64 = 10 * 1024 * 1024 * 1024;

/// Direction a Traffic Rule applies to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuleDirection {
    Inbound,
    Outbound,
    Both,
}

impl RuleDirection {
    fn directions(self) -> &'static [Direction] {
        match self {
            Self::Inbound => &[Direction::Inbound],
            Self::Outbound => &[Direction::Outbound],
            Self::Both => &[Direction::Inbound, Direction::Outbound],
        }
    }

    /// Storage and wire name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Inbound => "inbound",
            Self::Outbound => "outbound",
            Self::Both => "both",
        }
    }

    /// Parses a storage or wire name.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "inbound" => Some(Self::Inbound),
            "outbound" => Some(Self::Outbound),
            "both" => Some(Self::Both),
            _ => None,
        }
    }
}

/// Storage and wire name for a rule action.
pub const fn action_name(action: RuleAction) -> &'static str {
    match action {
        RuleAction::Limit => "limit",
        RuleAction::Block => "block",
    }
}

/// Parses a storage or wire action name.
pub fn action_from_name(name: &str) -> Option<RuleAction> {
    match name {
        "limit" => Some(RuleAction::Limit),
        "block" => Some(RuleAction::Block),
        _ => None,
    }
}

/// What a Traffic Rule matches.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuleMatch {
    Endpoint {
        address: Ipv4Addr,
        port: Option<u16>,
    },
    Cidr {
        address: Ipv4Addr,
        prefix_len: u8,
    },
    Application {
        identity: String,
    },
}

/// A persisted Traffic Rule in product terms.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrafficRule {
    pub id: u32,
    pub action: RuleAction,
    pub direction: RuleDirection,
    pub matcher: RuleMatch,
    pub rate_bytes_per_s: u64,
    pub burst_bytes: u64,
    pub enabled: bool,
}

/// A rule that could not be compiled into kernel state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnresolvedRule {
    pub rule_id: u32,
    pub reason: String,
}

/// Compilation result: the kernel program plus the rules left inactive.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CompiledProgram {
    pub policy: CompiledPolicy,
    pub unresolved: Vec<UnresolvedRule>,
}

/// Kernel-matchable key for one Application Identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppKey {
    Cgroup(u64),
    Comm([u8; 16]),
}

/// Resolves an Application Identity into kernel match keys.
pub trait ApplicationKeys {
    fn keys(&mut self, identity: &str) -> Result<Vec<AppKey>, String>;
}

/// One compiled match entry.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
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

/// Validates one rule in product terms.
pub fn validate_rule(rule: &TrafficRule) -> Result<(), String> {
    match &rule.matcher {
        RuleMatch::Endpoint { address, port } => {
            validate_address(*address)?;
            if port == &Some(0) {
                return Err("port 0 is not a valid match".to_owned());
            }
        }
        RuleMatch::Cidr {
            address,
            prefix_len,
        } => {
            validate_address(*address)?;
            if !(1..=32).contains(prefix_len) {
                return Err("CIDR prefix length must be between 1 and 32".to_owned());
            }
        }
        RuleMatch::Application { identity } => {
            if identity.trim().is_empty() {
                return Err("application identity is empty".to_owned());
            }
        }
    }

    match rule.action {
        RuleAction::Limit => {
            if !(MIN_RATE_BYTES_PER_S..=MAX_RATE_BYTES_PER_S).contains(&rule.rate_bytes_per_s) {
                return Err(format!(
                    "limit rate must be between {MIN_RATE_BYTES_PER_S} and \
                     {MAX_RATE_BYTES_PER_S} bytes per second"
                ));
            }
            if rule.burst_bytes == 0 {
                return Err("limit burst must be greater than zero".to_owned());
            }
        }
        RuleAction::Block => {
            if rule.rate_bytes_per_s != 0 || rule.burst_bytes != 0 {
                return Err("block rules carry no rate".to_owned());
            }
        }
    }
    Ok(())
}

fn validate_address(address: Ipv4Addr) -> Result<(), String> {
    if address.is_unspecified() || address.is_multicast() || address.is_broadcast() {
        return Err(format!("{address} is not a matchable endpoint address"));
    }
    Ok(())
}

/// Compiles enabled rules into kernel state.
///
/// Identity or validation problems mark a rule unresolved instead of failing
/// the whole program; a capacity overflow fails because the kernel maps cannot
/// represent the result at all.
pub fn compile(
    rules: &[TrafficRule],
    keys: &mut dyn ApplicationKeys,
    revision: u64,
    enabled: bool,
) -> Result<CompiledProgram, String> {
    let mut compiled = Vec::new();
    let mut unresolved = Vec::new();
    for rule in rules.iter().filter(|rule| rule.enabled) {
        match compile_rule(rule, keys) {
            Ok(rule) => compiled.push(rule),
            Err(reason) => unresolved.push(UnresolvedRule {
                rule_id: rule.id,
                reason,
            }),
        }
    }

    if compiled.len() > MAX_TRAFFIC_RULES {
        return Err(format!(
            "{} enabled rules exceed the {MAX_TRAFFIC_RULES} rule capacity",
            compiled.len()
        ));
    }
    check_capacity(&compiled)?;

    Ok(CompiledProgram {
        policy: CompiledPolicy {
            revision,
            enabled,
            rules: compiled,
        },
        unresolved,
    })
}

fn compile_rule(
    rule: &TrafficRule,
    keys: &mut dyn ApplicationKeys,
) -> Result<CompiledRule, String> {
    validate_rule(rule)?;

    let matches = match &rule.matcher {
        RuleMatch::Endpoint { address, port } => rule
            .direction
            .directions()
            .iter()
            .map(|direction| MatchEntry::EndpointExact {
                direction: *direction,
                key: EndpointMatchKey {
                    addr: ipv4_storage(*address),
                    port_be: port.map(u16::to_be).unwrap_or(0),
                    reserved: [0; 6],
                },
            })
            .collect(),
        RuleMatch::Cidr {
            address,
            prefix_len,
        } => rule
            .direction
            .directions()
            .iter()
            .map(|direction| MatchEntry::EndpointCidr {
                direction: *direction,
                prefix_len: u32::from(*prefix_len),
                addr: address.octets(),
            })
            .collect(),
        RuleMatch::Application { identity } => {
            let keys = keys.keys(identity)?;
            if keys.is_empty() {
                return Err(format!("no kernel match key for {identity}"));
            }
            let mut entries = Vec::new();
            for direction in rule.direction.directions() {
                for key in &keys {
                    entries.push(match key {
                        AppKey::Cgroup(cgroup_id) => MatchEntry::AppCgroup {
                            direction: *direction,
                            cgroup_id: *cgroup_id,
                        },
                        AppKey::Comm(comm) => MatchEntry::AppComm {
                            direction: *direction,
                            comm: *comm,
                        },
                    });
                }
            }
            entries
        }
    };

    let (rate, burst) = match rule.action {
        RuleAction::Limit => (rule.rate_bytes_per_s, rule.burst_bytes),
        RuleAction::Block => (0, 0),
    };
    let states = rule
        .direction
        .directions()
        .iter()
        .map(|direction| CompiledState {
            key: BucketKey {
                rule_id: rule.id,
                direction: *direction as u8,
                reserved: [0; 3],
            },
            rate_bytes_per_s: rate,
            burst_bytes: burst,
        })
        .collect();

    Ok(CompiledRule {
        id: rule.id,
        action: rule.action,
        matches,
        states,
    })
}

fn check_capacity(rules: &[CompiledRule]) -> Result<(), String> {
    let mut unique: [std::collections::HashSet<MatchEntry>; 8] = Default::default();
    for rule in rules {
        for entry in &rule.matches {
            let index = match entry {
                MatchEntry::AppCgroup {
                    direction: Direction::Inbound,
                    ..
                } => 0,
                MatchEntry::AppCgroup {
                    direction: Direction::Outbound,
                    ..
                } => 1,
                MatchEntry::AppComm {
                    direction: Direction::Inbound,
                    ..
                } => 2,
                MatchEntry::AppComm {
                    direction: Direction::Outbound,
                    ..
                } => 3,
                MatchEntry::EndpointExact {
                    direction: Direction::Inbound,
                    ..
                } => 4,
                MatchEntry::EndpointExact {
                    direction: Direction::Outbound,
                    ..
                } => 5,
                MatchEntry::EndpointCidr {
                    direction: Direction::Inbound,
                    ..
                } => 6,
                MatchEntry::EndpointCidr {
                    direction: Direction::Outbound,
                    ..
                } => 7,
            };
            unique[index].insert(*entry);
        }
    }
    if let Some(overflow) = unique
        .iter()
        .position(|entries| entries.len() > MAX_TRAFFIC_RULES)
    {
        return Err(format!(
            "match tier {overflow} holds {} entries, more than the \
             {MAX_TRAFFIC_RULES} kernel capacity",
            unique[overflow].len()
        ));
    }
    Ok(())
}

fn ipv4_storage(address: Ipv4Addr) -> [u8; 16] {
    let mut storage = [0u8; 16];
    storage[12..].copy_from_slice(&address.octets());
    storage
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

    struct FakeKeys {
        keys: Vec<AppKey>,
        error: Option<&'static str>,
    }

    impl ApplicationKeys for FakeKeys {
        fn keys(&mut self, _identity: &str) -> Result<Vec<AppKey>, String> {
            match self.error {
                Some(reason) => Err(reason.to_owned()),
                None => Ok(self.keys.clone()),
            }
        }
    }

    fn traffic_rule(id: u32, matcher: RuleMatch, direction: RuleDirection) -> TrafficRule {
        TrafficRule {
            id,
            action: RuleAction::Limit,
            direction,
            matcher,
            rate_bytes_per_s: 1_000_000,
            burst_bytes: 1_000_000,
            enabled: true,
        }
    }

    #[test]
    fn endpoint_rules_compile_one_entry_per_direction() {
        let rules = vec![traffic_rule(
            7,
            RuleMatch::Endpoint {
                address: "203.0.113.9".parse().expect("address"),
                port: Some(443),
            },
            RuleDirection::Both,
        )];
        let mut keys = FakeKeys {
            keys: Vec::new(),
            error: None,
        };
        let program = compile(&rules, &mut keys, 3, true).expect("compiles");

        assert_eq!(program.policy.revision, 3);
        assert!(program.policy.enabled);
        assert_eq!(program.policy.rules.len(), 1);
        let rule = &program.policy.rules[0];
        assert_eq!(rule.states.len(), 2);
        assert_eq!(rule.matches.len(), 2);
        assert!(rule.matches.contains(&MatchEntry::EndpointExact {
            direction: Direction::Inbound,
            key: EndpointMatchKey {
                addr: ipv4_storage("203.0.113.9".parse().expect("address")),
                port_be: 443u16.to_be(),
                reserved: [0; 6],
            },
        }));
        assert!(rule.matches.contains(&MatchEntry::EndpointExact {
            direction: Direction::Outbound,
            key: EndpointMatchKey {
                addr: ipv4_storage("203.0.113.9".parse().expect("address")),
                port_be: 443u16.to_be(),
                reserved: [0; 6],
            },
        }));
    }

    #[test]
    fn endpoint_rules_without_a_port_use_the_wildcard() {
        let rules = vec![traffic_rule(
            1,
            RuleMatch::Endpoint {
                address: "198.51.100.4".parse().expect("address"),
                port: None,
            },
            RuleDirection::Outbound,
        )];
        let mut keys = FakeKeys {
            keys: Vec::new(),
            error: None,
        };
        let program = compile(&rules, &mut keys, 1, true).expect("compiles");

        assert!(matches!(
            program.policy.rules[0].matches[0],
            MatchEntry::EndpointExact { key, .. } if key.port_be == 0
        ));
    }

    #[test]
    fn cidr_rules_compile_the_prefix() {
        let rules = vec![traffic_rule(
            1,
            RuleMatch::Cidr {
                address: "192.0.2.0".parse().expect("address"),
                prefix_len: 24,
            },
            RuleDirection::Inbound,
        )];
        let mut keys = FakeKeys {
            keys: Vec::new(),
            error: None,
        };
        let program = compile(&rules, &mut keys, 1, true).expect("compiles");

        assert_eq!(
            program.policy.rules[0].matches,
            vec![MatchEntry::EndpointCidr {
                direction: Direction::Inbound,
                prefix_len: 24,
                addr: [192, 0, 2, 0],
            }]
        );
    }

    #[test]
    fn application_rules_compile_every_resolved_key() {
        let rules = vec![traffic_rule(
            5,
            RuleMatch::Application {
                identity: "cont:abc".to_owned(),
            },
            RuleDirection::Outbound,
        )];
        let mut keys = FakeKeys {
            keys: vec![AppKey::Cgroup(41), AppKey::Cgroup(42)],
            error: None,
        };
        let program = compile(&rules, &mut keys, 1, true).expect("compiles");

        assert_eq!(
            program.policy.rules[0].matches,
            vec![
                MatchEntry::AppCgroup {
                    direction: Direction::Outbound,
                    cgroup_id: 41,
                },
                MatchEntry::AppCgroup {
                    direction: Direction::Outbound,
                    cgroup_id: 42,
                },
            ]
        );
    }

    #[test]
    fn unresolved_identities_leave_the_rule_inactive() {
        let rules = vec![traffic_rule(
            9,
            RuleMatch::Application {
                identity: "proc:/usr/bin/curl".to_owned(),
            },
            RuleDirection::Outbound,
        )];
        let mut keys = FakeKeys {
            keys: Vec::new(),
            error: Some("no comm"),
        };
        let program = compile(&rules, &mut keys, 1, true).expect("compiles");

        assert!(program.policy.rules.is_empty());
        assert_eq!(
            program.unresolved,
            vec![UnresolvedRule {
                rule_id: 9,
                reason: "no comm".to_owned(),
            }]
        );
    }

    #[test]
    fn block_rules_carry_no_rate() {
        let mut rule = traffic_rule(
            2,
            RuleMatch::Endpoint {
                address: "203.0.113.1".parse().expect("address"),
                port: None,
            },
            RuleDirection::Outbound,
        );
        rule.action = RuleAction::Block;
        rule.rate_bytes_per_s = 0;
        rule.burst_bytes = 0;
        let mut keys = FakeKeys {
            keys: Vec::new(),
            error: None,
        };
        let program = compile(&[rule], &mut keys, 1, true).expect("compiles");

        let state = &program.policy.rules[0].states[0];
        assert_eq!(state.rate_bytes_per_s, 0);
        assert_eq!(state.burst_bytes, 0);
    }

    #[test]
    fn invalid_rules_are_unresolved_with_a_reason() {
        let mut too_slow = traffic_rule(
            1,
            RuleMatch::Endpoint {
                address: "203.0.113.1".parse().expect("address"),
                port: None,
            },
            RuleDirection::Outbound,
        );
        too_slow.rate_bytes_per_s = 1;
        too_slow.burst_bytes = 1;

        let mut keys = FakeKeys {
            keys: Vec::new(),
            error: None,
        };
        let program = compile(&[too_slow], &mut keys, 1, true).expect("compiles");

        assert!(program.policy.rules.is_empty());
        assert_eq!(program.unresolved[0].rule_id, 1);
        assert!(program.unresolved[0].reason.contains("limit rate"));
    }

    #[test]
    fn match_capacity_overflow_fails_the_program() {
        let rules = vec![traffic_rule(
            1,
            RuleMatch::Application {
                identity: "cont:big".to_owned(),
            },
            RuleDirection::Outbound,
        )];
        let mut keys = FakeKeys {
            keys: (0..65).map(AppKey::Cgroup).collect(),
            error: None,
        };

        let error = compile(&rules, &mut keys, 1, true).expect_err("capacity overflow");
        assert!(error.contains("kernel capacity"), "{error}");
    }

    #[test]
    fn endpoint_rules_fill_a_match_map_exactly() {
        let rules: Vec<TrafficRule> = (0..MAX_TRAFFIC_RULES)
            .map(|index| {
                traffic_rule(
                    index as u32 + 1,
                    RuleMatch::Endpoint {
                        address: Ipv4Addr::new(203, 0, 113, index as u8 + 1),
                        port: None,
                    },
                    RuleDirection::Outbound,
                )
            })
            .collect();
        let mut keys = FakeKeys {
            keys: Vec::new(),
            error: None,
        };

        let program = compile(&rules, &mut keys, 1, true).expect("compiles at capacity");
        assert_eq!(program.policy.rules.len(), MAX_TRAFFIC_RULES);
    }

    #[test]
    fn disabled_rules_are_skipped() {
        let mut rule = traffic_rule(
            1,
            RuleMatch::Endpoint {
                address: "203.0.113.1".parse().expect("address"),
                port: None,
            },
            RuleDirection::Outbound,
        );
        rule.enabled = false;
        let mut keys = FakeKeys {
            keys: Vec::new(),
            error: None,
        };
        let program = compile(&[rule], &mut keys, 1, true).expect("compiles");

        assert!(program.policy.rules.is_empty());
        assert!(program.unresolved.is_empty());
    }
}

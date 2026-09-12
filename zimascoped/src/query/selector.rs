//! Serializable [`Selector`]: the one query language shared by every
//! control-plane feature that locates resources and acts on them.
//!
//! The IR is a closed set on purpose: the wire shape is the persisted shape,
//! and every variant answers a kernel-capability question before a rule is
//! created (ADR-0005).

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

/// Reason reported for selectors the packet path cannot prove yet.
const IPV6_REASON: &str = "IPv6 matching is a later phase";

/// What an action targets.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Selector {
    /// Direction-relative remote endpoint, optionally narrowed to one port.
    Endpoint { address: IpAddr, port: Option<u16> },
    /// Remote address range, matched by longest prefix.
    Cidr { address: IpAddr, prefix_len: u8 },
    /// Application Identity: `cont:<container id>`, `proc:<exe>` or
    /// `proc:comm:<comm>`.
    Application { id: String },
}

/// How a selector reaches the kernel packet path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelPlan {
    /// Targets follow from the selector alone and stay valid until it changes.
    Direct,
    /// Targets depend on observed evidence and may expire or need a refresh.
    Resolved { refresh: Refresh, expires: bool },
    /// The selector or address family cannot be enforced in this phase.
    Unsupported { reason: &'static str },
}

/// What re-resolves a `Resolved` selector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Refresh {
    /// Container cgroup ids re-resolve on the cgroup-index cadence.
    ContainerIndex,
    /// An executable path resolves to `comm` through the applications table.
    ApplicationsTable,
    /// Domain or enrichment evidence; re-resolve when it changes or expires.
    Evidence,
}

impl KernelPlan {
    /// Wire name used by the preflight response.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Resolved { .. } => "resolved",
            Self::Unsupported { .. } => "unsupported",
        }
    }
}

impl Selector {
    /// Storage and wire name of the selector kind.
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Endpoint { .. } => "endpoint",
            Self::Cidr { .. } => "cidr",
            Self::Application { .. } => "application",
        }
    }

    /// Validates one selector in product terms.
    ///
    /// IPv6 and unknown application prefixes are rejected here as invalid
    /// selectors, not silently compiled into nothing.
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::Endpoint { address, port } => {
                validate_address(*address)?;
                if port == &Some(0) {
                    return Err("port 0 is not a valid match".to_owned());
                }
            }
            Self::Cidr {
                address,
                prefix_len,
            } => {
                validate_address(*address)?;
                if !(1..=32).contains(prefix_len) {
                    return Err("CIDR prefix length must be between 1 and 32".to_owned());
                }
            }
            Self::Application { id } => {
                if id.trim().is_empty() {
                    return Err("application identity is empty".to_owned());
                }
            }
        }
        Ok(())
    }

    /// The kernel capability of this selector.
    pub fn kernel_plan(&self) -> KernelPlan {
        match self {
            Self::Endpoint { address, .. } | Self::Cidr { address, .. } => {
                if address.is_ipv6() {
                    KernelPlan::Unsupported {
                        reason: IPV6_REASON,
                    }
                } else {
                    KernelPlan::Direct
                }
            }
            Self::Application { id } => {
                if id.starts_with("proc:comm:") {
                    KernelPlan::Direct
                } else if id.starts_with("cont:") {
                    KernelPlan::Resolved {
                        refresh: Refresh::ContainerIndex,
                        expires: false,
                    }
                } else if id.starts_with("proc:") {
                    KernelPlan::Resolved {
                        refresh: Refresh::ApplicationsTable,
                        expires: false,
                    }
                } else {
                    KernelPlan::Unsupported {
                        reason: "application identity must start with cont:, proc: or proc:comm:",
                    }
                }
            }
        }
    }
}

fn validate_address(address: IpAddr) -> Result<(), String> {
    if address.is_ipv6() {
        return Err(IPV6_REASON.to_owned());
    }
    let IpAddr::V4(address) = address else {
        return Err(IPV6_REASON.to_owned());
    };
    if address.is_unspecified() || address.is_multicast() || address.is_broadcast() {
        return Err(format!("{address} is not a matchable endpoint address"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(address: &str, port: Option<u16>) -> Selector {
        Selector::Endpoint {
            address: address.parse().expect("address"),
            port,
        }
    }

    #[test]
    fn every_variant_round_trips_through_json() {
        for selector in [
            endpoint("203.0.113.9", Some(443)),
            endpoint("203.0.113.9", None),
            Selector::Cidr {
                address: "192.0.2.0".parse().expect("address"),
                prefix_len: 24,
            },
            Selector::Application {
                id: "cont:abc123".to_owned(),
            },
        ] {
            let json = serde_json::to_string(&selector).expect("serialize");
            let restored: Selector = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(restored, selector);
        }
    }

    #[test]
    fn wire_shape_is_flat_and_tagged() {
        let selector = Selector::Application {
            id: "proc:comm:curl".to_owned(),
        };
        assert_eq!(
            serde_json::to_value(&selector).expect("serialize"),
            serde_json::json!({ "kind": "application", "id": "proc:comm:curl" })
        );
    }

    #[test]
    fn unknown_kinds_are_rejected() {
        let error = serde_json::from_str::<Selector>(r#"{"kind":"domain","domain":"example.com"}"#)
            .expect_err("unknown kind");
        assert!(error.to_string().contains("unknown variant"), "{error}");
    }

    #[test]
    fn unknown_variant_fields_are_rejected() {
        let error = serde_json::from_str::<Selector>(
            r#"{"kind":"endpoint","address":"203.0.113.9","port":443,"sneaky":true}"#,
        )
        .expect_err("unknown field");
        assert!(error.to_string().contains("unknown field"), "{error}");
    }

    #[test]
    fn endpoint_validation_rejects_unmatchable_addresses() {
        assert!(endpoint("0.0.0.0", None).validate().is_err());
        assert!(endpoint("224.0.0.1", None).validate().is_err());
        assert!(endpoint("255.255.255.255", None).validate().is_err());
        assert!(endpoint("203.0.113.9", Some(0)).validate().is_err());
        assert!(endpoint("203.0.113.9", Some(443)).validate().is_ok());
        assert!(endpoint("2001:db8::1", None).validate().is_err());
    }

    #[test]
    fn cidr_validation_bounds_the_prefix() {
        let cidr = |prefix_len| Selector::Cidr {
            address: "192.0.2.0".parse().expect("address"),
            prefix_len,
        };
        assert!(cidr(0).validate().is_err());
        assert!(cidr(24).validate().is_ok());
        assert!(cidr(33).validate().is_err());
    }

    #[test]
    fn application_validation_rejects_empty_identities() {
        assert!(
            Selector::Application {
                id: "  ".to_owned()
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn kernel_plan_follows_the_capability_matrix() {
        assert_eq!(
            endpoint("203.0.113.9", None).kernel_plan(),
            KernelPlan::Direct
        );
        assert_eq!(
            Selector::Cidr {
                address: "192.0.2.0".parse().expect("address"),
                prefix_len: 24,
            }
            .kernel_plan(),
            KernelPlan::Direct
        );
        assert_eq!(
            Selector::Application {
                id: "proc:comm:curl".to_owned(),
            }
            .kernel_plan(),
            KernelPlan::Direct
        );
        assert_eq!(
            Selector::Application {
                id: "cont:abc123".to_owned(),
            }
            .kernel_plan(),
            KernelPlan::Resolved {
                refresh: Refresh::ContainerIndex,
                expires: false,
            }
        );
        assert_eq!(
            Selector::Application {
                id: "proc:/usr/bin/curl".to_owned(),
            }
            .kernel_plan(),
            KernelPlan::Resolved {
                refresh: Refresh::ApplicationsTable,
                expires: false,
            }
        );
        assert!(matches!(
            endpoint("2001:db8::1", None).kernel_plan(),
            KernelPlan::Unsupported { .. }
        ));
        assert!(matches!(
            Selector::Application {
                id: "mystery:1".to_owned(),
            }
            .kernel_plan(),
            KernelPlan::Unsupported { .. }
        ));
    }
}

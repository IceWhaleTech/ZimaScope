//! Fallible lowering of the observation query into an enforceable selector.
//!
//! The observation filter carries dimensions the packet path cannot prove
//! (time windows, Flow state, association confidence and everything read-only).
//! Lowering names those fields instead of silently dropping them, so "act on
//! this view" can explain exactly what is not enforceable (ADR-0005).

use std::fmt;

use crate::api::dto::FlowQuery;

use super::selector::Selector;

/// A [`FlowQuery`] that cannot become a single selector.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnsupportedQuery {
    /// Query fields that block enforcement; empty when the query was empty.
    pub fields: Vec<&'static str>,
    pub reason: String,
}

impl fmt::Display for UnsupportedQuery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.fields.is_empty() {
            return formatter.write_str(&self.reason);
        }
        write!(formatter, "{} ({})", self.reason, self.fields.join(", "))
    }
}

impl std::error::Error for UnsupportedQuery {}

impl TryFrom<&FlowQuery> for Selector {
    type Error = UnsupportedQuery;

    fn try_from(query: &FlowQuery) -> Result<Self, Self::Error> {
        let unsupported: Vec<&'static str> = [
            ("range", query.range.is_some()),
            ("protocol", query.protocol.is_some()),
            ("domain", query.domain.is_some()),
            ("country", query.country.is_some()),
            ("asn", query.asn.is_some()),
            ("organization", query.organization.is_some()),
            ("scope", query.scope.is_some()),
            ("exclude_scope", !query.exclude_scope.is_empty()),
            ("state", query.state.is_some()),
            ("has_domain", query.has_domain.is_some()),
            ("evidence", query.evidence.is_some()),
            ("confidence", query.confidence.is_some()),
            ("hide_noise", query.hide_noise.is_some()),
            ("q", query.q.is_some()),
            ("sort", query.sort.is_some()),
            ("limit", query.limit.is_some()),
            ("offset", query.offset.is_some()),
        ]
        .into_iter()
        .filter_map(|(field, present)| present.then_some(field))
        .collect();
        if !unsupported.is_empty() {
            return Err(UnsupportedQuery {
                fields: unsupported,
                reason: "these filters cannot be proven per packet".to_owned(),
            });
        }

        let addresses: Vec<_> = [query.ip, query.src_ip, query.dst_ip]
            .into_iter()
            .flatten()
            .collect();
        if addresses.len() > 1 {
            return Err(UnsupportedQuery {
                fields: vec!["ip", "src_ip", "dst_ip"],
                reason: "only one address filter can become a selector".to_owned(),
            });
        }
        let address = addresses.first().copied();
        if query.port.is_some() && address.is_none() {
            return Err(UnsupportedQuery {
                fields: vec!["port"],
                reason: "a port filter needs an address filter".to_owned(),
            });
        }

        // `direction` is intentionally not part of a selector; callers map it
        // onto the rule direction themselves.
        let endpoint = address.map(|address| Selector::Endpoint {
            address,
            port: query.port,
        });
        let application = query
            .application_id
            .clone()
            .map(|id| Selector::Application { id });

        match (endpoint, application) {
            (Some(selector), None) | (None, Some(selector)) => Ok(selector),
            (Some(_), Some(_)) => Err(UnsupportedQuery {
                fields: vec!["ip", "application_id"],
                reason: "an endpoint and an application cannot compose in this phase".to_owned(),
            }),
            (None, None) => Err(UnsupportedQuery {
                fields: Vec::new(),
                reason: "the query has no enforceable filter".to_owned(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_address_filter_lowers_to_an_endpoint() {
        let query = FlowQuery {
            ip: Some("203.0.113.9".parse().expect("address")),
            port: Some(443),
            ..FlowQuery::default()
        };
        assert_eq!(
            Selector::try_from(&query).expect("lowers"),
            Selector::Endpoint {
                address: "203.0.113.9".parse().expect("address"),
                port: Some(443),
            }
        );
    }

    #[test]
    fn an_application_filter_lowers_to_an_application() {
        let query = FlowQuery {
            application_id: Some("cont:abc123".to_owned()),
            direction: Some(zimascope_common::model::FlowDirection::Outbound),
            ..FlowQuery::default()
        };
        assert_eq!(
            Selector::try_from(&query).expect("lowers"),
            Selector::Application {
                id: "cont:abc123".to_owned(),
            }
        );
    }

    #[test]
    fn conflicting_address_filters_are_rejected() {
        let query = FlowQuery {
            src_ip: Some("203.0.113.9".parse().expect("address")),
            dst_ip: Some("198.51.100.4".parse().expect("address")),
            ..FlowQuery::default()
        };
        let error = Selector::try_from(&query).expect_err("rejected");
        assert_eq!(error.fields, vec!["ip", "src_ip", "dst_ip"]);
    }

    #[test]
    fn observation_only_fields_are_named() {
        let query = FlowQuery {
            range: Some(crate::api::dto::TimeRange::Hour1),
            state: Some(crate::api::dto::FlowStateParam::Active),
            q: Some("youtube".to_owned()),
            limit: Some(50),
            ip: Some("203.0.113.9".parse().expect("address")),
            ..FlowQuery::default()
        };
        let error = Selector::try_from(&query).expect_err("rejected");
        assert_eq!(error.fields, vec!["range", "state", "q", "limit"]);
    }

    #[test]
    fn endpoint_and_application_cannot_compose() {
        let query = FlowQuery {
            ip: Some("203.0.113.9".parse().expect("address")),
            application_id: Some("cont:abc123".to_owned()),
            ..FlowQuery::default()
        };
        let error = Selector::try_from(&query).expect_err("rejected");
        assert_eq!(error.fields, vec!["ip", "application_id"]);
    }

    #[test]
    fn a_port_without_an_address_is_rejected() {
        let query = FlowQuery {
            port: Some(443),
            ..FlowQuery::default()
        };
        let error = Selector::try_from(&query).expect_err("rejected");
        assert_eq!(error.fields, vec!["port"]);
    }

    #[test]
    fn an_empty_query_has_nothing_to_enforce() {
        let error = Selector::try_from(&FlowQuery::default()).expect_err("rejected");
        assert!(error.fields.is_empty());
        assert!(error.to_string().contains("no enforceable filter"));
    }
}

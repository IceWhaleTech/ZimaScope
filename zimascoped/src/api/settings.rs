//! Settings resource for `GET/PUT/PATCH /v1/settings`.
//!
//! Settings are validated before they are stored. Invalid values are rejected
//! with `422 Unprocessable Entity`; the stored settings are never partially
//! applied.

use serde::{Deserialize, Serialize};

use super::error::ApiError;

/// Retention values accepted by the product (PRD 8.9 / 11).
pub const RETENTION_DAYS: [u16; 3] = [1, 7, 30];

const MIN_FLOW_ENTRIES: u32 = 1_024;
const MAX_FLOW_ENTRIES: u32 = 1_048_576;
const MIN_DISK_QUOTA_MB: u32 = 64;
const MAX_DISK_QUOTA_MB: u32 = 1_048_576;
const MAX_INTERFACE_NAME_LEN: usize = 15;

/// Complete user-visible configuration.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    /// Master switch for collection.
    pub enabled: bool,
    pub boundary: BoundarySettings,
    pub domains: DomainObservationSettings,
    pub history: HistorySettings,
    pub resources: ResourceSettings,
    /// mihomo/Clash external-controller integration (fake-IP resolution).
    pub proxy: ProxySettings,
    /// Master switch for Traffic Rule enforcement.
    pub traffic_rules: TrafficRuleSettings,
}

/// Traffic Rule enforcement controls.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TrafficRuleSettings {
    pub enabled: bool,
}

impl Default for TrafficRuleSettings {
    fn default() -> Self {
        Self { enabled: true }
    }
}

/// Resolves fake-IP destinations through a local/remote proxy control API.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProxySettings {
    pub enabled: bool,
    /// e.g. `http://192.168.100.3:9090`; http only for now.
    pub controller_url: String,
    /// mihomo `secret`.
    pub secret: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BoundarySettings {
    /// Device Boundary uplinks. Empty means "follow the default route".
    pub interfaces: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DomainObservationSettings {
    pub enabled: bool,
    pub dns: bool,
    pub tls_sni: bool,
    pub http_host: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HistorySettings {
    pub enabled: bool,
    pub retention_days: u16,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ResourceSettings {
    pub max_flow_entries: u32,
    pub disk_quota_mb: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            enabled: true,
            boundary: BoundarySettings::default(),
            domains: DomainObservationSettings::default(),
            history: HistorySettings::default(),
            resources: ResourceSettings::default(),
            proxy: ProxySettings::default(),
            traffic_rules: TrafficRuleSettings::default(),
        }
    }
}

impl Default for DomainObservationSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            dns: true,
            tls_sni: true,
            http_host: true,
        }
    }
}

impl Default for HistorySettings {
    fn default() -> Self {
        Self {
            enabled: true,
            retention_days: 7,
        }
    }
}

impl Default for ResourceSettings {
    fn default() -> Self {
        Self {
            max_flow_entries: 65_536,
            disk_quota_mb: 1_024,
        }
    }
}

impl Settings {
    /// Trims and deduplicates interface names; disabled observation switches
    /// are cleared so the stored state is internally consistent.
    pub fn normalize(&mut self) {
        for interface in &mut self.boundary.interfaces {
            *interface = interface.trim().to_owned();
        }
        self.boundary.interfaces.retain(|name| !name.is_empty());
        self.boundary.interfaces.dedup();

        if !self.domains.enabled {
            self.domains.dns = false;
            self.domains.tls_sni = false;
            self.domains.http_host = false;
        }

        self.proxy.controller_url = self
            .proxy
            .controller_url
            .trim()
            .trim_end_matches('/')
            .to_owned();
        self.proxy.secret = self.proxy.secret.trim().to_owned();
        if !self.proxy.enabled {
            self.proxy.secret.clear();
        }
    }

    pub fn validate(&self) -> Result<(), ApiError> {
        if self.boundary.interfaces.len() > 8 {
            return Err(ApiError::unprocessable(
                "boundary.interfaces accepts at most 8 interfaces",
            ));
        }
        for interface in &self.boundary.interfaces {
            if interface.len() > MAX_INTERFACE_NAME_LEN {
                return Err(ApiError::unprocessable(format!(
                    "boundary.interfaces contains an invalid interface name: {interface:?}"
                )));
            }
        }
        if !RETENTION_DAYS.contains(&self.history.retention_days) {
            return Err(ApiError::unprocessable(
                "history.retention_days must be one of 1, 7 or 30",
            ));
        }
        if !(MIN_FLOW_ENTRIES..=MAX_FLOW_ENTRIES).contains(&self.resources.max_flow_entries) {
            return Err(ApiError::unprocessable(format!(
                "resources.max_flow_entries must be between {MIN_FLOW_ENTRIES} and {MAX_FLOW_ENTRIES}"
            )));
        }
        if !(MIN_DISK_QUOTA_MB..=MAX_DISK_QUOTA_MB).contains(&self.resources.disk_quota_mb) {
            return Err(ApiError::unprocessable(format!(
                "resources.disk_quota_mb must be between {MIN_DISK_QUOTA_MB} and {MAX_DISK_QUOTA_MB}"
            )));
        }
        if self.proxy.enabled {
            if !self.proxy.controller_url.starts_with("http://")
                || self.proxy.controller_url.len() > 200
            {
                return Err(ApiError::unprocessable(
                    "proxy.controller_url must be an http:// URL (https is not supported yet)",
                ));
            }
            if self.proxy.secret.len() > 128 {
                return Err(ApiError::unprocessable(
                    "proxy.secret must be at most 128 characters",
                ));
            }
        }
        Ok(())
    }
}

/// Partial settings update for `PATCH /v1/settings`.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SettingsPatch {
    pub enabled: Option<bool>,
    pub boundary: Option<BoundaryPatch>,
    pub domains: Option<DomainObservationPatch>,
    pub history: Option<HistoryPatch>,
    pub resources: Option<ResourcePatch>,
    pub proxy: Option<ProxyPatch>,
    pub traffic_rules: Option<TrafficRulePatch>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BoundaryPatch {
    pub interfaces: Option<Vec<String>>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DomainObservationPatch {
    pub enabled: Option<bool>,
    pub dns: Option<bool>,
    pub tls_sni: Option<bool>,
    pub http_host: Option<bool>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HistoryPatch {
    pub enabled: Option<bool>,
    pub retention_days: Option<u16>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ResourcePatch {
    pub max_flow_entries: Option<u32>,
    pub disk_quota_mb: Option<u32>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProxyPatch {
    pub enabled: Option<bool>,
    pub controller_url: Option<String>,
    pub secret: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TrafficRulePatch {
    pub enabled: Option<bool>,
}

impl SettingsPatch {
    pub fn apply(self, settings: &mut Settings) {
        if let Some(enabled) = self.enabled {
            settings.enabled = enabled;
        }
        if let Some(boundary) = self.boundary {
            if let Some(interfaces) = boundary.interfaces {
                settings.boundary.interfaces = interfaces;
            }
        }
        if let Some(domains) = self.domains {
            if let Some(enabled) = domains.enabled {
                settings.domains.enabled = enabled;
            }
            if let Some(dns) = domains.dns {
                settings.domains.dns = dns;
            }
            if let Some(tls_sni) = domains.tls_sni {
                settings.domains.tls_sni = tls_sni;
            }
            if let Some(http_host) = domains.http_host {
                settings.domains.http_host = http_host;
            }
        }
        if let Some(history) = self.history {
            if let Some(enabled) = history.enabled {
                settings.history.enabled = enabled;
            }
            if let Some(retention_days) = history.retention_days {
                settings.history.retention_days = retention_days;
            }
        }
        if let Some(resources) = self.resources {
            if let Some(max_flow_entries) = resources.max_flow_entries {
                settings.resources.max_flow_entries = max_flow_entries;
            }
            if let Some(disk_quota_mb) = resources.disk_quota_mb {
                settings.resources.disk_quota_mb = disk_quota_mb;
            }
        }
        if let Some(proxy) = self.proxy {
            if let Some(enabled) = proxy.enabled {
                settings.proxy.enabled = enabled;
            }
            if let Some(controller_url) = proxy.controller_url {
                settings.proxy.controller_url = controller_url;
            }
            if let Some(secret) = proxy.secret {
                settings.proxy.secret = secret;
            }
        }
        if let Some(traffic_rules) = self.traffic_rules {
            if let Some(enabled) = traffic_rules.enabled {
                settings.traffic_rules.enabled = enabled;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_the_product() {
        let settings = Settings::default();
        assert!(settings.enabled);
        assert!(settings.boundary.interfaces.is_empty());
        assert_eq!(settings.history.retention_days, 7);
        assert!(settings.validate().is_ok());
    }

    #[test]
    fn rejects_invalid_retention_and_resource_limits() {
        let mut settings = Settings::default();
        settings.history.retention_days = 5;
        assert!(settings.validate().is_err());

        let mut settings = Settings::default();
        settings.resources.max_flow_entries = 1;
        assert!(settings.validate().is_err());

        let mut settings = Settings::default();
        settings.resources.disk_quota_mb = 1;
        assert!(settings.validate().is_err());
    }

    #[test]
    fn normalize_clears_disabled_evidence_and_interface_duplicates() {
        let mut settings = Settings::default();
        settings.domains.enabled = false;
        settings.boundary.interfaces = vec![" eth0 ".into(), "eth0".into(), String::new()];
        settings.normalize();

        assert!(!settings.domains.dns);
        assert!(!settings.domains.tls_sni);
        assert!(!settings.domains.http_host);
        assert_eq!(settings.boundary.interfaces, vec!["eth0".to_owned()]);
    }

    #[test]
    fn patch_applies_only_present_fields() {
        let mut settings = Settings::default();
        let patch = SettingsPatch {
            enabled: Some(false),
            history: Some(HistoryPatch {
                retention_days: Some(30),
                ..HistoryPatch::default()
            }),
            ..SettingsPatch::default()
        };

        patch.apply(&mut settings);

        assert!(!settings.enabled);
        assert_eq!(settings.history.retention_days, 30);
        assert!(settings.history.enabled);
        assert!(settings.domains.enabled);
    }
}

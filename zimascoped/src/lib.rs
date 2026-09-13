//! ZimaScope local agent: collection, enrichment, persistence and API.

pub mod api;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod cgroup;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod collector;
#[allow(dead_code)]
mod enrichment;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub mod policy;
pub mod proxy;
pub mod query;

pub use collector::fingerprint::{FingerprintLibrary, SharedFingerprints, shared_default};
pub use collector::interfaces::InterfaceKind;
pub use collector::{BatchReceiver, Collector, CollectorConfig, InterfaceSelector, PolicyHandle};

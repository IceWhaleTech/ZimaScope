//! ZimaScope local agent: collection, enrichment, persistence and API.

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod collector;
#[allow(dead_code)]
mod enrichment;

pub use collector::{BatchReceiver, Collector, CollectorConfig, InterfaceSelector};

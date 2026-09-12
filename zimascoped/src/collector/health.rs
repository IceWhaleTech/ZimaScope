//! Observation Gap accounting and health snapshots.

use std::time::SystemTime;

use hashbrown::HashMap;
use zimascope_common::{
    kernel_abi,
    model::{
        ApplicationHealth, CollectorHealth, CollectorState, GapReason, InterfaceHealth,
        KernelCounters, ObservationGap,
    },
};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum GapKey {
    FlowMapReadFailed,
    OwnerMapReadFailed,
    KernelStatsReadFailed,
    DomainEventsReadFailed,
    ServiceEventsReadFailed,
    InterfaceDetached(u32),
}

pub(crate) struct HealthTracker {
    open_gaps: HashMap<GapKey, ObservationGap>,
    closed_gaps: Vec<ObservationGap>,
    last_kernel: KernelCounters,
    kernel_seen: bool,
    last_delta: KernelCounters,
}

impl HealthTracker {
    pub fn new() -> Self {
        Self {
            open_gaps: HashMap::new(),
            closed_gaps: Vec::new(),
            last_kernel: KernelCounters::default(),
            kernel_seen: false,
            last_delta: KernelCounters::default(),
        }
    }

    pub fn open_gap(&mut self, key: GapKey, at: SystemTime) {
        if self.open_gaps.contains_key(&key) {
            return;
        }

        let reason = match key {
            GapKey::FlowMapReadFailed
            | GapKey::OwnerMapReadFailed
            | GapKey::KernelStatsReadFailed
            | GapKey::DomainEventsReadFailed
            | GapKey::ServiceEventsReadFailed => GapReason::MapReadFailed,
            GapKey::InterfaceDetached(ifindex) => GapReason::InterfaceDetached { ifindex },
        };
        self.open_gaps.insert(
            key,
            ObservationGap {
                started_at: at,
                ended_at: None,
                reason,
            },
        );
    }

    pub fn close_gap(&mut self, key: GapKey, at: SystemTime) {
        if let Some(mut gap) = self.open_gaps.remove(&key) {
            gap.ended_at = Some(at);
            self.closed_gaps.push(gap);
        }
    }

    pub fn close_all(&mut self, at: SystemTime) {
        let keys: Vec<GapKey> = self.open_gaps.keys().copied().collect();
        for key in keys {
            self.close_gap(key, at);
        }
    }

    pub fn has_open_gaps(&self) -> bool {
        !self.open_gaps.is_empty()
    }

    /// Records cumulative kernel counters and returns the delta since the
    /// previous poll. A counter decrease means the kernel object was reloaded,
    /// so the new cumulative values become the delta.
    pub fn record_kernel(&mut self, stats: kernel_abi::KernelStats) -> KernelCounters {
        let current = KernelCounters {
            packets_seen: stats.packets_seen,
            packets_parsed: stats.packets_parsed,
            parse_failures: stats.parse_failures,
            map_update_failures: stats.map_update_failures,
            flow_evictions: stats.flow_evictions,
            domain_events_emitted: stats.domain_events_emitted,
            domain_events_dropped: stats.domain_events_dropped,
            service_events_emitted: stats.service_events_emitted,
            service_events_dropped: stats.service_events_dropped,
            owner_events_inserted: stats.owner_events_inserted,
            owner_events_dropped: stats.owner_events_dropped,
            policy_dropped_packets: stats.policy_dropped_packets,
            policy_dropped_bytes: stats.policy_dropped_bytes,
            policy_missing_state: stats.policy_missing_state,
        };

        let delta = if self.kernel_seen && is_monotonic(self.last_kernel, current) {
            KernelCounters {
                packets_seen: current.packets_seen - self.last_kernel.packets_seen,
                packets_parsed: current.packets_parsed - self.last_kernel.packets_parsed,
                parse_failures: current.parse_failures - self.last_kernel.parse_failures,
                map_update_failures: current.map_update_failures
                    - self.last_kernel.map_update_failures,
                flow_evictions: current.flow_evictions - self.last_kernel.flow_evictions,
                domain_events_emitted: current.domain_events_emitted
                    - self.last_kernel.domain_events_emitted,
                domain_events_dropped: current.domain_events_dropped
                    - self.last_kernel.domain_events_dropped,
                service_events_emitted: current.service_events_emitted
                    - self.last_kernel.service_events_emitted,
                service_events_dropped: current.service_events_dropped
                    - self.last_kernel.service_events_dropped,
                owner_events_inserted: current.owner_events_inserted
                    - self.last_kernel.owner_events_inserted,
                owner_events_dropped: current.owner_events_dropped
                    - self.last_kernel.owner_events_dropped,
                policy_dropped_packets: current.policy_dropped_packets
                    - self.last_kernel.policy_dropped_packets,
                policy_dropped_bytes: current.policy_dropped_bytes
                    - self.last_kernel.policy_dropped_bytes,
                policy_missing_state: current.policy_missing_state
                    - self.last_kernel.policy_missing_state,
            }
        } else {
            current
        };

        self.last_kernel = current;
        self.kernel_seen = true;
        self.last_delta = delta;
        delta
    }

    pub fn snapshot(
        &mut self,
        state: CollectorState,
        interfaces: Vec<InterfaceHealth>,
        map_entries: usize,
        map_capacity: usize,
        application: ApplicationHealth,
    ) -> CollectorHealth {
        let mut gaps: Vec<ObservationGap> = self.open_gaps.values().cloned().collect();
        gaps.append(&mut self.closed_gaps);

        CollectorHealth {
            state,
            attached_interfaces: interfaces,
            map_entries,
            map_capacity,
            kernel: self.last_delta,
            gaps,
            application,
        }
    }
}

fn is_monotonic(previous: KernelCounters, current: KernelCounters) -> bool {
    current.packets_seen >= previous.packets_seen
        && current.packets_parsed >= previous.packets_parsed
        && current.parse_failures >= previous.parse_failures
        && current.map_update_failures >= previous.map_update_failures
        && current.flow_evictions >= previous.flow_evictions
        && current.domain_events_emitted >= previous.domain_events_emitted
        && current.domain_events_dropped >= previous.domain_events_dropped
        && current.service_events_emitted >= previous.service_events_emitted
        && current.service_events_dropped >= previous.service_events_dropped
        && current.owner_events_inserted >= previous.owner_events_inserted
        && current.owner_events_dropped >= previous.owner_events_dropped
        && current.policy_dropped_packets >= previous.policy_dropped_packets
        && current.policy_dropped_bytes >= previous.policy_dropped_bytes
        && current.policy_missing_state >= previous.policy_missing_state
}

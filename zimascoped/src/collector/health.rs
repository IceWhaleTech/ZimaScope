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

    /// Records the outcome of one kernel read: closes the Observation Gap on
    /// success and opens it on failure. Returns the value on success.
    pub fn observe<T, E>(
        &mut self,
        result: Result<T, E>,
        key: GapKey,
        at: SystemTime,
    ) -> Option<T> {
        match result {
            Ok(value) => {
                self.close_gap(key, at);
                Some(value)
            }
            Err(_) => {
                self.open_gap(key, at);
                None
            }
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
        let current = KernelCounters::from(stats);
        let delta = if self.kernel_seen && current.is_monotonic_from(&self.last_kernel) {
            current.delta_from(&self.last_kernel)
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

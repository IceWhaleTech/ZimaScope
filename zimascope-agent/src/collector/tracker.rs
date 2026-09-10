//! Flow reconciliation between kernel map snapshots and user-space state.

use std::time::{Duration, Instant};

use hashbrown::HashMap;
use zimascope_common::{
    kernel_abi,
    model::{
        EndReason, Endpoint, FlowDirection, FlowKey, FlowState, FlowUpdate, Protocol,
        TrafficCounters,
    },
};

use std::num::NonZeroU32;

/// Maps the kernel monotonic timestamp timeline onto [`Instant`] values.
///
/// eBPF timestamps come from `bpf_ktime_get_ns` (CLOCK_MONOTONIC). The anchor
/// is set from the newest observation in the first batch, so every Flow in a
/// batch keeps its relative ordering.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct MonoClock {
    anchor: Option<(u64, Instant)>,
}

impl MonoClock {
    pub fn anchor_if_needed(&mut self, mono_ns: u64, at: Instant) {
        if self.anchor.is_none() {
            self.anchor = Some((mono_ns, at));
        }
    }

    pub fn to_instant(self, mono_ns: u64) -> Instant {
        match self.anchor {
            None => Instant::now(),
            Some((base_ns, base)) => {
                if mono_ns >= base_ns {
                    base.checked_add(Duration::from_nanos(mono_ns - base_ns))
                        .unwrap_or(base)
                } else {
                    base.checked_sub(Duration::from_nanos(base_ns - mono_ns))
                        .unwrap_or(base)
                }
            }
        }
    }
}

/// One Flow merged across all per-CPU map values.
#[derive(Clone, Debug)]
pub(crate) struct MergedFlow {
    pub key: FlowKey,
    pub total: TrafficCounters,
    pub first_seen_ns: u64,
    pub last_seen_ns: u64,
    pub tcp_flags: u16,
}

#[derive(Clone, Copy, Debug)]
struct PreviousFlow {
    total: TrafficCounters,
    first_seen: Instant,
    last_seen: Instant,
    last_seen_ns: u64,
    tcp_flags: u16,
    state: FlowState,
    generation: u64,
}

const TCP_FIN: u16 = 0x001;
const TCP_RST: u16 = 0x004;

/// Tracks deltas and lifecycle for every Flow seen so far.
pub(crate) struct FlowTracker {
    previous: HashMap<FlowKey, PreviousFlow>,
    idle_timeout: Duration,
    generation: u64,
    clock: MonoClock,
    merged: Vec<MergedFlow>,
}

impl FlowTracker {
    pub fn new(idle_timeout: Duration) -> Self {
        Self {
            previous: HashMap::new(),
            idle_timeout,
            generation: 0,
            clock: MonoClock::default(),
            merged: Vec::new(),
        }
    }

    pub fn clock_mut(&mut self) -> &mut MonoClock {
        &mut self.clock
    }

    /// Validates and merges the per-CPU values of one kernel map entry.
    ///
    /// `first_seen` ignores zero values so other CPUs' untouched slots do not
    /// poison the minimum.
    pub fn merge_entry(
        key: &kernel_abi::FlowKey,
        values: &[kernel_abi::FlowValue],
    ) -> Option<MergedFlow> {
        if values.is_empty() {
            return None;
        }

        let mut packets = 0u64;
        let mut bytes = 0u64;
        let mut first_seen_ns = 0u64;
        let mut last_seen_ns = 0u64;
        let mut tcp_flags = 0u16;

        for value in values {
            packets = packets.saturating_add(value.packets);
            bytes = bytes.saturating_add(value.bytes);
            if value.packets > 0 && (first_seen_ns == 0 || value.first_seen_mono_ns < first_seen_ns)
            {
                first_seen_ns = value.first_seen_mono_ns;
            }
            last_seen_ns = last_seen_ns.max(value.last_seen_mono_ns);
            tcp_flags |= value.tcp_flags;
        }

        Some(MergedFlow {
            key: decode_key(key)?,
            total: TrafficCounters { packets, bytes },
            first_seen_ns,
            last_seen_ns,
            tcp_flags,
        })
    }

    /// Reconciles one poll's merged entries and ages missing ones.
    ///
    /// The returned updates describe observed deltas and closed Flows. Callers
    /// must only call this after a successful map read.
    pub fn reconcile(&mut self, now: Instant) -> Vec<FlowUpdate> {
        self.generation = self.generation.wrapping_add(1);
        let generation = self.generation;

        let newest_ns = self.merged.iter().map(|flow| flow.last_seen_ns).max();
        if let Some(newest_ns) = newest_ns {
            self.clock.anchor_if_needed(newest_ns, now);
        }

        let mut updates = Vec::new();

        let mut merged_buffer = core::mem::take(&mut self.merged);
        for merged in merged_buffer.drain(..) {
            if let Some(update) = self.observe(&merged, now, generation) {
                updates.push(update);
            }
        }
        self.merged = merged_buffer;

        let idle_timeout = self.idle_timeout;
        self.previous.retain(|key, previous| {
            if previous.generation == generation {
                return true;
            }

            let age = now.saturating_duration_since(previous.last_seen);
            if previous.state != FlowState::Active || age < idle_timeout {
                return true;
            }

            updates.push(FlowUpdate {
                key: key.clone(),
                delta: TrafficCounters::default(),
                total: previous.total,
                first_seen: previous.first_seen,
                last_seen: previous.last_seen,
                state: FlowState::Ended(EndReason::EvictedOrUnknown),
            });

            false
        });

        updates
    }

    fn observe(
        &mut self,
        merged: &MergedFlow,
        now: Instant,
        generation: u64,
    ) -> Option<FlowUpdate> {
        let first_seen = self.clock.to_instant(merged.first_seen_ns);
        let last_seen = self.clock.to_instant(merged.last_seen_ns);

        let previous = match self.previous.get_mut(&merged.key) {
            Some(previous) => previous,
            None => {
                self.previous.insert(
                    merged.key.clone(),
                    PreviousFlow {
                        total: merged.total,
                        first_seen,
                        last_seen,
                        last_seen_ns: merged.last_seen_ns,
                        tcp_flags: merged.tcp_flags,
                        state: FlowState::Active,
                        generation,
                    },
                );
                return Some(FlowUpdate {
                    key: merged.key.clone(),
                    delta: merged.total,
                    total: merged.total,
                    first_seen,
                    last_seen,
                    state: FlowState::Active,
                });
            }
        };

        previous.generation = generation;

        let recreated = merged.total.packets < previous.total.packets
            || merged.total.bytes < previous.total.bytes;
        let active = recreated || merged.last_seen_ns > previous.last_seen_ns;

        if !active && previous.state != FlowState::Active {
            return None;
        }

        let delta = if recreated {
            merged.total
        } else {
            TrafficCounters {
                packets: merged.total.packets.saturating_sub(previous.total.packets),
                bytes: merged.total.bytes.saturating_sub(previous.total.bytes),
            }
        };

        let gained_fin = merged.tcp_flags & TCP_FIN != 0 && previous.tcp_flags & TCP_FIN == 0;
        let gained_rst = merged.tcp_flags & TCP_RST != 0 && previous.tcp_flags & TCP_RST == 0;
        let idle =
            !active && now.saturating_duration_since(previous.last_seen) >= self.idle_timeout;

        let state = if gained_rst {
            FlowState::Ended(EndReason::TcpReset)
        } else if gained_fin {
            FlowState::Ended(EndReason::TcpFin)
        } else if idle {
            FlowState::Ended(EndReason::IdleTimeout)
        } else {
            FlowState::Active
        };

        let first_seen = if recreated {
            first_seen
        } else {
            previous.first_seen
        };

        previous.total = merged.total;
        previous.first_seen = first_seen;
        previous.last_seen = last_seen;
        previous.last_seen_ns = merged.last_seen_ns;
        previous.tcp_flags = merged.tcp_flags;
        previous.state = state;

        Some(FlowUpdate {
            key: merged.key.clone(),
            delta,
            total: merged.total,
            first_seen,
            last_seen,
            state,
        })
    }

    /// Reusable buffer for merging a poll's map entries.
    pub fn merged_buffer(&mut self) -> &mut Vec<MergedFlow> {
        self.merged.clear();
        &mut self.merged
    }
}

fn decode_key(key: &kernel_abi::FlowKey) -> Option<FlowKey> {
    let direction = FlowDirection::from_abi(key.direction)?;
    let protocol = Protocol::from_abi(key.protocol)?;
    if key.ip_family != kernel_abi::IpFamily::V4 as u8 {
        return None;
    }

    let source = std::net::IpAddr::V4(std::net::Ipv4Addr::new(
        key.src_addr[12],
        key.src_addr[13],
        key.src_addr[14],
        key.src_addr[15],
    ));
    let destination = std::net::IpAddr::V4(std::net::Ipv4Addr::new(
        key.dst_addr[12],
        key.dst_addr[13],
        key.dst_addr[14],
        key.dst_addr[15],
    ));

    Some(FlowKey {
        source: Endpoint {
            address: source,
            port: Some(u16::from_be(key.src_port_be)),
        },
        destination: Endpoint {
            address: destination,
            port: Some(u16::from_be(key.dst_port_be)),
        },
        interface_index: NonZeroU32::new(key.ifindex)?,
        protocol,
        direction,
    })
}

#[cfg(test)]
mod tests {
    use zimascope_common::kernel_abi::{Direction, IpFamily, TransportProtocol};

    use super::*;

    fn key() -> kernel_abi::FlowKey {
        let mut src_addr = [0u8; 16];
        src_addr[12..].copy_from_slice(&[10, 0, 0, 2]);
        let mut dst_addr = [0u8; 16];
        dst_addr[12..].copy_from_slice(&[1, 1, 1, 1]);
        kernel_abi::FlowKey {
            src_addr,
            dst_addr,
            src_port_be: 40_000u16.to_be(),
            dst_port_be: 443u16.to_be(),
            ifindex: 7,
            protocol: TransportProtocol::Tcp as u8,
            direction: Direction::Outbound as u8,
            ip_family: IpFamily::V4 as u8,
            reserved: 0,
        }
    }

    fn value(packets: u64, bytes: u64, first: u64, last: u64, flags: u16) -> kernel_abi::FlowValue {
        kernel_abi::FlowValue {
            packets,
            bytes,
            first_seen_mono_ns: first,
            last_seen_mono_ns: last,
            tcp_flags: flags,
            parse_flags: 0,
            reserved: 0,
        }
    }

    fn observe(
        tracker: &mut FlowTracker,
        key: &kernel_abi::FlowKey,
        values: &[kernel_abi::FlowValue],
        now: Instant,
    ) -> Vec<FlowUpdate> {
        tracker
            .merged_buffer()
            .push(FlowTracker::merge_entry(key, values).expect("valid key"));
        tracker.reconcile(now)
    }

    #[test]
    fn merge_sums_per_cpu_values() {
        let values = vec![
            value(3, 300, 100, 200, 0x0002),
            value(2, 200, 50, 300, 0x0010),
        ];
        let merged = FlowTracker::merge_entry(&key(), &values).expect("valid");
        assert_eq!(merged.total.packets, 5);
        assert_eq!(merged.total.bytes, 500);
        assert_eq!(merged.first_seen_ns, 50);
        assert_eq!(merged.last_seen_ns, 300);
        assert_eq!(merged.tcp_flags, 0x0012);
    }

    #[test]
    fn merge_ignores_untouched_cpu_slots_for_first_seen() {
        let values = vec![value(0, 0, 0, 0, 0), value(1, 100, 500, 700, 0)];
        let merged = FlowTracker::merge_entry(&key(), &values).expect("valid");
        assert_eq!(merged.first_seen_ns, 500);
        assert_eq!(merged.last_seen_ns, 700);
        assert_eq!(merged.total.packets, 1);
    }

    #[test]
    fn invalid_keys_are_rejected() {
        let mut invalid = key();
        invalid.direction = 9;
        assert!(FlowTracker::merge_entry(&invalid, &[value(1, 1, 1, 1, 0)]).is_none());

        let mut invalid = key();
        invalid.protocol = 99;
        assert!(FlowTracker::merge_entry(&invalid, &[value(1, 1, 1, 1, 0)]).is_none());

        let mut invalid = key();
        invalid.ip_family = 6;
        assert!(FlowTracker::merge_entry(&invalid, &[value(1, 1, 1, 1, 0)]).is_none());

        let mut invalid = key();
        invalid.ifindex = 0;
        assert!(FlowTracker::merge_entry(&invalid, &[value(1, 1, 1, 1, 0)]).is_none());
    }

    #[test]
    fn reports_deltas_across_polls() {
        let mut tracker = FlowTracker::new(Duration::from_secs(30));
        let now = Instant::now();
        let key = key();

        let first = observe(&mut tracker, &key, &[value(3, 300, 100, 200, 0)], now);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].delta.packets, 3);
        assert_eq!(first[0].total.packets, 3);
        assert_eq!(first[0].state, FlowState::Active);

        let second = observe(
            &mut tracker,
            &key,
            &[value(5, 500, 100, 400, 0)],
            now + Duration::from_millis(10),
        );
        assert_eq!(second[0].delta.packets, 2);
        assert_eq!(second[0].delta.bytes, 200);
        assert_eq!(second[0].total.packets, 5);
    }

    #[test]
    fn counter_reset_starts_a_new_observation() {
        let mut tracker = FlowTracker::new(Duration::from_secs(30));
        let now = Instant::now();
        let key = key();

        observe(&mut tracker, &key, &[value(5, 500, 100, 200, 0)], now);
        let updates = observe(
            &mut tracker,
            &key,
            &[value(2, 200, 100, 400, 0)],
            now + Duration::from_millis(10),
        );

        assert_eq!(updates[0].delta.packets, 2);
        assert_eq!(updates[0].delta.bytes, 200);
    }

    #[test]
    fn fin_transition_ends_the_flow() {
        let mut tracker = FlowTracker::new(Duration::from_secs(30));
        let now = Instant::now();
        let key = key();

        observe(&mut tracker, &key, &[value(1, 100, 100, 200, 0x0010)], now);
        let updates = observe(
            &mut tracker,
            &key,
            &[value(2, 200, 100, 300, 0x0011)],
            now + Duration::from_millis(10),
        );

        assert_eq!(updates[0].state, FlowState::Ended(EndReason::TcpFin));
    }

    #[test]
    fn rst_transition_ends_the_flow() {
        let mut tracker = FlowTracker::new(Duration::from_secs(30));
        let now = Instant::now();
        let key = key();

        observe(&mut tracker, &key, &[value(1, 100, 100, 200, 0x0010)], now);
        let updates = observe(
            &mut tracker,
            &key,
            &[value(2, 200, 100, 300, 0x0014)],
            now + Duration::from_millis(10),
        );

        assert_eq!(updates[0].state, FlowState::Ended(EndReason::TcpReset));
    }

    #[test]
    fn idle_flow_ends_after_the_timeout_and_does_not_repeat() {
        let timeout = Duration::from_secs(30);
        let mut tracker = FlowTracker::new(timeout);
        let now = Instant::now();
        let key = key();

        observe(&mut tracker, &key, &[value(1, 100, 100, 200, 0)], now);
        let ended = observe(
            &mut tracker,
            &key,
            &[value(1, 100, 100, 200, 0)],
            now + timeout,
        );

        assert_eq!(ended.len(), 1);
        assert_eq!(ended[0].state, FlowState::Ended(EndReason::IdleTimeout));

        let quiet = observe(
            &mut tracker,
            &key,
            &[value(1, 100, 100, 200, 0)],
            now + timeout + Duration::from_secs(1),
        );
        assert!(quiet.is_empty());
    }

    #[test]
    fn missing_entry_ends_as_evicted_after_the_timeout() {
        let timeout = Duration::from_secs(30);
        let mut tracker = FlowTracker::new(timeout);
        let now = Instant::now();
        let key = key();

        observe(&mut tracker, &key, &[value(1, 100, 100, 200, 0)], now);
        let aged = tracker.reconcile(now + timeout);

        assert_eq!(aged.len(), 1);
        assert_eq!(aged[0].state, FlowState::Ended(EndReason::EvictedOrUnknown));
        assert_eq!(aged[0].delta, TrafficCounters::default());
    }

    #[test]
    fn missing_entry_younger_than_timeout_is_kept() {
        let timeout = Duration::from_secs(30);
        let mut tracker = FlowTracker::new(timeout);
        let now = Instant::now();
        let key = key();

        observe(&mut tracker, &key, &[value(1, 100, 100, 200, 0)], now);
        assert!(tracker.reconcile(now + Duration::from_secs(1)).is_empty());
    }
}

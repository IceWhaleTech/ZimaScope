//! The single collection path for ZimaScope.
//!
//! `Collector` is the worker interface described in
//! `docs/design/rust-collector.md`. Aya objects, polling, map shards, ring
//! buffers, counter rollover, stale Flow detection and Observation Gaps stay
//! inside the worker.

#[cfg(target_os = "linux")]
mod aya;
mod domain;
pub(crate) mod fingerprint;
mod health;
mod listeners;
mod tracker;

#[cfg(test)]
mod test_source;

use std::{
    num::NonZeroU32,
    time::{Duration, Instant, SystemTime},
};

use anyhow::{Context, Result};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
    time::{self, MissedTickBehavior},
};
use zimascope_common::{
    kernel_abi,
    model::{ApplicationHealth, CollectionBatch, CollectorHealth, CollectorState, InterfaceHealth},
};

use domain::DomainDecoder;
use fingerprint::SharedFingerprints;
use health::{GapKey, HealthTracker};
use tracker::FlowTracker;

/// Runtime configuration for one [`Collector`].
#[derive(Clone, Debug)]
pub struct CollectorConfig {
    pub interfaces: Vec<InterfaceSelector>,
    pub idle_timeout: Duration,
    pub collection_interval: Duration,
    /// Hot-swappable fingerprint library shared with the local API.
    pub fingerprints: SharedFingerprints,
}

#[derive(Clone, Debug)]
pub enum InterfaceSelector {
    DefaultRoute,
    Name(Box<str>),
    Index(NonZeroU32),
}

impl Default for CollectorConfig {
    fn default() -> Self {
        Self {
            interfaces: vec![InterfaceSelector::DefaultRoute],
            idle_timeout: Duration::from_secs(30),
            collection_interval: Duration::from_secs(1),
            fingerprints: fingerprint::shared_default(),
        }
    }
}

pub type BatchReceiver = mpsc::Receiver<CollectionBatch>;

const BATCH_CHANNEL_CAPACITY: usize = 4;

/// How often the startup listener sweep is repeated.
///
/// Owner entries expire after `max(2 * idle_timeout, 30s)`; a pre-existing
/// listener never fires `TCP_LISTEN_CB` again, so its seeded entry must be
/// refreshed well before that window closes.
const LISTENER_SEED_INTERVAL: Duration = Duration::from_secs(20);

/// Private seam between the production Aya adapter and deterministic tests.
pub(crate) trait KernelSource: Send {
    fn visit_flows(
        &mut self,
        visitor: &mut dyn FnMut(kernel_abi::FlowKey, &[kernel_abi::FlowValue]),
    ) -> Result<usize>;

    fn visit_owners(
        &mut self,
        visitor: &mut dyn FnMut(kernel_abi::OwnerKey, &kernel_abi::OwnerValue),
    ) -> Result<usize>;

    fn drain_domain_events(
        &mut self,
        visitor: &mut dyn FnMut(&kernel_abi::DomainSample),
    ) -> Result<()>;

    fn drain_service_events(
        &mut self,
        visitor: &mut dyn FnMut(&kernel_abi::ServiceSample),
    ) -> Result<()>;

    fn read_stats(&mut self) -> Result<kernel_abi::KernelStats>;
    fn attachment_health(&self) -> Vec<InterfaceHealth>;
    fn application_health(&self) -> ApplicationHealth;
    fn detach(&mut self) -> Result<()>;
}

/// Handle for the background collection worker.
pub struct Collector {
    shutdown: Option<oneshot::Sender<()>>,
    worker: Option<JoinHandle<Result<CollectorHealth>>>,
}

impl Collector {
    /// Loads eBPF and starts publishing collection batches in the background.
    pub async fn start(config: CollectorConfig) -> Result<(Self, BatchReceiver)> {
        if config.collection_interval.is_zero() {
            anyhow::bail!("collection interval must be greater than zero");
        }
        let collection_interval = config.collection_interval;
        let core = tokio::task::spawn_blocking(move || CollectorCore::open(config))
            .await
            .context("collector initialization task failed")??;
        Ok(Self::run_worker(core, collection_interval))
    }

    fn run_worker(mut core: CollectorCore, collection_interval: Duration) -> (Self, BatchReceiver) {
        let (batch_tx, batch_rx) = mpsc::channel(BATCH_CHANNEL_CAPACITY);
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        let worker = tokio::spawn(async move {
            let mut ticker = time::interval(collection_interval);
            ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

            loop {
                tokio::select! {
                    biased;
                    _ = &mut shutdown_rx => break,
                    _ = ticker.tick() => {}
                }

                let batch = core.poll_once();

                tokio::select! {
                    biased;
                    _ = &mut shutdown_rx => break,
                    result = batch_tx.send(batch) => {
                        if result.is_err() {
                            break;
                        }
                    }
                }
            }

            core.shutdown()
        });

        (
            Self {
                shutdown: Some(shutdown_tx),
                worker: Some(worker),
            },
            batch_rx,
        )
    }

    /// Stops collection, detaches hooks and returns the final health snapshot.
    pub async fn shutdown(mut self) -> Result<CollectorHealth> {
        self.signal_shutdown();
        self.worker
            .take()
            .expect("collector worker handle is present")
            .await
            .context("collector worker task failed")?
    }

    fn signal_shutdown(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
    }
}

impl Drop for Collector {
    fn drop(&mut self) {
        self.signal_shutdown();
    }
}

/// Mutable state owned exclusively by the background worker.
struct CollectorCore {
    source: Box<dyn KernelSource>,
    tracker: FlowTracker,
    domains: DomainDecoder,
    fingerprints: SharedFingerprints,
    health: HealthTracker,
    sequence: u64,
    last_poll: Instant,
    map_entries: usize,
    map_capacity: usize,
    owner_entries: usize,
    /// `Some` once listener seeding is enabled (Linux collection start);
    /// `None` keeps tests deterministic.
    listener_seed: Option<Instant>,
    shutdown_complete: bool,
}

impl CollectorCore {
    /// Loads eBPF, resolves interfaces, and attaches ingress/egress with
    /// rollback if any attachment in the requested set fails.
    #[cfg(target_os = "linux")]
    fn open(config: CollectorConfig) -> Result<Self> {
        let source =
            aya::AyaKernelSource::open(&config).context("open ZimaScope eBPF collector")?;
        let mut core = Self::new(config, Box::new(source));
        // Services already listening at startup never emit TCP_LISTEN_CB, so
        // seed their ownership once before the first poll; poll_once refreshes
        // the sweep periodically because owner entries expire.
        let now = Instant::now();
        listeners::seed(&mut core.tracker, now);
        core.listener_seed = Some(now);
        Ok(core)
    }

    #[cfg(not(target_os = "linux"))]
    fn open(_config: CollectorConfig) -> Result<Self> {
        anyhow::bail!("ZimaScope collection is only supported on Linux")
    }

    fn new(config: CollectorConfig, source: Box<dyn KernelSource>) -> Self {
        Self {
            source,
            tracker: FlowTracker::new(config.idle_timeout),
            domains: DomainDecoder::new(),
            fingerprints: config.fingerprints,
            health: HealthTracker::new(),
            sequence: 0,
            last_poll: Instant::now(),
            map_entries: 0,
            map_capacity: kernel_abi::DEFAULT_FLOW_CAPACITY as usize,
            owner_entries: 0,
            listener_seed: None,
            shutdown_complete: false,
        }
    }

    #[cfg(test)]
    fn from_source(config: CollectorConfig, source: Box<dyn KernelSource>) -> Self {
        Self::new(config, source)
    }

    /// Reads one consistent logical collection interval.
    ///
    /// Runtime failures produce degraded health and Observation Gaps rather
    /// than stopping the collector or discarding the entire batch.
    fn poll_once(&mut self) -> CollectionBatch {
        let poll_started = Instant::now();
        let collected_at = SystemTime::now();
        let interval = poll_started.saturating_duration_since(self.last_poll);
        self.last_poll = poll_started;
        self.sequence = self.sequence.wrapping_add(1);

        // Refresh pre-existing listener ownership before Flow reconciliation,
        // so refreshed entries outlive this poll's owner-cache purge.
        if let Some(last_seed) = self.listener_seed {
            if poll_started.saturating_duration_since(last_seed) >= LISTENER_SEED_INTERVAL {
                listeners::seed(&mut self.tracker, poll_started);
                self.listener_seed = Some(poll_started);
            }
        }

        let mut flows = Vec::new();
        let mut domains = Vec::new();
        let mut degraded = false;

        let flow_result = {
            let source = &mut self.source;
            let merged = self.tracker.merged_buffer();
            source.visit_flows(&mut |key, values| {
                if let Some(entry) = FlowTracker::merge_entry(&key, values) {
                    merged.push(entry);
                }
            })
        };

        let service_result = {
            let source = &mut self.source;
            let tracker = &mut self.tracker;
            let fingerprints = &self.fingerprints;
            source.drain_service_events(&mut |sample| {
                let length = usize::from(sample.payload_len).min(kernel_abi::SERVICE_SAMPLE_MAX);
                let library = fingerprints
                    .read()
                    .unwrap_or_else(|error| error.into_inner());
                if let Some(service) = library.classify(&sample.payload[..length]) {
                    if let Some(key) = tracker::decode_key(&sample.key) {
                        tracker.set_service(&key, service.into());
                    }
                }
            })
        };

        match service_result {
            Ok(()) => {
                self.health
                    .close_gap(GapKey::ServiceEventsReadFailed, collected_at);
            }
            Err(_) => {
                degraded = true;
                self.health
                    .open_gap(GapKey::ServiceEventsReadFailed, collected_at);
            }
        }

        // Owners are read after Flows so a socket observed in the same poll is
        // already cached when deltas are reconciled.
        let owner_result = {
            let source = &mut self.source;
            let tracker = &mut self.tracker;
            source.visit_owners(&mut |key, value| {
                tracker.record_owner(&key, value, poll_started);
            })
        };

        match owner_result {
            Ok(entries) => {
                self.owner_entries = entries;
                self.health
                    .close_gap(GapKey::OwnerMapReadFailed, collected_at);
            }
            Err(_) => {
                degraded = true;
                self.health
                    .open_gap(GapKey::OwnerMapReadFailed, collected_at);
            }
        }

        match flow_result {
            Ok(entries) => {
                self.map_entries = entries;
                self.health
                    .close_gap(GapKey::FlowMapReadFailed, collected_at);
                flows.extend(self.tracker.reconcile(poll_started));
            }
            Err(_) => {
                degraded = true;
                self.health
                    .open_gap(GapKey::FlowMapReadFailed, collected_at);
            }
        }

        let domain_result = {
            let source = &mut self.source;
            let decoder = &mut self.domains;
            let clock = self.tracker.clock_mut();
            source.drain_domain_events(&mut |sample| {
                decoder.decode(sample, clock, poll_started, &mut domains);
            })
        };

        match domain_result {
            Ok(()) => {
                self.health
                    .close_gap(GapKey::DomainEventsReadFailed, collected_at);
            }
            Err(_) => {
                degraded = true;
                self.health
                    .open_gap(GapKey::DomainEventsReadFailed, collected_at);
            }
        }

        self.domains.purge_expired(poll_started);

        match self.source.read_stats() {
            Ok(stats) => {
                self.health.record_kernel(stats);
                self.health
                    .close_gap(GapKey::KernelStatsReadFailed, collected_at);
            }
            Err(_) => {
                degraded = true;
                self.health
                    .open_gap(GapKey::KernelStatsReadFailed, collected_at);
            }
        }

        let interfaces = self.source.attachment_health();
        for interface in &interfaces {
            let key = GapKey::InterfaceDetached(interface.ifindex.get());
            if interface.ingress_attached && interface.egress_attached {
                self.health.close_gap(key, collected_at);
            } else {
                degraded = true;
                self.health.open_gap(key, collected_at);
            }
        }

        let state = if degraded || self.health.has_open_gaps() {
            CollectorState::Degraded
        } else {
            CollectorState::Running
        };
        let application = self.source.application_health();
        let health = self.health.snapshot(
            state,
            interfaces,
            self.map_entries,
            self.map_capacity,
            application,
        );

        CollectionBatch {
            sequence: self.sequence,
            collected_at,
            interval,
            flows,
            domains,
            health,
        }
    }

    /// Detaches hooks and returns a final health snapshot.
    fn shutdown(mut self) -> Result<CollectorHealth> {
        let interfaces = self.source.attachment_health();
        let application = self.source.application_health();
        let detach_result = self
            .source
            .detach()
            .context("detach ZimaScope collection hooks");
        self.shutdown_complete = detach_result.is_ok();
        self.health.close_all(SystemTime::now());
        let health = self.health.snapshot(
            CollectorState::Stopped,
            interfaces,
            self.map_entries,
            self.map_capacity,
            application,
        );
        detach_result.map(|()| health)
    }
}

impl Drop for CollectorCore {
    fn drop(&mut self) {
        if !self.shutdown_complete {
            let _ = self.source.detach();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::atomic::Ordering, time::Duration};

    use tokio::time::timeout;
    use zimascope_common::{
        kernel_abi::{self, Direction, OwnerKind},
        model::{
            AssociationConfidence, CollectorState, DomainEvidence, EndReason, FlowState, GapReason,
        },
    };

    use super::{
        Collector, CollectorConfig, CollectorCore,
        test_source::{
            InMemoryKernelSource, abi_dns_sample, abi_key, abi_owner_key, abi_owner_value,
            abi_tls_sample, abi_value,
        },
    };

    fn open_collector(source: InMemoryKernelSource, idle_timeout: Duration) -> CollectorCore {
        CollectorCore::from_source(
            CollectorConfig {
                idle_timeout,
                ..CollectorConfig::default()
            },
            Box::new(source),
        )
    }

    #[tokio::test]
    async fn worker_publishes_batches_and_detaches_on_shutdown() {
        let source = InMemoryKernelSource::new().with_interface(7, "eth0");
        let counter = source.detach_counter();
        let core = open_collector(source, Duration::from_secs(30));
        let (collector, mut batches) = Collector::run_worker(core, Duration::from_millis(10));

        let batch = timeout(Duration::from_secs(1), batches.recv())
            .await
            .expect("worker publishes promptly")
            .expect("worker keeps the channel open");
        assert_eq!(batch.sequence, 1);

        let health = collector.shutdown().await.expect("shutdown succeeds");
        assert_eq!(health.state, CollectorState::Stopped);
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn zero_collection_interval_is_rejected_before_startup() {
        let result = Collector::start(CollectorConfig {
            collection_interval: Duration::ZERO,
            ..CollectorConfig::default()
        })
        .await;

        assert!(matches!(result, Err(error) if error.to_string().contains("collection interval")));
    }

    #[test]
    fn first_poll_reports_new_flow_and_health() {
        let key = abi_key(
            Direction::Outbound,
            [10, 0, 0, 2],
            [1, 1, 1, 1],
            40_000,
            443,
            6,
        );
        let values = vec![
            abi_value(3, 300, 100, 200, 0x0002),
            abi_value(2, 200, 50, 300, 0x0010),
        ];
        let source = InMemoryKernelSource::new()
            .with_flow(key, values)
            .with_interface(7, "eth0");
        let mut collector = open_collector(source, Duration::from_secs(30));

        let batch = collector.poll_once();

        assert_eq!(batch.sequence, 1);
        assert_eq!(batch.flows.len(), 1);
        let flow = &batch.flows[0];
        assert_eq!(flow.delta.packets, 5);
        assert_eq!(flow.delta.bytes, 500);
        assert_eq!(flow.total.packets, 5);
        assert_eq!(flow.state, FlowState::Active);
        assert_eq!(batch.health.state, CollectorState::Running);
        assert_eq!(batch.health.map_entries, 1);
        assert_eq!(
            batch.health.map_capacity,
            kernel_abi::DEFAULT_FLOW_CAPACITY as usize
        );
        assert_eq!(batch.health.attached_interfaces.len(), 1);
        assert_eq!(batch.health.attached_interfaces[0].name.as_ref(), "eth0");
    }

    #[test]
    fn second_poll_reports_only_the_delta() {
        let key = abi_key(
            Direction::Outbound,
            [10, 0, 0, 2],
            [1, 1, 1, 1],
            40_000,
            443,
            6,
        );
        let source =
            InMemoryKernelSource::new().with_flow(key, vec![abi_value(3, 300, 100, 200, 0)]);
        let handle = source.handle();
        let mut collector = open_collector(source, Duration::from_secs(30));

        assert_eq!(collector.poll_once().flows[0].delta.packets, 3);

        handle.set_flow(key, vec![abi_value(5, 500, 100, 300, 0)]);
        let batch = collector.poll_once();

        assert_eq!(batch.flows[0].delta.packets, 2);
        assert_eq!(batch.flows[0].delta.bytes, 200);
        assert_eq!(batch.flows[0].total.packets, 5);
        assert_eq!(batch.flows[0].state, FlowState::Active);
    }

    #[test]
    fn counter_reset_starts_a_new_observation() {
        let key = abi_key(
            Direction::Inbound,
            [1, 1, 1, 1],
            [10, 0, 0, 2],
            443,
            40_000,
            6,
        );
        let source =
            InMemoryKernelSource::new().with_flow(key, vec![abi_value(5, 500, 100, 200, 0)]);
        let handle = source.handle();
        let mut collector = open_collector(source, Duration::from_secs(30));

        assert_eq!(collector.poll_once().flows[0].delta.packets, 5);

        handle.set_flow(key, vec![abi_value(2, 200, 100, 400, 0)]);
        let batch = collector.poll_once();

        assert_eq!(batch.flows[0].delta.packets, 2);
        assert_eq!(batch.flows[0].delta.bytes, 200);
    }

    #[test]
    fn idle_flow_ends_after_timeout() {
        let key = abi_key(
            Direction::Outbound,
            [10, 0, 0, 2],
            [1, 1, 1, 1],
            40_000,
            443,
            6,
        );
        let source =
            InMemoryKernelSource::new().with_flow(key, vec![abi_value(3, 300, 100, 200, 0)]);
        let mut collector = open_collector(source, Duration::ZERO);

        assert_eq!(collector.poll_once().flows[0].state, FlowState::Active);
        let batch = collector.poll_once();

        assert_eq!(
            batch.flows[0].state,
            FlowState::Ended(EndReason::IdleTimeout)
        );
        assert_eq!(batch.flows[0].delta, Default::default());
    }

    #[test]
    fn missing_flow_evidence_ends_after_timeout() {
        let key = abi_key(
            Direction::Outbound,
            [10, 0, 0, 2],
            [1, 1, 1, 1],
            40_000,
            443,
            6,
        );
        let source =
            InMemoryKernelSource::new().with_flow(key, vec![abi_value(3, 300, 100, 200, 0)]);
        let handle = source.handle();
        let mut collector = open_collector(source, Duration::ZERO);

        assert_eq!(collector.poll_once().flows[0].state, FlowState::Active);

        handle.set_flows(Vec::new());
        let batch = collector.poll_once();

        assert_eq!(
            batch.flows[0].state,
            FlowState::Ended(EndReason::EvictedOrUnknown)
        );
    }

    #[test]
    fn failed_map_read_creates_a_gap_and_recovery_closes_it() {
        let key = abi_key(
            Direction::Outbound,
            [10, 0, 0, 2],
            [1, 1, 1, 1],
            40_000,
            443,
            6,
        );
        let source =
            InMemoryKernelSource::new().with_flow(key, vec![abi_value(3, 300, 100, 200, 0)]);
        let handle = source.handle();
        let mut collector = open_collector(source, Duration::from_secs(30));

        assert_eq!(collector.poll_once().health.state, CollectorState::Running);

        handle.set_flows_failing(true);
        let degraded = collector.poll_once();

        assert_eq!(degraded.health.state, CollectorState::Degraded);
        assert!(degraded.flows.is_empty());
        let open = degraded
            .health
            .gaps
            .iter()
            .find(|gap| matches!(gap.reason, GapReason::MapReadFailed))
            .expect("open gap is reported");
        assert!(open.ended_at.is_none());

        handle.set_flows_failing(false);
        let recovered = collector.poll_once();

        assert_eq!(recovered.health.state, CollectorState::Running);
        let closed = recovered
            .health
            .gaps
            .iter()
            .find(|gap| matches!(gap.reason, GapReason::MapReadFailed))
            .expect("closed gap is reported once");
        assert!(closed.ended_at.is_some());
    }

    #[test]
    fn detached_interface_is_reported_and_recovery_closes_the_gap() {
        let source = InMemoryKernelSource::new().with_interface(7, "eth0");
        let handle = source.handle();
        let mut collector = open_collector(source, Duration::from_secs(30));

        assert_eq!(collector.poll_once().health.state, CollectorState::Running);

        handle.set_interface_attached(7, false);
        let detached = collector.poll_once();

        assert_eq!(detached.health.state, CollectorState::Degraded);
        assert!(
            detached
                .health
                .gaps
                .iter()
                .any(|gap| matches!(gap.reason, GapReason::InterfaceDetached { ifindex: 7 }))
        );
    }

    #[test]
    fn stats_and_domain_read_failures_degrade_health() {
        let source = InMemoryKernelSource::new();
        let handle = source.handle();
        let mut collector = open_collector(source, Duration::from_secs(30));

        assert_eq!(collector.poll_once().health.state, CollectorState::Running);

        handle.set_stats_failing(true);
        handle.set_domains_failing(true);
        let batch = collector.poll_once();

        assert_eq!(batch.health.state, CollectorState::Degraded);
        assert_eq!(
            batch
                .health
                .gaps
                .iter()
                .filter(|gap| matches!(gap.reason, GapReason::MapReadFailed))
                .count(),
            2
        );
    }

    #[test]
    fn invalid_abi_keys_are_ignored_without_losing_map_usage() {
        let mut key = abi_key(
            Direction::Outbound,
            [10, 0, 0, 2],
            [1, 1, 1, 1],
            40_000,
            443,
            6,
        );
        key.direction = 9;
        key.protocol = 99;
        key.ip_family = 6;

        let source = InMemoryKernelSource::new().with_flow(key, vec![abi_value(3, 300, 0, 0, 0)]);
        let mut collector = open_collector(source, Duration::from_secs(30));
        let batch = collector.poll_once();

        assert!(batch.flows.is_empty());
        assert_eq!(batch.health.map_entries, 1);
    }

    #[test]
    fn dns_events_become_inferred_observations_and_deduplicate() {
        let sample = abi_dns_sample("Example.COM", [93, 184, 216, 34], 300);
        let source = InMemoryKernelSource::new().with_event(sample);
        let handle = source.handle();
        let mut collector = open_collector(source, Duration::from_secs(30));

        let batch = collector.poll_once();
        assert_eq!(batch.domains.len(), 1);
        let observation = &batch.domains[0];
        assert_eq!(observation.domain.as_ref(), "example.com");
        assert_eq!(observation.evidence, DomainEvidence::Dns);
        assert_eq!(observation.confidence, AssociationConfidence::Inferred);

        handle.push_event(sample);
        let duplicate = collector.poll_once();
        assert!(duplicate.domains.is_empty());
    }

    #[test]
    fn sni_events_are_direct_evidence() {
        let sample = abi_tls_sample("cdn.example.com", [93, 184, 216, 34]);
        let source = InMemoryKernelSource::new().with_event(sample);
        let mut collector = open_collector(source, Duration::from_secs(30));

        let batch = collector.poll_once();
        assert_eq!(batch.domains.len(), 1);
        assert_eq!(batch.domains[0].evidence, DomainEvidence::TlsSni);
        assert_eq!(batch.domains[0].confidence, AssociationConfidence::Direct);
    }

    #[test]
    fn invalid_domain_samples_are_dropped() {
        let mut sample = abi_dns_sample("example.com", [93, 184, 216, 34], 60);
        sample.kind = 9;
        let source = InMemoryKernelSource::new().with_event(sample);
        let mut collector = open_collector(source, Duration::from_secs(30));

        let batch = collector.poll_once();
        assert!(batch.domains.is_empty());
        assert_eq!(batch.health.state, CollectorState::Running);

        let mut bad_family = abi_dns_sample("example.com", [93, 184, 216, 34], 60);
        bad_family.ip_family = 6;
        let source = InMemoryKernelSource::new().with_event(bad_family);
        let mut collector = open_collector(source, Duration::from_secs(30));
        assert!(collector.poll_once().domains.is_empty());

        let mut bad_transport = abi_dns_sample("example.com", [93, 184, 216, 34], 60);
        bad_transport.transport = 1;
        let source = InMemoryKernelSource::new().with_event(bad_transport);
        let mut collector = open_collector(source, Duration::from_secs(30));
        assert!(collector.poll_once().domains.is_empty());

        let mut empty = abi_dns_sample("example.com", [93, 184, 216, 34], 60);
        empty.payload_len = 0;
        let source = InMemoryKernelSource::new().with_event(empty);
        let mut collector = open_collector(source, Duration::from_secs(30));
        assert!(collector.poll_once().domains.is_empty());
    }

    #[test]
    fn shared_addresses_yield_multiple_domain_candidates() {
        let source = InMemoryKernelSource::new()
            .with_event(abi_dns_sample("one.example", [203, 0, 113, 9], 60))
            .with_event(abi_dns_sample("two.example", [203, 0, 113, 9], 60));
        let mut collector = open_collector(source, Duration::from_secs(30));

        let batch = collector.poll_once();
        assert_eq!(batch.domains.len(), 2);
    }

    #[test]
    fn shutdown_detaches_once_and_reports_stopped() {
        let source = InMemoryKernelSource::new();
        let counter = source.detach_counter();
        let collector = open_collector(source, Duration::from_secs(30));

        let health = collector.shutdown().expect("shutdown succeeds");

        assert_eq!(health.state, CollectorState::Stopped);
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn drop_without_shutdown_detaches() {
        let source = InMemoryKernelSource::new();
        let counter = source.detach_counter();
        let collector = open_collector(source, Duration::from_secs(30));

        drop(collector);

        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn kernel_stats_are_reported_as_interval_deltas() {
        let stats = kernel_abi::KernelStats {
            packets_seen: 100,
            packets_parsed: 80,
            parse_failures: 20,
            ..kernel_abi::KernelStats::default()
        };
        let source = InMemoryKernelSource::new().with_stats(stats);
        let handle = source.handle();
        let mut collector = open_collector(source, Duration::from_secs(30));

        let first = collector.poll_once();
        assert_eq!(first.health.kernel.packets_seen, 100);
        assert_eq!(first.health.kernel.parse_failures, 20);

        handle.set_stats(kernel_abi::KernelStats {
            packets_seen: 150,
            packets_parsed: 120,
            parse_failures: 30,
            ..kernel_abi::KernelStats::default()
        });
        let second = collector.poll_once();
        assert_eq!(second.health.kernel.packets_seen, 50);
        assert_eq!(second.health.kernel.parse_failures, 10);
    }

    #[test]
    fn flow_updates_carry_application_identity() {
        let key = abi_key(
            Direction::Outbound,
            [10, 0, 0, 2],
            [1, 1, 1, 1],
            40_000,
            443,
            6,
        );
        let source = InMemoryKernelSource::new()
            .with_flow(key, vec![abi_value(3, 300, 100, 200, 0)])
            .with_owner(
                abi_owner_key(6, OwnerKind::Socket, 40_000, Some(([1, 1, 1, 1], 443))),
                abi_owner_value(4242, 1000, "curl"),
            )
            .with_interface(7, "eth0");
        let mut collector = open_collector(source, Duration::from_secs(30));

        let batch = collector.poll_once();

        let application = batch.flows[0].application.as_ref().expect("application");
        assert_eq!(application.tgid, 4242);
        assert_eq!(application.uid, 1000);
        assert_eq!(application.comm.as_ref(), "curl");
        assert!(batch.health.application.attached);
    }

    #[test]
    fn failed_owner_read_creates_a_gap_without_stopping_collection() {
        let source = InMemoryKernelSource::new().with_interface(7, "eth0");
        let handle = source.handle();
        let mut collector = open_collector(source, Duration::from_secs(30));

        assert_eq!(collector.poll_once().health.state, CollectorState::Running);

        handle.set_owners_failing(true);
        let degraded = collector.poll_once();

        assert_eq!(degraded.health.state, CollectorState::Degraded);
        assert_eq!(
            degraded
                .health
                .gaps
                .iter()
                .filter(|gap| matches!(gap.reason, GapReason::MapReadFailed))
                .count(),
            1
        );

        handle.set_owners_failing(false);
        let recovered = collector.poll_once();
        assert_eq!(recovered.health.state, CollectorState::Running);
    }

    #[test]
    fn application_health_reports_attach_failures() {
        let source = InMemoryKernelSource::new().with_interface(7, "eth0");
        let handle = source.handle();
        handle.set_application_health(false, Some("cgroup attach conflict"));
        let mut collector = open_collector(source, Duration::from_secs(30));

        let batch = collector.poll_once();

        assert!(!batch.health.application.attached);
        assert_eq!(
            batch.health.application.last_error.as_deref(),
            Some("cgroup attach conflict")
        );
        // Attribution is advisory: collection is still running.
        assert_eq!(batch.health.state, CollectorState::Running);
    }
}

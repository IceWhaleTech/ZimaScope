# Rust Collector Design

This document is the implementation contract for the ZimaScope collection path. It complements [ADR-0001](../adr/0001-map-aggregation-and-single-collector.md).

## Module shape

```text
zimascope-common
  kernel_abi.rs       fixed-size types shared with eBPF
  model.rs            user-space domain values

zimascope-ebpf
  tc.rs               ingress/egress entry points
  parse.rs            bounded Ethernet/VLAN/IPv4/TCP/UDP parsing
  maps.rs             flow, domain-event, and statistics maps

zimascope-agent
  collector/mod.rs    external Collector interface
  collector/aya.rs    production Aya adapter
  collector/tracker.rs
  collector/domain.rs
  collector/health.rs
  pipeline.rs         enrichment, persistence, and API publication
```

`Collector` is a deep module. Callers do not manage Aya objects, map shards, ring buffers, interface attachments, counter rollover, stale Flow detection, or Observation Gap creation.

## Kernel ABI

Kernel ABI structs contain no `String`, `Vec`, embedded Rust enums, pointers, references, or platform-sized integers. Numeric enums below define validated discriminants, while ABI structs store their values as `u8`. All multi-byte network fields retain network byte order and use a `_be` suffix.

```rust
#![no_std]

pub const ABI_VERSION: u16 = 1;
pub const DOMAIN_MAX_LEN: usize = 253;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct AbiMetadata {
    pub version: u16,
    pub flow_key_size: u16,
    pub flow_value_size: u16,
    pub domain_event_size: u16,
    pub kernel_stats_size: u16,
    pub reserved: [u8; 6],
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpFamily {
    V4 = 4,
    V6 = 6,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    Inbound = 1,
    Outbound = 2,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportProtocol {
    Tcp = 6,
    Udp = 17,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DomainEvidenceKind {
    Dns = 1,
    TlsSni = 2,
    HttpHost = 3,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FlowKey {
    pub src_addr: [u8; 16],
    pub dst_addr: [u8; 16],
    pub src_port_be: u16,
    pub dst_port_be: u16,
    pub ifindex: u32,
    pub protocol: u8,
    pub direction: u8,
    pub ip_family: u8,
    pub reserved: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct FlowValue {
    pub packets: u64,
    pub bytes: u64,
    pub first_seen_mono_ns: u64,
    pub last_seen_mono_ns: u64,
    pub tcp_flags: u16,
    pub parse_flags: u16,
    pub reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DomainEvent {
    pub observed_mono_ns: u64,
    pub expires_mono_ns: u64,
    pub client_context: u64,
    pub address: [u8; 16],
    pub ifindex: u32,
    pub domain_len: u16,
    pub evidence: u8,
    pub ip_family: u8,
    pub direction: u8,
    pub reserved: u8,
    pub domain: [u8; DOMAIN_MAX_LEN],
    pub padding: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct KernelStats {
    pub packets_seen: u64,
    pub packets_parsed: u64,
    pub parse_failures: u64,
    pub map_update_failures: u64,
    pub flow_evictions: u64,
    pub domain_events_emitted: u64,
    pub domain_events_dropped: u64,
}
```

Implementation requirements:

- Store one `AbiMetadata` value in a dedicated single-entry map and reject startup when its version or recorded sizes do not match user space.
- Add compile-time size and alignment assertions for every ABI type.
- Implement the required Aya `Pod` markers only after verifying that every byte, including padding, is initialized.
- Encode IPv4 in the final four bytes of zero-extended 16-byte storage and retain the family discriminant, so the key layout does not change when IPv6 is added.
- Emit one DNS event per domain/address association. TLS SNI and HTTP Host use the peer address from the observed Flow.
- Validate enum discriminants, lengths, and UTF-8 in user space before producing domain values.

## User-space model

These structs are not shared with eBPF and may use normal Rust types.

```rust
use std::{
    net::IpAddr,
    num::{NonZeroU32, NonZeroUsize},
    time::{Duration, Instant, SystemTime},
};

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct FlowKey {
    pub source: Endpoint,
    pub destination: Endpoint,
    pub interface_index: NonZeroU32,
    pub protocol: Protocol,
    pub direction: FlowDirection,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Endpoint {
    pub address: IpAddr,
    pub port: Option<u16>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Protocol {
    Tcp,
    Udp,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FlowDirection {
    Inbound,
    Outbound,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TrafficCounters {
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowState {
    Active,
    Ended(EndReason),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndReason {
    IdleTimeout,
    TcpFin,
    TcpReset,
    EvictedOrUnknown,
}

#[derive(Clone, Debug)]
pub struct FlowUpdate {
    pub key: FlowKey,
    pub delta: TrafficCounters,
    pub total: TrafficCounters,
    pub first_seen: Instant,
    pub last_seen: Instant,
    pub state: FlowState,
}

#[derive(Clone, Debug)]
pub struct DomainObservation {
    pub domain: Box<str>,
    pub address: IpAddr,
    pub evidence: DomainEvidence,
    pub confidence: AssociationConfidence,
    pub client_context: u64,
    pub observed_at: Instant,
    pub expires_at: Instant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DomainEvidence {
    Dns,
    TlsSni,
    HttpHost,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssociationConfidence {
    Direct,
    Inferred,
}

#[derive(Clone, Debug)]
pub struct CollectionBatch {
    pub sequence: u64,
    pub collected_at: SystemTime,
    pub interval: Duration,
    pub flows: Vec<FlowUpdate>,
    pub domains: Vec<DomainObservation>,
    pub health: CollectorHealth,
}

#[derive(Clone, Debug)]
pub struct CollectorHealth {
    pub state: CollectorState,
    pub attached_interfaces: Vec<InterfaceHealth>,
    pub map_entries: usize,
    pub map_capacity: usize,
    pub kernel: KernelCounters,
    pub gaps: Vec<ObservationGap>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CollectorState {
    Starting,
    Running,
    Degraded,
    Stopped,
}

#[derive(Clone, Debug)]
pub struct InterfaceHealth {
    pub ifindex: NonZeroU32,
    pub name: Box<str>,
    pub ingress_attached: bool,
    pub egress_attached: bool,
    pub last_error: Option<Box<str>>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct KernelCounters {
    pub packets_seen: u64,
    pub packets_parsed: u64,
    pub parse_failures: u64,
    pub map_update_failures: u64,
    pub flow_evictions: u64,
    pub domain_events_emitted: u64,
    pub domain_events_dropped: u64,
}

#[derive(Clone, Debug)]
pub struct ObservationGap {
    pub started_at: SystemTime,
    pub ended_at: Option<SystemTime>,
    pub reason: GapReason,
}

#[derive(Clone, Debug)]
pub enum GapReason {
    InterfaceDetached { ifindex: u32 },
    MapReadFailed,
}
```

`FlowUpdate::delta` is the traffic observed since the previous successful poll. `total` is the cumulative value currently represented by the kernel map. Persistence consumes deltas; the live view may use totals.

## Collector interface

```rust
use anyhow::Result;
use std::{num::NonZeroU32, time::Duration};
use tokio::sync::mpsc;

pub struct CollectorConfig {
    pub interfaces: Vec<InterfaceSelector>,
    pub idle_timeout: Duration,
    pub collection_interval: Duration,
}

pub enum InterfaceSelector {
    DefaultRoute,
    Name(Box<str>),
    Index(NonZeroU32),
}

pub struct Collector {
    // Shutdown channel and worker task remain private.
}

impl Collector {
    /// Loads eBPF and starts the single background collection worker.
    pub async fn start(
        config: CollectorConfig,
    ) -> Result<(Self, mpsc::Receiver<CollectionBatch>)>;

    /// Detaches hooks and returns a final health snapshot.
    pub async fn shutdown(self) -> Result<CollectorHealth>;
}
```

`Collector` is a Tokio worker handle. It owns polling and publishes ordered batches through one bounded `mpsc` receiver. The private `CollectorCore::poll_once` remains the deterministic test seam. Storage, enrichment, aggregation, and multi-subscriber publication belong to the downstream pipeline. Dropping the receiver stops the worker; dropping the handle requests best-effort shutdown; `shutdown` waits for detachment and reports cleanup failures explicitly.

Recommended defaults:

```rust
impl Default for CollectorConfig {
    fn default() -> Self {
        Self {
            interfaces: vec![InterfaceSelector::DefaultRoute],
            idle_timeout: Duration::from_secs(30),
            collection_interval: Duration::from_secs(1),
        }
    }
}
```

## Internal seams

The production Aya adapter and deterministic in-memory test adapter justify one internal seam. It is private to the collector module.

```rust
trait KernelSource: Send {
    fn visit_flows(
        &mut self,
        visitor: &mut dyn FnMut(kernel_abi::FlowKey, &[kernel_abi::FlowValue]),
    ) -> anyhow::Result<MapSummary>;

    fn drain_domain_events(
        &mut self,
        visitor: &mut dyn FnMut(&kernel_abi::DomainEvent),
    ) -> anyhow::Result<EventSummary>;

    fn read_stats(&mut self) -> anyhow::Result<kernel_abi::KernelStats>;
    fn attachment_health(&self) -> Vec<InterfaceHealth>;
    fn detach(&mut self) -> anyhow::Result<()>;
}

struct AyaKernelSource {
    // Ebpf, map handles, ring buffer, and RAII TC links.
}

struct InMemoryKernelSource {
    // Test snapshots, events, errors, and attachment state.
}

struct FlowTracker {
    previous: hashbrown::HashMap<FlowKey, PreviousFlow>,
    idle_timeout: Duration,
}

struct PreviousFlow {
    total: TrafficCounters,
    first_seen: Instant,
    last_seen: Instant,
    tcp_flags: u16,
    missed_polls: u8,
}

struct DomainDecoder {
    dedupe: hashbrown::HashMap<DomainDedupeKey, Instant>,
}

#[derive(Eq, Hash, PartialEq)]
struct DomainDedupeKey {
    domain: Box<str>,
    address: IpAddr,
    evidence: DomainEvidence,
    client_context: u64,
}

struct HealthTracker {
    open_gaps: hashbrown::HashMap<GapKey, ObservationGap>,
    last_kernel_stats: KernelCounters,
}
```

Do not add public traits for storage, GeoIP, clocks, or logging to `Collector`. Those are downstream modules or private test utilities, not part of its external interface.

## Worker poll algorithm

On each configured interval, private `CollectorCore::poll_once` performs these bounded steps:

1. Read and merge per-CPU Flow values: sum counters, take the minimum `first_seen`, maximum `last_seen`, and OR TCP/parse flags.
2. Convert validated ABI keys into user-space `FlowKey` values.
3. Calculate deltas with saturating subtraction. A lower total indicates eviction/recreation or counter reset and starts a new logical observation.
4. Mark missing entries as ended only after the configured idle timeout; a failed map read creates an Observation Gap and does not age flows.
5. Drain at most the configured domain-event budget, validate and normalize domains, then deduplicate by domain, address, evidence, and client context until expiry.
6. Read cumulative kernel statistics and convert them to deltas for health reporting.
7. Send one `CollectionBatch` through the bounded worker channel; perform no GeoIP lookup, SQLite write, JSON serialization, or UI work inside collection.

## Error model

Startup and shutdown failures use `anyhow::Result` because the agent is an executable, not a reusable library with a public error contract. Add context at every system seam so the final error still identifies the operation and target:

```rust
use anyhow::{bail, Context, Result};

impl CollectorCore {
    fn open(config: CollectorConfig) -> Result<Self> {
        let mut source = AyaKernelSource::load()
            .context("load ZimaScope eBPF program")?;

        let abi = source
            .read_abi_metadata()
            .context("read eBPF ABI metadata")?;

        if abi.version != ABI_VERSION {
            bail!(
                "eBPF ABI mismatch: expected {}, found {}",
                ABI_VERSION,
                abi.version
            );
        }

        source
            .attach(&config.interfaces)
            .context("attach ZimaScope TC ingress/egress hooks")?;

        Ok(Self::from_source(config, Box::new(source)))
    }
}
```

Do not erase useful context with bare `?` at Aya, netlink, interface, map, or filesystem calls. Runtime collection failures are normally represented through `CollectorHealth`; collection continues wherever safe. No error path may drop, reject, delay, or modify a network packet.

## Packet-path rules

- Flow packets update per-CPU map values and never wake user space individually.
- Domain evidence is emitted after bounded parsing. User space owns deduplication; the bounded ring buffer provides backpressure.
- Map polling is one sequential pass per interval; do not query the same map separately for overview, persistence, and UI.
- Reuse buffers across polls. The eBPF object's fixed map capacity is reported through collector health.
- Keep enrichment, persistence, rollups, and serialization off the collector path.
- Prefer the simplest correct implementation, then benchmark before adding kernel-side caches or rate controls.

## Required tests

- ABI size, alignment, byte order, version, invalid discriminant, and truncated-domain tests.
- Ingress/egress direction tests through network namespaces and veth pairs.
- Per-CPU merge, counter reset, map eviction, stale Flow, and failed-poll tests.
- DNS TTL, shared-IP candidates, TLS SNI/HTTP Host direct evidence, invalid UTF-8, and event-drop tests.
- Attach rollback and shutdown cleanup tests.
- A performance fixture with fixed hardware profile, packet sizes, PPS, Flow cardinality, duration, and enabled feature set for the 1% CPU gate.

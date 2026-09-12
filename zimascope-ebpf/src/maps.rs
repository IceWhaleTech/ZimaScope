//! eBPF map definitions.
//!
//! All maps are bounded. Flow counters live in a per-CPU LRU hash so the
//! packet path never contends on a global lock, and user space reads one
//! consistent snapshot per poll. Domain samples leave the kernel through a
//! ring buffer because domain evidence cannot be reconstructed from counters.
//!
//! Traffic Rule maps are bounded by `DEFAULT_TRAFFIC_RULE_CAPACITY`. The rule
//! state map is declared as a BTF map because its value carries a
//! `bpf_spin_lock`, which the kernel only accepts in a BTF-described map.

use aya_ebpf::{
    btf_maps::HashMap as BtfHashMap,
    macros::{btf_map, map},
    maps::{Array, HashMap, LpmTrie, LruHashMap, LruPerCpuHashMap, PerCpuArray, RingBuf},
};
use zimascope_common::kernel_abi::{
    AbiMetadata, BucketKey, DEFAULT_FLOW_CAPACITY, DEFAULT_LISTENER_CAPACITY,
    DEFAULT_OWNER_CAPACITY, DEFAULT_TRAFFIC_RULE_CAPACITY, DomainSample, EndpointMatchKey, FlowKey,
    FlowValue, KernelStats, OwnerKey, OwnerValue, PolicyConfig, RuleRef, RuleState, ServiceSample,
};

/// Byte size of the bounded domain-sample ring buffer.
pub const DOMAIN_EVENT_RING_BYTES: u32 = 512 * 1024;

/// Byte size of the bounded service-fingerprint ring buffer.
pub const SERVICE_EVENT_RING_BYTES: u32 = 256 * 1024;

/// One rule state entry per rule and direction.
const RULE_STATE_CAPACITY: usize = (DEFAULT_TRAFFIC_RULE_CAPACITY * 2) as usize;

#[map(name = "abi_metadata")]
pub static ABI_METADATA: Array<AbiMetadata> = Array::with_max_entries(1, 0);

#[map(name = "flow_map")]
pub static FLOW_MAP: LruPerCpuHashMap<FlowKey, FlowValue> =
    LruPerCpuHashMap::with_max_entries(DEFAULT_FLOW_CAPACITY, 0);

#[map(name = "kernel_stats")]
pub static KERNEL_STATS: PerCpuArray<KernelStats> = PerCpuArray::with_max_entries(1, 0);

#[map(name = "domain_events")]
pub static DOMAIN_EVENTS: RingBuf = RingBuf::with_byte_size(DOMAIN_EVENT_RING_BYTES, 0);

#[map(name = "service_events")]
pub static SERVICE_EVENTS: RingBuf = RingBuf::with_byte_size(SERVICE_EVENT_RING_BYTES, 0);

/// Owning process of connected TCP sockets, keyed by local port and remote
/// endpoint. A plain LRU hash is used because writers run in process context
/// on any CPU while the poller reads one snapshot.
#[map(name = "owner_map")]
pub static OWNER_MAP: LruHashMap<OwnerKey, OwnerValue> =
    LruHashMap::with_max_entries(DEFAULT_OWNER_CAPACITY, 0);

/// Owning process of listening ports, used when no connected-socket entry
/// matches (server-side Flows whose accept runs in softirq context).
#[map(name = "listener_map")]
pub static LISTENER_MAP: LruHashMap<OwnerKey, OwnerValue> =
    LruHashMap::with_max_entries(DEFAULT_LISTENER_CAPACITY, 0);

/// Traffic Rule fast path: one entry carries the master switch, the tier
/// flags and the applied revision.
#[map(name = "policy_config")]
pub static POLICY_CONFIG: Array<PolicyConfig> = Array::with_max_entries(1, 0);

/// Token bucket and counters for every rule-direction pair.
#[btf_map(name = "rule_states")]
pub static RULE_STATES: BtfHashMap<BucketKey, RuleState, RULE_STATE_CAPACITY> = BtfHashMap::new();

#[map(name = "app_cgroup_ingress")]
pub static APP_CGROUP_INGRESS: HashMap<u64, RuleRef> =
    HashMap::with_max_entries(DEFAULT_TRAFFIC_RULE_CAPACITY, 0);

#[map(name = "app_cgroup_egress")]
pub static APP_CGROUP_EGRESS: HashMap<u64, RuleRef> =
    HashMap::with_max_entries(DEFAULT_TRAFFIC_RULE_CAPACITY, 0);

#[map(name = "app_comm_ingress")]
pub static APP_COMM_INGRESS: HashMap<[u8; 16], RuleRef> =
    HashMap::with_max_entries(DEFAULT_TRAFFIC_RULE_CAPACITY, 0);

#[map(name = "app_comm_egress")]
pub static APP_COMM_EGRESS: HashMap<[u8; 16], RuleRef> =
    HashMap::with_max_entries(DEFAULT_TRAFFIC_RULE_CAPACITY, 0);

#[map(name = "endpoint_exact_ingress")]
pub static ENDPOINT_EXACT_INGRESS: HashMap<EndpointMatchKey, RuleRef> =
    HashMap::with_max_entries(DEFAULT_TRAFFIC_RULE_CAPACITY, 0);

#[map(name = "endpoint_exact_egress")]
pub static ENDPOINT_EXACT_EGRESS: HashMap<EndpointMatchKey, RuleRef> =
    HashMap::with_max_entries(DEFAULT_TRAFFIC_RULE_CAPACITY, 0);

#[map(name = "endpoint_cidr_ingress")]
pub static ENDPOINT_CIDR_INGRESS: LpmTrie<[u8; 4], RuleRef> =
    LpmTrie::with_max_entries(DEFAULT_TRAFFIC_RULE_CAPACITY, 0);

#[map(name = "endpoint_cidr_egress")]
pub static ENDPOINT_CIDR_EGRESS: LpmTrie<[u8; 4], RuleRef> =
    LpmTrie::with_max_entries(DEFAULT_TRAFFIC_RULE_CAPACITY, 0);

// Keep the sample and policy types referenced so the ABI layouts stay checked.
const _: () = assert!(core::mem::size_of::<DomainSample>() == 552);
const _: () = assert!(core::mem::size_of::<ServiceSample>() == 128);
const _: () = assert!(core::mem::size_of::<OwnerKey>() == 24);
const _: () = assert!(core::mem::size_of::<OwnerValue>() == 48);
const _: () = assert!(core::mem::size_of::<RuleRef>() == 8);
const _: () = assert!(core::mem::size_of::<BucketKey>() == 8);
const _: () = assert!(core::mem::size_of::<RuleState>() == 72);
const _: () = assert!(core::mem::size_of::<EndpointMatchKey>() == 24);
const _: () = assert!(core::mem::size_of::<PolicyConfig>() == 8);

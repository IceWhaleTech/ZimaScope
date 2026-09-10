//! eBPF map definitions.
//!
//! All maps are bounded. Flow counters live in a per-CPU LRU hash so the
//! packet path never contends on a global lock, and user space reads one
//! consistent snapshot per poll. Domain evidence leaves the kernel through a
//! ring buffer because it cannot be reconstructed from counters.

use aya_ebpf::{
    macros::map,
    maps::{Array, LruPerCpuHashMap, PerCpuArray, RingBuf},
};
use zimascope_common::kernel_abi::{
    AbiMetadata, DEFAULT_FLOW_CAPACITY, DomainEvent, FlowKey, FlowValue, KernelStats,
};

/// Byte size of the bounded domain-evidence ring buffer.
pub const DOMAIN_EVENT_RING_BYTES: u32 = 256 * 1024;

#[map(name = "abi_metadata")]
pub static ABI_METADATA: Array<AbiMetadata> = Array::with_max_entries(1, 0);

#[map(name = "flow_map")]
pub static FLOW_MAP: LruPerCpuHashMap<FlowKey, FlowValue> =
    LruPerCpuHashMap::with_max_entries(DEFAULT_FLOW_CAPACITY, 0);

#[map(name = "kernel_stats")]
pub static KERNEL_STATS: PerCpuArray<KernelStats> = PerCpuArray::with_max_entries(1, 0);

#[map(name = "domain_events")]
pub static DOMAIN_EVENTS: RingBuf = RingBuf::with_byte_size(DOMAIN_EVENT_RING_BYTES, 0);

// Keep the domain event type referenced so the ABI layout stays checked here.
const _: () = assert!(core::mem::size_of::<DomainEvent>() == 304);

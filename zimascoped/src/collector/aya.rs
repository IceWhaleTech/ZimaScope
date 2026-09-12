//! Production Aya adapter for the [`KernelSource`] seam.
//!
//! Everything Linux-specific lives here: object loading, map shards, TC/tcx
//! attachment, interface resolution and ring-buffer draining.
//!
//! On Linux 6.6+ programs attach through the kernel's tcx interface, which
//! needs no `clsact` qdisc and cleans up with its link. Older kernels fall
//! back to the legacy netlink classification path, where a `clsact` qdisc is
//! still added.

use std::{fs, num::NonZeroU32, ptr};

use anyhow::{Context, Result, bail};
use aya::{
    Ebpf,
    maps::{
        Array, HashMap as AyaHashMap, IterableMap, LpmTrie, MapData, MapError, PerCpuArray,
        PerCpuHashMap, RingBuf, lpm_trie::Key as LpmKey,
    },
    programs::{
        CgroupAttachMode, CgroupSockAddr, Link, ProgramError, SchedClassifier, SockOps,
        TcAttachType,
        cgroup_sock_addr::CgroupSockAddrLink,
        sock_ops::SockOpsLink,
        tc::{self, SchedClassifierLink as TcLink},
    },
    util::KernelVersion,
};
use zimascope_common::{
    kernel_abi::{
        self, ABI_METADATA_MAP, APP_CGROUP_EGRESS_MAP, APP_CGROUP_INGRESS_MAP, APP_COMM_EGRESS_MAP,
        APP_COMM_INGRESS_MAP, AbiMetadata, BucketKey, DOMAIN_EVENTS_MAP, Direction, DomainSample,
        ENDPOINT_CIDR_EGRESS_MAP, ENDPOINT_CIDR_INGRESS_MAP, ENDPOINT_EXACT_EGRESS_MAP,
        ENDPOINT_EXACT_INGRESS_MAP, EndpointMatchKey, FLOW_MAP, FlowKey, FlowValue,
        KERNEL_STATS_MAP, KernelStats, LISTENER_MAP, OWNER_MAP, OwnerKey, OwnerValue,
        POLICY_CONFIG_MAP, PolicyConfig, RULE_STATES_MAP, RuleRef, RuleState, SERVICE_EVENTS_MAP,
        SOCK_OWNER_PROGRAM, ServiceSample, UDP_OWNER_PROGRAM,
    },
    model::{ApplicationHealth, InterfaceHealth},
};

use super::{CollectorConfig, InterfaceSelector, KernelSource};
use crate::policy::{MatchEntry, PolicyOp, config_value};

mod object {
    include!(concat!(env!("OUT_DIR"), "/ebpf_object.rs"));
}

/// The cgroup v2 root every process belongs to.
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// `BPF_F_LOCK` takes the map value's spin lock while copying; the rule state
/// map requires it for every user-space read and update.
const BPF_F_LOCK: u64 = 4;

/// Declares a `#[repr(transparent)]` newtype that makes a `zimascope-common`
/// ABI type usable as an aya map key or value.
///
/// Safety: every wrapped type is `#[repr(C)]` with its size and alignment
/// asserted in `kernel_abi`; the transparent wrapper inherits that layout.
macro_rules! pod_newtype {
    ($($name:ident($inner:ty)),+ $(,)?) => {
        $(
            #[repr(transparent)]
            #[derive(Clone, Copy)]
            struct $name($inner);

            // Safety: `#[repr(transparent)]` over a `#[repr(C)]` POD type
            // with no padding.
            unsafe impl aya::Pod for $name {}
        )+
    };
}

pod_newtype! {
    PodFlowKey(FlowKey),
    PodFlowValue(FlowValue),
    PodKernelStats(KernelStats),
    PodAbiMetadata(AbiMetadata),
    PodOwnerKey(OwnerKey),
    PodOwnerValue(OwnerValue),
    PodPolicyConfig(PolicyConfig),
    PodBucketKey(BucketKey),
    PodRuleState(RuleState),
    PodRuleRef(RuleRef),
    PodEndpointMatchKey(EndpointMatchKey),
}

/// Reads one fixed-size sample from a ring-buffer slot.
///
/// Returns `None` when the slot is shorter than the sample. The bytes come
/// from ZimaScope's own eBPF maps, so the sample's bit patterns are trusted.
fn sample_from_ring<T: Copy>(bytes: &[u8]) -> Option<T> {
    if bytes.len() < core::mem::size_of::<T>() {
        return None;
    }
    // Safety: the length is checked above and `read_unaligned` tolerates any
    // alignment.
    Some(unsafe { ptr::read_unaligned(bytes.as_ptr().cast::<T>()) })
}

/// A policy map for each direction, so direction dispatch happens in one
/// place instead of once per map kind.
struct DirectionPair<T> {
    ingress: T,
    egress: T,
}

impl<T> DirectionPair<T> {
    fn get_mut(&mut self, direction: Direction) -> &mut T {
        match direction {
            Direction::Inbound => &mut self.ingress,
            Direction::Outbound => &mut self.egress,
        }
    }
}

/// Typed handles for every Traffic Rule map.
struct PolicyMaps {
    config: Array<MapData, PodPolicyConfig>,
    states: AyaHashMap<MapData, PodBucketKey, PodRuleState>,
    app_cgroup: DirectionPair<AyaHashMap<MapData, u64, PodRuleRef>>,
    app_comm: DirectionPair<AyaHashMap<MapData, [u8; 16], PodRuleRef>>,
    endpoint_exact: DirectionPair<AyaHashMap<MapData, PodEndpointMatchKey, PodRuleRef>>,
    endpoint_cidr: DirectionPair<LpmTrie<MapData, [u8; 4], PodRuleRef>>,
}

/// Owns every Aya object required for one collection session.
pub(crate) struct AyaKernelSource {
    ebpf: Ebpf,
    flows: PerCpuHashMap<MapData, PodFlowKey, PodFlowValue>,
    stats: PerCpuArray<MapData, PodKernelStats>,
    domains: RingBuf<MapData>,
    services: RingBuf<MapData>,
    owners: AyaHashMap<MapData, PodOwnerKey, PodOwnerValue>,
    listeners: AyaHashMap<MapData, PodOwnerKey, PodOwnerValue>,
    policy: PolicyMaps,
    owner_link: Option<SockOpsLink>,
    owner_error: Option<Box<str>>,
    udp_link: Option<CgroupSockAddrLink>,
    udp_error: Option<Box<str>>,
    attached: Vec<AttachedInterface>,
}

struct AttachedInterface {
    ifindex: NonZeroU32,
    name: Box<str>,
    tcx: bool,
    ingress: Option<TcLink>,
    egress: Option<TcLink>,
}

impl AyaKernelSource {
    pub fn open(config: &CollectorConfig) -> Result<Self> {
        if object::EBPF_OBJECT.is_empty() {
            bail!(
                "ZimaScope eBPF object is not embedded; build zimascope-ebpf for \
                 bpfel-unknown-none first (set ZIMASCOPE_EBPF_OBJECT to its path)"
            );
        }

        let mut ebpf = Ebpf::load(object::EBPF_OBJECT).context("load ZimaScope eBPF object")?;

        verify_abi(&mut ebpf)?;

        let flows = take_flow_map(&mut ebpf)?;
        let capacity = flows
            .map()
            .info()
            .context("read flow map info")?
            .max_entries() as usize;

        let expected_capacity = kernel_abi::DEFAULT_FLOW_CAPACITY as usize;
        if capacity != expected_capacity {
            bail!(
                "flow map capacity mismatch: expected {expected_capacity}, \
                 eBPF object provides {capacity}; rebuild the object"
            );
        }

        let stats = PerCpuArray::try_from(
            ebpf.take_map(KERNEL_STATS_MAP)
                .with_context(|| format!("eBPF map {KERNEL_STATS_MAP:?} is missing"))?,
        )
        .context("convert kernel stats map")?;

        let domains = RingBuf::try_from(
            ebpf.take_map(DOMAIN_EVENTS_MAP)
                .with_context(|| format!("eBPF map {DOMAIN_EVENTS_MAP:?} is missing"))?,
        )
        .context("convert domain event ring buffer")?;

        let services = RingBuf::try_from(
            ebpf.take_map(SERVICE_EVENTS_MAP)
                .with_context(|| format!("eBPF map {SERVICE_EVENTS_MAP:?} is missing"))?,
        )
        .context("convert service event ring buffer")?;

        let owners = take_owner_map(&mut ebpf, OWNER_MAP)?;
        let listeners = take_owner_map(&mut ebpf, LISTENER_MAP)?;

        load_programs(&mut ebpf)?;
        let policy = take_policy_maps(&mut ebpf)?;

        // Application Identity is advisory: TC collection starts even when the
        // cgroup attach is unavailable, and health explains why.
        let (owner_link, owner_error) = match attach_owner_program(&mut ebpf) {
            Ok(link) => (Some(link), None),
            Err(error) => (None, Some(format!("{error:#}").into())),
        };
        let (udp_link, udp_error) = match attach_udp_owner_program(&mut ebpf) {
            Ok(link) => (Some(link), None),
            Err(error) => (None, Some(format!("{error:#}").into())),
        };

        let interfaces = resolve_interfaces(&config.interfaces)?;
        let attached = attach_interfaces(&mut ebpf, &interfaces)
            .context("attach ZimaScope TC ingress/egress hooks")?;

        Ok(Self {
            ebpf,
            flows,
            stats,
            domains,
            services,
            owners,
            listeners,
            policy,
            owner_link,
            owner_error,
            udp_link,
            udp_error,
            attached,
        })
    }
}

impl KernelSource for AyaKernelSource {
    fn visit_flows(&mut self, visitor: &mut dyn FnMut(FlowKey, &[FlowValue])) -> Result<usize> {
        let mut entries = 0usize;
        let mut values: Vec<FlowValue> = Vec::new();

        for item in self.flows.iter() {
            let (key, per_cpu) = item.context("read flow map entry")?;
            values.clear();
            values.extend(per_cpu.iter().map(|value| value.0));
            visitor(key.0, &values);
            entries += 1;
        }

        Ok(entries)
    }

    fn visit_owners(&mut self, visitor: &mut dyn FnMut(OwnerKey, &OwnerValue)) -> Result<usize> {
        let mut entries = 0usize;
        for item in self.owners.iter() {
            let (key, value) = item.context("read owner map entry")?;
            visitor(key.0, &value.0);
            entries += 1;
        }
        for item in self.listeners.iter() {
            let (key, value) = item.context("read listener map entry")?;
            visitor(key.0, &value.0);
            entries += 1;
        }
        Ok(entries)
    }

    fn drain_domain_events(&mut self, visitor: &mut dyn FnMut(&DomainSample)) -> Result<()> {
        while let Some(item) = self.domains.next() {
            if let Some(sample) = sample_from_ring::<DomainSample>(&item) {
                visitor(&sample);
            }
        }
        Ok(())
    }

    fn drain_service_events(&mut self, visitor: &mut dyn FnMut(&ServiceSample)) -> Result<()> {
        while let Some(item) = self.services.next() {
            if let Some(sample) = sample_from_ring::<ServiceSample>(&item) {
                visitor(&sample);
            }
        }
        Ok(())
    }

    fn read_stats(&mut self) -> Result<KernelStats> {
        let values = self.stats.get(&0, 0).context("read kernel stats")?;
        let mut total = KernelStats::default();
        for value in values.iter() {
            let value = value.0;
            total.packets_seen = total.packets_seen.saturating_add(value.packets_seen);
            total.packets_parsed = total.packets_parsed.saturating_add(value.packets_parsed);
            total.parse_failures = total.parse_failures.saturating_add(value.parse_failures);
            total.map_update_failures = total
                .map_update_failures
                .saturating_add(value.map_update_failures);
            total.flow_evictions = total.flow_evictions.saturating_add(value.flow_evictions);
            total.domain_events_emitted = total
                .domain_events_emitted
                .saturating_add(value.domain_events_emitted);
            total.domain_events_dropped = total
                .domain_events_dropped
                .saturating_add(value.domain_events_dropped);
            total.service_events_emitted = total
                .service_events_emitted
                .saturating_add(value.service_events_emitted);
            total.service_events_dropped = total
                .service_events_dropped
                .saturating_add(value.service_events_dropped);
            total.owner_events_inserted = total
                .owner_events_inserted
                .saturating_add(value.owner_events_inserted);
            total.owner_events_dropped = total
                .owner_events_dropped
                .saturating_add(value.owner_events_dropped);
            total.policy_dropped_packets = total
                .policy_dropped_packets
                .saturating_add(value.policy_dropped_packets);
            total.policy_dropped_bytes = total
                .policy_dropped_bytes
                .saturating_add(value.policy_dropped_bytes);
            total.policy_missing_state = total
                .policy_missing_state
                .saturating_add(value.policy_missing_state);
        }
        Ok(total)
    }

    fn attachment_health(&self) -> Vec<InterfaceHealth> {
        self.attached
            .iter()
            .map(|attached| {
                let mut health = InterfaceHealth {
                    ifindex: attached.ifindex,
                    name: attached.name.clone(),
                    ingress_attached: false,
                    egress_attached: false,
                    last_error: None,
                };

                // The legacy netlink path cannot be queried portably; the
                // stored link state is the best information available there.
                if !attached.tcx {
                    health.ingress_attached = attached.ingress.is_some();
                    health.egress_attached = attached.egress.is_some();
                    return health;
                }

                let mut errors = Vec::new();
                match verify_tcx(
                    &attached.name,
                    TcAttachType::Ingress,
                    kernel_abi::TC_INGRESS_PROGRAM,
                ) {
                    Ok(true) => health.ingress_attached = true,
                    Ok(false) => errors.push("ingress program is no longer attached".to_owned()),
                    Err(error) => errors.push(format!("query ingress tcx: {error}")),
                }
                match verify_tcx(
                    &attached.name,
                    TcAttachType::Egress,
                    kernel_abi::TC_EGRESS_PROGRAM,
                ) {
                    Ok(true) => health.egress_attached = true,
                    Ok(false) => errors.push("egress program is no longer attached".to_owned()),
                    Err(error) => errors.push(format!("query egress tcx: {error}")),
                }

                health.last_error = errors.into_iter().next().map(Into::into);
                health
            })
            .collect()
    }

    fn application_health(&self) -> ApplicationHealth {
        ApplicationHealth {
            attached: self.owner_link.is_some(),
            udp_attached: self.udp_link.is_some(),
            last_error: self.owner_error.clone().or_else(|| self.udp_error.clone()),
        }
    }

    fn apply_policy(&mut self, operations: &[PolicyOp]) -> Result<()> {
        for operation in operations {
            self.apply_policy_op(operation)
                .with_context(|| format!("apply policy operation {operation:?}"))?;
        }
        Ok(())
    }

    fn read_rule_states(&mut self, keys: &[BucketKey]) -> Result<Vec<Option<RuleState>>> {
        let mut states = Vec::with_capacity(keys.len());
        for key in keys {
            match self.policy.states.get(&PodBucketKey(*key), BPF_F_LOCK) {
                Ok(value) => states.push(Some(value.0)),
                Err(MapError::KeyNotFound) => states.push(None),
                Err(error) => return Err(error).context("read rule state"),
            }
        }
        Ok(states)
    }

    fn detach(&mut self) -> Result<()> {
        let mut first_error = None;
        if let Some(link) = self.owner_link.take() {
            if let Err(error) = link.detach() {
                first_error = Some(anyhow::anyhow!("detach socket owner program: {error}"));
            }
        }
        if let Some(link) = self.udp_link.take() {
            if let Err(error) = link.detach() {
                if first_error.is_none() {
                    first_error = Some(anyhow::anyhow!("detach UDP owner program: {error}"));
                }
            }
        }
        for attached in self.attached.drain(..) {
            for (direction, link) in [("ingress", attached.ingress), ("egress", attached.egress)] {
                let Some(link) = link else { continue };
                if let Err(error) = link.detach() {
                    if first_error.is_none() {
                        first_error = Some(anyhow::anyhow!(
                            "detach {} hook on {}: {error}",
                            direction,
                            attached.name
                        ));
                    }
                }
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

impl AyaKernelSource {
    fn apply_policy_op(&mut self, operation: &PolicyOp) -> Result<()> {
        match operation {
            PolicyOp::SetEnabled {
                enabled,
                app_rules,
                endpoint_rules,
                revision,
            } => {
                let value = config_value(*enabled, *app_rules, *endpoint_rules, *revision);
                self.policy
                    .config
                    .set(0, PodPolicyConfig(value), 0)
                    .context("write policy config")?;
            }
            PolicyOp::UpsertState {
                key,
                rate_bytes_per_s,
                burst_bytes,
            } => {
                let pod_key = PodBucketKey(*key);
                let existing = self
                    .policy
                    .states
                    .get(&pod_key, BPF_F_LOCK)
                    .ok()
                    .map(|value| value.0);
                let mut state = existing.unwrap_or_default();
                state.rate_bytes_per_s = *rate_bytes_per_s;
                state.burst_bytes = *burst_bytes;
                if existing.is_none() {
                    state.tokens = *burst_bytes;
                }
                self.policy
                    .states
                    .insert(pod_key, PodRuleState(state), BPF_F_LOCK)
                    .context("write rule state")?;
            }
            PolicyOp::RemoveState { key } => {
                self.policy
                    .states
                    .remove(&PodBucketKey(*key))
                    .context("remove rule state")?;
            }
            PolicyOp::UpsertMatch { entry, rule } => {
                let value = PodRuleRef(*rule);
                match entry {
                    MatchEntry::AppCgroup {
                        direction,
                        cgroup_id,
                    } => self
                        .policy
                        .app_cgroup
                        .get_mut(*direction)
                        .insert(*cgroup_id, value, 0)
                        .context("insert application cgroup match")?,
                    MatchEntry::AppComm { direction, comm } => self
                        .policy
                        .app_comm
                        .get_mut(*direction)
                        .insert(*comm, value, 0)
                        .context("insert application comm match")?,
                    MatchEntry::EndpointExact { direction, key } => self
                        .policy
                        .endpoint_exact
                        .get_mut(*direction)
                        .insert(PodEndpointMatchKey(*key), value, 0)
                        .context("insert endpoint match")?,
                    MatchEntry::EndpointCidr {
                        direction,
                        prefix_len,
                        addr,
                    } => self
                        .policy
                        .endpoint_cidr
                        .get_mut(*direction)
                        .insert(&LpmKey::new(*prefix_len, *addr), value, 0)
                        .context("insert CIDR match")?,
                }
            }
            PolicyOp::RemoveMatch { entry } => match entry {
                MatchEntry::AppCgroup {
                    direction,
                    cgroup_id,
                } => self
                    .policy
                    .app_cgroup
                    .get_mut(*direction)
                    .remove(cgroup_id)
                    .context("remove application cgroup match")?,
                MatchEntry::AppComm { direction, comm } => self
                    .policy
                    .app_comm
                    .get_mut(*direction)
                    .remove(comm)
                    .context("remove application comm match")?,
                MatchEntry::EndpointExact { direction, key } => self
                    .policy
                    .endpoint_exact
                    .get_mut(*direction)
                    .remove(&PodEndpointMatchKey(*key))
                    .context("remove endpoint match")?,
                MatchEntry::EndpointCidr {
                    direction,
                    prefix_len,
                    addr,
                } => self
                    .policy
                    .endpoint_cidr
                    .get_mut(*direction)
                    .remove(&LpmKey::new(*prefix_len, *addr))
                    .context("remove CIDR match")?,
            },
        }
        Ok(())
    }
}

impl Drop for AyaKernelSource {
    fn drop(&mut self) {
        let _ = self.detach();
        let _ = &self.ebpf;
    }
}

fn verify_abi(ebpf: &mut Ebpf) -> Result<()> {
    let mut metadata: Array<MapData, PodAbiMetadata> = Array::try_from(
        ebpf.take_map(ABI_METADATA_MAP)
            .with_context(|| format!("eBPF map {ABI_METADATA_MAP:?} is missing"))?,
    )
    .context("convert ABI metadata map")?;

    metadata
        .set(0, PodAbiMetadata(AbiMetadata::CURRENT), 0)
        .context("publish ABI metadata")?;
    let published = metadata.get(&0, 0).context("read back ABI metadata")?.0;

    if published.version != kernel_abi::ABI_VERSION {
        bail!(
            "eBPF ABI mismatch: expected version {}, found {}",
            kernel_abi::ABI_VERSION,
            published.version
        );
    }

    let expected = AbiMetadata::CURRENT;
    if published.flow_key_size != expected.flow_key_size
        || published.flow_value_size != expected.flow_value_size
        || published.domain_sample_size != expected.domain_sample_size
        || published.kernel_stats_size != expected.kernel_stats_size
        || published.owner_key_size != expected.owner_key_size
        || published.owner_value_size != expected.owner_value_size
        || published.rule_state_size != expected.rule_state_size
        || published.policy_config_size != expected.policy_config_size
    {
        bail!("eBPF ABI mismatch: recorded struct sizes do not match user space");
    }

    Ok(())
}

/// Takes and validates every Traffic Rule map before attachment.
fn take_policy_maps(ebpf: &mut Ebpf) -> Result<PolicyMaps> {
    let rules = kernel_abi::DEFAULT_TRAFFIC_RULE_CAPACITY as usize;
    Ok(PolicyMaps {
        config: take_policy_array(ebpf, POLICY_CONFIG_MAP, 1)?,
        states: take_policy_map(ebpf, RULE_STATES_MAP, rules * 2)?,
        app_cgroup: DirectionPair {
            ingress: take_policy_map(ebpf, APP_CGROUP_INGRESS_MAP, rules)?,
            egress: take_policy_map(ebpf, APP_CGROUP_EGRESS_MAP, rules)?,
        },
        app_comm: DirectionPair {
            ingress: take_policy_map(ebpf, APP_COMM_INGRESS_MAP, rules)?,
            egress: take_policy_map(ebpf, APP_COMM_EGRESS_MAP, rules)?,
        },
        endpoint_exact: DirectionPair {
            ingress: take_policy_map(ebpf, ENDPOINT_EXACT_INGRESS_MAP, rules)?,
            egress: take_policy_map(ebpf, ENDPOINT_EXACT_EGRESS_MAP, rules)?,
        },
        endpoint_cidr: DirectionPair {
            ingress: take_policy_trie(ebpf, ENDPOINT_CIDR_INGRESS_MAP, rules)?,
            egress: take_policy_trie(ebpf, ENDPOINT_CIDR_EGRESS_MAP, rules)?,
        },
    })
}

fn take_policy_array(
    ebpf: &mut Ebpf,
    name: &str,
    capacity: usize,
) -> Result<Array<MapData, PodPolicyConfig>> {
    let map = ebpf
        .take_map(name)
        .with_context(|| format!("eBPF map {name:?} is missing"))?;
    let typed = Array::try_from(map).with_context(|| format!("convert {name:?} map"))?;
    check_capacity(typed.map(), name, capacity)?;
    Ok(typed)
}

fn take_policy_map<K, V>(
    ebpf: &mut Ebpf,
    name: &str,
    capacity: usize,
) -> Result<AyaHashMap<MapData, K, V>>
where
    K: aya::Pod,
    V: aya::Pod,
{
    let map = ebpf
        .take_map(name)
        .with_context(|| format!("eBPF map {name:?} is missing"))?;
    let typed = AyaHashMap::try_from(map).with_context(|| format!("convert {name:?} map"))?;
    check_capacity(typed.map(), name, capacity)?;
    Ok(typed)
}

fn take_policy_trie(
    ebpf: &mut Ebpf,
    name: &str,
    capacity: usize,
) -> Result<LpmTrie<MapData, [u8; 4], PodRuleRef>> {
    let map = ebpf
        .take_map(name)
        .with_context(|| format!("eBPF map {name:?} is missing"))?;
    let typed = LpmTrie::try_from(map).with_context(|| format!("convert {name:?} map"))?;
    check_capacity(typed.map(), name, capacity)?;
    Ok(typed)
}

fn check_capacity(map: &MapData, name: &str, capacity: usize) -> Result<()> {
    let actual = map
        .info()
        .with_context(|| format!("read {name:?} map info"))?
        .max_entries() as usize;
    if actual != capacity {
        bail!(
            "policy map {name:?} capacity mismatch: expected {capacity}, \
             eBPF object provides {actual}; rebuild the object"
        );
    }
    Ok(())
}

fn take_flow_map(ebpf: &mut Ebpf) -> Result<PerCpuHashMap<MapData, PodFlowKey, PodFlowValue>> {
    let map = ebpf
        .take_map(FLOW_MAP)
        .with_context(|| format!("eBPF map {FLOW_MAP:?} is missing"))?;
    PerCpuHashMap::try_from(map).context("convert flow map")
}

fn take_owner_map(
    ebpf: &mut Ebpf,
    name: &str,
) -> Result<AyaHashMap<MapData, PodOwnerKey, PodOwnerValue>> {
    let map = ebpf
        .take_map(name)
        .with_context(|| format!("eBPF map {name:?} is missing"))?;
    AyaHashMap::try_from(map).context("convert owner map")
}

fn load_programs(ebpf: &mut Ebpf) -> Result<()> {
    for name in [
        kernel_abi::TC_INGRESS_PROGRAM,
        kernel_abi::TC_EGRESS_PROGRAM,
    ] {
        let program: &mut SchedClassifier = ebpf
            .program_mut(name)
            .with_context(|| format!("eBPF program {name:?} is missing"))?
            .try_into()
            .context("convert program to SchedClassifier")?;
        program
            .load()
            .with_context(|| format!("load eBPF program {name:?}"))?;
    }

    let owner: &mut SockOps = ebpf
        .program_mut(SOCK_OWNER_PROGRAM)
        .with_context(|| format!("eBPF program {SOCK_OWNER_PROGRAM:?} is missing"))?
        .try_into()
        .context("convert program to SockOps")?;
    owner
        .load()
        .with_context(|| format!("load eBPF program {SOCK_OWNER_PROGRAM:?}"))?;

    let udp: &mut CgroupSockAddr = ebpf
        .program_mut(UDP_OWNER_PROGRAM)
        .with_context(|| format!("eBPF program {UDP_OWNER_PROGRAM:?} is missing"))?
        .try_into()
        .context("convert program to CgroupSockAddr")?;
    udp.load()
        .with_context(|| format!("load eBPF program {UDP_OWNER_PROGRAM:?}"))?;

    Ok(())
}

/// Attaches the socket-owner program to the cgroup v2 root.
///
/// The kernel rejects attach flags on the `bpf_link` path
/// (`cgroup_bpf_link_attach` returns `EINVAL` for nonzero flags), and each
/// link is independent, so `Single` (flags 0) never replaces a program owned
/// by another tool. A conflict is reported through Application health instead
/// of failing collection.
fn attach_owner_program(ebpf: &mut Ebpf) -> Result<SockOpsLink> {
    let program: &mut SockOps = ebpf
        .program_mut(SOCK_OWNER_PROGRAM)
        .with_context(|| format!("eBPF program {SOCK_OWNER_PROGRAM:?} is missing"))?
        .try_into()
        .context("convert program to SockOps")?;
    let cgroup =
        fs::File::open(CGROUP_ROOT).with_context(|| format!("open cgroup root {CGROUP_ROOT:?}"))?;
    let link_id = program
        .attach(&cgroup, CgroupAttachMode::Single)
        .context("attach socket owner program to the cgroup root")?;
    program
        .take_link(link_id)
        .context("take socket owner program link")
}

/// Attaches the UDP send-owner program to the cgroup v2 root.
///
/// `cgroup/sendmsg4` reports the destination in the sending process context,
/// which is what UDP attribution needs; `connect4` is not required because
/// every UDP send passes through `udp_sendmsg`.
fn attach_udp_owner_program(ebpf: &mut Ebpf) -> Result<CgroupSockAddrLink> {
    let program: &mut CgroupSockAddr = ebpf
        .program_mut(UDP_OWNER_PROGRAM)
        .with_context(|| format!("eBPF program {UDP_OWNER_PROGRAM:?} is missing"))?
        .try_into()
        .context("convert program to CgroupSockAddr")?;

    let cgroup =
        fs::File::open(CGROUP_ROOT).with_context(|| format!("open cgroup root {CGROUP_ROOT:?}"))?;
    let link_id = program
        .attach(&cgroup, CgroupAttachMode::Single)
        .context("attach UDP owner program to the cgroup root")?;
    program
        .take_link(link_id)
        .context("take UDP owner program link")
}

fn attach_interfaces(
    ebpf: &mut Ebpf,
    interfaces: &[(NonZeroU32, String)],
) -> Result<Vec<AttachedInterface>> {
    let mut attached = Vec::new();
    let tcx = kernel_supports_tcx();

    for (ifindex, name) in interfaces {
        let result = attach_one(ebpf, *ifindex, name, tcx);
        match result {
            Ok(interface) => attached.push(interface),
            Err(error) => {
                detach_all(&mut attached);
                return Err(error);
            }
        }
    }

    Ok(attached)
}

fn attach_one(
    ebpf: &mut Ebpf,
    ifindex: NonZeroU32,
    name: &str,
    tcx: bool,
) -> Result<AttachedInterface> {
    if !tcx {
        if let Err(error) = tc::qdisc_add_clsact(name) {
            if !matches!(error, tc::TcError::AlreadyAttached) {
                return Err(
                    anyhow::Error::new(error).context(format!("add clsact qdisc to {name}"))
                );
            }
        }
    }

    let ingress = attach_hook(
        ebpf,
        name,
        TcAttachType::Ingress,
        kernel_abi::TC_INGRESS_PROGRAM,
    )?;
    let egress = match attach_hook(
        ebpf,
        name,
        TcAttachType::Egress,
        kernel_abi::TC_EGRESS_PROGRAM,
    ) {
        Ok(link) => link,
        Err(error) => {
            let _ = ingress.detach();
            return Err(error);
        }
    };

    Ok(AttachedInterface {
        ifindex,
        name: name.into(),
        tcx,
        ingress: Some(ingress),
        egress: Some(egress),
    })
}

fn attach_hook(
    ebpf: &mut Ebpf,
    name: &str,
    attach_type: TcAttachType,
    program: &str,
) -> Result<TcLink> {
    let program: &mut SchedClassifier = ebpf
        .program_mut(program)
        .with_context(|| format!("eBPF program {program:?} is missing"))?
        .try_into()
        .context("convert program to SchedClassifier")?;

    let link_id = program
        .attach(name, attach_type)
        .with_context(|| format!("attach {program:?} to {name}"))?;
    program
        .take_link(link_id)
        .with_context(|| format!("take link for {program:?} on {name}"))
}

fn verify_tcx(
    name: &str,
    attach_type: TcAttachType,
    expected_program: &str,
) -> Result<bool, ProgramError> {
    let (_, programs) = SchedClassifier::query_tcx(name, attach_type)?;
    Ok(programs
        .iter()
        .any(|program| program.name_as_str() == Some(expected_program)))
}

fn kernel_supports_tcx() -> bool {
    KernelVersion::current()
        .map(|current| current >= KernelVersion::new(6, 6, 0))
        .unwrap_or(false)
}

fn detach_all(attached: &mut Vec<AttachedInterface>) {
    for interface in attached.drain(..) {
        if let Some(link) = interface.ingress {
            let _ = link.detach();
        }
        if let Some(link) = interface.egress {
            let _ = link.detach();
        }
    }
}

/// Resolves configured selectors into `(ifindex, name)` pairs.
fn resolve_interfaces(selectors: &[InterfaceSelector]) -> Result<Vec<(NonZeroU32, String)>> {
    if selectors.is_empty() {
        bail!("no Device Boundary interfaces configured");
    }

    let mut resolved = Vec::with_capacity(selectors.len());
    for selector in selectors {
        let name = match selector {
            InterfaceSelector::DefaultRoute => default_route_interface()?,
            InterfaceSelector::Name(name) => name.to_string(),
            InterfaceSelector::Index(index) => name_for_index(index.get())?,
        };
        let ifindex = ifindex_for_name(&name)?;
        resolved.push((ifindex, name));
    }

    for (position, (_, name)) in resolved.iter().enumerate() {
        if resolved
            .iter()
            .take(position)
            .any(|(_, other)| other == name)
        {
            bail!("duplicate Device Boundary interface {name:?}");
        }
    }

    Ok(resolved)
}

/// Picks the non-virtual interface that carries the default route.
fn default_route_interface() -> Result<String> {
    let route = fs::read_to_string("/proc/net/route").context("read /proc/net/route")?;

    let mut best: Option<(u32, String)> = None;
    for line in route.lines().skip(1) {
        let mut fields = line.split_whitespace();
        let Some(name) = fields.next() else { continue };
        let Some(destination) = fields.next() else {
            continue;
        };
        let Some(_gateway) = fields.next() else {
            continue;
        };
        let Some(flags) = fields.next() else { continue };
        let Some(_ref_count) = fields.next() else {
            continue;
        };
        let Some(_use) = fields.next() else { continue };
        let Some(metric) = fields.next() else {
            continue;
        };

        if destination != "00000000" {
            continue;
        }
        let flags = u32::from_str_radix(flags, 16).unwrap_or(0);
        if flags & 0x1 == 0 {
            continue;
        }
        let metric = metric.parse::<u32>().unwrap_or(u32::MAX);
        if is_virtual_interface(name) {
            continue;
        }
        if best
            .as_ref()
            .is_none_or(|(best_metric, _)| metric < *best_metric)
        {
            best = Some((metric, name.to_string()));
        }
    }

    best.map(|(_, name)| name)
        .context("no default route interface found in /proc/net/route")
}

fn is_virtual_interface(name: &str) -> bool {
    const VIRTUAL_PREFIXES: [&str; 6] = ["lo", "docker", "br-", "virbr", "veth", "tun"];
    VIRTUAL_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix))
}

fn name_for_index(ifindex: u32) -> Result<String> {
    let entries = fs::read_dir("/sys/class/net").context("read /sys/class/net")?;
    for entry in entries {
        let entry = entry.context("read /sys/class/net entry")?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if ifindex_for_name(&name).is_ok_and(|index| index.get() == ifindex) {
            return Ok(name);
        }
    }
    bail!("no interface with ifindex {ifindex}")
}

fn ifindex_for_name(name: &str) -> Result<NonZeroU32> {
    let path = format!("/sys/class/net/{name}/ifindex");
    let value = fs::read_to_string(&path).with_context(|| format!("read {path}"))?;
    let index: u32 = value.trim().parse().context("parse ifindex")?;
    NonZeroU32::new(index).with_context(|| format!("interface {name:?} has ifindex 0"))
}

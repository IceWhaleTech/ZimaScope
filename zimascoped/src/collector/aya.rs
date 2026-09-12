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
        Array, HashMap as AyaHashMap, IterableMap, Map as AyaMap, MapData, PerCpuArray,
        PerCpuHashMap, RingBuf,
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
        self, ABI_METADATA_MAP, AbiMetadata, DOMAIN_EVENTS_MAP, DomainSample, FLOW_MAP, FlowKey,
        FlowValue, KERNEL_STATS_MAP, KernelStats, LISTENER_MAP, OWNER_MAP, OwnerKey, OwnerValue,
        SERVICE_EVENTS_MAP, SOCK_OWNER_PROGRAM, ServiceSample, UDP_OWNER_PROGRAM,
    },
    model::{ApplicationHealth, InterfaceHealth},
};

use super::{CollectorConfig, InterfaceSelector, KernelSource};

mod object {
    include!(concat!(env!("OUT_DIR"), "/ebpf_object.rs"));
}

/// The cgroup v2 root every process belongs to.
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

#[repr(transparent)]
#[derive(Clone, Copy)]
struct PodFlowKey(FlowKey);

// Safety: `#[repr(transparent)]` over a `#[repr(C)]` POD type with no padding.
unsafe impl aya::Pod for PodFlowKey {}

#[repr(transparent)]
#[derive(Clone, Copy)]
struct PodFlowValue(FlowValue);

// Safety: `#[repr(transparent)]` over a `#[repr(C)]` POD type with no padding.
unsafe impl aya::Pod for PodFlowValue {}

#[repr(transparent)]
#[derive(Clone, Copy)]
struct PodKernelStats(KernelStats);

// Safety: `#[repr(transparent)]` over a `#[repr(C)]` POD type with no padding.
unsafe impl aya::Pod for PodKernelStats {}

#[repr(transparent)]
#[derive(Clone, Copy)]
struct PodAbiMetadata(AbiMetadata);

// Safety: `#[repr(transparent)]` over a `#[repr(C)]` POD type with no padding.
unsafe impl aya::Pod for PodAbiMetadata {}

#[repr(transparent)]
#[derive(Clone, Copy)]
struct PodOwnerKey(OwnerKey);

// Safety: `#[repr(transparent)]` over a `#[repr(C)]` POD type with no padding.
unsafe impl aya::Pod for PodOwnerKey {}

#[repr(transparent)]
#[derive(Clone, Copy)]
struct PodOwnerValue(OwnerValue);

// Safety: `#[repr(transparent)]` over a `#[repr(C)]` POD type with no padding.
unsafe impl aya::Pod for PodOwnerValue {}

/// Owns every Aya object required for one collection session.
pub(crate) struct AyaKernelSource {
    ebpf: Ebpf,
    flows: PerCpuHashMap<MapData, PodFlowKey, PodFlowValue>,
    stats: PerCpuArray<MapData, PodKernelStats>,
    domains: RingBuf<MapData>,
    services: RingBuf<MapData>,
    owners: AyaHashMap<MapData, PodOwnerKey, PodOwnerValue>,
    listeners: AyaHashMap<MapData, PodOwnerKey, PodOwnerValue>,
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
        verify_policy_maps(&mut ebpf)?;

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
            let bytes: &[u8] = &item;
            if bytes.len() < core::mem::size_of::<DomainSample>() {
                continue;
            }
            let sample = unsafe { ptr::read_unaligned(bytes.as_ptr().cast::<DomainSample>()) };
            visitor(&sample);
        }
        Ok(())
    }

    fn drain_service_events(&mut self, visitor: &mut dyn FnMut(&ServiceSample)) -> Result<()> {
        while let Some(item) = self.services.next() {
            let bytes: &[u8] = &item;
            if bytes.len() < core::mem::size_of::<ServiceSample>() {
                continue;
            }
            let sample = unsafe { ptr::read_unaligned(bytes.as_ptr().cast::<ServiceSample>()) };
            visitor(&sample);
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

/// Verifies the fixed capacities of every Traffic Rule map before attachment.
///
/// Called after program loading so the kernel already holds the map
/// references; the temporary handles can be dropped.
fn verify_policy_maps(ebpf: &mut Ebpf) -> Result<()> {
    let rules = kernel_abi::DEFAULT_TRAFFIC_RULE_CAPACITY as usize;
    let expected: [(&str, usize); 10] = [
        (kernel_abi::POLICY_CONFIG_MAP, 1),
        (kernel_abi::RULE_STATES_MAP, rules * 2),
        (kernel_abi::APP_CGROUP_INGRESS_MAP, rules),
        (kernel_abi::APP_CGROUP_EGRESS_MAP, rules),
        (kernel_abi::APP_COMM_INGRESS_MAP, rules),
        (kernel_abi::APP_COMM_EGRESS_MAP, rules),
        (kernel_abi::ENDPOINT_EXACT_INGRESS_MAP, rules),
        (kernel_abi::ENDPOINT_EXACT_EGRESS_MAP, rules),
        (kernel_abi::ENDPOINT_CIDR_INGRESS_MAP, rules),
        (kernel_abi::ENDPOINT_CIDR_EGRESS_MAP, rules),
    ];

    for (name, capacity) in expected {
        let map = ebpf
            .take_map(name)
            .with_context(|| format!("eBPF map {name:?} is missing"))?;
        let actual = read_map_capacity(map, name)?;
        if actual != capacity {
            bail!(
                "policy map {name:?} capacity mismatch: expected {capacity}, \
                 eBPF object provides {actual}; rebuild the object"
            );
        }
    }

    Ok(())
}

/// Extracts the shared [`MapData`] handle from a taken map of any type.
fn read_map_capacity(map: AyaMap, name: &str) -> Result<usize> {
    let data = match map {
        AyaMap::Array(data)
        | AyaMap::ArrayOfMaps(data)
        | AyaMap::BloomFilter(data)
        | AyaMap::CgroupArray(data)
        | AyaMap::CgroupStorage(data)
        | AyaMap::CgrpStorage(data)
        | AyaMap::CpuMap(data)
        | AyaMap::DevMap(data)
        | AyaMap::DevMapHash(data)
        | AyaMap::HashMap(data)
        | AyaMap::HashOfMaps(data)
        | AyaMap::InodeStorage(data)
        | AyaMap::LpmTrie(data)
        | AyaMap::LruHashMap(data)
        | AyaMap::PerCpuArray(data)
        | AyaMap::PerCpuCgroupStorage(data)
        | AyaMap::PerCpuHashMap(data)
        | AyaMap::PerCpuLruHashMap(data)
        | AyaMap::PerfEventArray(data)
        | AyaMap::ProgramArray(data)
        | AyaMap::Queue(data)
        | AyaMap::ReusePortSockArray(data)
        | AyaMap::RingBuf(data)
        | AyaMap::SockHash(data)
        | AyaMap::SockMap(data)
        | AyaMap::SkStorage(data)
        | AyaMap::Stack(data)
        | AyaMap::StackTraceMap(data)
        | AyaMap::Unsupported(data)
        | AyaMap::XskMap(data) => data,
    };
    Ok(data
        .info()
        .with_context(|| format!("read {name:?} map info"))?
        .max_entries() as usize)
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

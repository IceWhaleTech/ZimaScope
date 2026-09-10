//! Production Aya adapter for the [`KernelSource`] seam.
//!
//! Everything Linux-specific lives here: object loading, map shards, generic
//! netlink/TC attachment, interface resolution and ring-buffer draining.

use std::{fs, num::NonZeroU32, ptr};

use anyhow::{Context, Result, bail};
use aya::{
    Ebpf,
    maps::{Array, IterableMap, MapData, PerCpuArray, PerCpuHashMap, RingBuf},
    programs::{
        Link, SchedClassifier, TcAttachType,
        tc::{self, SchedClassifierLink as TcLink},
    },
};
use zimascope_common::{
    kernel_abi::{
        self, ABI_METADATA_MAP, AbiMetadata, DOMAIN_EVENTS_MAP, DomainEvent, FLOW_MAP, FlowKey,
        FlowValue, KERNEL_STATS_MAP, KernelStats,
    },
    model::InterfaceHealth,
};

use super::{CollectorConfig, InterfaceSelector, KernelSource};

mod object {
    include!(concat!(env!("OUT_DIR"), "/ebpf_object.rs"));
}

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

/// Owns every Aya object required for one collection session.
pub(crate) struct AyaKernelSource {
    ebpf: Ebpf,
    flows: PerCpuHashMap<MapData, PodFlowKey, PodFlowValue>,
    stats: PerCpuArray<MapData, PodKernelStats>,
    domains: RingBuf<MapData>,
    attached: Vec<AttachedInterface>,
}

struct AttachedInterface {
    health: InterfaceHealth,
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

        load_programs(&mut ebpf)?;

        let interfaces = resolve_interfaces(&config.interfaces)?;
        let attached = attach_interfaces(&mut ebpf, &interfaces)
            .context("attach ZimaScope TC ingress/egress hooks")?;

        Ok(Self {
            ebpf,
            flows,
            stats,
            domains,
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

    fn drain_domain_events(&mut self, visitor: &mut dyn FnMut(&DomainEvent)) -> Result<()> {
        while let Some(item) = self.domains.next() {
            let bytes: &[u8] = &item;
            if bytes.len() < core::mem::size_of::<DomainEvent>() {
                continue;
            }
            let event = unsafe { ptr::read_unaligned(bytes.as_ptr().cast::<DomainEvent>()) };
            visitor(&event);
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
            .map(|attached| attached.health.clone())
            .collect()
    }

    fn detach(&mut self) -> Result<()> {
        let mut first_error = None;
        for attached in self.attached.drain(..) {
            for (direction, link) in [("ingress", attached.ingress), ("egress", attached.egress)] {
                let Some(link) = link else { continue };
                if let Err(error) = link.detach() {
                    if first_error.is_none() {
                        first_error = Some(anyhow::anyhow!(
                            "detach {} hook on {}: {error}",
                            direction,
                            attached.health.name
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
        || published.domain_event_size != expected.domain_event_size
        || published.kernel_stats_size != expected.kernel_stats_size
    {
        bail!("eBPF ABI mismatch: recorded struct sizes do not match user space");
    }

    Ok(())
}

fn take_flow_map(ebpf: &mut Ebpf) -> Result<PerCpuHashMap<MapData, PodFlowKey, PodFlowValue>> {
    let map = ebpf
        .take_map(FLOW_MAP)
        .with_context(|| format!("eBPF map {FLOW_MAP:?} is missing"))?;
    PerCpuHashMap::try_from(map).context("convert flow map")
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
    Ok(())
}

fn attach_interfaces(
    ebpf: &mut Ebpf,
    interfaces: &[(NonZeroU32, String)],
) -> Result<Vec<AttachedInterface>> {
    let mut attached = Vec::new();

    for (ifindex, name) in interfaces {
        let result = attach_one(ebpf, *ifindex, name);
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

fn attach_one(ebpf: &mut Ebpf, ifindex: NonZeroU32, name: &str) -> Result<AttachedInterface> {
    if let Err(error) = tc::qdisc_add_clsact(name) {
        if !matches!(error, tc::TcError::AlreadyAttached) {
            return Err(anyhow::Error::new(error).context(format!("add clsact qdisc to {name}")));
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
        health: InterfaceHealth {
            ifindex,
            name: name.into(),
            ingress_attached: true,
            egress_attached: true,
            last_error: None,
        },
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

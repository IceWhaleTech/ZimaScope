#![cfg(target_os = "linux")]

//! Linux network-namespace harness for the Device Boundary observation path.
//!
//! Loads the built eBPF object, attaches it to a veth pair, generates traffic
//! in both directions and reads the kernel maps back. Requires root, iproute2
//! and a kernel with BPF/tcx support:
//!
//! ```text
//! cargo xtask build-ebpf
//! sudo -E cargo test -p zimascoped --test boundary -- --ignored
//! ```

use std::{
    env,
    net::UdpSocket,
    path::{Path, PathBuf},
    process::Command,
    sync::Mutex,
    thread,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use aya::{
    Ebpf,
    maps::{
        Array, HashMap as AyaHashMap, LpmTrie, MapData, PerCpuArray, PerCpuHashMap,
        lpm_trie::Key as LpmKey,
    },
    programs::{
        SchedClassifier, TcAttachType,
        tc::{self, SchedClassifierLink},
    },
    util::KernelVersion,
};
use zimascope_common::kernel_abi::{
    APP_COMM_EGRESS_MAP, BucketKey, Direction, ENDPOINT_CIDR_EGRESS_MAP, ENDPOINT_EXACT_EGRESS_MAP,
    EndpointMatchKey, FLOW_MAP, FlowKey, FlowValue, IpFamily, KERNEL_STATS_MAP, KernelStats,
    OWNER_MAP, OwnerKey, OwnerKind, OwnerValue, POLICY_CONFIG_MAP, PolicyConfig, RULE_STATES_MAP,
    RuleAction, RuleRef, RuleState, TC_EGRESS_PROGRAM, TC_INGRESS_PROGRAM, TransportProtocol,
};

const NS: &str = "zs-boundary";
const HOST_IFACE: &str = "zs-veth0";
const PEER_IFACE: &str = "zs-veth1";
const HOST_ADDR: &str = "10.99.77.1";
const PEER_ADDR: &str = "10.99.77.2";
const UDP_PORT: u16 = 39_001;
const PACKETS: usize = 16;
const CHILD_ENV: &str = "ZS_BOUNDARY_CHILD";

/// Every harness test owns the same namespace and veth names, so they run one
/// at a time.
static HARNESS: Mutex<()> = Mutex::new(());

fn serialized() -> std::sync::MutexGuard<'static, ()> {
    HARNESS.lock().unwrap_or_else(|error| error.into_inner())
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
struct PodPolicyConfig(PolicyConfig);

// Safety: `#[repr(transparent)]` over a `#[repr(C)]` POD type with no padding.
unsafe impl aya::Pod for PodPolicyConfig {}

#[repr(transparent)]
#[derive(Clone, Copy)]
struct PodBucketKey(BucketKey);

// Safety: `#[repr(transparent)]` over a `#[repr(C)]` POD type with no padding.
unsafe impl aya::Pod for PodBucketKey {}

#[repr(transparent)]
#[derive(Clone, Copy)]
struct PodRuleState(RuleState);

// Safety: `#[repr(transparent)]` over a `#[repr(C)]` POD type with no padding.
unsafe impl aya::Pod for PodRuleState {}

#[repr(transparent)]
#[derive(Clone, Copy)]
struct PodEndpointMatchKey(EndpointMatchKey);

// Safety: `#[repr(transparent)]` over a `#[repr(C)]` POD type with no padding.
unsafe impl aya::Pod for PodEndpointMatchKey {}

#[repr(transparent)]
#[derive(Clone, Copy)]
struct PodRuleRef(RuleRef);

// Safety: `#[repr(transparent)]` over a `#[repr(C)]` POD type with no padding.
unsafe impl aya::Pod for PodRuleRef {}

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

#[test]
#[ignore = "requires root, iproute2 and a kernel with BPF/tcx"]
fn records_both_directions_at_the_boundary() -> Result<()> {
    let _guard = serialized();
    let harness = Harness::new()?;

    send_outbound()?;
    send_inbound_from_peer()?;
    thread::sleep(Duration::from_millis(300));

    let outbound = harness.flow_totals(Direction::Outbound, HOST_ADDR, PEER_ADDR, UDP_PORT)?;
    let inbound = harness.flow_totals(Direction::Inbound, PEER_ADDR, HOST_ADDR, UDP_PORT)?;

    assert!(
        outbound.0 >= PACKETS as u64,
        "outbound packets: {}",
        outbound.0
    );
    assert!(outbound.1 > 0, "outbound bytes are zero");
    assert!(
        inbound.0 >= PACKETS as u64,
        "inbound packets: {}",
        inbound.0
    );
    assert!(inbound.1 > 0, "inbound bytes are zero");

    let packets_seen = harness.packets_seen()?;
    assert!(
        packets_seen >= (PACKETS * 2) as u64,
        "packets_seen: {packets_seen}"
    );
    Ok(())
}

#[test]
#[ignore = "requires root, iproute2 and a kernel with BPF/tcx"]
fn blocks_a_matching_endpoint() -> Result<()> {
    let _guard = serialized();
    let mut harness = Harness::new()?;
    harness.set_rule(1, RuleAction::Block, 0, 0)?;

    send_outbound()?;
    thread::sleep(Duration::from_millis(200));

    let outbound = harness.flow_totals(Direction::Outbound, HOST_ADDR, PEER_ADDR, UDP_PORT)?;
    assert_eq!(outbound.0, 0, "blocked packets reached the Flow map");

    let dropped = harness.policy_dropped_packets()?;
    assert!(dropped >= PACKETS as u64, "policy drops: {dropped}");

    let state = harness.rule_state(1, Direction::Outbound)?;
    assert!(state.matched_packets >= PACKETS as u64);
    assert!(state.dropped_packets >= PACKETS as u64);
    Ok(())
}

#[test]
#[ignore = "requires root, iproute2 and a kernel with BPF/tcx"]
fn disabled_policy_passes_matching_traffic() -> Result<()> {
    let _guard = serialized();
    let mut harness = Harness::new()?;
    harness.set_rule(1, RuleAction::Block, 0, 0)?;
    harness.disable_policy()?;

    send_outbound()?;
    thread::sleep(Duration::from_millis(200));

    let outbound = harness.flow_totals(Direction::Outbound, HOST_ADDR, PEER_ADDR, UDP_PORT)?;
    assert!(
        outbound.0 >= PACKETS as u64,
        "outbound packets: {}",
        outbound.0
    );
    assert_eq!(harness.policy_dropped_packets()?, 0);
    Ok(())
}

#[test]
#[ignore = "requires root, iproute2 and a kernel with BPF/tcx"]
fn limit_drops_traffic_above_the_burst() -> Result<()> {
    let _guard = serialized();
    let mut harness = Harness::new()?;
    harness.set_rule(2, RuleAction::Limit, 128, 128)?;

    send_outbound()?;
    thread::sleep(Duration::from_millis(200));

    let state = harness.rule_state(2, Direction::Outbound)?;
    assert!(
        state.dropped_packets >= (PACKETS - 4) as u64,
        "dropped packets: {}",
        state.dropped_packets
    );
    assert!(state.matched_packets >= PACKETS as u64);

    let outbound = harness.flow_totals(Direction::Outbound, HOST_ADDR, PEER_ADDR, UDP_PORT)?;
    assert!(
        outbound.0 <= 4,
        "limited packets that passed: {}",
        outbound.0
    );
    Ok(())
}

#[test]
#[ignore = "requires root, iproute2 and a kernel with BPF/tcx"]
fn blocks_a_matching_cidr() -> Result<()> {
    let _guard = serialized();
    let mut harness = Harness::new()?;
    harness.insert_state(4, 0, 0)?;
    harness.insert_cidr(4, RuleAction::Block, 24)?;
    harness.write_config(true, false, true)?;

    send_outbound()?;
    thread::sleep(Duration::from_millis(200));

    let outbound = harness.flow_totals(Direction::Outbound, HOST_ADDR, PEER_ADDR, UDP_PORT)?;
    assert_eq!(outbound.0, 0, "CIDR-blocked packets reached the Flow map");
    let state = harness.rule_state(4, Direction::Outbound)?;
    assert!(state.dropped_packets >= PACKETS as u64);
    Ok(())
}

#[test]
#[ignore = "requires root, iproute2 and a kernel with BPF/tcx"]
fn blocks_a_matching_application() -> Result<()> {
    let _guard = serialized();
    let mut harness = Harness::new()?;
    harness.insert_state(5, 0, 0)?;
    harness.insert_comm(5, RuleAction::Block, "zs-harness")?;
    harness.insert_owner("zs-harness")?;
    harness.write_config(true, true, false)?;

    send_outbound()?;
    thread::sleep(Duration::from_millis(200));

    let outbound = harness.flow_totals(Direction::Outbound, HOST_ADDR, PEER_ADDR, UDP_PORT)?;
    assert_eq!(
        outbound.0, 0,
        "application-blocked packets reached the Flow map"
    );
    let state = harness.rule_state(5, Direction::Outbound)?;
    assert!(state.dropped_packets >= PACKETS as u64);
    Ok(())
}

#[test]
#[ignore = "requires root, iproute2 and a kernel with BPF/tcx"]
fn missing_rule_state_fails_open() -> Result<()> {
    let _guard = serialized();
    let mut harness = Harness::new()?;
    harness.insert_exact(9, RuleAction::Block, UDP_PORT)?;
    harness.write_config(true, false, true)?;

    send_outbound()?;
    thread::sleep(Duration::from_millis(200));

    let outbound = harness.flow_totals(Direction::Outbound, HOST_ADDR, PEER_ADDR, UDP_PORT)?;
    assert!(
        outbound.0 >= PACKETS as u64,
        "missing state blocked traffic"
    );
    let missing = harness.policy_missing_state()?;
    assert!(missing >= PACKETS as u64, "policy_missing_state: {missing}");
    Ok(())
}

#[test]
#[ignore = "requires root, iproute2 and a kernel with BPF/tcx"]
fn limit_allows_traffic_below_the_rate() -> Result<()> {
    let _guard = serialized();
    let mut harness = Harness::new()?;
    harness.set_rule(6, RuleAction::Limit, 1_000_000, 1_000_000)?;

    send_outbound()?;
    thread::sleep(Duration::from_millis(200));

    let outbound = harness.flow_totals(Direction::Outbound, HOST_ADDR, PEER_ADDR, UDP_PORT)?;
    assert!(
        outbound.0 >= PACKETS as u64,
        "below-rate traffic was dropped"
    );
    let state = harness.rule_state(6, Direction::Outbound)?;
    assert_eq!(state.dropped_packets, 0);
    Ok(())
}

#[test]
#[ignore = "helper process invoked inside the peer namespace"]
fn sends_udp_from_peer() {
    if env::var_os(CHILD_ENV).is_none() {
        return;
    }
    let socket = UdpSocket::bind((PEER_ADDR, 0)).expect("bind peer socket");
    for _ in 0..PACKETS {
        socket
            .send_to(&[0u8; 64], (HOST_ADDR, UDP_PORT))
            .expect("send inbound datagram");
    }
    thread::sleep(Duration::from_millis(100));
}

struct Harness {
    _ebpf: Ebpf,
    flows: PerCpuHashMap<MapData, PodFlowKey, PodFlowValue>,
    stats: PerCpuArray<MapData, PodKernelStats>,
    config: Array<MapData, PodPolicyConfig>,
    states: AyaHashMap<MapData, PodBucketKey, PodRuleState>,
    exact_egress: AyaHashMap<MapData, PodEndpointMatchKey, PodRuleRef>,
    cidr_egress: LpmTrie<MapData, [u8; 4], PodRuleRef>,
    comm_egress: AyaHashMap<MapData, [u8; 16], PodRuleRef>,
    owners: AyaHashMap<MapData, PodOwnerKey, PodOwnerValue>,
    _links: Vec<SchedClassifierLink>,
    _boundary: Boundary,
}

impl Harness {
    fn new() -> Result<Self> {
        let boundary = Boundary::create()?;
        let mut ebpf = Ebpf::load(&std::fs::read(object_path()?)?).context("load eBPF object")?;
        let links = load_and_attach(&mut ebpf, HOST_IFACE)?;

        let flows = PerCpuHashMap::try_from(ebpf.take_map(FLOW_MAP).context("take flow map")?)
            .context("convert flow map")?;
        let stats = PerCpuArray::try_from(
            ebpf.take_map(KERNEL_STATS_MAP)
                .context("take kernel stats map")?,
        )
        .context("convert kernel stats map")?;
        let config = Array::try_from(
            ebpf.take_map(POLICY_CONFIG_MAP)
                .context("take policy config map")?,
        )
        .context("convert policy config map")?;
        let states = AyaHashMap::try_from(
            ebpf.take_map(RULE_STATES_MAP)
                .context("take rule states map")?,
        )
        .context("convert rule states map")?;
        let exact_egress = AyaHashMap::try_from(
            ebpf.take_map(ENDPOINT_EXACT_EGRESS_MAP)
                .context("take endpoint exact egress map")?,
        )
        .context("convert endpoint exact egress map")?;
        let cidr_egress = LpmTrie::try_from(
            ebpf.take_map(ENDPOINT_CIDR_EGRESS_MAP)
                .context("take endpoint CIDR egress map")?,
        )
        .context("convert endpoint CIDR egress map")?;
        let comm_egress = AyaHashMap::try_from(
            ebpf.take_map(APP_COMM_EGRESS_MAP)
                .context("take application comm egress map")?,
        )
        .context("convert application comm egress map")?;
        let owners = AyaHashMap::try_from(ebpf.take_map(OWNER_MAP).context("take owner map")?)
            .context("convert owner map")?;

        Ok(Self {
            _ebpf: ebpf,
            flows,
            stats,
            config,
            states,
            exact_egress,
            cidr_egress,
            comm_egress,
            owners,
            _links: links,
            _boundary: boundary,
        })
    }

    /// Installs one outbound exact-endpoint rule with fail-open ordering:
    /// state first, match entry second, configuration last.
    fn set_rule(&mut self, rule_id: u32, action: RuleAction, rate: u64, burst: u64) -> Result<()> {
        self.insert_state(rule_id, rate, burst)?;
        self.insert_exact(rule_id, action, UDP_PORT)?;
        self.write_config(true, false, true)
    }

    fn insert_state(&mut self, rule_id: u32, rate: u64, burst: u64) -> Result<()> {
        let state = RuleState {
            rate_bytes_per_s: rate,
            burst_bytes: burst,
            tokens: burst,
            ..RuleState::default()
        };
        let key = BucketKey {
            rule_id,
            direction: Direction::Outbound as u8,
            reserved: [0; 3],
        };
        self.states
            .insert(PodBucketKey(key), PodRuleState(state), 0)
            .context("insert rule state")
    }

    fn insert_exact(&mut self, rule_id: u32, action: RuleAction, port: u16) -> Result<()> {
        let mut addr = [0u8; 16];
        addr[12..].copy_from_slice(&PEER_ADDR.parse::<std::net::Ipv4Addr>()?.octets());
        let match_key = EndpointMatchKey {
            addr,
            port_be: port.to_be(),
            reserved: [0; 6],
        };
        self.exact_egress
            .insert(
                PodEndpointMatchKey(match_key),
                PodRuleRef(rule_ref(rule_id, action)),
                0,
            )
            .context("insert endpoint match")
    }

    fn insert_cidr(&mut self, rule_id: u32, action: RuleAction, prefix_len: u32) -> Result<()> {
        let octets = PEER_ADDR.parse::<std::net::Ipv4Addr>()?.octets();
        let mut network = [0u8; 4];
        network[..3].copy_from_slice(&octets[..3]);
        self.cidr_egress
            .insert(
                &LpmKey::new(prefix_len, network),
                PodRuleRef(rule_ref(rule_id, action)),
                0,
            )
            .context("insert CIDR match")
    }

    fn insert_comm(&mut self, rule_id: u32, action: RuleAction, comm: &str) -> Result<()> {
        let mut bytes = [0u8; 16];
        let length = comm.len().min(15);
        bytes[..length].copy_from_slice(&comm.as_bytes()[..length]);
        self.comm_egress
            .insert(bytes, PodRuleRef(rule_ref(rule_id, action)), 0)
            .context("insert comm match")
    }

    fn insert_owner(&mut self, comm: &str) -> Result<()> {
        let mut remote_addr = [0u8; 16];
        remote_addr[12..].copy_from_slice(&PEER_ADDR.parse::<std::net::Ipv4Addr>()?.octets());
        let mut comm_bytes = [0u8; 16];
        let length = comm.len().min(15);
        comm_bytes[..length].copy_from_slice(&comm.as_bytes()[..length]);
        self.owners
            .insert(
                PodOwnerKey(OwnerKey {
                    remote_addr,
                    remote_port_be: UDP_PORT.to_be(),
                    local_port_be: 0,
                    protocol: TransportProtocol::Udp as u8,
                    kind: OwnerKind::Socket as u8,
                    ip_family: IpFamily::V4 as u8,
                    reserved: 0,
                }),
                PodOwnerValue(OwnerValue {
                    tgid: 4_242,
                    pid: 4_242,
                    uid: 1_000,
                    reserved: 0,
                    cgroup_id: 0,
                    comm: comm_bytes,
                    observed_mono_ns: 1,
                }),
                0,
            )
            .context("insert owner")
    }

    fn disable_policy(&mut self) -> Result<()> {
        self.write_config(false, false, false)
    }

    fn write_config(&mut self, enabled: bool, app_rules: bool, endpoint_rules: bool) -> Result<()> {
        self.config
            .set(
                0,
                PodPolicyConfig(PolicyConfig {
                    enabled: u8::from(enabled),
                    app_rules: u8::from(app_rules),
                    endpoint_rules: u8::from(endpoint_rules),
                    reserved: 0,
                    revision: 1,
                }),
                0,
            )
            .context("write policy config")
    }

    fn policy_missing_state(&self) -> Result<u64> {
        let values = self.stats.get(&0, 0).context("read kernel stats")?;
        Ok(values
            .iter()
            .map(|value| value.0.policy_missing_state)
            .sum())
    }

    fn rule_state(&self, rule_id: u32, direction: Direction) -> Result<RuleState> {
        let key = BucketKey {
            rule_id,
            direction: direction as u8,
            reserved: [0; 3],
        };
        self.states
            .get(&PodBucketKey(key), 0)
            .map(|value| value.0)
            .context("read rule state")
    }

    fn policy_dropped_packets(&self) -> Result<u64> {
        let values = self.stats.get(&0, 0).context("read kernel stats")?;
        Ok(values
            .iter()
            .map(|value| value.0.policy_dropped_packets)
            .sum())
    }

    fn packets_seen(&self) -> Result<u64> {
        let values = self.stats.get(&0, 0).context("read kernel stats")?;
        Ok(values.iter().map(|value| value.0.packets_seen).sum())
    }

    fn flow_totals(
        &self,
        direction: Direction,
        src: &str,
        dst: &str,
        udp_port: u16,
    ) -> Result<(u64, u64)> {
        let src_addr = ipv4(src);
        let dst_addr = ipv4(dst);
        let port_be = udp_port.to_be();
        let mut packets = 0u64;
        let mut bytes = 0u64;
        for item in self.flows.iter() {
            let (key, values) = item.context("read flow map entry")?;
            let key = key.0;
            if key.direction != direction as u8
                || key.src_addr != src_addr
                || key.dst_addr != dst_addr
                || key.dst_port_be != port_be
            {
                continue;
            }
            packets += values.iter().map(|value| value.0.packets).sum::<u64>();
            bytes += values.iter().map(|value| value.0.bytes).sum::<u64>();
        }
        Ok((packets, bytes))
    }
}

struct Boundary;

impl Boundary {
    fn create() -> Result<Self> {
        let _ = run("ip", &["netns", "del", NS]);
        let _ = run("ip", &["link", "del", HOST_IFACE]);
        run("ip", &["netns", "add", NS])?;
        run(
            "ip",
            &[
                "link", "add", HOST_IFACE, "type", "veth", "peer", "name", PEER_IFACE,
            ],
        )?;
        run("ip", &["link", "set", PEER_IFACE, "netns", NS])?;
        run(
            "ip",
            &["addr", "add", &format!("{HOST_ADDR}/24"), "dev", HOST_IFACE],
        )?;
        run("ip", &["link", "set", HOST_IFACE, "up"])?;
        run(
            "ip",
            &[
                "netns",
                "exec",
                NS,
                "ip",
                "addr",
                "add",
                &format!("{PEER_ADDR}/24"),
                "dev",
                PEER_IFACE,
            ],
        )?;
        run(
            "ip",
            &["netns", "exec", NS, "ip", "link", "set", PEER_IFACE, "up"],
        )?;
        run(
            "ip",
            &["netns", "exec", NS, "ip", "link", "set", "lo", "up"],
        )?;
        Ok(Self)
    }
}

impl Drop for Boundary {
    fn drop(&mut self) {
        let _ = run("ip", &["netns", "del", NS]);
        let _ = run("ip", &["link", "del", HOST_IFACE]);
    }
}

fn run(program: &str, args: &[&str]) -> Result<()> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("run {program} {args:?}"))?;
    if !output.status.success() {
        bail!(
            "{program} {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

fn object_path() -> Result<PathBuf> {
    if let Some(path) = env::var_os("ZIMASCOPE_EBPF_OBJECT") {
        return Ok(PathBuf::from(path));
    }
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = manifest
        .parent()
        .context("workspace root")?
        .join("target/bpfel-unknown-none/release/zimascope-ebpf");
    if !path.is_file() {
        bail!(
            "eBPF object missing at {}; run cargo xtask build-ebpf",
            path.display()
        );
    }
    Ok(path)
}

fn load_and_attach(ebpf: &mut Ebpf, interface: &str) -> Result<Vec<SchedClassifierLink>> {
    for name in [TC_INGRESS_PROGRAM, TC_EGRESS_PROGRAM] {
        let program: &mut SchedClassifier = ebpf
            .program_mut(name)
            .with_context(|| format!("eBPF program {name:?} is missing"))?
            .try_into()
            .context("convert program to SchedClassifier")?;
        program
            .load()
            .with_context(|| format!("load eBPF program {name:?}"))?;
    }

    let supports_tcx =
        KernelVersion::current().is_ok_and(|current| current >= KernelVersion::new(6, 6, 0));
    if !supports_tcx {
        if let Err(error) = tc::qdisc_add_clsact(interface) {
            if !matches!(error, tc::TcError::AlreadyAttached) {
                return Err(
                    anyhow::Error::new(error).context(format!("add clsact qdisc to {interface}"))
                );
            }
        }
    }

    let mut links = Vec::new();
    for (attach_type, name) in [
        (TcAttachType::Ingress, TC_INGRESS_PROGRAM),
        (TcAttachType::Egress, TC_EGRESS_PROGRAM),
    ] {
        let program: &mut SchedClassifier = ebpf
            .program_mut(name)
            .with_context(|| format!("eBPF program {name:?} is missing"))?
            .try_into()
            .context("convert program to SchedClassifier")?;
        let link_id = program
            .attach(interface, attach_type)
            .with_context(|| format!("attach {name:?} to {interface}"))?;
        links.push(
            program
                .take_link(link_id)
                .with_context(|| format!("take link for {name:?}"))?,
        );
    }
    Ok(links)
}

fn rule_ref(rule_id: u32, action: RuleAction) -> RuleRef {
    RuleRef {
        rule_id,
        action: action as u8,
        reserved: [0; 3],
    }
}

fn ipv4(addr: &str) -> [u8; 16] {
    let parsed: std::net::Ipv4Addr = addr.parse().expect("valid IPv4 address");
    let mut storage = [0u8; 16];
    storage[12..].copy_from_slice(&parsed.octets());
    storage
}

fn send_outbound() -> Result<()> {
    let socket = UdpSocket::bind((HOST_ADDR, 0)).context("bind host socket")?;
    for _ in 0..PACKETS {
        socket
            .send_to(&[0u8; 64], (PEER_ADDR, UDP_PORT))
            .context("send outbound datagram")?;
    }
    Ok(())
}

fn send_inbound_from_peer() -> Result<()> {
    let executable = env::current_exe().context("resolve test executable")?;
    let status = Command::new("ip")
        .args(["netns", "exec", NS])
        .arg(&executable)
        .args(["--exact", "sends_udp_from_peer", "--ignored", "--nocapture"])
        .env(CHILD_ENV, "1")
        .status()
        .context("run peer-side sender in the namespace")?;
    if !status.success() {
        bail!("peer-side sender failed with {status}");
    }
    Ok(())
}

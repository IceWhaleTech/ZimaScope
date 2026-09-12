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
    thread,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use aya::{
    Ebpf,
    maps::{MapData, PerCpuArray, PerCpuHashMap},
    programs::{
        SchedClassifier, TcAttachType,
        tc::{self, SchedClassifierLink},
    },
    util::KernelVersion,
};
use zimascope_common::kernel_abi::{
    self, FLOW_MAP, FlowKey, FlowValue, KERNEL_STATS_MAP, KernelStats, TC_EGRESS_PROGRAM,
    TC_INGRESS_PROGRAM,
};

const NS: &str = "zs-boundary";
const HOST_IFACE: &str = "zs-veth0";
const PEER_IFACE: &str = "zs-veth1";
const HOST_ADDR: &str = "10.99.77.1";
const PEER_ADDR: &str = "10.99.77.2";
const UDP_PORT: u16 = 39_001;
const PACKETS: usize = 16;
const CHILD_ENV: &str = "ZS_BOUNDARY_CHILD";

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

#[test]
#[ignore = "requires root, iproute2 and a kernel with BPF/tcx"]
fn records_both_directions_at_the_boundary() -> Result<()> {
    let _boundary = Boundary::create()?;
    let mut ebpf = Ebpf::load(&std::fs::read(object_path()?)?).context("load eBPF object")?;
    let links = load_and_attach(&mut ebpf, HOST_IFACE)?;

    let flows = PerCpuHashMap::<MapData, PodFlowKey, PodFlowValue>::try_from(
        ebpf.take_map(FLOW_MAP).context("take flow map")?,
    )
    .context("convert flow map")?;
    let stats = PerCpuArray::<MapData, PodKernelStats>::try_from(
        ebpf.take_map(KERNEL_STATS_MAP)
            .context("take kernel stats map")?,
    )
    .context("convert kernel stats map")?;

    send_outbound()?;
    send_inbound_from_peer()?;
    thread::sleep(Duration::from_millis(300));

    let outbound = flow_counters(
        &flows,
        kernel_abi::Direction::Outbound as u8,
        HOST_ADDR,
        PEER_ADDR,
    )?;
    let inbound = flow_counters(
        &flows,
        kernel_abi::Direction::Inbound as u8,
        PEER_ADDR,
        HOST_ADDR,
    )?;

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

    let values = stats.get(&0, 0).context("read kernel stats")?;
    let packets_seen: u64 = values.iter().map(|value| value.0.packets_seen).sum();
    assert!(
        packets_seen >= (PACKETS * 2) as u64,
        "packets_seen: {packets_seen}"
    );

    drop(links);
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

fn flow_counters(
    flows: &PerCpuHashMap<MapData, PodFlowKey, PodFlowValue>,
    direction: u8,
    src: &str,
    dst: &str,
) -> Result<(u64, u64)> {
    let src_addr = ipv4(src);
    let dst_addr = ipv4(dst);
    let mut packets = 0u64;
    let mut bytes = 0u64;
    for item in flows.iter() {
        let (key, values) = item.context("read flow map entry")?;
        let key = key.0;
        if key.direction != direction || key.src_addr != src_addr || key.dst_addr != dst_addr {
            continue;
        }
        packets += values.iter().map(|value| value.0.packets).sum::<u64>();
        bytes += values.iter().map(|value| value.0.bytes).sum::<u64>();
    }
    Ok((packets, bytes))
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

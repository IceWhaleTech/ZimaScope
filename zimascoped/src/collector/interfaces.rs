//! Device Boundary interface discovery and classification.
//!
//! This is the one place that judges interfaces: default-route selection,
//! virtual-NIC exclusion, duplicate-risk warnings and the `/v1/interfaces`
//! catalog all read from here. Classification is a pure function over facts
//! read from `/sys/class/net`, so the rules are testable without a real
//! network namespace.

use std::{collections::HashMap, fs, io, num::NonZeroU32, path::Path};

use anyhow::{Context, Result};

pub const SYS_CLASS_NET: &str = "/sys/class/net";
pub const PROC_NET_ROUTE: &str = "/proc/net/route";

/// `ARPHRD_LOOPBACK` from `<linux/if_arp.h>`.
const ARPHRD_LOOPBACK: u32 = 772;

/// `IFF_UP` from `<linux/if.h>`.
const IFF_UP: u32 = 0x1;

/// Product-facing class of a network interface.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterfaceKind {
    Loopback,
    Physical,
    Bridge,
    DockerBridge,
    Bond,
    Vlan,
    TunTap,
    Wireguard,
    Veth,
    Virtual,
    Other,
}

impl InterfaceKind {
    /// Whether the interface is a physical uplink.
    pub const fn is_physical(self) -> bool {
        matches!(self, Self::Physical)
    }

    /// Whether the interface is virtual or stacked above another interface.
    pub const fn is_virtual(self) -> bool {
        !self.is_physical()
    }
}

/// `/sys/class/net`-derived facts that decide the [`InterfaceKind`].
#[derive(Clone, Debug, Default)]
pub struct InterfaceFacts {
    pub ifindex: u32,
    pub arphrd_type: Option<u32>,
    pub has_bridge: bool,
    pub has_bonding: bool,
    pub has_tun_flags: bool,
    pub has_wireguard: bool,
    pub has_device: bool,
    pub has_lower: bool,
    pub iflink: Option<u32>,
}

/// Classifies one interface from its facts.
///
/// Bridges are checked before `device/` because some virtual devices expose a
/// `device` symlink; stacked devices are checked before the physical fallback
/// for the same reason.
pub fn classify(name: &str, facts: &InterfaceFacts) -> InterfaceKind {
    if name == "lo" || facts.arphrd_type == Some(ARPHRD_LOOPBACK) {
        return InterfaceKind::Loopback;
    }
    if facts.has_bridge {
        return if is_container_bridge(name) {
            InterfaceKind::DockerBridge
        } else {
            InterfaceKind::Bridge
        };
    }
    if facts.has_bonding {
        return InterfaceKind::Bond;
    }
    if facts.has_wireguard {
        return InterfaceKind::Wireguard;
    }
    if facts.has_tun_flags {
        return InterfaceKind::TunTap;
    }
    if facts.has_lower {
        return if name.contains('.') {
            InterfaceKind::Vlan
        } else {
            InterfaceKind::Virtual
        };
    }
    if facts.has_device {
        return InterfaceKind::Physical;
    }
    if facts.iflink.is_some_and(|peer| peer != facts.ifindex) {
        return InterfaceKind::Veth;
    }
    InterfaceKind::Other
}

/// Container bridges created by Docker/Compose.
fn is_container_bridge(name: &str) -> bool {
    name == "docker0" || name.starts_with("br-")
}

/// One interface as reported to settings, the picker and status.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InterfaceInfo {
    pub name: String,
    pub ifindex: NonZeroU32,
    pub kind: InterfaceKind,
    /// `IFF_UP` flag.
    pub up: bool,
    /// Whether this interface currently carries the selected default route.
    pub default_route: bool,
    /// Bridge or bond this interface is enslaved to, when any.
    pub master: Option<String>,
}

/// Enumerates the host interfaces from the real `/sys/class/net`.
pub fn system() -> io::Result<Vec<InterfaceInfo>> {
    enumerate(Path::new(SYS_CLASS_NET), Path::new(PROC_NET_ROUTE))
}

/// Enumerates interfaces under `root`, marking the default route from
/// `route_file`. Sorted by ifindex so output is deterministic.
pub fn enumerate(root: &Path, route_file: &Path) -> io::Result<Vec<InterfaceInfo>> {
    let mut infos = Vec::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.is_empty() || !entry.path().is_dir() {
            continue;
        }
        let facts = read_facts(root, &name)?;
        let Some(ifindex) = NonZeroU32::new(facts.ifindex) else {
            continue;
        };
        let kind = classify(&name, &facts);
        infos.push(InterfaceInfo {
            name,
            ifindex,
            kind,
            up: read_flags(root, &entry.file_name()).is_some_and(|flags| flags & IFF_UP != 0),
            default_route: false,
            master: read_master(root, &entry.file_name()),
        });
    }

    let routes = fs::read_to_string(route_file)
        .map(|contents| parse_default_routes(&contents))
        .unwrap_or_default();
    let kinds: HashMap<&str, InterfaceKind> = infos
        .iter()
        .map(|info| (info.name.as_str(), info.kind))
        .collect();
    if let Some(route) = select_default_route(&routes, |name| {
        kinds.get(name).copied().unwrap_or(InterfaceKind::Other)
    }) {
        for info in &mut infos {
            info.default_route = info.name == route.name;
        }
    }

    infos.sort_by_key(|info| info.ifindex);
    Ok(infos)
}

fn read_facts(root: &Path, name: &str) -> io::Result<InterfaceFacts> {
    let dir = root.join(name);
    let ifindex = read_number(&dir.join("ifindex"))? as u32;
    Ok(InterfaceFacts {
        ifindex,
        arphrd_type: read_number(&dir.join("type"))
            .ok()
            .map(|value| value as u32),
        has_bridge: dir.join("bridge").is_dir(),
        has_bonding: dir.join("bonding").exists(),
        has_tun_flags: dir.join("tun_flags").exists(),
        has_wireguard: dir.join("wireguard").is_dir(),
        has_device: dir.join("device").exists(),
        has_lower: has_lower_link(&dir),
        iflink: read_number(&dir.join("iflink"))
            .ok()
            .map(|value| value as u32),
    })
}

fn has_lower_link(dir: &Path) -> bool {
    let Ok(entries) = fs::read_dir(dir) else {
        return false;
    };
    entries
        .flatten()
        .any(|entry| entry.file_name().to_string_lossy().starts_with("lower_"))
}

fn read_flags(root: &Path, name: &std::ffi::OsStr) -> Option<u32> {
    let raw = fs::read_to_string(root.join(name).join("flags")).ok()?;
    let raw = raw.trim();
    let raw = raw.strip_prefix("0x").unwrap_or(raw);
    u32::from_str_radix(raw, 16).ok()
}

fn read_master(root: &Path, name: &std::ffi::OsStr) -> Option<String> {
    let target = fs::read_link(root.join(name).join("master")).ok()?;
    Some(target.file_name()?.to_string_lossy().into_owned())
}

fn read_number(path: &Path) -> io::Result<u64> {
    let raw = fs::read_to_string(path)?;
    raw.trim()
        .parse()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

/// One `default` row from `/proc/net/route`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DefaultRoute {
    pub name: String,
    pub metric: u32,
}

/// Parses the IPv4 default routes (`Destination == 00000000`, `RTF_UP`).
pub fn parse_default_routes(contents: &str) -> Vec<DefaultRoute> {
    contents
        .lines()
        .skip(1)
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let name = fields.next()?;
            let destination = fields.next()?;
            let _gateway = fields.next()?;
            let flags = fields.next()?;
            let _ref_count = fields.next()?;
            let _use = fields.next()?;
            let metric = fields.next()?;

            if destination != "00000000" {
                return None;
            }
            if u32::from_str_radix(flags, 16).unwrap_or(0) & 0x1 == 0 {
                return None;
            }
            Some(DefaultRoute {
                name: name.to_owned(),
                metric: metric.parse().unwrap_or(u32::MAX),
            })
        })
        .collect()
}

/// Picks the default-route interface: the best non-virtual candidate first,
/// then the best virtual one (VPN full tunnels), never loopback.
pub fn select_default_route(
    routes: &[DefaultRoute],
    kind_of: impl Fn(&str) -> InterfaceKind,
) -> Option<&DefaultRoute> {
    let mut candidates: Vec<&DefaultRoute> = routes
        .iter()
        .filter(|route| kind_of(&route.name) != InterfaceKind::Loopback)
        .collect();
    candidates.sort_by_key(|route| route.metric);
    candidates
        .iter()
        .copied()
        .find(|route| !kind_of(&route.name).is_virtual())
        .or_else(|| candidates.first().copied())
}

/// Resolves the host default-route interface name, if any.
pub fn system_default_route() -> Result<String> {
    let infos = system().context("enumerate /sys/class/net")?;
    let contents = fs::read_to_string(PROC_NET_ROUTE).context("read /proc/net/route")?;
    let routes = parse_default_routes(&contents);
    let kinds: HashMap<&str, InterfaceKind> = infos
        .iter()
        .map(|info| (info.name.as_str(), info.kind))
        .collect();
    select_default_route(&routes, |name| {
        kinds.get(name).copied().unwrap_or(InterfaceKind::Other)
    })
    .map(|route| route.name.clone())
    .context("no default route interface found in /proc/net/route")
}

/// Resolves an interface name to its ifindex under `root`.
pub fn ifindex_for_name(root: &Path, name: &str) -> Result<NonZeroU32> {
    let path = root.join(name).join("ifindex");
    let value = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let index: u32 = value.trim().parse().context("parse ifindex")?;
    NonZeroU32::new(index).with_context(|| format!("interface {name:?} has ifindex 0"))
}

/// Resolves an ifindex to its interface name under `root`.
pub fn name_for_index(root: &Path, ifindex: u32) -> Result<String> {
    let entries = fs::read_dir(root).with_context(|| format!("read {}", root.display()))?;
    let mut candidates = Vec::new();
    for entry in entries {
        let entry = entry.context("read /sys/class/net entry")?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if let Ok(path) = fs::read_to_string(root.join(&name).join("ifindex")) {
            if path.trim().parse::<u32>() == Ok(ifindex) {
                candidates.push(name);
            }
        }
    }
    candidates.sort();
    candidates
        .into_iter()
        .next()
        .with_context(|| format!("no interface with ifindex {ifindex}"))
}

/// A duplicate-count or configuration hazard for the selected boundary set.
#[allow(dead_code)]
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct BoundaryWarning {
    /// Stable machine code: `bridge_port_overlap`, `uplink_overlap`,
    /// `loopback`, `missing_interface`.
    pub kind: &'static str,
    pub message: String,
    pub interfaces: Vec<String>,
}

/// Judges a selected boundary set against the current interfaces.
///
/// Warnings never block saving: an interface that is absent now may appear
/// later (docker0, a VPN tunnel) and the collector attaches it when it does.
#[allow(dead_code)]
pub fn boundary_warnings(selected: &[String], infos: &[InterfaceInfo]) -> Vec<BoundaryWarning> {
    let by_name: HashMap<&str, &InterfaceInfo> = infos
        .iter()
        .map(|info| (info.name.as_str(), info))
        .collect();
    let mut warnings = Vec::new();
    let mut sorted: Vec<&String> = selected.iter().collect();
    sorted.sort();
    sorted.dedup();

    for name in &sorted {
        let Some(info) = by_name.get(name.as_str()) else {
            warnings.push(BoundaryWarning {
                kind: "missing_interface",
                message: format!("{name} is not present; it will be attached when it appears"),
                interfaces: vec![(*name).clone()],
            });
            continue;
        };
        if info.kind == InterfaceKind::Loopback {
            warnings.push(BoundaryWarning {
                kind: "loopback",
                message: format!("{name} is loopback; it is normally excluded"),
                interfaces: vec![(*name).clone()],
            });
        }
    }

    for name in &sorted {
        let Some(info) = by_name.get(name.as_str()) else {
            continue;
        };
        if !matches!(
            info.kind,
            InterfaceKind::Bridge | InterfaceKind::DockerBridge
        ) {
            continue;
        }
        let ports: Vec<String> = infos
            .iter()
            .filter(|candidate| candidate.master.as_deref() == Some(name.as_str()))
            .filter(|candidate| by_name.contains_key(candidate.name.as_str()))
            .map(|candidate| candidate.name.clone())
            .collect();
        if !ports.is_empty() {
            warnings.push(BoundaryWarning {
                kind: "bridge_port_overlap",
                message: format!(
                    "{name} and its bridge ports are both selected; the same traffic may be counted twice"
                ),
                interfaces: std::iter::once((*name).clone())
                    .chain(ports)
                    .collect(),
            });
        }
    }

    let physical_default: Vec<&str> = sorted
        .iter()
        .filter_map(|name| by_name.get(name.as_str()))
        .filter(|info| info.kind.is_physical() && info.default_route)
        .map(|info| info.name.as_str())
        .collect();
    let virtual_selected: Vec<&str> = sorted
        .iter()
        .filter_map(|name| by_name.get(name.as_str()))
        .filter(|info| {
            matches!(
                info.kind,
                InterfaceKind::Bridge
                    | InterfaceKind::DockerBridge
                    | InterfaceKind::Bond
                    | InterfaceKind::Vlan
                    | InterfaceKind::TunTap
                    | InterfaceKind::Wireguard
                    | InterfaceKind::Virtual
            )
        })
        .map(|info| info.name.as_str())
        .collect();
    if !physical_default.is_empty() && !virtual_selected.is_empty() {
        warnings.push(BoundaryWarning {
            kind: "uplink_overlap",
            message: format!(
                "{} and {} are both selected; encapsulated or bridged traffic may be counted twice",
                physical_default.join(", "),
                virtual_selected.join(", ")
            ),
            interfaces: physical_default
                .iter()
                .chain(virtual_selected.iter())
                .map(|name| (*name).to_owned())
                .collect(),
        });
    }

    warnings
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn facts(ifindex: u32) -> InterfaceFacts {
        InterfaceFacts {
            ifindex,
            ..InterfaceFacts::default()
        }
    }

    #[test]
    fn classifies_every_common_interface_kind() {
        assert_eq!(
            classify("lo", &facts(1)),
            InterfaceKind::Loopback,
            "name and ARPHRD both mark loopback"
        );
        assert_eq!(
            classify(
                "eth0",
                &InterfaceFacts {
                    has_device: true,
                    arphrd_type: Some(1),
                    ..facts(2)
                }
            ),
            InterfaceKind::Physical
        );
        assert_eq!(
            classify(
                "br0",
                &InterfaceFacts {
                    has_bridge: true,
                    ..facts(3)
                }
            ),
            InterfaceKind::Bridge
        );
        assert_eq!(
            classify(
                "docker0",
                &InterfaceFacts {
                    has_bridge: true,
                    ..facts(4)
                }
            ),
            InterfaceKind::DockerBridge
        );
        assert_eq!(
            classify(
                "br-abc123",
                &InterfaceFacts {
                    has_bridge: true,
                    ..facts(5)
                }
            ),
            InterfaceKind::DockerBridge
        );
        assert_eq!(
            classify(
                "bond0",
                &InterfaceFacts {
                    has_bonding: true,
                    ..facts(6)
                }
            ),
            InterfaceKind::Bond
        );
        assert_eq!(
            classify(
                "tun0",
                &InterfaceFacts {
                    has_tun_flags: true,
                    ..facts(7)
                }
            ),
            InterfaceKind::TunTap
        );
        assert_eq!(
            classify(
                "wg0",
                &InterfaceFacts {
                    has_wireguard: true,
                    ..facts(8)
                }
            ),
            InterfaceKind::Wireguard
        );
        assert_eq!(
            classify(
                "eth0.10",
                &InterfaceFacts {
                    has_lower: true,
                    ..facts(9)
                }
            ),
            InterfaceKind::Vlan
        );
        assert_eq!(
            classify(
                "macvlan0",
                &InterfaceFacts {
                    has_lower: true,
                    ..facts(10)
                }
            ),
            InterfaceKind::Virtual
        );
        assert_eq!(
            classify(
                "veth1234",
                &InterfaceFacts {
                    iflink: Some(11),
                    ..facts(12)
                }
            ),
            InterfaceKind::Veth
        );
        assert_eq!(classify("weird0", &facts(13)), InterfaceKind::Other);
    }

    #[test]
    fn stacked_and_bridged_devices_win_over_device_symlinks() {
        let stacked = InterfaceFacts {
            has_device: true,
            has_lower: true,
            arphrd_type: Some(1),
            ..facts(1)
        };
        assert_eq!(classify("eth0.20", &stacked), InterfaceKind::Vlan);
        let bridged = InterfaceFacts {
            has_device: true,
            has_bridge: true,
            ..facts(2)
        };
        assert_eq!(classify("docker0", &bridged), InterfaceKind::DockerBridge);
    }

    #[test]
    fn parses_only_up_default_routes_with_metrics() {
        let contents = "\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
eth0\t00000000\t0102A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
eth1\t00000000\t0102A8C0\t0000\t0\t0\t50\t00000000\t0\t0\t0\n\
eth2\t0002A8C0\t00000000\t0003\t0\t0\t0\t00FFFFFF\t0\t0\t0\n\
wg0\t00000000\t00000000\t0003\t0\t0\t600\t00000000\t0\t0\t0\n";
        let routes = parse_default_routes(contents);
        assert_eq!(
            routes,
            vec![
                DefaultRoute {
                    name: "eth0".to_owned(),
                    metric: 100
                },
                DefaultRoute {
                    name: "wg0".to_owned(),
                    metric: 600
                },
            ],
            "the down eth1 route and the non-default eth2 route are skipped"
        );
    }

    #[test]
    fn default_route_prefers_physical_then_falls_back_to_vpn() {
        let routes = vec![
            DefaultRoute {
                name: "wg0".to_owned(),
                metric: 50,
            },
            DefaultRoute {
                name: "eth0".to_owned(),
                metric: 100,
            },
        ];
        let kind = |name: &str| match name {
            "wg0" => InterfaceKind::Wireguard,
            _ => InterfaceKind::Physical,
        };
        assert_eq!(
            select_default_route(&routes, kind).map(|route| route.name.as_str()),
            Some("eth0"),
            "a physical default route wins over a lower-metric VPN"
        );

        let vpn_only = vec![DefaultRoute {
            name: "wg0".to_owned(),
            metric: 50,
        }];
        assert_eq!(
            select_default_route(&vpn_only, kind).map(|route| route.name.as_str()),
            Some("wg0"),
            "a full-tunnel VPN is used when it is the only default route"
        );
    }

    #[test]
    fn default_route_never_picks_loopback() {
        let routes = vec![DefaultRoute {
            name: "lo".to_owned(),
            metric: 1,
        }];
        assert!(select_default_route(&routes, |_| InterfaceKind::Loopback).is_none());
    }

    #[test]
    fn enumerates_a_fake_sysfs_tree() {
        let root = temp_dir("enumerate");
        fs::create_dir_all(root.join("eth0")).expect("create eth0");
        fs::write(root.join("eth0/ifindex"), "2\n").expect("write ifindex");
        fs::write(root.join("eth0/type"), "1\n").expect("write type");
        fs::write(root.join("eth0/flags"), "0x1003\n").expect("write flags");
        fs::create_dir_all(root.join("eth0/device")).expect("create device");
        fs::create_dir_all(root.join("docker0")).expect("create docker0");
        fs::write(root.join("docker0/ifindex"), "5\n").expect("write ifindex");
        fs::write(root.join("docker0/type"), "1\n").expect("write type");
        fs::create_dir_all(root.join("docker0/bridge")).expect("create bridge");
        let route = root.join("route");
        fs::write(
            &route,
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n\
             eth0\t00000000\t0102A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
             docker0\t00000000\t00000000\t0003\t0\t0\t0\t00000000\t0\t0\t0\n",
        )
        .expect("write route");

        let infos = enumerate(&root, &route).expect("enumerate");
        assert_eq!(infos.len(), 2);
        assert_eq!(infos[0].name, "eth0");
        assert_eq!(infos[0].kind, InterfaceKind::Physical);
        assert!(infos[0].up);
        assert!(infos[0].default_route);
        assert_eq!(infos[1].name, "docker0");
        assert_eq!(infos[1].kind, InterfaceKind::DockerBridge);
        assert!(!infos[1].default_route, "the physical default route wins");

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn resolves_names_and_indexes_under_a_fake_sysfs_tree() {
        let root = temp_dir("lookup");
        fs::create_dir_all(root.join("eth0")).expect("create eth0");
        fs::write(root.join("eth0/ifindex"), "7\n").expect("write ifindex");

        assert_eq!(ifindex_for_name(&root, "eth0").expect("resolve").get(), 7);
        assert_eq!(name_for_index(&root, 7).expect("resolve"), "eth0");
        assert!(ifindex_for_name(&root, "missing").is_err());
        assert!(name_for_index(&root, 99).is_err());

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn boundary_warnings_flag_bridge_ports_and_uplink_overlap() {
        let infos = vec![
            InterfaceInfo {
                name: "eth0".to_owned(),
                ifindex: NonZeroU32::new(2).expect("nonzero"),
                kind: InterfaceKind::Physical,
                up: true,
                default_route: true,
                master: None,
            },
            InterfaceInfo {
                name: "br0".to_owned(),
                ifindex: NonZeroU32::new(3).expect("nonzero"),
                kind: InterfaceKind::Bridge,
                up: true,
                default_route: false,
                master: None,
            },
            InterfaceInfo {
                name: "veth1".to_owned(),
                ifindex: NonZeroU32::new(4).expect("nonzero"),
                kind: InterfaceKind::Veth,
                up: true,
                default_route: false,
                master: Some("br0".to_owned()),
            },
            InterfaceInfo {
                name: "docker0".to_owned(),
                ifindex: NonZeroU32::new(5).expect("nonzero"),
                kind: InterfaceKind::DockerBridge,
                up: true,
                default_route: false,
                master: None,
            },
        ];

        let warnings = boundary_warnings(
            &["br0".to_owned(), "veth1".to_owned(), "missing0".to_owned()],
            &infos,
        );
        let kinds: Vec<&str> = warnings.iter().map(|warning| warning.kind).collect();
        assert!(kinds.contains(&"bridge_port_overlap"));
        assert!(kinds.contains(&"missing_interface"));

        let warnings = boundary_warnings(&["eth0".to_owned(), "docker0".to_owned()], &infos);
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].kind, "uplink_overlap");
        assert_eq!(warnings[0].interfaces, vec!["eth0", "docker0"]);
    }

    fn temp_dir(label: &str) -> PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "zimascope-interfaces-{label}-{}-{unique}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("create temp dir");
        path
    }
}

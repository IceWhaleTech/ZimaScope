use std::{
    num::NonZeroU32,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use anyhow::{Result, bail};
use zimascope_common::{
    kernel_abi::{self, Direction, FlowKey, FlowValue, IpFamily, KernelStats},
    model::InterfaceHealth,
};

use super::KernelSource;

#[derive(Default)]
struct State {
    flows: Vec<(FlowKey, Vec<FlowValue>)>,
    events: Vec<kernel_abi::DomainEvent>,
    stats: KernelStats,
    interfaces: Vec<InterfaceHealth>,
    fail_flow_read: bool,
    fail_domain_read: bool,
    fail_stats_read: bool,
}

/// Deterministic in-memory adapter behind the private [`KernelSource`] seam.
pub(crate) struct InMemoryKernelSource {
    state: Arc<Mutex<State>>,
    detach_count: Arc<AtomicUsize>,
}

impl Default for InMemoryKernelSource {
    fn default() -> Self {
        Self {
            state: Arc::new(Mutex::new(State::default())),
            detach_count: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl InMemoryKernelSource {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_flow(self, key: FlowKey, values: Vec<FlowValue>) -> Self {
        self.handle().set_flow(key, values);
        self
    }

    pub fn with_event(self, event: kernel_abi::DomainEvent) -> Self {
        self.handle().push_event(event);
        self
    }

    pub fn with_stats(self, stats: KernelStats) -> Self {
        self.state.lock().expect("test state").stats = stats;
        self
    }

    pub fn with_interface(self, ifindex: u32, name: &str) -> Self {
        self.handle().add_interface(ifindex, name);
        self
    }

    pub fn handle(&self) -> InMemoryHandle {
        InMemoryHandle {
            state: Arc::clone(&self.state),
        }
    }

    /// Returns a handle that counts detach calls on this source.
    pub fn detach_counter(&self) -> Arc<AtomicUsize> {
        Arc::clone(&self.detach_count)
    }
}

/// Mutation handle for a running in-memory source.
pub(crate) struct InMemoryHandle {
    state: Arc<Mutex<State>>,
}

impl InMemoryHandle {
    pub fn set_flows(&self, flows: Vec<(FlowKey, Vec<FlowValue>)>) {
        self.state.lock().expect("test state").flows = flows;
    }

    pub fn set_flow(&self, key: FlowKey, values: Vec<FlowValue>) {
        let mut state = self.state.lock().expect("test state");
        state.flows.retain(|(existing, _)| *existing != key);
        state.flows.push((key, values));
    }

    pub fn push_event(&self, event: kernel_abi::DomainEvent) {
        self.state.lock().expect("test state").events.push(event);
    }

    pub fn set_flows_failing(&self, fail: bool) {
        self.state.lock().expect("test state").fail_flow_read = fail;
    }

    pub fn set_stats(&self, stats: KernelStats) {
        self.state.lock().expect("test state").stats = stats;
    }

    pub fn set_domains_failing(&self, fail: bool) {
        self.state.lock().expect("test state").fail_domain_read = fail;
    }

    pub fn set_stats_failing(&self, fail: bool) {
        self.state.lock().expect("test state").fail_stats_read = fail;
    }

    pub fn set_interface_attached(&self, ifindex: u32, attached: bool) {
        let mut state = self.state.lock().expect("test state");
        if let Some(interface) = state
            .interfaces
            .iter_mut()
            .find(|interface| interface.ifindex.get() == ifindex)
        {
            interface.ingress_attached = attached;
            interface.egress_attached = attached;
        }
    }

    pub fn add_interface(&self, ifindex: u32, name: &str) {
        self.state
            .lock()
            .expect("test state")
            .interfaces
            .push(InterfaceHealth {
                ifindex: NonZeroU32::new(ifindex).expect("test ifindex is non-zero"),
                name: name.into(),
                ingress_attached: true,
                egress_attached: true,
                last_error: None,
            });
    }
}

impl KernelSource for InMemoryKernelSource {
    fn visit_flows(&mut self, visitor: &mut dyn FnMut(FlowKey, &[FlowValue])) -> Result<usize> {
        let state = self.state.lock().expect("test state");
        if state.fail_flow_read {
            bail!("injected flow map read failure");
        }
        for (key, values) in &state.flows {
            visitor(*key, values);
        }
        Ok(state.flows.len())
    }

    fn drain_domain_events(
        &mut self,
        visitor: &mut dyn FnMut(&kernel_abi::DomainEvent),
    ) -> Result<()> {
        let mut state = self.state.lock().expect("test state");
        if state.fail_domain_read {
            bail!("injected domain event read failure");
        }
        let events = core::mem::take(&mut state.events);
        for event in &events {
            visitor(event);
        }
        Ok(())
    }

    fn read_stats(&mut self) -> Result<KernelStats> {
        let state = self.state.lock().expect("test state");
        if state.fail_stats_read {
            bail!("injected kernel stats read failure");
        }
        Ok(state.stats)
    }

    fn attachment_health(&self) -> Vec<InterfaceHealth> {
        self.state.lock().expect("test state").interfaces.clone()
    }

    fn detach(&mut self) -> Result<()> {
        self.detach_count.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

pub(crate) fn abi_key(
    direction: Direction,
    src: [u8; 4],
    dst: [u8; 4],
    src_port: u16,
    dst_port: u16,
    protocol: u8,
) -> FlowKey {
    let mut src_addr = [0u8; 16];
    src_addr[12..].copy_from_slice(&src);
    let mut dst_addr = [0u8; 16];
    dst_addr[12..].copy_from_slice(&dst);

    FlowKey {
        src_addr,
        dst_addr,
        src_port_be: src_port.to_be(),
        dst_port_be: dst_port.to_be(),
        ifindex: 7,
        protocol,
        direction: direction as u8,
        ip_family: IpFamily::V4 as u8,
        reserved: 0,
    }
}

pub(crate) fn abi_value(
    packets: u64,
    bytes: u64,
    first_seen_ns: u64,
    last_seen_ns: u64,
    tcp_flags: u16,
) -> FlowValue {
    FlowValue {
        packets,
        bytes,
        first_seen_mono_ns: first_seen_ns,
        last_seen_mono_ns: last_seen_ns,
        tcp_flags,
        parse_flags: 0,
        reserved: 0,
    }
}

pub(crate) fn abi_domain_event(
    evidence: u8,
    domain: &str,
    address: [u8; 4],
    observed_mono_ns: u64,
    expires_mono_ns: u64,
    client_context: u64,
) -> kernel_abi::DomainEvent {
    let mut event = kernel_abi::DomainEvent {
        observed_mono_ns,
        expires_mono_ns,
        client_context,
        address: [0u8; 16],
        ifindex: 7,
        domain_len: domain.len() as u16,
        evidence,
        ip_family: IpFamily::V4 as u8,
        direction: Direction::Outbound as u8,
        reserved: 0,
        domain: [0u8; kernel_abi::DOMAIN_MAX_LEN],
        padding: 0,
    };
    event.address[12..].copy_from_slice(&address);
    event.domain[..domain.len()].copy_from_slice(domain.as_bytes());
    event
}

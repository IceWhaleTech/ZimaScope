use std::{
    num::NonZeroU32,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use anyhow::{Result, bail};
use zimascope_common::{
    kernel_abi::{
        self, Direction, FlowKey, FlowValue, IpFamily, KernelStats, OwnerKey, OwnerKind,
        OwnerValue, SampleKind, TransportProtocol,
    },
    model::{ApplicationHealth, InterfaceHealth},
};

use super::KernelSource;

#[derive(Default)]
struct State {
    flows: Vec<(FlowKey, Vec<FlowValue>)>,
    owners: Vec<(OwnerKey, OwnerValue)>,
    events: Vec<kernel_abi::DomainSample>,
    services: Vec<kernel_abi::ServiceSample>,
    stats: KernelStats,
    interfaces: Vec<InterfaceHealth>,
    application_attached: bool,
    udp_attached: bool,
    application_error: Option<Box<str>>,
    fail_flow_read: bool,
    fail_owner_read: bool,
    fail_domain_read: bool,
    fail_service_read: bool,
    fail_stats_read: bool,
}

/// Deterministic in-memory adapter behind the private [`KernelSource`] seam.
pub(crate) struct InMemoryKernelSource {
    state: Arc<Mutex<State>>,
    detach_count: Arc<AtomicUsize>,
}

impl Default for InMemoryKernelSource {
    fn default() -> Self {
        let state = State {
            application_attached: true,
            udp_attached: true,
            ..State::default()
        };
        Self {
            state: Arc::new(Mutex::new(state)),
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

    pub fn with_owner(self, key: OwnerKey, value: OwnerValue) -> Self {
        self.handle().push_owner(key, value);
        self
    }

    pub fn with_event(self, sample: kernel_abi::DomainSample) -> Self {
        self.handle().push_event(sample);
        self
    }

    pub fn with_service(self, sample: kernel_abi::ServiceSample) -> Self {
        self.handle().push_service(sample);
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

    pub fn push_event(&self, sample: kernel_abi::DomainSample) {
        self.state.lock().expect("test state").events.push(sample);
    }

    pub fn push_service(&self, sample: kernel_abi::ServiceSample) {
        self.state.lock().expect("test state").services.push(sample);
    }

    pub fn set_flows_failing(&self, fail: bool) {
        self.state.lock().expect("test state").fail_flow_read = fail;
    }

    pub fn push_owner(&self, key: OwnerKey, value: OwnerValue) {
        self.state
            .lock()
            .expect("test state")
            .owners
            .push((key, value));
    }

    pub fn set_owners_failing(&self, fail: bool) {
        self.state.lock().expect("test state").fail_owner_read = fail;
    }

    pub fn set_application_health(&self, attached: bool, error: Option<&str>) {
        let mut state = self.state.lock().expect("test state");
        state.application_attached = attached;
        state.application_error = error.map(Into::into);
    }

    pub fn set_stats(&self, stats: KernelStats) {
        self.state.lock().expect("test state").stats = stats;
    }

    pub fn set_domains_failing(&self, fail: bool) {
        self.state.lock().expect("test state").fail_domain_read = fail;
    }

    pub fn set_services_failing(&self, fail: bool) {
        self.state.lock().expect("test state").fail_service_read = fail;
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

    fn visit_owners(&mut self, visitor: &mut dyn FnMut(OwnerKey, &OwnerValue)) -> Result<usize> {
        let state = self.state.lock().expect("test state");
        if state.fail_owner_read {
            bail!("injected owner map read failure");
        }
        for (key, value) in &state.owners {
            visitor(*key, value);
        }
        Ok(state.owners.len())
    }

    fn drain_domain_events(
        &mut self,
        visitor: &mut dyn FnMut(&kernel_abi::DomainSample),
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

    fn drain_service_events(
        &mut self,
        visitor: &mut dyn FnMut(&kernel_abi::ServiceSample),
    ) -> Result<()> {
        let mut state = self.state.lock().expect("test state");
        if state.fail_service_read {
            bail!("injected service event read failure");
        }
        let events = core::mem::take(&mut state.services);
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

    fn application_health(&self) -> ApplicationHealth {
        let state = self.state.lock().expect("test state");
        ApplicationHealth {
            attached: state.application_attached,
            udp_attached: state.udp_attached,
            last_error: state.application_error.clone(),
        }
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
        service_flags: 0,
        reserved: 0,
    }
}

pub(crate) fn abi_owner_key(
    protocol: u8,
    kind: OwnerKind,
    local_port: u16,
    remote: Option<([u8; 4], u16)>,
) -> OwnerKey {
    let mut remote_addr = [0u8; 16];
    let remote_port_be = match remote {
        Some((address, port)) => {
            remote_addr[12..].copy_from_slice(&address);
            port.to_be()
        }
        None => 0,
    };

    OwnerKey {
        remote_addr,
        remote_port_be,
        local_port_be: local_port.to_be(),
        protocol,
        kind: kind as u8,
        ip_family: IpFamily::V4 as u8,
        reserved: 0,
    }
}

pub(crate) fn abi_owner_value(tgid: u32, uid: u32, comm: &str) -> OwnerValue {
    let mut raw = [0u8; 16];
    let bytes = comm.as_bytes();
    let length = bytes.len().min(raw.len());
    raw[..length].copy_from_slice(&bytes[..length]);

    OwnerValue {
        tgid,
        pid: tgid,
        uid,
        reserved: 0,
        cgroup_id: 0,
        comm: raw,
        observed_mono_ns: 1_000,
    }
}

pub(crate) fn abi_domain_sample(
    kind: u8,
    transport: u8,
    address: [u8; 4],
    observed_mono_ns: u64,
    payload: &[u8],
) -> kernel_abi::DomainSample {
    let length = payload.len().min(kernel_abi::DOMAIN_SAMPLE_MAX);
    let mut sample = kernel_abi::DomainSample {
        observed_mono_ns,
        ifindex: 7,
        payload_len: length as u16,
        kind,
        transport,
        ip_family: IpFamily::V4 as u8,
        direction: Direction::Outbound as u8,
        reserved: [0; 6],
        address: [0; 16],
        payload: [0; kernel_abi::DOMAIN_SAMPLE_MAX],
    };
    sample.address[12..].copy_from_slice(&address);
    sample.payload[..length].copy_from_slice(&payload[..length]);
    sample
}

/// Builds a DNS response sample carrying one A record.
pub(crate) fn abi_dns_sample(
    domain: &str,
    address: [u8; 4],
    ttl_secs: u32,
) -> kernel_abi::DomainSample {
    let mut message = Vec::new();
    message.extend_from_slice(&0x1234u16.to_be_bytes());
    message.extend_from_slice(&0x8180u16.to_be_bytes());
    message.extend_from_slice(&1u16.to_be_bytes());
    message.extend_from_slice(&1u16.to_be_bytes());
    message.extend_from_slice(&0u16.to_be_bytes());
    message.extend_from_slice(&0u16.to_be_bytes());
    for label in domain.split('.') {
        message.push(label.len() as u8);
        message.extend_from_slice(label.as_bytes());
    }
    message.push(0);
    message.extend_from_slice(&1u16.to_be_bytes());
    message.extend_from_slice(&1u16.to_be_bytes());
    message.push(0xC0);
    message.push(0x0C);
    message.extend_from_slice(&1u16.to_be_bytes());
    message.extend_from_slice(&1u16.to_be_bytes());
    message.extend_from_slice(&ttl_secs.to_be_bytes());
    message.extend_from_slice(&4u16.to_be_bytes());
    message.extend_from_slice(&address);

    abi_domain_sample(
        SampleKind::Dns as u8,
        TransportProtocol::Udp as u8,
        [8, 8, 8, 8],
        1_000,
        &message,
    )
}

/// Builds a TLS ClientHello sample carrying one SNI value.
pub(crate) fn abi_tls_sample(sni: &str, address: [u8; 4]) -> kernel_abi::DomainSample {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0u8; 32]);
    body.push(0);
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&[0x13, 0x01]);
    body.push(1);
    body.push(0);

    let entry_len = 1 + 2 + sni.len();
    let mut server_name = Vec::new();
    server_name.extend_from_slice(&(entry_len as u16).to_be_bytes());
    server_name.push(0);
    server_name.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    server_name.extend_from_slice(sni.as_bytes());

    let mut extensions = Vec::new();
    extensions.extend_from_slice(&0u16.to_be_bytes());
    extensions.extend_from_slice(&(server_name.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&server_name);

    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    let mut handshake = Vec::new();
    handshake.push(0x01);
    handshake.extend_from_slice(&[
        (body.len() >> 16) as u8,
        (body.len() >> 8) as u8,
        body.len() as u8,
    ]);
    handshake.extend_from_slice(&body);

    let mut record = Vec::new();
    record.push(0x16);
    record.extend_from_slice(&[0x03, 0x01]);
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);

    abi_domain_sample(
        SampleKind::TlsClientHello as u8,
        TransportProtocol::Tcp as u8,
        address,
        1_000,
        &record,
    )
}

# ZimaScope Network Observability

ZimaScope describes network activity at the boundary of a ZimaOS device. This glossary keeps product language honest when encrypted protocols or shared infrastructure prevent exact attribution.

## Language

**Flow**:
A bidirectional or directional network activity record grouped by protocol, addresses and ports during a bounded time window.
_Avoid_: Request, packet capture

**Device Boundary**:
The set of selected uplink interfaces where traffic enters or leaves the ZimaOS host. Direction is always defined relative to this boundary.
_Avoid_: Internet boundary, physical port

**Inbound Traffic**:
Traffic observed entering the ZimaOS device through the Device Boundary.
_Avoid_: Download traffic

**Outbound Traffic**:
Traffic observed leaving the ZimaOS device through the Device Boundary.
_Avoid_: Upload traffic

**Endpoint**:
A network peer identified by IP address and, when available, port and protocol.
_Avoid_: Server, website

**Associated Domain**:
A domain linked to a Flow through an observed DNS answer, TLS SNI, or HTTP Host value. It is not guaranteed to be the domain of every application request carried by that Flow.
_Avoid_: Request domain, real domain

**Domain Evidence**:
The observable source used to associate a domain with a Flow: DNS, TLS SNI, or HTTP Host.
_Avoid_: Domain type

**Association Confidence**:
The product's qualitative assessment of how directly Domain Evidence identifies the domain used by a Flow.
_Avoid_: Accuracy percentage

**IP Profile**:
Locally enriched information about an IP address, including address scope, country/region, ASN and organization.
_Avoid_: Exact IP location

**Fake IP**:
A synthetic address handed out by a local proxy's fake-IP DNS, where the proxy resolves and dials the real destination. ZimaScope classifies the RFC 2544 range (198.18.0.0/15) and reports it without country or ASN attribution.
_Avoid_: Proxy IP, virtual server

**Application Identity**:
The process, ZimaOS application, container or workload associated with a Flow when the system has sufficient evidence.
_Avoid_: App owner

**Attribution Coverage**:
The share of boundary traffic that carries an Application Identity. Unattributed traffic is still a valid Flow; the remainder is reported, never redistributed or guessed.
_Avoid_: Attribution accuracy

**Observation Gap**:
A known interval or protocol condition in which ZimaScope could not observe, process or retain complete network metadata.
_Avoid_: No traffic

**Fingerprint**:
A byte-pattern rule that identifies an application protocol from the first payload of a Flow. Matches are observed evidence; unmatched Flows stay TCP/UDP.
_Avoid_: Port inference, service guess

**Traffic Rule**:
A user-confirmed policy that limits or blocks Flows matching an Endpoint, a CIDR, or an Application Identity. Rules are directional and evaluated at the Device Boundary.
_Avoid_: Firewall rule, QoS rule

**Limit**:
A Traffic Rule action that drops over-limit packets so matching traffic settles at or below the configured rate. This is policing; ZimaScope never queues or delays packets.
_Avoid_: Shaping, throttling, bandwidth guarantee

**Block**:
A Traffic Rule action that drops every matching packet. Blocked traffic is not counted as boundary traffic and never appears as a Flow.
_Avoid_: Reject, reset

**Policing**:
The enforcement method for Traffic Rules: over-limit packets are dropped at the Device Boundary instead of queued. Enforcement is fail-open — any missing evidence passes the packet.
_Avoid_: Shaping, traffic control

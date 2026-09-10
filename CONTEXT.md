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

**Application Identity**:
The process, ZimaOS application, container or workload associated with a Flow when the system has sufficient evidence.
_Avoid_: App owner

**Observation Gap**:
A known interval or protocol condition in which ZimaScope could not observe, process or retain complete network metadata.
_Avoid_: No traffic

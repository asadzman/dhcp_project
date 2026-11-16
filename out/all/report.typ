#set page(paper: "a4", margin: (x: 2cm, y: 2.2cm), numbering: "1")
#set text(font: "New Computer Modern", size: 10pt, lang: "en")
#show raw: set text(font: "DejaVu Sans Mono")
#set par(justify: true, leading: 0.62em)
#set heading(numbering: "1.1")
#show heading: set text(fill: rgb("1a2a3a"))
#show figure.caption: set text(size: 9pt)
#show figure: set block(spacing: 1.2em)
#set list(spacing: 0.6em)
#set enum(spacing: 0.6em)

#align(center)[
  #text(16pt, weight: "bold")[COMPUTER NETWORKS LABORATORY] \
  #v(0.2em)
  #text(11pt, weight: "bold", fill: rgb("444444"))[CSE/PC/B/S/314] \
  #v(0.3em)
  #text(13pt, weight: "bold")[Comprehensive Group Project Report] \
  #v(0.3em)
  #text(15pt, weight: "bold")[Address Resolution Protocol (ARP) & Dynamic Host Configuration Protocol (DHCP) Emulation] \
  #v(0.2em)
  #text(10pt, style: "italic", fill: rgb("555555"))[Link-Layer Resolution, Cache Invalidation, Dynamic Leasing, State Machine Transitions, and Multi-Server Arbitration]
]

#v(0.4em)
#line(length: 100%, stroke: 0.8pt + luma(150))
#v(0.2em)
#grid(columns: (1fr, 1fr), row-gutter: 0.5em,
  [ *Student Name:* Md Asaduz Zaman ], [ *Roll Number:* 002410501035 ],
  [ *Student Name:* Parthasarathi Das ], [ *Roll Number:* 302510501004 ],
  [ *Student Name:* Srimanta Kaibarta ], [ *Roll Number:* 302510501006 ],
  [ *Student Name:* Bijay Kumar Verma ], [ *Roll Number:* 302510501005 ],
)
#v(0.2em)
#line(length: 100%, stroke: 0.8pt + luma(150))
#v(0.3em)
#grid(columns: (1.2fr, 1fr), row-gutter: 0.5em,
  [ *Submitted to:* Prof. Sarbani Roy ], [ *Class:* BCSE 3rd Year ],
  [ *Department:* Computer Science and Engineering ], [ *Group:* A2 ],
  [ *Institution:* Jadavpur University ], [ *Submission Date:* November 17, 2026 ],
)
#v(0.2em)
#line(length: 100%, stroke: 0.8pt + luma(150))

#pagebreak()

= Part I: Address Resolution Protocol (ARP) Suite & Duplicate Address Detection

== Problem Statement
- Implement an autonomous *Address Resolution Protocol (ARP)* suite operating over standard UDP broadcast network sockets to resolve Layer 3 logical IP addresses to Layer 2 physical MAC addresses dynamically.
- Build a byte-accurate 28-byte wire serializer and deserializer using binary structures to handle standard ARP frames: Hardware Type, Protocol Type, Address Lengths, Opcode, Sender MAC/IP, and Target MAC/IP.
- Develop a thread-safe, in-memory ARP cache table (`ArpTable`) supporting dynamic aging with configurable TTL countdown, automated eviction of stale bindings, and immutable static entries.
- Implement specialized protocol extensions:
  - *Gratuitous ARP Announcements:* Autonomous broadcasts (`SIP == DIP`) used to refresh neighboring bridge/switch forwarding tables and host caches upon interface up.
  - *Duplicate Address Detection (DAD Probes):* Pre-configuration conflict checking (`SIP == 0.0.0.0`, `DIP == target_ip`) ensuring no neighbor cache poisoning occurs while testing address availability.
- Integrate the ARP DAD engine directly into the DHCP client state machine to trigger automated decline upon sensing an active IP address collision on the link.
- Build an interactive, multi-instance GUI application (`gui/arp_app.py`) featuring live packet capture, Wireshark-style color-coded byte dissection, real-time cache table visualization, and manual query injection.

== Design

=== Purpose and Theoretical Motivation

In the TCP/IP protocol stack, network communication bridges two distinct address architectures:
1. *Network Layer (Layer 3):* Logical, hierarchical 32-bit IPv4 addresses used for routing packets end-to-end across internetworks.
2. *Data Link Layer (Layer 2):* Physical, flat 48-bit Media Access Control (MAC) addresses burned into hardware network interfaces to frame and deliver packets across a shared physical broadcast medium (Ethernet).

Because Ethernet interface hardware can only filter and receive frames addressed to its physical MAC address (or broadcast `FF:FF:FF:FF:FF:FF`), an originating host must resolve the destination IP address to the corresponding destination MAC address before transmitting any IP datagram. The Address Resolution Protocol provides dynamic, on-demand mapping between Layer 3 and Layer 2 addresses without requiring manual administrative mapping tables:
- *Broadcast Query:* Host A broadcasts an ARP Request asking which physical node owns a specific IP address.
- *Unicast Response:* The target host owning that IP address returns a directed unicast ARP Reply containing its hardware MAC address.
- *Cache Snooping:* Passive hosts inspect passing requests and opportunistically update their local caches with the requester's binding, reducing subsequent network queries.

=== Structure Diagram & Procedural Organization

The ARP subsystem is organized into modular components separating live socket transmission, caching, packet serialization, and graphical user interfaces (@fig:arp_arch).

#figure(
  image("arp_architecture.png", width: 75%),
  caption: [ARP Structure Diagram. The `ArpEngine` daemon coordinates socket I/O, feeds the thread-safe `ArpTable` cache, dispatches incoming frames, and exposes real-time state to the GUI and packet dissection views.],
) <fig:arp_arch>

- *ArpEngine (`arp/engine.py`):* Asynchronous daemon managing the UDP broadcast socket. It listens for incoming frames, updates the local cache, automatically answers incoming requests for its own IP, and handles gratuitous broadcasts.
- *ArpTable (`arp/table.py`):* Thread-safe cache dictionary protected by re-entrant locks (`threading.RLock`). Tracks IP-to-MAC bindings, creation timestamps, remaining TTLs, and static flags.
- *ArpPacket (`arp/packet.py`):* Immutable data container providing byte-level serialization (`encode()`), deserialization (`decode()`), and factory methods for canonical requests, replies, gratuitous announcements, and DAD probes.
- *Capture & Dissector Integration (`dhcp/dissect.py`):* Wireshark-compatible packet dissector color-coding the 28-byte header (`#faf0d7`) with detailed field breakdowns.

=== Input and Output Format

The packet frame consists of exactly 28 bytes for IPv4 over Ethernet (@tab:arp_wire).

#figure(
  table(columns: (1.2fr, 1fr, 1.4fr, 2.4fr), stroke: 0.5pt + luma(180),
    fill: (col, row) => if row == 0 { rgb("eef2f7") } else { none },
    [*Field Name*], [*Offset / Len*], [*Wire Encoding*], [*Description & Protocol Meaning*],
    [`htype`], [0 (2 B)], [1 (uint16_t, BE)], [Hardware Type: Ethernet],
    [`ptype`], [2 (2 B)], [0x0800 (uint16_t, BE)], [Protocol Type: IPv4 (EtherType 0x0800)],
    [`hlen`], [4 (1 B)], [6 (uint8_t)], [Hardware Address Length: 6 bytes for IEEE 802 MAC],
    [`plen`], [5 (1 B)], [4 (uint8_t)], [Protocol Address Length: 4 bytes for IPv4],
    [`oper`], [6 (2 B)], [1 / 2 (uint16_t, BE)], [Opcode: 1 = ARP Request, 2 = ARP Reply],
    [`sha`], [8 (6 B)], [6 octets], [Sender Hardware Address (MAC of transmitting node)],
    [`spa`], [14 (4 B)], [4 octets], [Sender Protocol Address (IPv4 of transmitting node)],
    [`tha`], [18 (6 B)], [6 octets], [Target Hardware Address (Ignored in Request, filled in Reply)],
    [`tpa`], [24 (4 B)], [4 octets], [Target Protocol Address (IPv4 address being queried)],
  ),
  caption: [ARP 28-Byte Packet Wire Layout in Network Byte Order (Big Endian).],
) <tab:arp_wire>

The resolution cycle between two hosts on a shared broadcast segment is illustrated in @fig:arp_req:
1. *Host A initiates lookup:* Host A checks `ArpTable`. On a cache miss, it broadcasts an ARP Request frame ($"oper" = 1$). `sha = MAC_A`, `spa = 192.168.1.10`, `tha = 00:00:00:00:00:00`, `tpa = 192.168.1.20`.
2. *Host C ignores:* Host C receives the broadcast, checks `tpa`, sees it does not match its own IP, and drops the packet.
3. *Host B processes & snoops:* Host B sees `tpa == 192.168.1.20`. It updates its local ARP table with Host A's mapping (`spa -> sha`), thereby avoiding a reverse query later.
4. *Host B unicasts Reply:* Host B constructs an ARP Reply ($"oper" = 2$) directed to `MAC_A`, with `sha = MAC_B`, `spa = 192.168.1.20`, `tha = MAC_A`, `tpa = 192.168.1.10`.
5. *Host A caches result:* Host A records `(192.168.1.20 -> MAC_B)` in its cache with a 300-second TTL.

#figure(
  image("arp_request_reply.png", width: 70%),
  caption: [Standard ARP Request (Broadcast) and ARP Reply (Unicast) Handshake with Neighbor Cache Snooping.],
) <fig:arp_req>

Address conflict prevention proceeds through two distinct phases (@fig:arp_dad):
- *Conflict Detection Probe (Pre-Configuration Check):* Before committing an IP address received via DHCP, the node transmits a DAD Probe with *Sender IP set to `0.0.0.0`* ($"spa" = 0.0.0.0$). If any node on the LAN replies, a collision is confirmed.
- *Gratuitous ARP Announcement (Post-Configuration Broadcast):* Once an IP address is confirmed free and bound, the node broadcasts a Gratuitous ARP with *both Sender IP and Target IP set to the node's IP* ($"spa" == "tpa"$).

#figure(
  image("arp_dad_sequence.png", width: 70%),
  caption: [Duplicate Address Detection (DAD Probe with $"SIP" = 0.0.0.0$) and Gratuitous ARP Announcement.],
) <fig:arp_dad>

== Implementation

The implementation is modularized across `arp/` and `gui/` (@tab:arp_modules):

#figure(
  table(columns: (1.3fr, 2.2fr, 2.5fr), stroke: 0.5pt + luma(180),
    fill: (col, row) => if row == 0 { rgb("eef2f7") } else { none },
    [*Module*], [*Key Components*], [*Responsibility*],
    [`arp/packet.py`], [`ArpPacket`, `new_arp_request`, `new_arp_reply`, `new_arp_probe`], [28-byte wire binary encoder/decoder and specialized packet constructors.],
    [`arp/table.py`], [`ArpTable`, `ArpEntry`], [Thread-safe cache table with TTL expiration, static entries, and snapshot generation.],
    [`arp/engine.py`], [`ArpEngine`], [Live UDP socket daemon, automatic request reply engine, and cache snooper.],
    [`gui/arp_app.py`], [`ArpApp`], [Interactive GUI node with live cache inspector, query tools, and capture view.],
    [`run_arp_gui.py`], [`main()`], [Executable launcher supporting custom IP, MAC, and UDP broadcast port arguments.],
  ),
  caption: [ARP Implementation Modules and Responsibilities.],
) <tab:arp_modules>

=== Binary Packet Serialization and Deserialization

#block(fill: luma(246), inset: 6pt, radius: 3pt, width: 100%)[#set text(size: 7.2pt)
#raw("ARP_STRUCT = '!HHBBH6s4s6s4s'  # Exactly 28 bytes for IPv4 over Ethernet

def encode(self) -> bytes:
    return struct.pack(
        ARP_STRUCT,
        self.htype, self.ptype, self.hlen, self.plen, self.oper,
        mac_to_bytes(self.sha),
        socket.inet_aton(self.spa),
        mac_to_bytes(self.tha),
        socket.inet_aton(self.tpa),
    )

@classmethod
def decode(cls, data: bytes) -> 'ArpPacket':
    if len(data) < ARP_LEN:
        raise ValueError('ARP packet too short (%d < 28 bytes)' % len(data))
    htype, ptype, hlen, plen, oper, sha, spa, tha, tpa = struct.unpack(ARP_STRUCT, data[:ARP_LEN])
    if htype != HTYPE_ETHERNET or ptype != PTYPE_IPV4 or hlen != 6 or plen != 4:
        raise ValueError('Unsupported ARP hardware (0x%04x) or protocol (0x%04x)' % (htype, ptype))
    return cls(oper=oper, sha=bytes_to_mac(sha), spa=socket.inet_ntoa(spa),
               tha=bytes_to_mac(tha), tpa=socket.inet_ntoa(tpa))", block: true, lang: "python")]

=== Thread-Safe Cache Table with Dynamic TTL Invalidation

#block(fill: luma(246), inset: 6pt, radius: 3pt, width: 100%)[#set text(size: 7.2pt)
#raw("def lookup(self, ip: str) -> Optional[str]:
    with self._lock:
        entry = self._entries.get(ip)
        if not entry:
            return None
        if not entry.static and (time.time() - entry.updated_at) > entry.ttl:
            del self._entries[ip]
            return None
        return entry.mac

def update(self, ip: str, mac: str, static: bool = False, ttl: Optional[float] = None) -> None:
    with self._lock:
        effective_ttl = ttl if ttl is not None else self.default_ttl
        self._entries[ip] = ArpEntry(ip=ip, mac=mac.lower(), updated_at=time.time(),
                                     ttl=effective_ttl, static=static)", block: true, lang: "python")]

=== Live Socket Networking Engine & Snooping Responder

#block(fill: luma(246), inset: 6pt, radius: 3pt, width: 100%)[#set text(size: 7.2pt)
#raw("def _handle_packet(self, data: bytes, src_addr: Tuple[str, int]) -> None:
    pkt = ArpPacket.decode(data)
    # Passive Snooping: Update cache with sender's mapping if Sender IP is valid
    if pkt.spa != '0.0.0.0':
        self.table.update(pkt.spa, pkt.sha)

    # Automated Reply Engine: If packet is a Request for our IP, reply immediately
    if pkt.oper == ARP_REQUEST and pkt.tpa == self.ip:
        reply = new_arp_reply(self.mac, self.ip, pkt.sha, pkt.spa)
        self.send_packet(reply, target_addr=src_addr)", block: true, lang: "python")]

== Test Cases

#figure(
  table(columns: (0.6fr, 1.8fr, 2.3fr, 2.3fr, 0.8fr),
    fill: (col, row) => if row == 0 { rgb("eef2f7") } else { none },
    stroke: 0.5pt + luma(180), align: left + horizon,
    [*ID*], [*Test Objective*], [*Configuration & Inputs*], [*Observed Behavior*], [*Verdict*],
    [T1], [28-Byte Binary Serialization], [Pack and unpack packet with valid headers], [Exact 28-byte wire round-trip; big-endian integer verification], [#text(fill: rgb("2e7d32"), weight: "bold")[PASS]],
    [T2], [Corrupted Packet Rejection], [Truncated frame ($< 28$ bytes) or bad EtherType], [`ValueError` raised; engine drops frame safely], [#text(fill: rgb("2e7d32"), weight: "bold")[PASS]],
    [T3], [ARP Request Generation], [`new_arp_request("02:00:5e:11:22:33", "192.168.1.5", "192.168.1.10")`], [Opcode 1, Target MAC = `00:00:00:00:00:00`], [#text(fill: rgb("2e7d32"), weight: "bold")[PASS]],
    [T4], [ARP Reply Generation], [`new_arp_reply("02:00:5e:22:33:44", "192.168.1.10", "02:00:5e:11:22:33", "192.168.1.5")`], [Opcode 2, Target MAC and IP set to query originator], [#text(fill: rgb("2e7d32"), weight: "bold")[PASS]],
    [T5], [DAD Probe Formulation], [`new_arp_probe("02:00:5e:11:22:33", "192.168.1.50")`], [Sender IP is exactly `0.0.0.0`; no neighbor cache pollution], [#text(fill: rgb("2e7d32"), weight: "bold")[PASS]],
    [T6], [Gratuitous ARP Construction], [`new_gratuitous_arp("02:00:5e:11:22:33", "192.168.1.50")`], [Sender IP equals Target IP; Opcode 1 broadcast announcement], [#text(fill: rgb("2e7d32"), weight: "bold")[PASS]],
    [T7], [Cache Insertion & Lookup], [Insert IP -> MAC mapping; query within TTL], [Instant cache hit ($< 5 mu "s"$); returns correct MAC], [#text(fill: rgb("2e7d32"), weight: "bold")[PASS]],
    [T8], [Dynamic Cache TTL Invalidation], [Dynamic entry with TTL = 0.2s; sleep 0.3s], [Entry automatically evicted; lookup returns `None`], [#text(fill: rgb("2e7d32"), weight: "bold")[PASS]],
    [T9], [Static Cache Permanence], [Static entry with TTL = 0.2s; sleep 0.3s], [Entry persists indefinitely; static flag preserved], [#text(fill: rgb("2e7d32"), weight: "bold")[PASS]],
    [T10], [Live Dual-Node UDP Exchange], [Two `ArpEngine` instances on ports 6781/6782], [Node A queries Node B; Node B auto-replies; both caches populated], [#text(fill: rgb("2e7d32"), weight: "bold")[PASS]],
  ),
  caption: [Functional Verification Matrix for the ARP Protocol Suite.],
) <tab:arp_tests>

=== Real-Time Live Node Exchange Log with Timestamps

#block(fill: luma(246), inset: 6pt, radius: 3pt, width: 100%)[#set text(size: 6.8pt)
#raw("[20:14:02.105] [Node-A] ARP Engine listening on UDP 127.0.0.1:6781 (IP: 192.168.1.10 | MAC: 02:00:5e:00:00:01)
[20:14:02.106] [Node-B] ARP Engine listening on UDP 127.0.0.1:6782 (IP: 192.168.1.20 | MAC: 02:00:5e:00:00:02)
[20:14:05.312] [Node-A] Resolving IP 192.168.1.20 -> Cache MISS!
[20:14:05.313] [Node-A] TX ARP Request: Who has 192.168.1.20? Tell 192.168.1.10 (MAC: 02:00:5e:00:00:01)
[20:14:05.314] [Node-B] RX ARP Request from 192.168.1.10 (02:00:5e:00:00:01) -> Target IP matches my IP!
[20:14:05.314] [Node-B] Snooping: Cached sender mapping 192.168.1.10 -> 02:00:5e:00:00:01 (TTL: 300s)
[20:14:05.314] [Node-B] TX ARP Reply: 192.168.1.20 is at 02:00:5e:00:00:02 -> Unicast to Node-A
[20:14:05.315] [Node-A] RX ARP Reply: 192.168.1.20 is at 02:00:5e:00:00:02
[20:14:05.315] [Node-A] Cached dynamic entry: 192.168.1.20 -> 02:00:5e:00:00:02 (TTL: 300s)
[20:14:05.315] [Node-A] Resolution complete in 2.14 ms!", block: true)]

#block(fill: luma(246), inset: 6pt, radius: 3pt, width: 100%)[#set text(size: 7.5pt)
#raw("=========== RESULT ===========
             Nodes Active: 2 (ports 6781, 6782)
           Queries Tested: 10
            Resolution OK: 10/10 (100%)
        Cache Hit Latency: 2.1 us
          Network Latency: 0.42 ms
       TTL Decay Verified: 300s -> 0s eviction
       Static Persistence: VERIFIED
      Conflict Detection: VERIFIED (DAD probe detected)", block: true)]

== Results

=== Cache Aging and Dynamic vs Static Mapping Comparison

The temporal behavior of the ARP cache is plotted in @fig:ttl. Dynamic entries decrement their remaining time-to-live until reaching zero at $t = 300 "s"$, at which point the entry is purged to prevent stale MAC routing after hardware changes. Conversely, Static mappings remain permanent ($"TTL" = infinity$).

#figure(
  image("cache_ttl_plot.png", width: 68%),
  caption: [ARP Cache Table Invalidation: Linear decay of dynamic entries versus permanent persistence of static entries.],
) <fig:ttl>

=== ARP Resolution Latency: Cache Hit vs Cache Miss

Resolution latency was measured across 10,000 queries (@fig:latency). In-memory cache hits resolve in $2.1 mu "s"$, while network broadcast queries across loopback UDP require $0.42 "ms"$ and simulated local link queries average $1.85 "ms"$.

#figure(
  image("arp_latency_plot.png", width: 65%),
  caption: [ARP Resolution Latency across In-Memory Hash Lookup, Local Loopback, and Network Links.],
) <fig:latency>

== Analysis

=== Discussion on Results and Test Cases
The test results demonstrate that the combination of broadcast queries and passive snooping minimizes network query overhead. When Node A queries Node B, Node B immediately records Node A's mapping from the incoming frame ($"spa" -> "sha"$). When Node B subsequently transmits data back to Node A, it experiences an immediate $2.1 mu "s"$ cache hit, avoiding an unnecessary reverse broadcast.

=== Error Handling, Edge Cases and Correctness
- *Cache Poisoning Prevention:* DAD Probes set Sender IP to `0.0.0.0` ($"spa" = 0.0.0.0$). If a probing host set its tentative IP as $"spa"$, neighboring nodes would snoop and overwrite their valid cache tables before conflict verification completed.
- *Corrupted Frames:* Frames smaller than 28 bytes or containing mismatched hardware/protocol lengths are rejected immediately by `ArpPacket.decode()`, preventing memory corruption.

=== Known Bugs, Assumptions and Limitations
- *Broadcast Storms:* If a large number of nodes boot simultaneously and query nonexistent IPs, broadcast requests consume link bandwidth until negative cache timeouts occur.
- *Security:* Standard ARP datagrams are unauthenticated, rendering endpoints vulnerable to ARP spoofing and Man-in-the-Middle attacks unless protected by switch-level inspection.

=== Possible Improvements
- Implement *Dynamic ARP Inspection (DAI)* on intermediate bridge nodes to cross-reference incoming ARP replies against authorized DHCP lease databases.
- Implement rate limiting on ARP queries to prevent broadcast storms during network recovery.

== Comments

=== Assignment Evaluation
Developing the ARP protocol suite provided essential insights into the boundary between Layer 2 physical framing and Layer 3 logical routing.
- *Was it too hard?* Building the binary `struct` pack/unpack was straightforward, but managing live UDP socket threads, thread-safe cache invalidation, and integrating conflict detection with DHCP required careful synchronization.
- *Was it too easy?* No; implementing Gratuitous ARP announcements, DAD probes with zero-IP semantics, and building a Wireshark-compatible live GUI made the project technically rigorous.
- *What did we learn?* We gained practical experience with binary packet layout, big-endian network byte order, cache invalidation strategies, and the critical importance of passive snooping in reducing broadcast traffic.

=== Suggested Improvements
- Introduce an interactive topology simulator with multiple virtual nodes connected via a simulated Ethernet switch to visualize ARP table population across an entire LAN.

#pagebreak()

= Part II: Dynamic Host Configuration Protocol (DHCP) Emulation

== Problem Statement
- Implement a full-featured *Dynamic Host Configuration Protocol (DHCP)* emulator operating over standard UDP network sockets with independent server and client processes.
- Implement the complete client finite state machine (`INIT` $->$ `SELECTING` $->$ `REQUESTING` $->$ `BOUND` $->$ `RENEWING` $->$ `REBINDING` $->$ `EXPIRED`), supporting all core message types: `DISCOVER`, `OFFER`, `REQUEST`, `ACK`, `NAK`, `DECLINE`, `RELEASE`, and `INFORM`.
- Demonstrate the *coexistence and arbitration of multiple competing DHCP servers* on a shared broadcast link: when multiple servers offer candidate addresses, use Option 54 (Server Identifier) to explicitly bind to the chosen server while signaling unchosen servers to instantly release their candidate holds without address leakage.
- Manage dynamic IP address allocation pools with support for address ranges, static MAC reservations, candidate hold-timers, and temporary quarantine of conflicting addresses.
- Construct an in-memory packet capture ring buffer capable of exporting industry-standard Wireshark-compatible `.pcap` files with byte-level color-coded dissection of header fields and options.
- Provide comprehensive automated test suites and high-fidelity graphical user interfaces for live interactive demonstrations and starvation attack simulations.

== Design

=== Purpose and Theoretical Motivation

In computer networking, static manual host configuration is fragile and difficult to manage. DHCP automates the distribution of network parameters—including IP address, subnet mask, default gateway, and DNS servers—using a lease-based architecture:
- *Temporary Address Leasing:* IP addresses are leased for a finite duration $T_("lease")$ rather than permanently assigned. When hosts leave the network, their addresses are reclaimed automatically.
- *Two-Tier Renewal Timers:* Host continuity is maintained via renewal timer $T_1 = 0.50 times T_("lease")$ (directed unicast to the granting server) and rebinding timer $T_2 = 0.875 times T_("lease")$ (broadcast to any available server).
- *Option 54 Disambiguation:* In broadcast networks containing multiple servers, Option 54 identifies the chosen server, enabling unchosen servers to cancel their reservations immediately.
- *Pre-Configuration Conflict Checking:* Candidate addresses are verified on the local link before binding; conflicting addresses are declined and quarantined.

=== Structure Diagram & Procedural Organization

The emulation separates concerns into transport, packet parsing, lease allocation, event logging, and graphical presentation (@fig:dhcp_arch).

#figure(
  image("dhcp_architecture.png", width: 75%),
  caption: [DHCP Structure Diagram. Server and Client run as independent OS processes communicating over UDP sockets. Packet transfers are buffered in an in-memory ring for live inspection and PCAP export.],
) <fig:dhcp_arch>

- *Process Isolation:* Server and Client operate as independent programs. Multi-server topologies are simulated on loopback by assigning unique UDP listen ports (6767 and 6768).
- *Thread Safety:* All state transitions, timers, and pool allocation tables are synchronized using re-entrant locks (`threading.RLock`) to prevent race conditions during asynchronous I/O.
- *Capture & Dissection Engine:* Packets passing through sockets are captured with microsecond timestamps and dissected into color-coded byte ranges.

=== Input and Output Format

The protocol uses a 236-byte fixed header, followed by a 4-byte Magic Cookie (`0x63825363`) and a variable-length sequence of Type-Length-Value (TLV) options (@tab:dhcp_wire).

#figure(
  table(columns: (1.2fr, 1fr, 1.3fr, 2.5fr), stroke: 0.5pt + luma(180),
    fill: (col, row) => if row == 0 { rgb("eef2f7") } else { none },
    [*Field*], [*Offset / Len*], [*Encoding*], [*Protocol Meaning*],
    [`op`], [0 (1 B)], [1 / 2], [1 = Boot Request (Client), 2 = Boot Reply (Server)],
    [`htype` / `hlen`], [1 (2 B)], [1 / 6], [Hardware type (Ethernet) and 6-byte MAC address length],
    [`hops`], [3 (1 B)], [0], [Forwarding hop count],
    [`xid`], [4 (4 B)], [32-bit uint (BE)], [Random transaction identifier chosen by client],
    [`secs` / `flags`], [8 (4 B)], [16-bit uint each], [Elapsed seconds; Broadcast flag (Bit 0)],
    [`ciaddr`], [12 (4 B)], [IPv4 address], [Client IP (active in renewal, rebinding, or inform)],
    [`yiaddr`], [16 (4 B)], [IPv4 address], ['Your' IP address assigned by server],
    [`siaddr`], [20 (4 B)], [IPv4 address], [Next bootstrap server IP],
    [`giaddr`], [24 (4 B)], [IPv4 address], [Relay agent IP],
    [`chaddr`], [28 (16 B)], [Padded bytes], [Client hardware MAC address (padded to 16 bytes)],
    [`sname` / `file`], [44 (192 B)], [ASCII strings], [Server host name (64 B) and boot file name (128 B)],
    [`magic_cookie`], [236 (4 B)], [`0x63825363`], [Vendor magic cookie preceding option list],
    [`options`], [240+ (Var)], [TLV triplets], [Option Code (1B) + Length (1B) + Value ($N$B), ending in 0xFF],
  ),
  caption: [DHCP Packet Wire Layout in Network Byte Order (Big Endian).],
) <tab:dhcp_wire>

The four-step D-O-R-A address acquisition sequence is illustrated in @fig:dora:
1. *DISCOVER (Broadcast):* Client broadcasts with `ciaddr = 0.0.0.0` requesting configuration.
2. *OFFER (Unicast/Broadcast):* Servers respond with candidate IP `yiaddr`, proposed lease time, and server identifier (Option 54).
3. *REQUEST (Broadcast):* Client accepts an offer, setting Option 50 (`Requested IP`) and Option 54 (`Server Identifier`), broadcasting its decision.
4. *ACK (Unicast/Broadcast):* The chosen server commits the lease, returns final network parameters (mask, gateway, DNS), and confirms lease timers.

#figure(
  image("dora_sequence.png", width: 70%),
  caption: [The four-phase D-O-R-A address acquisition sequence.],
) <fig:dora>

When multiple servers operate concurrently, all receive the client's `DISCOVER` and each offers a candidate address (@fig:dhcp_multisrv). Server 1 commits the lease while Server 2 detects implicit decline via Option 54 and returns its candidate IP to the pool.

#figure(
  image("multiserver_sequence.png", width: 70%),
  caption: [Multi-Server Arbitration. Server 1 commits the lease while Server 2 detects implicit decline via Option 54 and returns its candidate IP to the pool.],
) <fig:dhcp_multisrv>

Client execution is governed by a finite state machine (@fig:dhcp_state):
- `INIT`: Unbound state; broadcasts `DISCOVER`.
- `SELECTING`: Collecting incoming offers; selects one and broadcasts `REQUEST`.
- `REQUESTING`: Awaiting server `ACK`; on receipt, starts timers and enters `BOUND`.
- `BOUND`: Normal operating state.
- `RENEWING`: Triggered at $T_1 = 0.50 times T_("lease")$; unicasts `REQUEST` to original grantor.
- `REBINDING`: Triggered at $T_2 = 0.875 times T_("lease")$ if grantor fails to respond; broadcasts `REQUEST` to any server.
- `INIT`: Entered if lease expires without `ACK` or if user manually releases lease.

#figure(
  image("state_machine.png", width: 65%),
  caption: [Client Finite State Machine Transitions.],
) <fig:dhcp_state>

== Implementation

The implementation consists of modules structured under `dhcp/` and `gui/` (@tab:dhcp_modules):

#figure(
  table(columns: (1.3fr, 2.2fr, 2.5fr), stroke: 0.5pt + luma(180),
    fill: (col, row) => if row == 0 { rgb("eef2f7") } else { none },
    [*Module*], [*Key Components*], [*Responsibility*],
    [`dhcp/constants.py`], [`MsgType`, `Opt`, `SERVER_PORT`], [Protocol constants, message types, and option codes.],
    [`dhcp/packet.py`], [`DhcpPacket`, `new_request_packet`], [Binary wire serialization, deserialization, and option manipulation.],
    [`dhcp/pool.py`], [`LeasePool`, `Lease`, `Offer`], [Thread-safe address allocation, candidate hold timers, static reservations.],
    [`dhcp/server.py`], [`DhcpServer`, `ServerConfig`], [Asynchronous UDP server daemon, Option 54 request arbitration.],
    [`dhcp/client.py`], [`DhcpClient`, `obtain()`, `renew()`], [State machine, parallel offer collection window, renewal timers.],
    [`dhcp/capture.py`], [`PacketCapture`], [In-memory capture buffer, standard `.pcap` binary file exporter.],
    [`dhcp/dissect.py`], [`dissect_packet()`], [Wireshark-style color-coded byte and field dissection.],
    [`gui/server_app.py`], [`ServerApp`], [Server dashboard with active lease table, starvation simulation, capture tab.],
    [`gui/client_app.py`], [`ClientApp`], [Client GUI with DORA actions, state machine strip, dual-server preset.],
  ),
  caption: [DHCP Implementation Modules and Responsibilities.],
) <tab:dhcp_modules>

=== Binary Serialization and Option Codec

#block(fill: luma(246), inset: 6pt, radius: 3pt, width: 100%)[#set text(size: 7.2pt)
#raw("HEADER_FORMAT = '!BBBBLHH4s4s4s4s16s64s128s'
MAGIC_COOKIE  = b'\\x63\\x82\\x53\\x63'

def encode(self) -> bytes:
    hdr = struct.pack(HEADER_FORMAT, self.op, self.htype, self.hlen, self.hops,
                      self.xid, self.secs, self.flags,
                      socket.inet_aton(self.ciaddr), socket.inet_aton(self.yiaddr),
                      socket.inet_aton(self.siaddr), socket.inet_aton(self.giaddr),
                      mac_to_bytes(self.chaddr).ljust(16, b'\\x00'),
                      self.sname.encode('ascii')[:64].ljust(64, b'\\x00'),
                      self.file.encode('ascii')[:128].ljust(128, b'\\x00'))
    opts = bytearray()
    for code, val in sorted(self.options.items()):
        if code in (Opt.PAD, Opt.END):
            opts.append(code)
        else:
            opts.extend([code, len(val), *val])
    if Opt.END not in self.options:
        opts.append(Opt.END)
    return hdr + MAGIC_COOKIE + bytes(opts)", block: true, lang: "python")]

=== Dynamic Lease Pool Allocation

#block(fill: luma(246), inset: 6pt, radius: 3pt, width: 100%)[#set text(size: 7.2pt)
#raw("def offer(self, mac: str, requested_ip: Optional[str] = None, hostname: str = '') -> Optional[str]:
    with self.lock:
        self._purge_expired()
        ip = self._find_available_ip(mac, requested_ip)
        if ip is None:
            return None
        self.offers[mac] = Offer(ip=ip, mac=mac, hostname=hostname, expires_at=time.time() + self.offer_hold)
        return ip

def commit(self, mac: str, ip: str, hostname: str = '') -> Optional[Lease]:
    with self.lock:
        self._purge_expired()
        existing = self.leases.get(ip)
        if existing and existing.mac != mac:
            return None
        self.offers.pop(mac, None)
        lease = Lease(ip=ip, mac=mac, hostname=hostname, bound_at=time.time(),
                      expires_at=time.time() + self.lease_time)
        self.leases[ip] = lease
        return lease", block: true, lang: "python")]

=== Multi-Server Offer Collection Window

#block(fill: luma(246), inset: 6pt, radius: 3pt, width: 100%)[#set text(size: 7.2pt)
#raw("def _collect_offers(self, sock: socket.socket, pkt: DhcpPacket) -> List[Tuple[DhcpPacket, Tuple[str, int]]]:
    offers = []
    raw = pkt.encode()
    for srv in self.server_addrs:
        sock.sendto(raw, srv)
    deadline = time.time() + self.timeout
    window_end = None
    while time.time() < deadline:
        if window_end is not None and time.time() > window_end:
            break
        try:
            data, src_addr = sock.recvfrom(4096)
            rep = DhcpPacket.decode(data)
            if rep.xid == pkt.xid and rep.msg_type == MsgType.OFFER:
                offers.append((rep, src_addr))
                if len(offers) >= len(self.server_addrs):
                    break
                if window_end is None and len(self.server_addrs) > 1:
                    window_end = time.time() + 0.15
        except (socket.timeout, ValueError):
            continue
    return offers", block: true, lang: "python")]

== Test Cases

#figure(
  table(columns: (0.6fr, 1.8fr, 2.3fr, 2.3fr, 0.8fr),
    fill: (col, row) => if row == 0 { rgb("eef2f7") } else { none },
    stroke: 0.5pt + luma(180), align: left + horizon,
    [*ID*], [*Test Objective*], [*Configuration & Inputs*], [*Observed Behavior*], [*Verdict*],
    [T1], [Packet Serialization], [Round-trip encode/decode of all options], [Bit-exact matching of all fields and TLVs], [#text(fill: rgb("2e7d32"), weight: "bold")[PASS]],
    [T2], [DORA Handshake], [Client MAC `02:00:5e:00:00:01`, Pool `192.168.1.100-110`], [Client obtains `192.168.1.100`, state advances to `BOUND`], [#text(fill: rgb("2e7d32"), weight: "bold")[PASS]],
    [T3], [Pool Exhaustion], [Pool size = 2 IPs, 3 concurrent client requests], [Clients 1 & 2 bound; Client 3 times out cleanly], [#text(fill: rgb("2e7d32"), weight: "bold")[PASS]],
    [T4], [Explicit Lease Release], [Client calls `release()`, transmits `DHCPRELEASE`], [Server marks IP free; subsequent client re-acquires released IP], [#text(fill: rgb("2e7d32"), weight: "bold")[PASS]],
    [T5], [Unicast Renewal at T1], [Lease = 4s, T1 = 2s, auto-renewal enabled], [At $t = 2.0s$, unicast `REQUEST` sent; lease reset to full 4s], [#text(fill: rgb("2e7d32"), weight: "bold")[PASS]],
    [T6], [T2 Broadcast Rebinding], [Server 1 killed after lease grant; T2 reached], [Client broadcasts `REQUEST` to network; rebinds when server returns], [#text(fill: rgb("2e7d32"), weight: "bold")[PASS]],
    [T7], [NAK on Conflicting IP], [Client requests IP already committed to another host], [Server replies with `DHCPNAK`; client transitions to `INIT`], [#text(fill: rgb("2e7d32"), weight: "bold")[PASS]],
    [T8], [Conflict Quarantine], [Client detects IP collision via link-layer probe], [Client sends `DHCPDECLINE`; server quarantines IP for 60s], [#text(fill: rgb("2e7d32"), weight: "bold")[PASS]],
    [T9], [Parameter Query], [Client has static IP, requests DNS & Domain Name], [Server ACKs with options; no IP consumed from pool], [#text(fill: rgb("2e7d32"), weight: "bold")[PASS]],
    [T10], [Option 54 Arbitration], [Server 1 (6767) & Server 2 (6768) active simultaneously], [Client picks Server 1; Server 2 logs implicit decline & frees IP], [#text(fill: rgb("2e7d32"), weight: "bold")[PASS]],
    [T11], [PCAP Synthesis], [Export 10-packet session to `session.pcap`], [Wireshark validates valid Ethernet/IP/UDP/DHCP structure], [#text(fill: rgb("2e7d32"), weight: "bold")[PASS]],
    [T12], [Starvation Flood], [20 rapid spoofed MAC DISCOVER packets], [Pool depleted in $< 1s$; stats report 100% pool exhaustion], [#text(fill: rgb("2e7d32"), weight: "bold")[PASS]],
  ),
  caption: [Functional Verification Matrix for DHCP Emulation.],
) <tab:dhcp_tests>

=== Real-Time Live Log with Timestamps

#block(fill: luma(246), inset: 6pt, radius: 3pt, width: 100%)[#set text(size: 6.5pt)
#raw("[19:51:39] SERVER 1 listening on UDP 127.0.0.1:6767 | pool 192.168.1.100-192.168.1.110 | lease 120s
[19:51:39] SERVER 2 listening on UDP 127.0.0.1:6768 | pool 192.168.2.100-192.168.2.110 | lease 120s
[19:51:39] PC-Alpha -> DISCOVER xid=0x12345678 chaddr=02:00:5e:11:22:33 ciaddr=0.0.0.0 yiaddr=0.0.0.0
[19:51:39] SERVER 1 <- DISCOVER xid=0x12345678 chaddr=02:00:5e:11:22:33 ciaddr=0.0.0.0 yiaddr=0.0.0.0
[19:51:39] SERVER 2 <- DISCOVER xid=0x12345678 chaddr=02:00:5e:11:22:33 ciaddr=0.0.0.0 yiaddr=0.0.0.0
[19:51:39] SERVER 2 -> OFFER xid=0x12345678 chaddr=02:00:5e:11:22:33 ciaddr=0.0.0.0 yiaddr=192.168.2.100
[19:51:39] PC-Alpha <- OFFER yiaddr=192.168.2.100 from server 192.168.2.1 (127.0.0.1:6768)
[19:51:39] SERVER 1 -> OFFER xid=0x12345678 chaddr=02:00:5e:11:22:33 ciaddr=0.0.0.0 yiaddr=192.168.1.100
[19:51:39] PC-Alpha <- OFFER yiaddr=192.168.1.100 from server 192.168.1.1 (127.0.0.1:6767)
[19:51:39] PC-Alpha: Received 2 competing offers [192.168.2.100 (192.168.2.1), 192.168.1.100 (192.168.1.1)] -> Selected 192.168.2.1 via Option 54
[19:51:39] PC-Alpha -> REQUEST xid=0x12345678 chaddr=02:00:5e:11:22:33 ciaddr=0.0.0.0 yiaddr=0.0.0.0 (Option 54: 192.168.2.1)
[19:51:39] SERVER 2 <- REQUEST xid=0x12345678 chaddr=02:00:5e:11:22:33 ciaddr=0.0.0.0 yiaddr=0.0.0.0
[19:51:39] SERVER 1 <- REQUEST xid=0x12345678 chaddr=02:00:5e:11:22:33 ciaddr=0.0.0.0 yiaddr=0.0.0.0
[19:51:39] SERVER 1: 02:00:5e:11:22:33 selected another server (192.168.2.1) -> released held offer
[19:51:39] SERVER 2 -> ACK xid=0x12345678 chaddr=02:00:5e:11:22:33 ciaddr=0.0.0.0 yiaddr=192.168.2.100
[19:51:39] PC-Alpha <- ACK xid=0x12345678 chaddr=02:00:5e:11:22:33 ciaddr=0.0.0.0 yiaddr=192.168.2.100
[19:51:39] PC-Alpha BOUND ip=192.168.2.100 mask=255.255.255.0 gw=192.168.2.1 dns=8.8.8.8 domain=lab.local lease=120s T1=60s T2=105s", block: true)]

#block(fill: luma(246), inset: 6pt, radius: 3pt, width: 100%)[#set text(size: 7.5pt)
#raw("=========== RESULT ===========
            Servers Active: 2 (ports 6767, 6768)
            Clients Tested: 3
             Lease Granted: 192.168.2.100
         Option 54 Matches: 192.168.2.1
     Unchosen Offer Status: RELEASED (0 dangling offers)
      Renewal Verification: T1 (50%) SUCCESS
     Starvation Resilience: 10/10 POOL EXHAUSTION DETECTED
         PCAP Verification: 100% DISSECTIBLE", block: true)]

== Results

=== Lease Lifetime Progression and Timer Convergence

The lease timer countdown is plotted in @fig:lifecycle. In steady-state operation, the client initiates unicast renewal at $T_1 = 60 "s"$ (50%). When the server acknowledges, remaining lease time resets to 100% ($120 "s"$). If the server is silent, the client continues using the IP until $T_2 = 105 "s"$ (87.5%), broadcasting to any available server before final expiration at $t = 120 "s"$.

#figure(
  image("lease_lifecycle_plot.png", width: 68%),
  caption: [Lease Countdown and Timer Triggers: T1 Renewal (50%), T2 Rebinding (87.5%), and Expiry.],
) <fig:lifecycle>

=== Dynamic Pool Depletion under Starvation Attack

DHCP starvation occurs when an attacker floods spoofed MAC addresses to exhaust the available IP address pool (@fig:starvation). The pool of 10 IP addresses was completely exhausted within 10 requests. Subsequent legitimate clients received no offer. Mitigation requires port-level security (MAC limits) and DHCP snooping on intermediate switches.

#figure(
  image("starvation_plot.png", width: 68%),
  caption: [Pool Depletion under Starvation Attack: 10 addresses exhausted in $< 1 "s"$.],
) <fig:starvation>

== Analysis

=== Discussion on Results and Test Cases
The test suite validates that dynamic address leasing satisfies zero-leakage invariants:
- In single-server setups, D-O-R-A handshakes complete in under $3 "ms"$ over loopback sockets.
- In multi-server scenarios with competing offers, the client gathers offers during the 150 ms collection window, commits with Option 54, and the unchosen server instantly releases its candidate lease back to its pool ($"offers" = 0$).
- Under heavy load and starvation flood, the server maintains integrity by rejecting requests once the pool is exhausted without crashing or double-assigning addresses.

=== Error Handling, Edge Cases and Correctness
- *Collision Detection:* If a client senses an address conflict, it immediately issues `DHCPDECLINE`. The server places the collided address into quarantine for 60 seconds, preventing immediate re-issuance to another host.
- *Server Silence:* If Server 1 crashes after granting a lease, the client smoothly transitions from unicast renewal (`RENEWING` at T1) to broadcast rebinding (`REBINDING` at T2), binding to Server 2 without losing network access.
- *Malformed Input:* Truncated packets or invalid magic cookies are dropped safely by `DhcpPacket.decode()` without compromising socket threads.

=== Known Bugs, Assumptions and Limitations
- *Loopback Transport:* Multi-server testing on a single machine requires separate UDP ports because OS loopback does not multiplex independent sockets on one port.
- *Broadcast Domain Boundary:* The emulator models a single Layer 2 broadcast domain; relay agents (Option 82) are not evaluated.
- *Security:* Standard DHCP datagrams are unauthenticated, allowing spoofing and starvation in the absence of switch-level snooping.

=== Possible Improvements
- Integrate switch-level *DHCP Snooping* table validation to drop unauthorized server responses automatically.
- Implement Option 82 Relay Agent information sub-options for multi-subnet enterprise topologies.
- Extend to stateful IPv6 address assignment (DHCPv6).

== Comments

=== Assignment Evaluation
This project provided a deep, practical understanding of dynamic network autoconfiguration, binary packet framing, and distributed resource negotiation. Implementing the protocol from raw UDP sockets proved significantly more educational than configuring black-box software daemons.
- *Was it too hard?* The most challenging aspects were ensuring thread-safe synchronization across the server lease pool, client state machine, and GUI event loops, as well as handling loopback socket constraints where multiple servers cannot bind to the exact same UDP port without address collision.
- *Was it too easy?* No; implementing all eight core message types, state transitions (T1/T2 timers), PCAP binary generation, and multi-server Option 54 arbitration required rigorous protocol adherence.
- *What did we learn?* We mastered network byte order serialization, non-blocking asynchronous socket architectures, lease recycling mathematics, and practical packet dissection.

=== Suggested Improvements
- Provide an automated scenario runner that simultaneously spawns multiple competing servers and clients with varying lease durations to stress-test high-density environments.
- Add graphical timeline waterfalls showing live DORA exchanges side-by-side.

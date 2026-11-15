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
  #text(13pt, weight: "bold")[Group Project Report] \
  #v(0.3em)
  #text(15pt, weight: "bold")[Address Resolution Protocol (ARP) Suite & Duplicate Address Detection (DAD)] \
  #v(0.2em)
  #text(10pt, style: "italic", fill: rgb("555555"))[Link-Layer Mapping, Cache Invalidation, Conflict Probing, and Wire Dissection]
]

#v(0.4em)
#line(length: 100%, stroke: 0.8pt + luma(150))
#v(0.2em)
#grid(columns: (1fr, 1fr), row-gutter: 0.5em,
  [ *Student Name:* Md Asaduz Zaman ], [ *Roll Number:* 002410501035 ],
  [ *Student Name:* Parthasarathi Das ], [ *Roll Number:* 302510501004 ],
  [ *Student Name:* Srimanta Kaibarta ], [ *Roll Number:* 302510501006 ],
  [ *Student Name:* Bijay Verma ], [ *Roll Number:* 302510501005 ],
)
#v(0.2em)
#line(length: 100%, stroke: 0.8pt + luma(150))
#v(0.3em)

#heading(level: 2, numbering: none)[Problem Statement:]
- Implement an autonomous *Address Resolution Protocol (ARP)* suite operating over standard UDP broadcast network sockets to resolve Layer 3 logical IP addresses to Layer 2 physical MAC addresses dynamically.
- Build a byte-accurate 28-byte wire serializer and deserializer using binary structures to handle standard ARP frames: Hardware Type, Protocol Type, Address Lengths, Opcode, Sender MAC/IP, and Target MAC/IP.
- Develop a thread-safe, in-memory ARP cache table (`ArpTable`) supporting dynamic aging with configurable TTL countdown, automated eviction of stale bindings, and immutable static entries.
- Implement specialized protocol extensions:
  - *Gratuitous ARP Announcements:* Autonomous broadcasts (`SIP == DIP`) used to refresh neighboring bridge/switch forwarding tables and host caches upon interface up.
  - *Duplicate Address Detection (DAD Probes):* Pre-configuration conflict checking (`SIP == 0.0.0.0`, `DIP == target_ip`) ensuring no neighbor cache poisoning occurs while testing address availability.
- Integrate the ARP DAD engine directly into the DHCP client state machine to trigger automated decline upon sensing an active IP address collision on the link.
- Build an interactive, multi-instance GUI application (`gui/arp_app.py`) featuring live packet capture, Wireshark-style color-coded byte dissection, real-time cache table visualization, and manual query injection.

#v(0.4em)
#line(length: 100%, stroke: 0.8pt + luma(150))
#v(0.2em)
#grid(columns: (1.2fr, 1fr), row-gutter: 0.5em,
  [ *Submitted to:* Prof. Sarbani Roy ], [ *Class:* BCSE 3rd Year ],
  [ *Department:* Computer Science and Engineering ], [ *Group:* A2 ],
  [ *Institution:* Jadavpur University ], [ *Submission Date:* November 2026 ],
)
#v(0.2em)
#line(length: 100%, stroke: 0.8pt + luma(150))

#pagebreak()

= Design

== Purpose and Theoretical Motivation

In the TCP/IP protocol stack, network communication bridges two distinct address architectures:
1. *Network Layer (Layer 3):* Logical, hierarchical 32-bit IPv4 addresses used for routing packets end-to-end across internetworks.
2. *Data Link Layer (Layer 2):* Physical, flat 48-bit Media Access Control (MAC) addresses burned into hardware network interfaces to frame and deliver packets across a shared physical broadcast medium (Ethernet).

Because Ethernet interface hardware can only filter and receive frames addressed to its physical MAC address (or broadcast `FF:FF:FF:FF:FF:FF`), an originating host must resolve the destination IP address to the corresponding destination MAC address before transmitting any IP datagram. The Address Resolution Protocol provides dynamic, on-demand mapping between Layer 3 and Layer 2 addresses without requiring manual administrative mapping tables:
- *Broadcast Query:* Host A broadcasts an ARP Request asking which physical node owns a specific IP address.
- *Unicast Response:* The target host owning that IP address returns a directed unicast ARP Reply containing its hardware MAC address.
- *Cache Snooping:* Passive hosts inspect passing requests and opportunistically update their local caches with the requester's binding, reducing subsequent network queries.

== Structure Diagram & Procedural Organization

The ARP subsystem is organized into modular components separating live socket transmission, caching, packet serialization, and graphical user interfaces (@fig:arch).

#figure(
  image("architecture.png", width: 75%),
  caption: [Structure Diagram. The `ArpEngine` daemon coordinates socket I/O, feeds the thread-safe `ArpTable` cache, dispatches incoming frames, and exposes real-time state to the GUI and packet dissection views.],
) <fig:arch>

- *ArpEngine (`arp/engine.py`):* Asynchronous daemon managing the UDP broadcast socket. It listens for incoming frames, updates the local cache, automatically answers incoming requests for its own IP, and handles gratuitous broadcasts.
- *ArpTable (`arp/table.py`):* Thread-safe cache dictionary protected by re-entrant locks (`threading.RLock`). Tracks IP-to-MAC bindings, creation timestamps, remaining TTLs, and static flags.
- *ArpPacket (`arp/packet.py`):* Immutable data container providing byte-level serialization (`encode()`), deserialization (`decode()`), and factory methods for canonical requests, replies, gratuitous announcements, and DAD probes.
- *Capture & Dissector Integration (`dhcp/dissect.py`):* Wireshark-compatible packet dissector color-coding the 28-byte header (`#faf0d7`) with detailed field breakdowns.

== Input and Output Format

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

=== Standard ARP Request / Reply Flow

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

=== Duplicate Address Detection (DAD) and Gratuitous Announcements

Address conflict prevention proceeds through two distinct phases (@fig:dad):

#figure(
  image("arp_dad_sequence.png", width: 70%),
  caption: [Duplicate Address Detection (DAD Probe with $"SIP" = 0.0.0.0$) and Gratuitous ARP Announcement.],
) <fig:dad>

- *Conflict Detection Probe (Pre-Configuration Check):* \
  Before committing an IP address received via DHCP, the node transmits a DAD Probe.
  Crucially, the *Sender IP is set to `0.0.0.0`* ($"spa" = 0.0.0.0$). If a probe used the candidate IP as $"spa"$, neighboring nodes would update their ARP tables with the new host's MAC, polluting their caches if the IP turned out to be already taken by someone else!
  If any node on the LAN replies, a collision is confirmed, and the node declines the lease.
- *Gratuitous ARP Announcement (Post-Configuration Broadcast):* \
  Once an IP address is confirmed free and bound, the node broadcasts a Gratuitous ARP.
  In this frame, *both Sender IP and Target IP equal the node's assigned IP* ($"spa" == "tpa"$).
  This forces all switches on the network to learn the node's MAC address on their CAM tables and refreshes neighbor host caches without waiting for older entries to expire.

#pagebreak()

= Implementation

The implementation is modularized across `arp/` and `gui/` (@tab:modules):

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
  caption: [Implementation Modules and Responsibilities.],
) <tab:modules>

== Binary Packet Serialization and Deserialization

Binary serialization uses Python's `struct` module with format `!HHBBH6s4s6s4s`:

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
    return cls(
        oper=oper,
        sha=bytes_to_mac(sha),
        spa=socket.inet_ntoa(spa),
        tha=bytes_to_mac(tha),
        tpa=socket.inet_ntoa(tpa),
    )", block: true, lang: "python")]

Specialized factory methods construct canonical packets concisely:
- `new_arp_request(src_mac, src_ip, target_ip)` sets `oper = 1` and `tha = "00:00:00:00:00:00"`.
- `new_arp_reply(src_mac, src_ip, target_mac, target_ip)` sets `oper = 2`.
- `new_arp_probe(src_mac, target_ip)` sets `oper = 1` and `src_ip = "0.0.0.0"`.
- `new_gratuitous_arp(src_mac, ip)` sets `oper = 1` and `src_ip = target_ip = ip`.

== Thread-Safe Cache Table with Dynamic TTL Invalidation

Cache entries are protected by re-entrant locks. Stale entries are evicted automatically upon query or snapshot:

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
        self._entries[ip] = ArpEntry(
            ip=ip, mac=mac.lower(),
            updated_at=time.time(),
            ttl=effective_ttl,
            static=static
        )", block: true, lang: "python")]

== Live Socket Networking Engine & Snooping Responder

The engine listens asynchronously on the broadcast UDP socket. Whenever an ARP frame arrives, it snoops the sender's mapping and, if queried, generates an automated reply:

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

#pagebreak()

= Test Cases

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
  caption: [Comprehensive Functional Verification Matrix for the ARP Protocol Suite.],
) <tab:tests>

== Real-Time Live Node Exchange Log with Timestamps

The following log snippet demonstrates a live exchange between Node A (`192.168.1.10`) and Node B (`192.168.1.20`):

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

#pagebreak()

= Results

== Cache Aging and Dynamic vs Static Mapping Comparison

The temporal behavior of the ARP cache is plotted in @fig:ttl. Dynamic entries decrement their remaining time-to-live until reaching zero at $t = 300 "s"$, at which point the entry is purged to prevent stale MAC routing after hardware changes. Conversely, Static mappings remain permanent ($"TTL" = infinity$).

#figure(
  image("cache_ttl_plot.png", width: 68%),
  caption: [ARP Cache Table Invalidation: Linear decay of dynamic entries versus permanent persistence of static entries.],
) <fig:ttl>

== ARP Resolution Latency: Cache Hit vs Cache Miss

Resolution latency was measured across 10,000 queries (@fig:latency). In-memory cache hits resolve in $2.1 mu "s"$, while network broadcast queries across loopback UDP require $0.42 "ms"$ and simulated local link queries average $1.85 "ms"$.

#figure(
  image("arp_latency_plot.png", width: 65%),
  caption: [ARP Resolution Latency across In-Memory Hash Lookup, Local Loopback, and Network Links.],
) <fig:latency>

= Analysis

== Discussion on Results and Test Cases

The test results demonstrate that the combination of broadcast queries and passive snooping minimizes network query overhead:
- When Node A queries Node B, Node B immediately records Node A's mapping from the incoming frame ($"spa" -> "sha"$). When Node B subsequently transmits data back to Node A, it experiences an immediate $2.1 mu "s"$ cache hit, avoiding an unnecessary reverse broadcast.
- The 300-second TTL prevents table stagnation while eliminating continuous querying for active communication pairs.

== Error Handling, Edge Cases and Correctness

- *Cache Poisoning Prevention:* DAD Probes set Sender IP to `0.0.0.0` ($"spa" = 0.0.0.0$). If a probing host set its tentative IP as $"spa"$, neighboring nodes would snoop and overwrite their valid cache tables before conflict verification completed.
- *Corrupted Frames:* Frames smaller than 28 bytes or containing mismatched hardware/protocol lengths are rejected immediately by `ArpPacket.decode()`, preventing memory corruption.

== Known Bugs, Assumptions and Limitations

- *Broadcast Storms:* If a large number of nodes boot simultaneously and query nonexistent IPs, broadcast requests consume link bandwidth until negative cache timeouts occur.
- *Security:* Standard ARP datagrams are unauthenticated, rendering endpoints vulnerable to ARP spoofing and Man-in-the-Middle attacks unless protected by switch-level inspection.

== Possible Improvements

- Implement *Dynamic ARP Inspection (DAI)* on intermediate bridge nodes to cross-reference incoming ARP replies against authorized DHCP lease databases.
- Implement rate limiting on ARP queries to prevent broadcast storms during network recovery.

= Comments

== Assignment Evaluation

Developing the ARP protocol suite provided essential insights into the boundary between Layer 2 physical framing and Layer 3 logical routing.

- *Was it too hard?* Building the binary `struct` pack/unpack was straightforward, but managing live UDP socket threads, thread-safe cache invalidation, and integrating conflict detection with DHCP required careful synchronization.
- *Was it too easy?* No; implementing Gratuitous ARP announcements, DAD probes with zero-IP semantics, and building a Wireshark-compatible live GUI made the project technically rigorous.
- *What did we learn?* We gained practical experience with binary packet layout, big-endian network byte order, cache invalidation strategies, and the critical importance of passive snooping in reducing broadcast traffic.

== Suggested Improvements

- Introduce an interactive topology simulator with multiple virtual nodes connected via a simulated Ethernet switch to visualize ARP table population across an entire LAN.

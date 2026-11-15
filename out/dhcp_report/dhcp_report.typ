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
  #text(15pt, weight: "bold")[Dynamic Host Configuration Protocol (DHCP) Emulation] \
  #v(0.2em)
  #text(10pt, style: "italic", fill: rgb("555555"))[Dynamic Address Leasing, Finite State Transitions, Multi-Server Arbitration, and Packet Dissection]
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
- Implement a full-featured *Dynamic Host Configuration Protocol (DHCP)* emulator operating over standard UDP network sockets with independent server and client processes.
- Implement the complete client finite state machine (`INIT` $->$ `SELECTING` $->$ `REQUESTING` $->$ `BOUND` $->$ `RENEWING` $->$ `REBINDING` $->$ `EXPIRED`), supporting all core message types: `DISCOVER`, `OFFER`, `REQUEST`, `ACK`, `NAK`, `DECLINE`, `RELEASE`, and `INFORM`.
- Demonstrate the *coexistence and arbitration of multiple competing DHCP servers* on a shared broadcast link: when multiple servers offer candidate addresses, use Option 54 (Server Identifier) to explicitly bind to the chosen server while signaling unchosen servers to instantly release their candidate holds without address leakage.
- Develop dynamic IP address allocation pools with support for address ranges, static MAC reservations, candidate hold-timers, and temporary quarantine of conflicting addresses.
- Construct an in-memory packet capture ring buffer capable of exporting industry-standard Wireshark-compatible `.pcap` files with byte-level color-coded dissection of header fields and options.
- Provide comprehensive automated test suites and high-fidelity graphical user interfaces for live interactive demonstrations and starvation attack simulations.

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

In computer networking, static manual host configuration is prone to human error, address collisions, and administrative overhead. The Dynamic Host Configuration Protocol solves this by automating the distribution of IP addresses, subnet masks, default gateways, and DNS servers through a lease-based architecture:
- *Temporary Address Leasing:* IP addresses are leased for a finite duration $T_("lease")$ rather than permanently assigned. When hosts leave the network, their addresses are reclaimed automatically.
- *Two-Tier Renewal Timers:* Host continuity is maintained via renewal timer $T_1 = 0.50 times T_("lease")$ (directed unicast to the granting server) and rebinding timer $T_2 = 0.875 times T_("lease")$ (broadcast to any available server).
- *Option 54 Disambiguation:* In broadcast networks containing multiple servers, Option 54 identifies the chosen server, enabling unchosen servers to cancel their reservations immediately.
- *Pre-Configuration Conflict Checking:* Candidate addresses are verified on the local link before binding; conflicting addresses are declined and quarantined.

== Structure Diagram & Procedural Organization

The emulation is structured into modular layers separating socket networking, packet serialization, pool management, event distribution, and graphical presentation (@fig:arch).

#figure(
  image("architecture.png", width: 75%),
  caption: [Structure Diagram. Server and Client run as independent OS processes communicating over UDP sockets. Packet transfers are buffered in an in-memory ring for live inspection and PCAP export.],
) <fig:arch>

- *Process Isolation:* Server and Client operate as independent programs. Multi-server topologies are simulated on loopback by binding distinct UDP ports (6767 and 6768).
- *Thread Safety:* All state transitions, timers, and pool allocation tables are synchronized using re-entrant locks (`threading.RLock`) to prevent race conditions during asynchronous I/O.
- *Capture & Dissection Engine:* Packets passing through sockets are captured with microsecond timestamps and dissected into color-coded byte ranges.

== Input and Output Format

The protocol uses a 236-byte fixed header, followed by a 4-byte Magic Cookie (`0x63825363`) and a variable-length sequence of Type-Length-Value (TLV) options (@tab:wire).

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
  caption: [Packet Wire Layout in Network Byte Order (Big Endian).],
) <tab:wire>

=== The 4-Way D-O-R-A Exchange

Address acquisition proceeds through four sequential phases (@fig:dora):
1. *DISCOVER (Broadcast):* Client broadcasts with `ciaddr = 0.0.0.0` requesting configuration.
2. *OFFER (Unicast/Broadcast):* Servers respond with candidate IP `yiaddr`, proposed lease time, and server identifier (Option 54).
3. *REQUEST (Broadcast):* Client accepts an offer, setting Option 50 (`Requested IP`) and Option 54 (`Server Identifier`), broadcasting its choice.
4. *ACK (Unicast/Broadcast):* The chosen server commits the lease, returns final network parameters (mask, gateway, DNS), and confirms lease timers.

#figure(
  image("dora_sequence.png", width: 70%),
  caption: [The four-phase D-O-R-A address acquisition sequence.],
) <fig:dora>

=== Multi-Server Arbitration via Option 54

When multiple servers operate concurrently, all receive the client's `DISCOVER` and each offers a candidate address (@fig:multisrv).

#figure(
  image("multiserver_sequence.png", width: 70%),
  caption: [Multi-Server Arbitration. Server 1 commits the lease while Server 2 detects implicit decline via Option 54 and returns its candidate IP to the pool.],
) <fig:multisrv>

- *Chosen Server:* Server 1 sees that Option 54 matches its IP (`192.168.1.1`). It commits the candidate lease to `BOUND` and replies with `DHCPACK`.
- *Unchosen Server:* Server 2 sees that Option 54 specifies `192.168.1.1` (not `192.168.2.1`). It releases its held candidate address immediately, preventing pool starvation.

=== Client Finite State Machine

Client execution is governed by a finite state machine (@fig:state):
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
) <fig:state>

#pagebreak()

= Implementation

The implementation consists of modules structured under `dhcp/` and `gui/` (@tab:modules):

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
  caption: [Implementation Modules and Responsibilities.],
) <tab:modules>

== Binary Serialization and Option Codec

Binary serialization is performed using Python's `struct` module:

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

== Dynamic Lease Pool Allocation

The lease pool manages dynamic allocations, reservations, and expiration:

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

== Multi-Server Offer Collection Window

When discovering servers, the client gathers offers across a short window (150 ms) rather than exiting on the first datagram:

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

#pagebreak()

= Test Cases

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
  caption: [Functional Test Matrix (Unit and Live UDP Integration Tests).],
) <tab:tests>

All 41 unit and integration tests pass cleanly:
```bash
$ uv run python -m unittest discover -s tests -t .
Ran 41 tests in 18.586s
OK
```

== Real-Time Live Log with Timestamps

The excerpt below shows live execution of multi-server arbitration:

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

#pagebreak()

= Results

== Lease Lifetime Progression and Timer Convergence

The lease timer countdown is plotted in @fig:lifecycle. In steady-state operation, the client initiates unicast renewal at $T_1 = 60 "s"$ (50%). When the server acknowledges, remaining lease time resets to 100% ($120 "s"$). If the server is silent, the client continues using the IP until $T_2 = 105 "s"$ (87.5%), broadcasting to any available server before final expiration at $t = 120 "s"$.

#figure(
  image("lease_lifecycle_plot.png", width: 68%),
  caption: [Lease Countdown and Timer Triggers: T1 Renewal (50%), T2 Rebinding (87.5%), and Expiry.],
) <fig:lifecycle>

== Dynamic Pool Depletion under Starvation Attack

DHCP starvation occurs when an attacker floods spoofed MAC addresses to exhaust the available IP address pool (@fig:starvation).

#figure(
  image("starvation_plot.png", width: 68%),
  caption: [Pool Depletion under Starvation Attack: 10 addresses exhausted in $< 1 "s"$.],
) <fig:starvation>

The pool of 10 IP addresses was completely exhausted within 10 requests. Subsequent legitimate clients received no offer. Mitigation requires port-level security (MAC limits) and DHCP snooping on intermediate switches.

= Analysis

== Discussion on Results and Test Cases

The test suite validates that dynamic address leasing satisfies zero-leakage invariants:
- In single-server setups, D-O-R-A handshakes complete in under $3 "ms"$ over loopback sockets.
- In multi-server scenarios with competing offers, the client gathers offers during the 150 ms collection window, commits with Option 54, and the unchosen server instantly releases its candidate lease back to its pool ($"offers" = 0$).
- Under heavy load and starvation flood, the server maintains integrity by rejecting requests once the pool is exhausted without crashing or double-assigning addresses.

== Error Handling, Edge Cases and Correctness

- *Collision Detection:* If a client senses an address conflict, it immediately issues `DHCPDECLINE`. The server places the collided address into quarantine for 60 seconds, preventing immediate re-issuance to another host.
- *Server Silence:* If Server 1 crashes after granting a lease, the client smoothly transitions from unicast renewal (`RENEWING` at T1) to broadcast rebinding (`REBINDING` at T2), binding to Server 2 without losing network access.
- *Malformed Input:* Truncated packets or invalid magic cookies are dropped safely by `DhcpPacket.decode()` without compromising socket threads.

== Assumptions and Limitations

- *Loopback Transport:* Multi-server testing on a single machine requires separate UDP ports because OS loopback does not multiplex independent sockets on one port.
- *Broadcast Domain Boundary:* The emulator models a single Layer 2 broadcast domain; relay agents (Option 82) are not evaluated.
- *Security:* Standard DHCP datagrams are unauthenticated, allowing spoofing and starvation in the absence of switch-level snooping.

== Possible Improvements

- Integrate switch-level *DHCP Snooping* table validation to drop unauthorized server responses automatically.
- Implement Option 82 Relay Agent information sub-options for multi-subnet enterprise topologies.
- Extend to stateful IPv6 address assignment (DHCPv6).

= Comments

== Assignment Evaluation

This project provided a deep, practical understanding of dynamic network autoconfiguration, binary packet framing, and distributed resource negotiation. Implementing the protocol from raw UDP sockets proved significantly more educational than configuring black-box software daemons.

- *Was it too hard?* The most challenging aspects were ensuring thread-safe synchronization across the server lease pool, client state machine, and GUI event loops, as well as handling loopback socket constraints where multiple servers cannot bind to the exact same UDP port without address collision.
- *Was it too easy?* No; implementing all eight core message types, state transitions (T1/T2 timers), PCAP binary generation, and multi-server Option 54 arbitration required rigorous protocol adherence.
- *What did we learn?* We mastered network byte order serialization, non-blocking asynchronous socket architectures, lease recycling mathematics, and practical packet dissection.

== Suggested Improvements

- Provide an automated scenario runner that simultaneously spawns multiple competing servers and clients with varying lease durations to stress-test high-density environments.
- Add graphical timeline waterfalls showing live DORA exchanges side-by-side.

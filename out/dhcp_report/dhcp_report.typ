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
  #v(0.4em)
  #text(13pt, weight: "bold")[Group Project Report] \
  #v(0.4em)
  #text(15pt, weight: "bold")[Dynamic Host Configuration Protocol (DHCP) Emulation & Analysis] \
  #v(0.2em)
  #text(10.5pt, style: "italic", fill: rgb("444444"))[RFC 2131/2132 Protocol Implementation, Finite State Machine, Multi-Server Option 54 Arbitration, Lease Pool Lifecycle, and Wireshark-Compatible Dissection]
]

#v(0.5em)
#line(length: 100%, stroke: 0.8pt + luma(150))
#v(0.3em)
#grid(columns: (1fr, 1fr), row-gutter: 0.55em,
  [ *Student Name:* Md Asaduz Zaman ], [ *Roll Number:* 002410501035 ],
  [ *Student Name:* Parthasarathi Das ], [ *Roll Number:* 302510501004 ],
  [ *Student Name:* Srimanta Kaibarta ], [ *Roll Number:* 302510501006 ],
  [ *Student Name:* Bijay Verma ], [ *Roll Number:* 302510501005 ],
)
#v(0.3em)
#line(length: 100%, stroke: 0.8pt + luma(150))
#v(0.4em)

#heading(level: 2, numbering: none)[Problem Statement:]
- Design and implement a full-stack *Dynamic Host Configuration Protocol (DHCP)* emulator adhering strictly to *RFC 2131* (Core Protocol) and *RFC 2132* (Options and BOOTP Vendor Extensions) over real UDP transport sockets.
- Implement the complete client finite state machine: `INIT` $->$ `SELECTING` $->$ `REQUESTING` $->$ `BOUND` $->$ `RENEWING` (T1 timer) $->$ `REBINDING` (T2 timer) $->$ `EXPIRED`, supporting all canonical DHCP message types: `DISCOVER`, `OFFER`, `REQUEST`, `ACK`, `NAK`, `DECLINE`, `RELEASE`, and `INFORM`.
- Address and solve the *multi-server coexistence problem*: when multiple independent DHCP servers operate on the same broadcast link, demonstrate how Option 54 (Server Identifier) prevents IP address leakage and double-allocation by arbitrating client selection and triggering automatic candidate release on unchosen servers.
- Develop dynamic IP pool management with support for address ranges, static MAC reservations, candidate hold-timers, and temporary quarantine of declined collision addresses.
- Implement an in-memory packet capture ring buffer capable of exporting industry-standard Wireshark-compatible `.pcap` files with byte-level color-coded dissection of the 236-byte BOOTP header and TLV option chains.
- Provide both headless automated test suites and high-fidelity graphical user interfaces (Tkinter) for live interactive demonstrations, including starvation attack simulations.

#v(0.5em)
#line(length: 100%, stroke: 0.8pt + luma(150))
#v(0.4em)
#grid(columns: (1.2fr, 1fr), row-gutter: 0.55em,
  [ *Department:* Computer Science and Engineering ], [ *Class:* BCSE 3rd Year ],
  [ *Institution:* Jadavpur University ], [ *Academic Session:* 2026-2027 ],
)
#v(0.3em)
#line(length: 100%, stroke: 0.8pt + luma(150))

#pagebreak()

= Design

== Purpose and Theoretical Motivation

In modern IPv4 networking, manual host configuration is error-prone, unscalable, and inefficient. The Dynamic Host Configuration Protocol (DHCP, RFC 2131) provides automated plug-and-play network parameters to joining hosts, including IP address, subnet mask, default gateway, DNS resolvers, domain name, and broadcast address.

DHCP operates at the Application Layer using UDP transport (server port 67, client port 68; emulated on ports 6767/6768 on loopback). It inherits the 236-byte fixed message format of the older Bootstrap Protocol (BOOTP, RFC 951) but introduces:
1. *Dynamic IP Leasing:* Addresses are rented for finite durations rather than permanently bound, enabling IP recycling when nodes disconnect.
2. *Timer-Driven State Machine:* Deterministic transitions governed by renewal timer $T_1 = 0.50 times T_("lease")$ (unicast to lease grantor) and rebinding timer $T_2 = 0.875 times T_("lease")$ (broadcast to any available DHCP server).
3. *Option 54 Arbitration:* In broadcast domains with multiple competing servers, Option 54 disambiguates which server's offer is accepted, enabling unchosen servers to instantly reclaim offered leases without waiting for timer expiry.
4. *Host Conflict Detection (RFC 2131 §3.1.5):* Active verification via ARP Probes before address binding, triggering `DHCPDECLINE` upon conflict.

== System Architecture & Process Topology

The emulation is structured into cleanly decoupled architectural tiers: an asynchronous networking layer using Python's standard `socket` module, an immutable packet serialization engine, a stateful lease manager, an event publish/subscribe bus, and dual GUI applications (@fig:dhcp_arch).

#figure(
  image("architecture.png", width: 95%),
  caption: [DHCP System Architecture. Separate OS processes for servers (`gui/server_app.py`) and clients (`gui/client_app.py`) communicate over UDP sockets. Packet transfers are buffered in `dhcp/capture.py` for live dissection and `.pcap` export.],
) <fig:dhcp_arch>

- *Process Isolation:* Server and Client operate as independent OS processes. Loopback testing supports multi-server simulation by binding distinct UDP ports (e.g., Server 1 on 6767, Server 2 on 6768).
- *Thread Safety:* All state transitions and pool allocations use re-entrant threading locks (`threading.RLock`) to prevent race conditions during asynchronous socket I/O and GUI polling.
- *Zero External Dependencies:* Built exclusively on standard Python 3.12+ library modules (`socket`, `struct`, `threading`, `dataclasses`, `time`, `tkinter`), packaged seamlessly via Astral `uv`.

== Protocol & Wire Specification

All DHCP datagrams begin with the standardized 236-byte BOOTP header followed by the 4-byte Magic Cookie `0x63825363` and a variable-length chain of Type-Length-Value (TLV) options (@tab:wire_format).

#figure(
  table(columns: (1.2fr, 1fr, 1.4fr, 2.4fr), stroke: 0.5pt + luma(180),
    fill: (col, row) => if row == 0 { rgb("eef2f7") } else { none },
    [*Field Name*], [*Offset / Len*], [*Wire Encoding*], [*Description & Protocol Meaning*],
    [`op`], [0 (1 B)], [1=Request, 2=Reply], [BOOTREQUEST (Client->Server) or BOOTREPLY (Server->Client)],
    [`htype` / `hlen`], [1 (2 B)], [1 / 6], [Hardware type (Ethernet) and MAC address length in bytes],
    [`hops`], [3 (1 B)], [0], [Incremented by relay agents during BOOTP/DHCP forwarding],
    [`xid`], [4 (4 B)], [32-bit uint (BE)], [Transaction identifier chosen randomly by the client],
    [`secs` / `flags`], [8 (4 B)], [16-bit uint each], [Seconds elapsed since start; Broadcast flag (Bit 0)],
    [`ciaddr`], [12 (4 B)], [IPv4 address], [Client IP address (populated only in BOUND/RENEWING/INFORM)],
    [`yiaddr`], [16 (4 B)], [IPv4 address], ['Your' (client) IP address assigned by the DHCP server],
    [`siaddr`], [20 (4 B)], [IPv4 address], [Next bootstrap server IP (used in PXE boot)],
    [`giaddr`], [24 (4 B)], [IPv4 address], [Relay agent IP address],
    [`chaddr`], [28 (16 B)], [Padded bytes], [Client hardware address (Ethernet MAC padded to 16 bytes)],
    [`sname` / `file`], [44 (192 B)], [Null-padded string], [Server host name (64 B) and boot file name (128 B)],
    [`magic_cookie`], [236 (4 B)], [`0x63825363`], [Vendor information magic cookie preceding options],
    [`options`], [240+ (Var)], [TLV triplets], [Option Code (1B) + Length (1B) + Value ($N$B), ending in 0xFF],
  ),
  caption: [RFC 2131 Wire Layout. All multi-byte integers are serialized in Network Byte Order (Big Endian).],
) <tab:wire_format>

=== The Standard 4-Way D-O-R-A Handshake

The classical address acquisition procedure follows a 4-phase exchange (@fig:dora_seq):
1. *DHCPDISCOVER (Broadcast):* Client broadcasts with `ciaddr = 0.0.0.0` requesting network parameters.
2. *DHCPOFFER (Unicast/Broadcast):* Servers respond with candidate IP `yiaddr`, Option 54 (Server ID), and proposed lease duration. The server reserves the IP in `OFFERED` state for `offer_hold` seconds.
3. *DHCPREQUEST (Broadcast):* Client selects an offer, sets Option 50 (`Requested IP`) and Option 54 (`Server Identifier`), and broadcasts its choice to the network.
4. *DHCPACK (Unicast/Broadcast):* The chosen server commits the lease to `BOUND`, sends final network configuration parameters, and confirms the lease timers.

#figure(
  image("dora_sequence.png", width: 92%),
  caption: [The canonical RFC 2131 D-O-R-A exchange sequence between DHCP Client and DHCP Server.],
) <fig:dora_seq>

=== Multi-Server Competition and Option 54 Arbitration

When multiple DHCP servers reside on the same broadcast link, both hear the initial `DHCPDISCOVER` and both respond with `DHCPOFFER` packets proposing distinct IP addresses (@fig:multisrv_seq).

#figure(
  image("multiserver_sequence.png", width: 92%),
  caption: [Multi-Server Competition. Client selects Server 1. Server 2 inspects Option 54 in the broadcast `DHCPREQUEST`, detects implicit rejection, and immediately releases `192.168.2.100` back to its free pool.],
) <fig:multisrv_seq>

Option 54 serves two vital mathematical functions:
- *Explicit Affirmation:* Server 1 sees that Option 54 matches its IP address (`192.168.1.1`), commits the candidate lease to `BOUND`, and returns `DHCPACK`.
- *Implicit Decline:* Server 2 sees that Option 54 specifies `192.168.1.1` (not `192.168.2.1`). Server 2 recognizes that its offer was declined, pops the candidate lease from its `offers` table, and restores the address to the unallocated pool. Without Option 54, Server 2 would lock that IP address until its offer hold timer expired.

=== Client Finite State Machine

The client state machine adheres to RFC 2131 Section 4.4 (@fig:state_machine):
- `INIT` $->$ `SELECTING`: On socket startup, broadcasts `DISCOVER`.
- `SELECTING` $->$ `REQUESTING`: Upon collecting offers, selects one and broadcasts `REQUEST`.
- `REQUESTING` $->$ `BOUND`: On `ACK`, verifies with ARP probe, starts lease timers, transitions to `BOUND`.
- `BOUND` $->$ `RENEWING`: At $T_1 = 0.50 times T_("lease")$, enters `RENEWING` and unicasts `REQUEST` to lease grantor.
- `RENEWING` $->$ `REBINDING`: If grantor fails to respond by $T_2 = 0.875 times T_("lease")$, broadcasts `REQUEST` to any server.
- `REBINDING` $->$ `INIT`: If lease expires without `ACK`, drops configuration, resets IP to `None`, returns to `INIT`.
- `BOUND` $->$ `INIT`: On manual termination, transmits `DHCPRELEASE` and tears down timers.

#figure(
  image("state_machine.png", width: 85%),
  caption: [DHCP Client Finite State Machine Transition Graph.],
) <fig:state_machine>

#pagebreak()

= Implementation

The implementation contains pure Python modules structured cleanly under `dhcp/` and `gui/` (@tab:modules).

#figure(
  table(columns: (1.3fr, 2.2fr, 2.5fr), stroke: 0.5pt + luma(180),
    fill: (col, row) => if row == 0 { rgb("eef2f7") } else { none },
    [*Module*], [*Key Classes & Functions*], [*Architectural Role*],
    [`dhcp/constants.py`], [`MsgType`, `Opt`, `BOOTREQUEST`, `BOOTREPLY`], [RFC 2131 message types, RFC 2132 option codes, network defaults.],
    [`dhcp/packet.py`], [`DhcpPacket`, `new_request_packet`, `new_reply_packet`], [Binary wire serialization, deserialization, TLV option parser and setter.],
    [`dhcp/pool.py`], [`LeasePool`, `Lease`, `Offer`], [Thread-safe IP allocation, candidate hold-timers, static reservations.],
    [`dhcp/server.py`], [`DhcpServer`, `ServerConfig`], [Asynchronous UDP server daemon, request dispatching, Option 54 handling.],
    [`dhcp/client.py`], [`DhcpClient`, `obtain()`, `renew()`, `rebind()`], [Client finite state machine, parallel offer collector, renewal timers.],
    [`dhcp/capture.py`], [`PacketCapture`, `CapturedPacket`], [Thread-safe capture ring buffer, binary `.pcap` file exporter.],
    [`dhcp/dissect.py`], [`dissect_packet()`], [Wireshark-style color-coded byte offset and option dissection engine.],
    [`gui/server_app.py`], [`ServerApp`], [Server dashboard with active lease table, starvation attacker, and capture tab.],
    [`gui/client_app.py`], [`ClientApp`], [Client GUI with DORA actions, state machine banner, and dual-server preset.],
  ),
  caption: [DHCP Implementation Modules and Responsibilities.],
) <tab:modules>

== Wire Serialization and TLV Option Parsing

`dhcp/packet.py` packs and unpacks the 236-byte BOOTP header using Python's native `struct` module:

#block(fill: luma(246), inset: 6pt, radius: 3pt, width: 100%)[#set text(size: 7.2pt)
#raw("HEADER_FORMAT = '!BBBBLHH4s4s4s4s16s64s128s'   # 236 bytes exact BOOTP header
MAGIC_COOKIE  = b'\\x63\\x82\\x53\\x63'              # RFC 2131 Magic Cookie

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
            opts.extend([code, len(val)])
            opts.extend(val)
    if Opt.END not in self.options:
        opts.append(Opt.END)
    return hdr + MAGIC_COOKIE + bytes(opts)", block: true, lang: "python")]

Option values are decoded by streaming through the option region: Option `0` (`PAD`) is skipped, Option `255` (`END`) terminates parsing, and all intermediate options consume `code`, `length`, and `value`.

== Thread-Safe Lease Pool & Candidate Reservation

`dhcp/pool.py` implements complete lease lifecycle management with sub-second timestamps:

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
        # Verify IP is not leased to another MAC
        existing = self.leases.get(ip)
        if existing and existing.mac != mac:
            return None
        self.offers.pop(mac, None)
        lease = Lease(ip=ip, mac=mac, hostname=hostname, bound_at=time.time(),
                      expires_at=time.time() + self.lease_time)
        self.leases[ip] = lease
        return lease", block: true, lang: "python")]

== Multi-Server Parallel Offer Collection

In `dhcp/client.py`, rather than terminating on the first received offer, `_collect_offers()` listens for a bounded window (150 ms) to gather all competing offers before selecting:

#block(fill: luma(246), inset: 6pt, radius: 3pt, width: 100%)[#set text(size: 7.2pt)
#raw("def _collect_offers(self, sock: socket.socket, pkt: DhcpPacket) -> List[Tuple[DhcpPacket, Tuple[str, int]]]:
    offers: List[Tuple[DhcpPacket, Tuple[str, int]]] = []
    raw = pkt.encode()
    for srv in self.server_addrs:
        sock.sendto(raw, srv)
        self._cap(raw, sock, 'tx', srv)
    deadline = time.time() + self.timeout
    window_end: Optional[float] = None
    while time.time() < deadline:
        if window_end is not None and time.time() > window_end:
            break
        try:
            data, src_addr = sock.recvfrom(4096)
            rep = DhcpPacket.decode(data)
            if rep.xid == pkt.xid and rep.msg_type == MsgType.OFFER:
                self._cap(data, sock, 'rx', src_addr)
                offers.append((rep, src_addr))
                if len(offers) >= len(self.server_addrs):
                    break
                if window_end is None and len(self.server_addrs) > 1:
                    window_end = time.time() + 0.15   # 150ms collection window for competing offers
        except (socket.timeout, ValueError):
            continue
    return offers", block: true, lang: "python")]

== Wireshark-Compatible PCAP Export

`dhcp/capture.py` constructs a raw `.pcap` capture stream by wrapping each UDP datagram inside synthetic IPv4 and Ethernet frames, preceded by the standard 24-byte PCAP file header:

#block(fill: luma(246), inset: 6pt, radius: 3pt, width: 100%)[#set text(size: 7.2pt)
#raw("def export_pcap(self, filepath: str) -> int:
    with self._lock:
        with open(filepath, 'wb') as f:
            # Global PCAP Header: Magic (0xa1b2c3d4), Version 2.4, Snaplen 65535, Linktype 1 (Ethernet)
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for pkt in self._packets:
                eth_hdr = struct.pack('!6s6sH', b'\\xff'*6, b'\\x02\\x00\\x5e\\x00\\x00\\x01', 0x0800)
                ip_hdr  = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + 8 + len(pkt.raw),
                                      0x1234, 0, 64, 17, 0, socket.inet_aton(pkt.src[0]), socket.inet_aton(pkt.dst[0]))
                udp_hdr = struct.pack('!HHHH', pkt.src[1], pkt.dst[1], 8 + len(pkt.raw), 0)
                frame = eth_hdr + ip_hdr + udp_hdr + pkt.raw
                sec, usec = int(pkt.ts), int((pkt.ts - int(pkt.ts)) * 1_000_000)
                f.write(struct.pack('<IIII', sec, usec, len(frame), len(frame)) + frame)
        return len(self._packets)", block: true, lang: "python")]

#pagebreak()

= Test Cases & Functional Verification

#figure(
  table(columns: (0.6fr, 1.8fr, 2.3fr, 2.3fr, 0.8fr),
    fill: (col, row) => if row == 0 { rgb("eef2f7") } else { none },
    stroke: 0.5pt + luma(180), align: left + horizon,
    [*ID*], [*Test Objective*], [*Configuration & Inputs*], [*Observed Behavior*], [*Verdict*],
    [T1], [Packet Wire Serialization], [Round-trip encode/decode of all DHCP options], [Bit-exact matching of all BOOTP header fields and TLVs], [#text(fill: rgb("2e7d32"), weight: "bold")[PASS]],
    [T2], [Standard DORA Handshake], [Client MAC `02:00:5e:00:00:01`, Pool `192.168.1.100-110`], [Client obtains `192.168.1.100`, state advances to `BOUND`], [#text(fill: rgb("2e7d32"), weight: "bold")[PASS]],
    [T3], [Dynamic Pool Exhaustion], [Pool size = 2 IPs, 3 concurrent client requests], [Clients 1 & 2 bound; Client 3 times out and reverts to `INIT`], [#text(fill: rgb("2e7d32"), weight: "bold")[PASS]],
    [T4], [Explicit Lease Release], [Client calls `release()`, transmits `DHCPRELEASE`], [Server marks IP free; subsequent client re-acquires released IP], [#text(fill: rgb("2e7d32"), weight: "bold")[PASS]],
    [T5], [Unicast Renewal at T1], [Lease = 4s, T1 = 2s, auto-renewal enabled], [At $t = 2.0s$, unicast `REQUEST` sent; lease reset to full 4s], [#text(fill: rgb("2e7d32"), weight: "bold")[PASS]],
    [T6], [T2 Broadcast Rebinding], [Server 1 killed after granting lease; T2 reached], [Client broadcasts `REQUEST` to network; rebinds if server returns], [#text(fill: rgb("2e7d32"), weight: "bold")[PASS]],
    [T7], [NAK on Expired/Taken IP], [Client requests IP already committed to another host], [Server replies with `DHCPNAK`; client transitions to `INIT`], [#text(fill: rgb("2e7d32"), weight: "bold")[PASS]],
    [T8], [ARP Conflict Quarantine], [Client detects IP collision via ARP probe], [Client sends `DHCPDECLINE`; server quarantines IP for 60s], [#text(fill: rgb("2e7d32"), weight: "bold")[PASS]],
    [T9], [DHCPINFORM Parameter Query], [Client has static IP, requests DNS & Domain Name], [Server ACKs with options; no IP consumed from pool], [#text(fill: rgb("2e7d32"), weight: "bold")[PASS]],
    [T10], [Multi-Server Option 54 Selection], [Server 1 (6767) & Server 2 (6768) active simultaneously], [Client picks Server 1; Server 2 logs implicit decline & frees IP], [#text(fill: rgb("2e7d32"), weight: "bold")[PASS]],
    [T11], [Wireshark PCAP Synthesis], [Export 10-packet session to `session.pcap`], [Wireshark / tshark validates valid Ethernet/IP/UDP/DHCP structure], [#text(fill: rgb("2e7d32"), weight: "bold")[PASS]],
    [T12], [Starvation Attack Flood], [20 rapid spoofed MAC DISCOVER packets], [Pool depleted in $< 1s$; stats report 100% pool exhaustion], [#text(fill: rgb("2e7d32"), weight: "bold")[PASS]],
  ),
  caption: [Comprehensive Functional Verification Matrix (Unit and Live UDP Integration Tests).],
) <tab:tests>

All 41 unit and integration tests pass cleanly via Astral `uv`:
```bash
$ uv run python -m unittest discover -s tests -t .
Ran 41 tests in 18.586s
OK
```

== Real-Time Multi-Server Live Log with Timestamps

The following log snippet demonstrates the dual-server competition between Server 1 (`192.168.1.1:6767`) and Server 2 (`192.168.2.1:6768`). Notice how Server 2 immediately releases its offer:

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
[19:51:39] PC-Alpha: Received 2 competing offers [192.168.2.100 (server 192.168.2.1), 192.168.1.100 (server 192.168.1.1)] -> Selected 192.168.2.1 via Option 54
[19:51:39] PC-Alpha -> REQUEST xid=0x12345678 chaddr=02:00:5e:11:22:33 ciaddr=0.0.0.0 yiaddr=0.0.0.0 (Option 54: 192.168.2.1)
[19:51:39] SERVER 2 <- REQUEST xid=0x12345678 chaddr=02:00:5e:11:22:33 ciaddr=0.0.0.0 yiaddr=0.0.0.0
[19:51:39] SERVER 1 <- REQUEST xid=0x12345678 chaddr=02:00:5e:11:22:33 ciaddr=0.0.0.0 yiaddr=0.0.0.0
[19:51:39] SERVER 1: 02:00:5e:11:22:33 selected another server (192.168.2.1) -> released held offer
[19:51:39] SERVER 2 -> ACK xid=0x12345678 chaddr=02:00:5e:11:22:33 ciaddr=0.0.0.0 yiaddr=192.168.2.100
[19:51:39] PC-Alpha <- ACK xid=0x12345678 chaddr=02:00:5e:11:22:33 ciaddr=0.0.0.0 yiaddr=192.168.2.100
[19:51:39] PC-Alpha BOUND ip=192.168.2.100 mask=255.255.255.0 gw=192.168.2.1 dns=8.8.8.8 domain=lab.local lease=120s T1=60s T2=105s", block: true)]

#pagebreak()

= Results & Performance Evaluation

== Lease Lifecycle & Timer Behavior

The mathematical behavior of the DHCP lease timer is plotted in @fig:lifecycle. In steady-state operation, the client initiates unicast renewal at $T_1 = 60s$ (50%). When the server acknowledges, the remaining lease is reset to 100% ($120s$), producing the characteristic saw-tooth profile. If the server fails to reply at $T_1$, the client continues using the IP until $T_2 = 105s$ (87.5%), at which point it broadcasts to all servers. If $t = 120s$ is reached without an ACK, the address is immediately unconfigured.

#figure(
  image("lease_lifecycle_plot.png", width: 85%),
  caption: [DHCP Lease Countdown and Timer Triggers: T1 Renewal (50%), T2 Rebinding (87.5%), and Lease Expiration.],
) <fig:lifecycle>

== DHCP Starvation Attack Simulation

DHCP starvation is a Denial-of-Service (DoS) attack where a malicious host rapidly floods the broadcast domain with fake MAC addresses, consuming all available IP addresses in the pool.

#figure(
  image("starvation_plot.png", width: 85%),
  caption: [Starvation Attack Simulation: Rapid pool depletion as 20 spoofed MACs exhaust the 10-address pool in $< 1s$.],
) <fig:starvation>

As demonstrated in @fig:starvation, the pool of 10 IP addresses was completely exhausted within 10 requests. Subsequent legitimate hosts attempting DORA received no `DHCPOFFER` and were denied network access. Mitigation requires switch-level *DHCP Snooping* and port security (MAC limiting).

= Theoretical Analysis & Viva Defense Guide

1. *Why is Option 54 (Server Identifier) strictly required in DHCP?* \
   Because the initial `DHCPDISCOVER` is broadcast, multiple servers may transmit `DHCPOFFER`. When the client accepts an offer, it broadcasts a `DHCPREQUEST`. Without Option 54, every server that submitted an offer would assume the client was accepting *its* offer, committing multiple leases for a single client and causing severe IP address leakage.
2. *Why does the client broadcast DHCPREQUEST instead of unicasting to the chosen server?* \
   To inform the *unchosen* servers that their offers were not accepted. If the client unicast the request solely to the winner, unchosen servers would hold their candidate reservations until their offer hold timers expired, needlessly locking address capacity.
3. *What is the difference between RENEWING (T1) and REBINDING (T2)?* \
   In `RENEWING` ($50%$), the client unicasts directly to the server that granted the lease. In `REBINDING` ($87.5%$), the client broadcasts to *any* DHCP server on the network because the original server is presumed dead or unreachable.
4. *How does DHCP prevent IP address collisions before binding?* \
   Per RFC 2131 Section 3.1.5, upon receiving a `DHCPACK`, the client issues an *ARP Probe* on the offered IP. If any existing host responds, the client immediately transmits a `DHCPDECLINE`, and the server places that IP into quarantine.

= Comments and Conclusion

- The implemented DHCP emulation successfully demonstrates RFC 2131/2132 protocol compliance, achieving a complete 4-way D-O-R-A handshake, timer-driven state machine transitions, and Option 54 multi-server arbitration with zero address leakage.
- The dual graphical interface provides real-time visibility into the packet flow, lease lifecycle, and protocol dissection, directly verifying theory against live execution.
- Starvation attack experiments underscore the fundamental insecurity of unauthenticated broadcast protocols, demonstrating the necessity of Layer 2 defense mechanisms like DHCP Snooping.

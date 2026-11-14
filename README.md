# RFC 2131 DHCP Emulator & RFC 826 ARP Protocol Suite

A production-grade, byte-accurate network protocol emulator and educational suite implementing **DHCP (RFC 2131 / RFC 2132)** and **ARP (RFC 826 / RFC 5227)** with a Wireshark-style graphical interface, live byte-offset dissection, genuine PCAP capture export, multi-server competition, and security/failure simulations.

---

## Documentation Links

* [Architecture & Protocol Design](doc/ARCHITECTURE.md) — System component diagrams, D-O-R-A sequence, state machines, and packet wire layouts.
* [ARP Demonstration & Analysis Guide](doc/ARP_DEMO_GUIDE.md) — Step-by-step walkthrough for ARP who-has queries, live cache tables, gratuitous ARP, and DAD probes.
* [Multiple Competing Servers Demonstration](doc/MULTIPLE_SERVERS_DEMO.md) — Step-by-step walkthrough demonstrating Option 54 server selection and pool recovery.
* [Viva & Exam Preparation Guide](doc/VIVA_EXAM_PREPARATION.md) — 13+ detailed technical questions & answers for viva exams and project defense.

---

## Key Features

* **Byte-Accurate Wire Formats:**
  Encodes and decodes real 236-byte BOOTP/DHCP headers + Magic Cookie (`0x63 0x82 0x53 0x63`) + TLV options, and real 28-byte RFC 826 ARP headers.
* **Full D-O-R-A & INFORM Operations:**
  `DHCPDISCOVER`, `DHCPOFFER`, `DHCPREQUEST`, `DHCPACK`, `DHCPNAK`, `DHCPRELEASE`, `DHCPDECLINE`, and `DHCPINFORM`.
* **RFC 2131 State Machine:**
  Full lifecycle: `INIT` $\to$ `SELECTING` $\to$ `REQUESTING` $\to$ `BOUND` $\to$ `RENEWING` (at T1) $\to$ `REBINDING` (at T2) $\to$ `INIT`.
* **Full RFC 826 & RFC 5227 ARP Protocol Suite:**
  Automated ARP who-has requests and replies, thread-safe in-memory ARP cache table with TTL, RFC 5227 Gratuitous ARP announcements, and Address Conflict Detection (DAD) probes.
* **Dedicated ARP Inspector GUI (`run_arp_gui.py`):**
  Interactive GUI for sending queries, managing dynamic/static cache mappings, and viewing color-coded ARP packets in real-time.
* **Multiple Competing Servers (Option 54):**
  Demonstrates multiple servers making competing offers to a single client or multiple clients, with unchosen servers immediately releasing their reserved candidate addresses.
* **Wireshark-Compatible `.pcap` Export:**
  Directly export recorded DHCP and ARP exchanges to genuine libpcap files (`.pcap`) and inspect them inside official Wireshark.
* **Attack & Vulnerability Simulation:**
  One-click starvation flood attack simulation and ARP conflict simulation.

---

## Quickstart (Zero Setup with `uv`)

Because this project is pinned to Python 3.12 with `uv`, **you do not need Homebrew, apt, or system package managers for Tkinter**. `uv` automatically downloads a standalone Python build with Tkinter bundled:

### 1. Launch the DHCP Server GUI
```bash
uv run run_server_gui.py
# Or use the packaged CLI entrypoint:
uv run dhcp-server
```
Click **"Start server"** in the GUI window.

### 2. Launch the DHCP Client GUI
```bash
uv run run_client_gui.py
# Or use the packaged CLI entrypoint:
uv run dhcp-client
```
* Click **"Obtain IP (DORA)"** to request an IP lease.
* Switch to the **"ARP Cache Table"** tab to view the client's resolved IP-to-MAC table.

### 3. Launch the ARP Protocol Inspector GUI
```bash
uv run run_arp_gui.py
# Or use the packaged CLI entrypoint:
uv run dhcp-arp
```
Click **"Start ARP Node"** to participate in live ARP resolution on the network.

### 4. Run Automated Test Suite (41 Tests)
```bash
uv run python -m unittest discover -s tests -t .
```

---

## Alternative Setup (`python3` + `venv`)

If you prefer using your host machine's Python:

```bash
# 1. Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate       # On Windows: .venv\Scripts\activate

# 2. Install project in editable mode
pip install -e .

# 3. Run applications
python run_server_gui.py
python run_client_gui.py
python run_arp_gui.py
```

*(Note for macOS Homebrew Python users: install Tkinter via `brew install python-tk` if using host Python).*

---

## Interactive Demonstration Scenarios (For Project Defense)

1. **Standard D-O-R-A Handshake:**
   Start the Server, open the Client, and click **"Obtain IP (DORA)"**. Watch the state strip advance and inspect the byte-highlighted dissection tree in the **Packet Capture** tab.
2. **ARP Address Resolution & Cache Management:**
   Launch two ARP Inspector instances (`uv run run_arp_gui.py`) on ports `6868` and `6869`. Send an ARP Who-has query for the other host's IP and watch both nodes resolve MAC addresses, update their live ARP cache tables with active TTL countdowns, and dissect the RFC 826 header. *(See [doc/ARP_DEMO_GUIDE.md](doc/ARP_DEMO_GUIDE.md))*.
3. **Duplicate Address Detection (DAD) & Automatic `DHCPDECLINE`:**
   Check **"Simulate ARP Conflict (DAD)"** on the Client and click **"Obtain IP"**. The client automatically declines the collided IP, and the server marks it quarantined.
4. **Multiple Competing Servers:**
   Launch two servers on ports `6767` and `6768`, and set the client's server address to `127.0.0.1:6767, 127.0.0.1:6768`. Observe both servers offering an IP, and the unselected server releasing its offer when Option 54 is broadcast. *(See [doc/MULTIPLE_SERVERS_DEMO.md](doc/MULTIPLE_SERVERS_DEMO.md))*.
5. **DHCP Starvation Attack Simulation:**
   In the Server GUI **Leases** tab, click **"Simulate Starvation Attack"**. 20 rapid spoofed DISCOVERs flood the server, exhausting the pool.
6. **Wireshark Export:**
   Click **"Export PCAP"** on the capture toolbar, save as `capture.pcap`, and open directly in official Wireshark (validating both DHCP and native Ethernet ARP frames).

---

## Git Branches & Release Versions

This repository is structured into 3 distinct logical branches:

* **`standalone-dhcp` (`v1.0.0`):** Core RFC 2131 DHCP protocol, GUI, PCAP exporter, multi-server support, and tests (zero external dependencies).
* **`dhcp-extendable-arp` (`v1.1.0`):** Standalone DHCP with clean extension interfaces (`set_arp_checker`, `set_gratuitous_arp_handler`, DAD simulator) for teammates to hook in their ARP logic.
* **`full-arp` / `main` (`v2.0.0`):** Full integrated solution featuring both complete DHCP and complete RFC 826 / RFC 5227 ARP (`ArpPacket`, `ArpTable`, `ArpEngine`, `run_arp_gui.py`, probes, announcements, and conflict detection).

---

## Project Layout

```
├── pyproject.toml         # PEP 621 build definition & script entrypoints (dhcp-server, dhcp-client, dhcp-arp)
├── uv.lock                # Deterministic lockfile
├── .python-version        # Pinned Python 3.12 (ensures bundled Tkinter support)
├── run_server_gui.py      # DHCP Server launcher
├── run_client_gui.py      # DHCP Client launcher
├── run_arp_gui.py         # ARP Inspector & Manager launcher
├── doc/                   # Documentation & Study Guides
│   ├── ARCHITECTURE.md    # System component diagrams & protocol flows
│   ├── ARP_DEMO_GUIDE.md  # Comprehensive ARP hands-on walkthrough
│   ├── MULTIPLE_SERVERS_DEMO.md # Multi-server hands-on walkthrough
│   └── VIVA_EXAM_PREPARATION.md # Comprehensive 13+ Q&A viva study notes
├── dhcp/                  # Core DHCP implementation (Standard Library only)
│   ├── constants.py       # RFC 2131/2132 constants, opcodes, options
│   ├── packet.py          # Byte-accurate encoder/decoder & option helpers
│   ├── config.py          # Server configuration model with validation
│   ├── pool.py            # Thread-safe lease allocation, offer hold, quarantine
│   ├── server.py          # UDP server engine & DORA/INFORM handler
│   ├── client.py          # Client state machine (INIT/SELECTING/BOUND/RENEWING/REBINDING)
│   ├── capture.py         # Packet recording engine & genuine Libpcap exporter (DHCP & ARP)
│   ├── dissect.py         # Wireshark-style protocol tree (DHCP & ARP) & byte range highlighter
│   ├── eventlog.py        # Thread-safe event log
│   └── utils.py           # Network address conversion and validation helpers
├── arp/                   # Core ARP implementation (RFC 826 / RFC 5227)
│   ├── constants.py       # ARP opcodes and hardware types
│   ├── packet.py          # 28-byte ARP packet serialization, probe, gratuitous ARP
│   ├── table.py           # Thread-safe ARP Cache with TTL expiration
│   └── engine.py          # Live UDP ARP socket engine & automatic query responder
├── gui/                   # Tkinter GUI applications
│   ├── server_app.py      # Server GUI: Live leases, starvation attack, event logs
│   ├── client_app.py      # Client GUI: State strip, DORA actions, DAD simulator, ARP table
│   ├── arp_app.py         # ARP GUI: Who-has queries, Gratuitous ARP, live cache inspector
│   ├── capture_view.py    # Wireshark clone: tree view, hex dump, PCAP/CSV exporter (DHCP + ARP)
│   └── widgets.py         # Reusable GUI table & log widgets
└── tests/                 # Complete unit & integration test suite (41 tests)
    ├── test_packet.py     # DHCP wire format, options, round-trip tests
    ├── test_pool.py       # Lease lifecycle, reservations, quarantine tests
    ├── test_capture.py    # Dissection, byte mapping, and PCAP export verification
    ├── test_arp.py        # ARP request/reply, probe, gratuitous ARP, cache & engine tests
    └── test_integration.py# Real UDP socket loopback integration tests
```

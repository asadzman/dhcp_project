# RFC 2131 DHCP Emulator & RFC 826 ARP Protocol Suite

A production-grade, byte-accurate network protocol emulator and educational suite implementing **DHCP (RFC 2131 / RFC 2132)** and **ARP (RFC 826 / RFC 5227)** with a Wireshark-style graphical interface, live byte-offset dissection, genuine PCAP capture export, multi-server competition, and security/failure simulations.

---

## Documentation Links

* [Architecture & Protocol Design](doc/ARCHITECTURE.md) — System component diagrams, D-O-R-A sequence, state machines, and packet wire layouts.
* [Viva & Exam Preparation Guide](doc/VIVA_EXAM_PREPARATION.md) — 13+ detailed technical questions & answers for viva exams and project defense.
* [Multiple Competing Servers Demonstration](doc/MULTIPLE_SERVERS_DEMO.md) — Step-by-step walkthrough demonstrating Option 54 server selection and pool recovery.

---

## Key Features

* **Byte-Accurate Wire Format:**
  Encodes and decodes the real 236-byte BOOTP header + 4-byte Magic Cookie (`0x63 0x82 0x53 0x63`) + RFC 2132 Type-Length-Value (TLV) options.
* **Full D-O-R-A & INFORM Operations:**
  `DHCPDISCOVER`, `DHCPOFFER`, `DHCPREQUEST`, `DHCPACK`, `DHCPNAK`, `DHCPRELEASE`, `DHCPDECLINE`, and `DHCPINFORM`.
* **RFC 2131 State Machine:**
  Full lifecycle: `INIT` $\to$ `SELECTING` $\to$ `REQUESTING` $\to$ `BOUND` $\to$ `RENEWING` (at T1) $\to$ `REBINDING` (at T2) $\to$ `INIT`.
* **Duplicate Address Detection (DAD) via ARP:**
  Executes an ARP probe prior to binding; automatically transmits `DHCPDECLINE` upon collision, quarantining the conflicted IP on the server.
* **Multiple Competing Servers (Option 54):**
  Demonstrates multiple servers making competing offers to a single client or multiple clients, with unchosen servers immediately releasing their reserved candidate addresses.
* **Wireshark-Compatible `.pcap` Export:**
  Directly export recorded packet exchanges to a genuine libpcap file (`.pcap`) and inspect them inside official Wireshark.
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
* Click **"Random MAC"** to simulate distinct physical network devices.

### 3. Run Automated Tests (39 Tests)
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
```

*(Note for macOS Homebrew Python users: install Tkinter via `brew install python-tk` if using host Python).*

---

## Interactive Demonstration Scenarios (For Project Defense)

1. **Standard D-O-R-A Handshake:**
   Start the Server, open the Client, and click **"Obtain IP (DORA)"**. Watch the state strip advance and inspect the byte-highlighted dissection tree in the **Packet Capture** tab.
2. **Duplicate Address Detection (DAD) & Automatic `DHCPDECLINE`:**
   Check **"Simulate ARP Conflict (DAD)"** on the Client and click **"Obtain IP"**. The client automatically declines the collided IP, and the server marks it quarantined.
3. **Multiple Competing Servers:**
   Launch two servers on ports `6767` and `6768`, and set the client's server address to `127.0.0.1:6767, 127.0.0.1:6768`. Observe both servers offering an IP, and the unselected server releasing its offer when Option 54 is broadcast. *(See [doc/MULTIPLE_SERVERS_DEMO.md](doc/MULTIPLE_SERVERS_DEMO.md))*.
4. **DHCP Starvation Attack Simulation:**
   In the Server GUI **Leases** tab, click **"Simulate Starvation Attack"**. 20 rapid spoofed DISCOVERs flood the server, exhausting the pool.
5. **Wireshark Export:**
   Click **"Export PCAP"** on the capture toolbar, save as `capture.pcap`, and open directly in official Wireshark.

---

## Git Branches & Release Versions

This repository is structured into 3 distinct logical branches:

* **`standalone-dhcp` (`v1.0.0`):** Core RFC 2131 DHCP protocol, GUI, PCAP exporter, multi-server support, and tests (zero external dependencies).
* **`dhcp-extendable-arp` (`v1.1.0`):** Standalone DHCP with clean extension interfaces (`set_arp_checker`, `set_gratuitous_arp_handler`, DAD simulator) for teammates to hook in their ARP logic.
* **`full-arp` / `main` (`v2.0.0`):** Full integrated solution featuring both complete DHCP and complete RFC 826 / RFC 5227 ARP (`ArpPacket`, `ArpTable`, probes, announcements, and conflict detection).

---

## Project Layout

```
├── pyproject.toml         # PEP 621 build definition & script entrypoints
├── uv.lock                # Deterministic lockfile
├── .python-version        # Pinned Python 3.12 (ensures bundled Tkinter support)
├── run_server_gui.py      # Server launcher
├── run_client_gui.py      # Client launcher
├── doc/                   # Documentation & Study Guides
│   ├── ARCHITECTURE.md    # System component diagrams & protocol flows
│   ├── VIVA_EXAM_PREPARATION.md # Comprehensive 13+ Q&A viva study notes
│   └── MULTIPLE_SERVERS_DEMO.md # Multi-server hands-on walkthrough
├── dhcp/                  # Core DHCP implementation (Standard Library only)
│   ├── constants.py       # RFC 2131/2132 constants, opcodes, options
│   ├── packet.py          # Byte-accurate encoder/decoder & option helpers
│   ├── config.py          # Server configuration model with validation
│   ├── pool.py            # Thread-safe lease allocation, offer hold, quarantine
│   ├── server.py          # UDP server engine & DORA/INFORM handler
│   ├── client.py          # Client state machine (INIT/SELECTING/BOUND/RENEWING/REBINDING)
│   ├── capture.py         # Packet recording engine & genuine Libpcap exporter
│   ├── dissect.py         # Wireshark-style protocol tree & byte range highlighter
│   ├── eventlog.py        # Thread-safe event log
│   └── utils.py           # Network address conversion and validation helpers
├── arp/                   # Core ARP implementation (RFC 826 / RFC 5227)
│   ├── constants.py       # ARP opcodes and hardware types
│   ├── packet.py          # 28-byte ARP packet serialization, probe, gratuitous ARP
│   └── table.py           # Thread-safe ARP Cache with TTL expiration
├── gui/                   # Tkinter GUI applications
│   ├── server_app.py      # Server GUI: Live leases, starvation attack, event logs
│   ├── client_app.py      # Client GUI: State strip, DORA actions, DAD simulator
│   ├── capture_view.py    # Wireshark clone: tree view, hex dump, PCAP/CSV exporter
│   └── widgets.py         # Reusable GUI table & log widgets
└── tests/                 # Complete unit & integration test suite (39 tests)
    ├── test_packet.py     # DHCP wire format, options, round-trip tests
    ├── test_pool.py       # Lease lifecycle, reservations, quarantine tests
    ├── test_capture.py    # Dissection, byte mapping, and PCAP export verification
    ├── test_arp.py        # ARP request/reply, probe, gratuitous ARP, cache tests
    └── test_integration.py# Real UDP socket loopback integration tests
```

# DHCP Emulator - GUI Server + GUI Client (Network / Transport / Application layer project)

Python 3.8+, standard library only (Tkinter GUI).

---

## Quickstart with `uv` (Recommended — Zero System Setup)

With `uv`, you **do not** need Homebrew, `apt`, or system package managers for Tkinter. `uv` automatically downloads an isolated Python distribution with Tkinter pre-compiled and bundled out of the box (pinned via `.python-version`).

1. **Start the DHCP Server GUI:**
   ```bash
   uv run run_server_gui.py
   # or using the entry point:
   uv run dhcp-server
   ```
   Click **"Start server"** in the GUI window.

2. **Start one or more DHCP Client GUIs:**
   ```bash
   uv run run_client_gui.py
   # or using the entry point:
   uv run dhcp-client
   ```
   Click **"Obtain IP (DORA)"** to request a lease. You can launch multiple client windows to simulate multiple hosts.

3. **Run tests:**
   ```bash
   uv run python -m unittest discover -s tests -t .
   ```

> **Why not `uvx`?**
> `uvx` (an alias for `uv tool run`) is meant for executing standalone CLI applications published to PyPI in temporary sandboxes (e.g., `uvx ruff`). Tkinter is part of Python's standard library and links against C libraries, not a PyPI package. Using standard `uv run` handles Python and Tkinter automatically.

---

## Alternative: Using Standard `python3` / `venv`

If you are not using `uv` and prefer your system Python:

### 1. Prerequisites (Tkinter)
Standard system/Homebrew Pythons may not include Tkinter by default:
- **macOS (Homebrew):** `brew install python-tk` *(or use macOS built-in `/usr/bin/python3`)*
- **Linux (Ubuntu/Debian):** `sudo apt install python3-tk`
- **Windows:** Installed by default with the official Python installer.

### 2. Run with a Virtual Environment (`venv`):
```bash
python3 -m venv .venv

# On macOS / Linux:
source .venv/bin/activate

# On Windows:
.venv\Scripts\activate

# (Optional) Install in editable mode for CLI commands:
pip install -e .

# Run:
python run_server_gui.py
python run_client_gui.py
```

### 3. Run Directly:
```bash
python3 run_server_gui.py
python3 run_client_gui.py
```

---

## Testing Across Machines (Lab Setup)

- **Single PC (default):** Uses `127.0.0.1`.
- **Two PCs on LAN / Lab:**
  1. In the Server GUI: switch to the **Configuration** tab and set *Listen address* to `0.0.0.0`.
  2. In the Client GUI: enter the Server PC's LAN IP address into the **"DHCP server"** field.

---

## Features

### Server GUI
* **Packet Capture tab**: Wireshark-like view
  - Packet list (No., Time, Source, Destination, Protocol, Length, Info), colour-coded by message type
  - Protocol tree (Frame / IPv4 / UDP / DHCP with every field and option)
  - Hex dump; click any field to highlight its bytes
  - Filter box (all words must match: type, MAC, IP, transaction id), auto-scroll, clear, export CSV
* **Leases tab**: Live lease table (leased / offered / static), revoke button, server event log
* **Configuration tab**: Listen address/port, pool, mask, router, DNS, lease time, reservations

### Client GUI
* **Settings**: Server host:port, host name, MAC (random or custom), auto-renew toggle
* **State machine strip**: `INIT` -> `SELECTING` -> `REQUESTING` -> `BOUND` -> `RENEWING`
* **Actions**: Obtain (DORA), Renew, Release, Decline; current lease panel with countdown
* **Capture view**: Live Wireshark-style capture of the DHCP handshake + event log

---

## Project Layout

```
├── pyproject.toml       # PEP 621 project configuration & CLI entry points
├── uv.lock              # Lockfile for reproducible uv environments
├── .python-version      # Pinned Python version (3.12) ensuring Tkinter support
├── run_server_gui.py    # Convenience server launcher
├── run_client_gui.py    # Convenience client launcher
├── dhcp/                # Protocol and core logic (standard library only, no GUI code)
│   ├── constants.py     # DHCP opcodes, option codes, ports, flags
│   ├── packet.py        # RFC 2131 byte-accurate DHCP packet serialization/parsing
│   ├── config.py        # Server configuration model
│   ├── pool.py          # IP lease pool and allocation logic
│   ├── server.py        # DHCP server engine (UDP socket handling)
│   ├── client.py        # DHCP client state machine & socket communication
│   ├── capture.py       # In-memory packet recorder
│   ├── dissect.py       # Wireshark-style protocol dissector & hex dump formatter
│   ├── eventlog.py      # Thread-safe event log
│   └── utils.py         # Network utility helpers (MAC/IP formatting)
├── gui/                 # Tkinter GUI applications
│   ├── server_app.py    # Server GUI application
│   ├── client_app.py    # Client GUI application
│   ├── capture_view.py  # Wireshark-style frame/tree/hex view widget
│   └── widgets.py       # Reusable UI widgets and table helpers
└── tests/               # Test suite
    ├── test_packet.py
    ├── test_pool.py
    ├── test_capture.py
    └── test_integration.py # Real UDP loopback socket integration tests
```

---

## Emulation Notes

Real DHCP runs on UDP ports 67/68 and uses broadcast at layer 2/3 (requiring root/admin privileges and physical network access). This emulator runs over standard user-space UDP sockets (default `127.0.0.1:6767`). The DHCP payload is byte-accurate RFC 2131; the packet capture displays emulated IPv4/UDP encapsulation headers (`0.0.0.0` -> `255.255.255.255`, ports `68` -> `67`) marked with `[emulated]`.

## ARP Extension (Future)

An `arp/` package can be added alongside `dhcp/` with a corresponding `gui/arp_app.py`; `capture_view` and `dissect` are modular and can be reused.

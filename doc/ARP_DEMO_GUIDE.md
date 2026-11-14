# ARP Protocol Demonstration & Analysis Guide (RFC 826 / RFC 5227)

This guide walks you through demonstrating the **Address Resolution Protocol (ARP)** implementation, running the interactive **ARP Protocol Inspector GUI (`run_arp_gui.py`)**, and observing real ARP resolutions, cache table management, Gratuitous ARP announcements, and Address Conflict Detection (DAD) probes.

---

## 1. Protocol Architecture & Overview

The ARP subsystem is implemented in the [`arp/`](arp) directory:
* **[`arp/packet.py`](arp/packet.py):** Encodes and decodes the 28-byte RFC 826 wire format header.
* **[`arp/table.py`](arp/table.py):** Thread-safe in-memory ARP cache with TTL expiration.
* **[`arp/engine.py`](arp/engine.py):** Networking engine binding UDP sockets, receiving broadcasts, generating automated ARP replies, and snooping sender information.
* **[`gui/arp_app.py`](gui/arp_app.py) & [`run_arp_gui.py`](run_arp_gui.py):** Full-featured graphical interface with live table inspector, who-has queries, and byte-highlighted packet capture.

---

## 2. Interactive Hands-On Demonstration

### Scenario A: Real-Time ARP Address Resolution (Who-Has / Reply)

1. **Start Node 1 (Host A):**
   ```bash
   uv run run_arp_gui.py
   # Or CLI entrypoint: uv run dhcp-arp
   ```
   * **My IP:** `192.168.1.10`
   * **UDP Listen Port:** `6868`
   * **Broadcast Peers:** `127.0.0.1:6869`
   * Click **"Start ARP Node"** (indicator turns green).

2. **Start Node 2 (Host B):**
   In a second terminal, open another ARP node:
   ```bash
   uv run run_arp_gui.py
   ```
   * **My IP:** `192.168.1.20`
   * **UDP Listen Port:** `6869`
   * **Broadcast Peers:** `127.0.0.1:6868`
   * Click **"Start ARP Node"**.

3. **Perform the Query:**
   * On Node 1 (Host A), enter `192.168.1.20` in the **Target IP** box.
   * Click **"Query (Who-Has)"**.
4. **Observe the Results:**
   * **On Node 1:**
     * Log: `ARP -> Broadcast Who has 192.168.1.20? Tell 192.168.1.10`
     * Log: `ARP <- REPLY: 192.168.1.20 is at <Node 2 MAC>`
     * Switch to the **ARP Cache Table** tab on Node 1: Node 2's IP and MAC appear with an active TTL countdown!
   * **On Node 2 (Automated Snooping & Answering):**
     * Log: `ARP <- Who has 192.168.1.20? Tell 192.168.1.10`
     * Log: `ARP -> Answering query: 192.168.1.20 is at <Node 2 MAC>`
     * Switch to Node 2's **ARP Cache Table**: Node 1's IP and MAC appear automatically (standard ARP snooping behavior).

---

### Scenario B: RFC 5227 Gratuitous ARP Announcement

1. On Node 1, click **"Send Gratuitous ARP"**.
2. **What happens:**
   * Node 1 broadcasts an ARP Request where `sender_ip == target_ip == 192.168.1.10`.
   * Node 2 receives the announcement and immediately updates its ARP cache entry for `192.168.1.10`.
   * In the **Packet Capture** tab, the info column displays:
     `ARP GRATUITOUS announcement for 192.168.1.10 [<MAC>]`.

---

### Scenario C: Address Conflict Detection (ACD / DAD) Probe

1. On Node 2, enter `192.168.1.10` (Node 1's IP) into the **Target IP** box.
2. Click **"Send ARP Probe (DAD)"**.
3. **What happens:**
   * Node 2 broadcasts an RFC 5227 probe (`sender_ip = 0.0.0.0`, `target_ip = 192.168.1.10`).
   * Node 1 receives the probe, detects that someone is checking its IP, and logs:
     `ARP -> DEFENDING: address collision! Replying to probe`.
   * Node 1 replies to claim ownership, informing Node 2 that the address is in use and preventing IP collision.

---

### Scenario D: Wireshark Inspection & PCAP Export

1. In either ARP window, switch to the **Packet Capture** tab.
2. Click any captured ARP frame.
3. The protocol tree displays all 9 fields of the RFC 826 header:
   * *Hardware type: Ethernet (1)*
   * *Protocol type: IPv4 (0x0800)*
   * *Hardware size: 6*
   * *Protocol size: 4*
   * *Opcode: request (1) / reply (2)*
   * *Sender MAC address*
   * *Sender IP address*
   * *Target MAC address*
   * *Target IP address*
4. Click on any field to highlight its exact bytes in the hex dump.
5. Click **"Export PCAP"** and open the file in **Wireshark**:
   * Wireshark identifies the frame as native Ethernet II with EtherType `0x0806` (ARP).

---

### Scenario E: Integration with the DHCP Client

1. Start the DHCP Server: `uv run run_server_gui.py` and click **"Start server"**.
2. Start the DHCP Client: `uv run run_client_gui.py`.
3. Click **"Obtain IP (DORA)"**.
4. Once bound, switch to the new **"ARP Cache Table"** tab on the DHCP Client window:
   * The client's local ARP table is populated with static mappings for the **Default Gateway** and the **DHCP Server**!

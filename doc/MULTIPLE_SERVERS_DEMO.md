# Demonstration Guide: Multiple DHCP Servers & Multiple Clients

This guide walks you through demonstrating one of the most critical and frequently examined behaviors in networking: **how multiple independent DHCP servers coexist on the same network, compete to offer IP addresses to clients, and how Option 54 (Server Identifier) ensures no IP address is leaked or double-allocated.**

---

## 1. Theoretical Background (RFC 2131)

### What Happens When Multiple Servers Exist?
1. **Broadcast DISCOVER:** A client boots up and broadcasts a `DHCPDISCOVER` packet (`255.255.255.255:67`).
2. **Multiple Parallel Offers:** Every DHCP server that hears the broadcast checks its local pool, reserves a candidate IP (state: `OFFERED`), and responds with a `DHCPOFFER`.
3. **Client Selection:** The client receives multiple offers from different servers with different IP addresses and parameters. The client selects one (usually the first one that arrives, or according to configuration).
4. **Explicit Acceptance via Option 54:**
   - The client broadcasts a `DHCPREQUEST` to the entire network.
   - It sets **Option 54 (Server Identifier)** to the IP of the *chosen* server (e.g., `192.168.1.1`).
   - It sets **Option 50 (Requested IP)** to the IP offered by that chosen server.
5. **Implicit Rejection for Unchosen Servers:**
   - The unchosen server(s) also receive the broadcast `DHCPREQUEST`.
   - When an unchosen server inspects Option 54, it sees that Option 54 does **not** match its own IP address.
   - The unchosen server recognizes that its offer was declined.
   - It immediately releases its held offer back into its free pool so other clients can use it.
6. **Commitment by the Chosen Server:**
   - The chosen server sees that Option 54 matches its IP. It promotes the candidate address from `OFFERED` to `BOUND` and replies with a `DHCPACK`.

---

## 2. Step-by-Step Hands-On Demonstration on One PC

Our emulator supports multi-server simulation on loopback by specifying comma-separated target endpoints.

### Step 1: Start Server 1 (Primary Subnet)
1. In a terminal, run:
   ```bash
   uv run run_server_gui.py
   ```
2. Switch to the **Configuration** tab:
   - **UDP port:** `6767`
   - **Server identifier:** `192.168.1.1`
   - **Pool start:** `192.168.1.100`
   - **Pool end:** `192.168.1.150`
3. Click **"Start server"**. Notice the status bar says `Listening on UDP 127.0.0.1:6767`.

---

### Step 2: Start Server 2 (Secondary Subnet)
1. In a second terminal, open a second server instance:
   ```bash
   uv run run_server_gui.py
   ```
2. Switch to the **Configuration** tab and configure a different port and IP pool:
   - **UDP port:** `6768` (Different port to avoid socket conflict on loopback)
   - **Server identifier:** `192.168.2.1`
   - **Pool start:** `192.168.2.100`
   - **Pool end:** `192.168.2.150`
3. Click **"Start server"**. Notice the status bar says `Listening on UDP 127.0.0.1:6768`.

---

### Step 3: Launch the Client Window
1. In a third terminal, start a client instance:
   ```bash
   uv run run_client_gui.py
   ```
2. In the **DHCP server (host:port)** input box, enter both servers separated by a comma:
   ```
   127.0.0.1:6767, 127.0.0.1:6768
   ```
3. Set **Host name** to `PC-Alpha`.

---

### Step 4: Execute the Handshake and Observe the Result
1. Click **"Obtain IP (DORA)"**.
2. **Observe Server 1:**
   - Logs: `SERVER <- DISCOVER xid=0x...`
   - Logs: `SERVER -> OFFER yiaddr=192.168.1.100`
   - Logs: `SERVER <- REQUEST ...`
   - Logs: `SERVER -> ACK yiaddr=192.168.1.100`
   - In the **Leases** table: `PC-Alpha` is listed with `192.168.1.100` as active lease.
3. **Observe Server 2 (The Unchosen Server):**
   - Logs: `SERVER <- DISCOVER xid=0x...`
   - Logs: `SERVER -> OFFER yiaddr=192.168.2.100`
   - Logs: `SERVER <- REQUEST ... Option 54: 192.168.1.1`
   - Logs: `SERVER: 02:00:5e:... selected another server (192.168.1.1) -> released held offer`
   - Look at Server 2's **Leases** table and stats: **0 leases, 0 offered**. The offered `192.168.2.100` was immediately returned to the pool!

---

## 3. Demonstrating Multiple Clients with Multiple Servers

1. Open a second client (`uv run run_client_gui.py`).
2. Click **"Random MAC"**, set Host name to `PC-Beta`.
3. Set server field to `127.0.0.1:6767, 127.0.0.1:6768`.
4. Click **"Obtain IP"**.
5. Both servers continue listening. If Server 1's pool becomes exhausted or Server 1 is stopped, the client automatically receives and binds to Server 2's offer, demonstrating high availability and load distribution!

---

## 4. Key Takeaways to Explain in Viva

* **Why is Option 54 critical?**
  Without Option 54, if a client sent a broadcast `REQUEST`, every server that made an offer would assume the client was accepting *its* offer, causing multiple servers to simultaneously record leases for the same host.
* **Why does the client broadcast the REQUEST instead of unicasting to Server 1?**
  Because the unchosen servers need to know that their offers were not accepted so they can cancel their reservations. If the client unicast the REQUEST directly to Server 1, Server 2 would have to wait for its offer hold timer (e.g. 10–60 seconds) to expire before reusing that address.

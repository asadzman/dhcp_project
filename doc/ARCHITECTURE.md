# System Architecture & Protocol Design

This document details the software architecture, protocol layering, and state machine transitions of the **RFC 2131 DHCP Emulator & RFC 826 ARP Suite**.

---

## 1. System Component Architecture

```mermaid
flowchart TD
    subgraph UI["Graphical User Interface Layer (Tkinter)"]
        SGUI["Server GUI (gui/server_app.py)"]
        CGUI["Client GUI (gui/client_app.py)"]
        CVIEW["Wireshark Capture View (gui/capture_view.py)"]
    end

    subgraph PROTO["Core Protocol & Logic Layer (Standard Library)"]
        DSRV["DhcpServer (dhcp/server.py)"]
        DCLI["DhcpClient (dhcp/client.py)"]
        POOL["LeasePool (dhcp/pool.py)"]
        PKT["DhcpPacket (dhcp/packet.py)"]
        DISSECT["Protocol Dissector (dhcp/dissect.py)"]
        ARP["ArpPacket & ArpTable (arp/)"]
    end

    subgraph NET["Emulated Network Transport"]
        UDP["UDP Sockets (Loopback / LAN)"]
        RING["PacketCapture Buffer (dhcp/capture.py)"]
        PCAP["Libpcap File (.pcap)"]
    end

    SGUI --> DSRV
    CGUI --> DCLI
    DSRV --> POOL
    DSRV --> PKT
    DCLI --> PKT
    DCLI --> ARP
    DSRV --> UDP
    DCLI --> UDP
    UDP --> RING
    RING --> CVIEW
    RING --> PCAP
    CVIEW --> DISSECT
```

---

## 2. Standard D-O-R-A Protocol Flow

The standard 4-way Dynamic Host Configuration handshake:

```mermaid
sequenceDiagram
    autonumber
    participant Client as DHCP Client (0.0.0.0:68)
    participant Server as DHCP Server (192.168.1.1:67)

    Note over Client,Server: Phase 1: Discovery
    Client->>Server: DHCPDISCOVER (Broadcast 255.255.255.255)<br/>ciaddr: 0.0.0.0, xid: 0x39a2c1, Option 12: "PC-1"
    
    Note over Client,Server: Phase 2: Offer
    Server->>Client: DHCPOFFER (Broadcast / Unicast)<br/>yiaddr: 192.168.1.100, Option 54 (Server ID): 192.168.1.1, Lease: 120s

    Note over Client,Server: Phase 3: Request
    Client->>Server: DHCPREQUEST (Broadcast 255.255.255.255)<br/>Option 50 (Requested IP): 192.168.1.100, Option 54: 192.168.1.1

    Note over Client,Server: Phase 4: Acknowledgment
    Server->>Client: DHCPACK (Broadcast / Unicast)<br/>yiaddr: 192.168.1.100, Netmask, Gateway, DNS, T1: 60s, T2: 105s
    Note over Client: Client verifies with ARP Probe, then transitions to BOUND
```

---

## 3. Multiple Competing DHCP Servers (Option 54 Selection)

When two or more DHCP servers exist on the same broadcast link:

```mermaid
sequenceDiagram
    autonumber
    participant Client as Client (0.0.0.0)
    participant SrvA as Server A (192.168.1.1)
    participant SrvB as Server B (192.168.2.1)

    Client->>SrvA: DHCPDISCOVER (Broadcast)
    Client->>SrvB: DHCPDISCOVER (Broadcast)

    SrvA->>Client: DHCPOFFER (yiaddr: 192.168.1.100, Option 54: 192.168.1.1)
    SrvB->>Client: DHCPOFFER (yiaddr: 192.168.2.100, Option 54: 192.168.2.1)

    Note over Client: Client picks Server A's offer (first arrived)

    Client->>SrvA: DHCPREQUEST (Option 54: 192.168.1.1, Option 50: 192.168.1.100)
    Client->>SrvB: DHCPREQUEST (Option 54: 192.168.1.1, Option 50: 192.168.1.100)

    SrvA->>Client: DHCPACK (Commits lease 192.168.1.100)
    Note over SrvB: Server B sees Option 54 != 192.2.1.<br/>Implicit Decline -> Releases 192.168.2.100 back to pool!
```

---

## 4. Address Conflict Detection (ARP Probe & DHCPDECLINE)

RFC 2131 Section 3.1.5 and RFC 5227 Duplicate Address Detection (DAD):

```mermaid
sequenceDiagram
    autonumber
    participant Client as DHCP Client
    participant Server as DHCP Server
    participant Rogue as Host on LAN (192.168.1.100)

    Client->>Server: DHCPDISCOVER
    Server->>Client: DHCPOFFER (yiaddr: 192.168.1.100)
    Client->>Server: DHCPREQUEST (Requested: 192.168.1.100)
    Server->>Client: DHCPACK (yiaddr: 192.168.1.100)

    Note over Client: ARP Probe before binding
    Client->>Rogue: ARP Request (Who has 192.168.1.100? Tell 0.0.0.0)
    Rogue-->>Client: ARP Reply (192.168.1.100 is at 02:00:5e:xx:xx:xx)

    Note over Client: Conflict detected! Do NOT bind.
    Client->>Server: DHCPDECLINE (Option 50: 192.168.1.100, Option 54: Server IP)
    Note over Server: Server quarantines 192.168.1.100 for decline_hold seconds
    Note over Client: Reverts to INIT and restarts DORA
```

---

## 5. Client State Machine Transitions

```mermaid
stateDiagram-v2
    [*] --> INIT: Power on / No IP
    INIT --> SELECTING: Send DHCPDISCOVER
    SELECTING --> REQUESTING: Receive DHCPOFFER -> Send DHCPREQUEST
    SELECTING --> INIT: Timeout / No offer
    REQUESTING --> BOUND: Receive DHCPACK (and ARP probe clear)
    REQUESTING --> INIT: Receive DHCPNAK or ARP collision (DHCPDECLINE)
    
    BOUND --> RENEWING: Timer T1 expires (50% lease)
    RENEWING --> BOUND: Receive DHCPACK (unicast)
    RENEWING --> REBINDING: Timer T2 expires (87.5% lease) without reply
    
    REBINDING --> BOUND: Receive DHCPACK (broadcast)
    REBINDING --> INIT: Lease expires (100%) without reply
    
    BOUND --> INIT: User clicks "Release" (DHCPRELEASE)
```

---

## 6. Packet Layout & Wire Structure

### Fixed BOOTP Header (236 Bytes)
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     op (1)    |   htype (1)   |   hlen (6)    |   hops (0)    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            xid (4)                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           secs (2)            |           flags (2)           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          ciaddr (4)                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          yiaddr (4)                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          siaddr (4)                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          giaddr (4)                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          chaddr (16)                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          sname (64)                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          file (128)                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 magic cookie (4): 0x63 0x82 0x53 0x63         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    options (variable TLVs) ...                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

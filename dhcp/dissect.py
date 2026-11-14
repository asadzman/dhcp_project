"""Wireshark-style protocol dissector: turns a CapturedPacket into a tree of labelled byte ranges."""
from __future__ import annotations

import socket
import struct
import time
from dataclasses import dataclass, field
from typing import List

from .capture import CapturedPacket
from .constants import FIXED_HEADER_LEN, MAGIC_COOKIE, MsgType, Opt
from .utils import bytes_to_mac

OPT_NAMES = {1: "Subnet Mask", 3: "Router", 6: "Domain Name Server", 12: "Host Name",
             15: "Domain Name", 28: "Broadcast Address", 50: "Requested IP Address",
             51: "IP Address Lease Time", 53: "DHCP Message Type", 54: "DHCP Server Identifier",
             55: "Parameter Request List", 58: "Renewal Time Value", 59: "Rebinding Time Value",
             61: "Client identifier", 255: "End"}
MSG_NAMES = {1: "Discover", 2: "Offer", 3: "Request", 4: "Decline", 5: "ACK", 6: "NAK", 7: "Release", 8: "Inform"}


@dataclass
class Node:
    label: str
    start: int = -1             # byte range inside the DHCP payload (-1 = no bytes, e.g. emulated headers)
    length: int = 0
    children: List["Node"] = field(default_factory=list)

    def add(self, label: str, start: int = -1, length: int = 0) -> "Node":
        n = Node(label, start, length)
        self.children.append(n)
        return n


def _ip(b: bytes) -> str:
    return socket.inet_ntoa(b)


def dissect(cp: CapturedPacket) -> List[Node]:
    raw, p = cp.raw, cp.pkt
    top: List[Node] = []

    fr = Node("Frame %d: %d bytes on wire (%d bits)   [emulated]" % (cp.no, cp.length, cp.length * 8))
    fr.add("Arrival Time: %s" % time.strftime("%b %d, %Y %H:%M:%S", time.localtime(cp.wall_time)))
    fr.add("Time since first packet in capture: %.6f seconds" % cp.rel_time)
    fr.add("Frame Number: %d" % cp.no)
    fr.add("Capture direction: %s" % ("received" if cp.direction == "rx" else "sent"))
    fr.add("Real transport used by emulator: UDP %s:%d -> %s:%d" % (*cp.real_src, *cp.real_dst))
    top.append(fr)

    ip = Node("Internet Protocol Version 4, Src: %s, Dst: %s   [emulated]" % (cp.src, cp.dst))
    ip.add("Source Address: %s" % cp.src)
    ip.add("Destination Address: %s" % cp.dst)
    ip.add("Protocol: UDP (17)")
    top.append(ip)

    udp = Node("User Datagram Protocol, Src Port: %d, Dst Port: %d   [emulated]" % (cp.sport, cp.dport))
    udp.add("Source Port: %d" % cp.sport)
    udp.add("Destination Port: %d" % cp.dport)
    udp.add("Length: %d" % (cp.length + 8))
    top.append(udp)

    d = Node("Dynamic Host Configuration Protocol (%s)" % cp.type_name, 0, len(raw))
    d.add("Message type: Boot %s (%d)" % ("Request" if raw[0] == 1 else "Reply", raw[0]), 0, 1)
    d.add("Hardware type: Ethernet (0x%02x)" % raw[1], 1, 1)
    d.add("Hardware address length: %d" % raw[2], 2, 1)
    d.add("Hops: %d" % raw[3], 3, 1)
    d.add("Transaction ID: 0x%08x" % struct.unpack("!I", raw[4:8])[0], 4, 4)
    d.add("Seconds elapsed: %d" % struct.unpack("!H", raw[8:10])[0], 8, 2)
    flags = struct.unpack("!H", raw[10:12])[0]
    fl = d.add("Bootp flags: 0x%04x (%s)" % (flags, "Broadcast" if flags & 0x8000 else "Unicast"), 10, 2)
    fl.add("%d... .... .... .... = Broadcast flag: %s" % (1 if flags & 0x8000 else 0,
                                                         "Broadcast" if flags & 0x8000 else "Unicast"), 10, 2)
    fl.add(".000 0000 0000 0000 = Reserved flags: 0x0000", 10, 2)
    d.add("Client IP address: %s" % _ip(raw[12:16]), 12, 4)
    d.add("Your (client) IP address: %s" % _ip(raw[16:20]), 16, 4)
    d.add("Next server IP address: %s" % _ip(raw[20:24]), 20, 4)
    d.add("Relay agent IP address: %s" % _ip(raw[24:28]), 24, 4)
    d.add("Client MAC address: %s (Ethernet)" % bytes_to_mac(raw[28:34]), 28, 6)
    d.add("Client hardware address padding: %s" % raw[34:44].hex(), 34, 10)
    d.add("Server host name not given", 44, 64)
    d.add("Boot file name not given", 108, 128)
    d.add("Magic cookie: DHCP", 236, 4)

    i = FIXED_HEADER_LEN + 4
    while i < len(raw):
        code = raw[i]
        if code == Opt.END:
            o = d.add("Option: (255) End", i, 1)
            o.add("Option End: 255", i, 1)
            i += 1
            continue
        if code == Opt.PAD:
            d.add("Padding", i, 1)
            i += 1
            continue
        ln = raw[i + 1]
        val = raw[i + 2:i + 2 + ln]
        name = OPT_NAMES.get(code, "Unknown option")
        title = "Option: (%d) %s" % (code, name)
        if code == Opt.MSG_TYPE and val:
            title += " (%s)" % MSG_NAMES.get(val[0], val[0])
        o = d.add(title, i, 2 + ln)
        o.add("Length: %d" % ln, i + 1, 1)
        v = i + 2
        if code == Opt.MSG_TYPE and val:
            o.add("DHCP: %s (%d)" % (MSG_NAMES.get(val[0], "?"), val[0]), v, 1)
        elif code in (Opt.SUBNET_MASK, Opt.ROUTER, Opt.DNS, Opt.REQUESTED_IP, Opt.SERVER_ID):
            label = {1: "Subnet Mask", 3: "Router", 6: "Domain Name Server", 50: "Requested IP Address",
                     54: "DHCP Server Identifier"}[code]
            for k in range(0, len(val) - 3, 4):
                o.add("%s: %s" % (label, _ip(val[k:k + 4])), v + k, 4)
        elif code in (Opt.LEASE_TIME, Opt.RENEWAL_T1, Opt.REBINDING_T2) and len(val) == 4:
            secs = struct.unpack("!I", val)[0]
            o.add("%s: (%ds) %d seconds" % (name, secs, secs), v, 4)
        elif code == Opt.PARAM_REQUEST:
            for k, c in enumerate(val):
                o.add("Parameter Request List Item: (%d) %s" % (c, OPT_NAMES.get(c, "Unknown")), v + k, 1)
        elif code in (Opt.HOST_NAME, Opt.DOMAIN_NAME):
            text = val.decode("utf-8", errors="replace")
            o.add("%s: %s" % (name, text), v, ln)
        elif code == Opt.BROADCAST_ADDR and len(val) == 4:
            o.add("Broadcast Address: %s" % _ip(val), v, 4)
        elif code == Opt.CLIENT_ID and len(val) == 7:
            o.add("Hardware type: Ethernet (0x%02x)" % val[0], v, 1)
            o.add("Client MAC address: %s" % bytes_to_mac(val[1:]), v + 1, 6)
        else:
            o.add("Value: %s" % val.hex(), v, ln)
        i += 2 + ln
    top.append(d)
    return top


def hex_lines(raw: bytes) -> List[str]:
    """'0000  44 48 ...  |ascii|' lines. Byte i sits at column hex_col(i) / ascii_col(i)."""
    out = []
    for off in range(0, len(raw), 16):
        chunk = raw[off:off + 16]
        hx = ""
        for j in range(16):
            if j == 8:
                hx += " "
            hx += ("%02x " % chunk[j]) if j < len(chunk) else "   "
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append("%04x  %s %s" % (off, hx, asc))
    return out


def hex_col(i: int) -> int:
    j = i % 16
    return 6 + 3 * j + (1 if j >= 8 else 0)


def ascii_col(i: int) -> int:
    return 56 + (i % 16)

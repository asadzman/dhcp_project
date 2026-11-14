"""Packet capture: every DHCP packet the server/client sends or receives is recorded here
(like a mini Wireshark capture) so a GUI can list and dissect it."""
from __future__ import annotations

import socket
import struct
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, List, Optional, Tuple

from .constants import BOOTREQUEST, BROADCAST_FLAG, MsgType
from .packet import DhcpPacket
from .utils import mac_to_bytes

BROADCAST_IP = "255.255.255.255"
TYPE_LABEL = {MsgType.DISCOVER: "Discover", MsgType.OFFER: "Offer", MsgType.REQUEST: "Request",
              MsgType.DECLINE: "Decline", MsgType.ACK: "ACK", MsgType.NAK: "NAK",
              MsgType.RELEASE: "Release", MsgType.INFORM: "Inform"}


@dataclass
class CapturedPacket:
    no: int
    rel_time: float             # seconds since the first packet of the capture
    wall_time: float
    direction: str              # "rx" or "tx" (relative to whoever owns the capture)
    src: str                    # emulated L3 source (what a real LAN capture would show)
    dst: str
    sport: int
    dport: int
    real_src: Tuple[str, int]   # actual UDP socket endpoints used by the emulator
    real_dst: Tuple[str, int]
    raw: bytes
    pkt: Any                    # DhcpPacket or ArpPacket
    proto: str = "DHCP"

    @property
    def length(self) -> int:
        return len(self.raw)

    @property
    def type_name(self) -> str:
        if self.proto == "ARP":
            return "ARP"
        return TYPE_LABEL.get(getattr(self.pkt, "msg_type", None), "?")

    @property
    def info(self) -> str:
        if self.proto == "ARP":
            return getattr(self.pkt, "summary", lambda: "ARP Packet")()
        return "DHCP %-8s - Transaction ID 0x%08x" % (self.type_name, getattr(self.pkt, "xid", 0))

    def haystack(self) -> str:
        if self.proto == "ARP":
            return " ".join([str(self.no), self.src, self.dst, "arp", self.info]).lower()
        return " ".join([str(self.no), self.src, self.dst, "dhcp", self.type_name, getattr(self.pkt, "chaddr", ""),
                         "0x%08x" % getattr(self.pkt, "xid", 0), getattr(self.pkt, "yiaddr", ""),
                         getattr(self.pkt, "ciaddr", "")]).lower()


class PacketCapture:
    def __init__(self):
        self.packets: List[CapturedPacket] = []
        self._lock = threading.Lock()
        self._listeners: List[Callable[[CapturedPacket], None]] = []
        self._t0: Optional[float] = None

    def subscribe(self, fn: Callable[[CapturedPacket], None]) -> None:
        self._listeners.append(fn)

    def add(self, raw: bytes, real_src, real_dst, direction: str,
            server_ip: Optional[str] = None) -> Optional[CapturedPacket]:
        try:
            pkt = DhcpPacket.decode(raw)
        except ValueError:
            return None
        if pkt.op == BOOTREQUEST:
            src = pkt.ciaddr
            dst = server_ip if (pkt.ciaddr != "0.0.0.0" and server_ip) else BROADCAST_IP
            sport, dport = 68, 67
        else:
            src = server_ip or pkt.siaddr
            bcast = (pkt.flags & BROADCAST_FLAG) or pkt.msg_type == MsgType.NAK or pkt.yiaddr == "0.0.0.0"
            dst = BROADCAST_IP if bcast else pkt.yiaddr
            sport, dport = 67, 68
        now = time.time()
        with self._lock:
            if self._t0 is None:
                self._t0 = now
            cp = CapturedPacket(len(self.packets) + 1, now - self._t0, now, direction, src, dst, sport, dport,
                                tuple(real_src), tuple(real_dst), raw, pkt)
            self.packets.append(cp)
        for fn in list(self._listeners):
            fn(cp)
        return cp

    def add_arp(self, raw: bytes, real_src, real_dst, direction: str,
                arp_pkt: Any = None) -> Optional[CapturedPacket]:
        if arp_pkt is None:
            from arp.packet import ArpPacket
            try:
                arp_pkt = ArpPacket.decode(raw)
            except Exception:
                return None
        src = arp_pkt.sender_ip
        dst = arp_pkt.target_ip if arp_pkt.op == 2 else BROADCAST_IP
        now = time.time()
        with self._lock:
            if self._t0 is None:
                self._t0 = now
            cp = CapturedPacket(
                no=len(self.packets) + 1,
                rel_time=now - self._t0,
                wall_time=now,
                direction=direction,
                src=src,
                dst=dst,
                sport=0,
                dport=0,
                real_src=tuple(real_src),
                real_dst=tuple(real_dst),
                raw=raw,
                pkt=arp_pkt,
                proto="ARP"
            )
            self.packets.append(cp)
        for fn in list(self._listeners):
            fn(cp)
        return cp

    def get(self, no: int) -> Optional[CapturedPacket]:
        with self._lock:
            return self.packets[no - 1] if 1 <= no <= len(self.packets) else None

    def snapshot(self) -> List[CapturedPacket]:
        with self._lock:
            return list(self.packets)

    def clear(self) -> None:
        with self._lock:
            self.packets.clear()
            self._t0 = None

    def export_pcap(self, filepath: str) -> int:
        """Export all captured packets to a genuine libpcap file readable by Wireshark."""
        with self._lock:
            pkts = list(self.packets)

        # libpcap global header: magic, v2.4, thiszone=0, sigfigs=0, snaplen=65535, linktype=1 (Ethernet)
        global_hdr = struct.pack("!IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

        with open(filepath, "wb") as f:
            f.write(global_hdr)
            for cp in pkts:
                if cp.proto == "ARP":
                    # Native Ethernet II ARP Frame
                    try:
                        src_mac = mac_to_bytes(cp.pkt.sender_mac)
                    except Exception:
                        src_mac = b"\x02\x00\x5e\x00\x00\x01"
                    try:
                        is_bcast = (cp.pkt.target_mac == "00:00:00:00:00:00" or cp.pkt.target_mac == "ff:ff:ff:ff:ff:ff")
                        dst_mac = b"\xff\xff\xff\xff\xff\xff" if is_bcast else mac_to_bytes(cp.pkt.target_mac)
                    except Exception:
                        dst_mac = b"\xff\xff\xff\xff\xff\xff"
                    eth_hdr = dst_mac + src_mac + struct.pack("!H", 0x0806)  # EtherType 0x0806 (ARP)
                    frame = eth_hdr + cp.raw
                else:
                    # 1. Ethernet Header (14 bytes)
                    try:
                        chaddr_bytes = mac_to_bytes(cp.pkt.chaddr)
                    except Exception:
                        chaddr_bytes = b"\x02\x00\x5e\x00\x00\x01"

                    if cp.pkt.op == BOOTREQUEST:
                        src_mac = chaddr_bytes
                        dst_mac = b"\xff\xff\xff\xff\xff\xff"
                    else:
                        src_mac = b"\x02\x00\x5e\xfe\x00\x01"  # Emulated server MAC
                        is_bcast = (cp.dst == BROADCAST_IP or (cp.pkt.flags & BROADCAST_FLAG))
                        dst_mac = b"\xff\xff\xff\xff\xff\xff" if is_bcast else chaddr_bytes

                    eth_hdr = dst_mac + src_mac + struct.pack("!H", 0x0800)  # EtherType IPv4

                    # 2. IPv4 Header (20 bytes)
                    total_ip_len = 20 + 8 + len(cp.raw)
                    try:
                        src_ip_b = socket.inet_aton(cp.src)
                    except OSError:
                        src_ip_b = socket.inet_aton("0.0.0.0")
                    try:
                        dst_ip_b = socket.inet_aton(cp.dst)
                    except OSError:
                        dst_ip_b = socket.inet_aton(BROADCAST_IP)

                    ip_hdr_no_csum = struct.pack("!BBHHHBBH4s4s",
                                                 0x45, 0, total_ip_len, cp.no & 0xffff,
                                                 0x4000, 64, 17, 0, src_ip_b, dst_ip_b)

                    # Calculate IPv4 checksum
                    csum = 0
                    for i in range(0, 20, 2):
                        csum += (ip_hdr_no_csum[i] << 8) + ip_hdr_no_csum[i + 1]
                    while csum >> 16:
                        csum = (csum & 0xffff) + (csum >> 16)
                    csum = (~csum) & 0xffff

                    ip_hdr = struct.pack("!BBHHHBBH4s4s",
                                         0x45, 0, total_ip_len, cp.no & 0xffff,
                                         0x4000, 64, 17, csum, src_ip_b, dst_ip_b)

                    # 3. UDP Header (8 bytes)
                    udp_hdr = struct.pack("!HHHH", cp.sport, cp.dport, 8 + len(cp.raw), 0)

                    # Complete frame
                    frame = eth_hdr + ip_hdr + udp_hdr + cp.raw

                # Packet Record Header (16 bytes)
                sec = int(cp.wall_time)
                usec = int((cp.wall_time - sec) * 1_000_000)
                pkt_hdr = struct.pack("!IIII", sec, usec, len(frame), len(frame))

                f.write(pkt_hdr + frame)

        return len(pkts)

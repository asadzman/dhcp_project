"""Packet capture: every DHCP packet the server/client sends or receives is recorded here
(like a mini Wireshark capture) so a GUI can list and dissect it."""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Callable, List, Optional, Tuple

from .constants import BOOTREQUEST, BROADCAST_FLAG, MsgType
from .packet import DhcpPacket

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
    pkt: DhcpPacket

    @property
    def length(self) -> int:
        return len(self.raw)

    @property
    def type_name(self) -> str:
        return TYPE_LABEL.get(self.pkt.msg_type, "?")

    @property
    def info(self) -> str:
        return "DHCP %-8s - Transaction ID 0x%08x" % (self.type_name, self.pkt.xid)

    def haystack(self) -> str:
        return " ".join([str(self.no), self.src, self.dst, "dhcp", self.type_name, self.pkt.chaddr,
                         "0x%08x" % self.pkt.xid, self.pkt.yiaddr, self.pkt.ciaddr]).lower()


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

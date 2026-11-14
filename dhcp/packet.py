"""DHCP/BOOTP packet: encode and decode the RFC 2131 wire format."""
from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .constants import (BOOTREPLY, BOOTREQUEST, BROADCAST_FLAG, FIXED_HEADER_LEN,
                        HTYPE_ETHERNET, MAGIC_COOKIE, MsgType, Opt)
from .utils import bytes_to_mac, mac_to_bytes

# op htype hlen hops | xid | secs flags | ciaddr yiaddr siaddr giaddr | chaddr | sname | file
_HDR = struct.Struct("!BBBBIHH4s4s4s4s16s64s128s")
assert _HDR.size == FIXED_HEADER_LEN


@dataclass
class DhcpPacket:
    op: int
    xid: int
    chaddr: str
    ciaddr: str = "0.0.0.0"
    yiaddr: str = "0.0.0.0"
    siaddr: str = "0.0.0.0"
    giaddr: str = "0.0.0.0"
    secs: int = 0
    flags: int = BROADCAST_FLAG
    hops: int = 0
    options: Dict[int, bytes] = field(default_factory=dict)

    # ---------- option helpers ----------
    @property
    def msg_type(self) -> Optional[MsgType]:
        raw = self.options.get(Opt.MSG_TYPE)
        try:
            return MsgType(raw[0]) if raw else None
        except ValueError:
            return None

    def set_msg_type(self, t: MsgType) -> "DhcpPacket":
        self.options[Opt.MSG_TYPE] = bytes([int(t)])
        return self

    def set_ip(self, code: int, *ips: str) -> "DhcpPacket":
        self.options[code] = b"".join(socket.inet_aton(i) for i in ips)
        return self

    def get_ips(self, code: int) -> List[str]:
        raw = self.options.get(code, b"")
        return [socket.inet_ntoa(raw[i:i + 4]) for i in range(0, len(raw) - 3, 4)]

    def get_ip(self, code: int) -> Optional[str]:
        ips = self.get_ips(code)
        return ips[0] if ips else None

    def set_u32(self, code: int, value: int) -> "DhcpPacket":
        self.options[code] = struct.pack("!I", value)
        return self

    def get_u32(self, code: int) -> Optional[int]:
        raw = self.options.get(code)
        return struct.unpack("!I", raw)[0] if raw and len(raw) == 4 else None

    # ---------- wire format ----------
    def encode(self) -> bytes:
        hdr = _HDR.pack(self.op, HTYPE_ETHERNET, 6, self.hops, self.xid, self.secs, self.flags,
                        socket.inet_aton(self.ciaddr), socket.inet_aton(self.yiaddr),
                        socket.inet_aton(self.siaddr), socket.inet_aton(self.giaddr),
                        mac_to_bytes(self.chaddr) + b"\0" * 10, b"\0" * 64, b"\0" * 128)
        body = bytearray(MAGIC_COOKIE)
        for code, val in self.options.items():
            body += bytes([code, len(val)]) + val
        body.append(Opt.END)
        return hdr + bytes(body)

    @classmethod
    def decode(cls, data: bytes) -> "DhcpPacket":
        if len(data) < FIXED_HEADER_LEN + 4 or data[FIXED_HEADER_LEN:FIXED_HEADER_LEN + 4] != MAGIC_COOKIE:
            raise ValueError("not a DHCP packet")
        (op, _ht, _hl, hops, xid, secs, flags, ci, yi, si, gi,
         chaddr, _sname, _file) = _HDR.unpack(data[:FIXED_HEADER_LEN])
        options: Dict[int, bytes] = {}
        i = FIXED_HEADER_LEN + 4
        while i < len(data) and data[i] != Opt.END:
            if data[i] == Opt.PAD:
                i += 1
                continue
            if i + 1 >= len(data):
                raise ValueError("truncated option")
            code, ln = data[i], data[i + 1]
            options[code] = data[i + 2:i + 2 + ln]
            i += 2 + ln
        return cls(op, xid, bytes_to_mac(chaddr[:6]), socket.inet_ntoa(ci), socket.inet_ntoa(yi),
                   socket.inet_ntoa(si), socket.inet_ntoa(gi), secs, flags, hops, options)

    def summary(self) -> str:
        t = self.msg_type
        return "%s xid=0x%08x chaddr=%s ciaddr=%s yiaddr=%s" % (
            t.name if t else "?", self.xid, self.chaddr, self.ciaddr, self.yiaddr)


def new_request_packet(xid: int, mac: str, msg_type: MsgType) -> DhcpPacket:
    pkt = DhcpPacket(BOOTREQUEST, xid, mac)
    pkt.set_msg_type(msg_type)
    pkt.options[Opt.CLIENT_ID] = b"\x01" + mac_to_bytes(mac)
    return pkt


def new_reply_packet(request: DhcpPacket, msg_type: MsgType, server_ip: str, yiaddr: str = "0.0.0.0") -> DhcpPacket:
    pkt = DhcpPacket(BOOTREPLY, request.xid, request.chaddr, yiaddr=yiaddr, siaddr=server_ip,
                     flags=request.flags)
    pkt.set_msg_type(msg_type)
    pkt.set_ip(Opt.SERVER_ID, server_ip)
    return pkt

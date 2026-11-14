"""RFC 826 ARP Packet serialization and parsing."""
from __future__ import annotations

import socket
import struct
from dataclasses import dataclass
from typing import Optional

from dhcp.utils import bytes_to_mac, mac_to_bytes
from .constants import (ARP_HEADER_LEN, ArpOpcode, HLEN_ETHERNET, HTYPE_ETHERNET,
                        PLEN_IPV4, PTYPE_IPV4)

# 28 bytes: htype(2), ptype(2), hlen(1), plen(1), oper(2), sha(6), spa(4), tha(6), tpa(4)
_ARP_STRUCT = struct.Struct("!HHBBH6s4s6s4s")
assert _ARP_STRUCT.size == ARP_HEADER_LEN


@dataclass
class ArpPacket:
    op: int
    sender_mac: str
    sender_ip: str
    target_mac: str
    target_ip: str
    hw_type: int = HTYPE_ETHERNET
    proto_type: int = PTYPE_IPV4

    def encode(self) -> bytes:
        return _ARP_STRUCT.pack(
            self.hw_type, self.proto_type,
            HLEN_ETHERNET, PLEN_IPV4, self.op,
            mac_to_bytes(self.sender_mac), socket.inet_aton(self.sender_ip),
            mac_to_bytes(self.target_mac), socket.inet_aton(self.target_ip),
        )

    @classmethod
    def decode(cls, data: bytes) -> "ArpPacket":
        if len(data) < ARP_HEADER_LEN:
            raise ValueError("packet too short for ARP (got %d bytes)" % len(data))
        hw, proto, hlen, plen, op, sha, spa, tha, tpa = _ARP_STRUCT.unpack(data[:ARP_HEADER_LEN])
        if hlen != HLEN_ETHERNET or plen != PLEN_IPV4:
            raise ValueError("unsupported address lengths in ARP packet")
        return cls(
            op=op,
            sender_mac=bytes_to_mac(sha),
            sender_ip=socket.inet_ntoa(spa),
            target_mac=bytes_to_mac(tha),
            target_ip=socket.inet_ntoa(tpa),
            hw_type=hw,
            proto_type=proto,
        )

    @property
    def is_probe(self) -> bool:
        """RFC 5227 Address Conflict Detection Probe: sender IP is 0.0.0.0."""
        return self.op == ArpOpcode.REQUEST and self.sender_ip == "0.0.0.0"

    @property
    def is_gratuitous(self) -> bool:
        """Gratuitous ARP announcement: sender IP equals target IP."""
        return self.sender_ip == self.target_ip

    def summary(self) -> str:
        name = "REQUEST" if self.op == ArpOpcode.REQUEST else ("REPLY" if self.op == ArpOpcode.REPLY else f"OP-{self.op}")
        if self.is_probe:
            return f"ARP PROBE for {self.target_ip} from {self.sender_mac}"
        if self.is_gratuitous:
            return f"ARP GRATUITOUS announcement for {self.sender_ip} ({self.sender_mac})"
        if self.op == ArpOpcode.REQUEST:
            return f"ARP Who has {self.target_ip}? Tell {self.sender_ip} [{self.sender_mac}]"
        return f"ARP {self.sender_ip} is at {self.sender_mac}"


# ---------- Factory Helpers ----------
def new_arp_request(sender_mac: str, sender_ip: str, target_ip: str) -> ArpPacket:
    """Standard ARP Who-has query."""
    return ArpPacket(
        op=int(ArpOpcode.REQUEST),
        sender_mac=sender_mac,
        sender_ip=sender_ip,
        target_mac="00:00:00:00:00:00",
        target_ip=target_ip,
    )


def new_arp_reply(sender_mac: str, sender_ip: str, target_mac: str, target_ip: str) -> ArpPacket:
    """Standard unicast ARP reply."""
    return ArpPacket(
        op=int(ArpOpcode.REPLY),
        sender_mac=sender_mac,
        sender_ip=sender_ip,
        target_mac=target_mac,
        target_ip=target_ip,
    )


def new_arp_probe(sender_mac: str, target_ip: str) -> ArpPacket:
    """RFC 5227 Duplicate Address Detection Probe before claiming an IP."""
    return ArpPacket(
        op=int(ArpOpcode.REQUEST),
        sender_mac=sender_mac,
        sender_ip="0.0.0.0",
        target_mac="00:00:00:00:00:00",
        target_ip=target_ip,
    )


def new_gratuitous_arp(sender_mac: str, ip: str) -> ArpPacket:
    """RFC 5227 Gratuitous ARP announcement sent upon DHCP bind."""
    return ArpPacket(
        op=int(ArpOpcode.REQUEST),
        sender_mac=sender_mac,
        sender_ip=ip,
        target_mac="ff:ff:ff:ff:ff:ff",
        target_ip=ip,
    )

"""Small address helpers shared by every module."""
import random
import socket
import struct


def mac_to_bytes(mac: str) -> bytes:
    parts = mac.split(":")
    if len(parts) != 6:
        raise ValueError("bad MAC: %r" % mac)
    return bytes(int(p, 16) for p in parts)


def bytes_to_mac(raw: bytes) -> str:
    return ":".join("%02x" % b for b in raw)


def ip_to_int(ip: str) -> int:
    return struct.unpack("!I", socket.inet_aton(ip))[0]


def int_to_ip(value: int) -> str:
    return socket.inet_ntoa(struct.pack("!I", value))


def is_valid_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def is_valid_mac(mac: str) -> bool:
    try:
        mac_to_bytes(mac)
        return True
    except ValueError:
        return False


def random_mac() -> str:
    """Locally-administered unicast MAC."""
    return bytes_to_mac(bytes([0x02, 0x00, 0x5E] + [random.randint(0, 255) for _ in range(3)]))

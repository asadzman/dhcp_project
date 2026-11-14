"""Protocol constants for the DHCP emulator (RFC 2131 / RFC 2132)."""
from enum import IntEnum

LOOPBACK = "127.0.0.1"
SERVER_PORT = 6767          # real DHCP uses UDP 67/68 (needs root), so we shift the ports
BOOTREQUEST = 1
BOOTREPLY = 2
HTYPE_ETHERNET = 1
MAGIC_COOKIE = b"\x63\x82\x53\x63"
FIXED_HEADER_LEN = 236
BROADCAST_FLAG = 0x8000


class MsgType(IntEnum):
    DISCOVER = 1
    OFFER = 2
    REQUEST = 3
    DECLINE = 4
    ACK = 5
    NAK = 6
    RELEASE = 7
    INFORM = 8


class Opt(IntEnum):
    PAD = 0
    SUBNET_MASK = 1
    ROUTER = 3
    DNS = 6
    HOST_NAME = 12
    DOMAIN_NAME = 15
    BROADCAST_ADDR = 28
    REQUESTED_IP = 50
    LEASE_TIME = 51
    MSG_TYPE = 53
    SERVER_ID = 54
    PARAM_REQUEST = 55
    RENEWAL_T1 = 58
    REBINDING_T2 = 59
    CLIENT_ID = 61
    END = 255

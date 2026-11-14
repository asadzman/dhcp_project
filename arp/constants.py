"""ARP Protocol Constants (RFC 826 / RFC 5227)."""
from enum import IntEnum

ETHERTYPE_ARP = 0x0806
HTYPE_ETHERNET = 1
PTYPE_IPV4 = 0x0800
HLEN_ETHERNET = 6
PLEN_IPV4 = 4
ARP_HEADER_LEN = 28


class ArpOpcode(IntEnum):
    REQUEST = 1
    REPLY = 2
    RREQUEST = 3
    RREPLY = 4

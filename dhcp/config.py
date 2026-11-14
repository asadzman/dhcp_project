"""Server configuration."""
from dataclasses import dataclass, field
from typing import Dict, List

from .constants import LOOPBACK, SERVER_PORT
from .utils import ip_to_int, is_valid_ip, is_valid_mac


@dataclass
class ServerConfig:
    server_ip: str = "192.168.1.1"          # identity put in option 54 (not the socket address)
    pool_start: str = "192.168.1.100"
    pool_end: str = "192.168.1.150"
    subnet_mask: str = "255.255.255.0"
    router: str = "192.168.1.1"
    dns: List[str] = field(default_factory=lambda: ["8.8.8.8"])
    lease_time: int = 120                   # seconds
    offer_hold: int = 10                    # seconds an OFFER keeps its address reserved
    decline_hold: int = 60                  # seconds a DECLINEd address is quarantined
    reservations: Dict[str, str] = field(default_factory=dict)   # mac -> ip (static lease)
    host: str = LOOPBACK
    port: int = SERVER_PORT

    def validate(self) -> None:
        for name in ("server_ip", "pool_start", "pool_end", "subnet_mask", "router"):
            if not is_valid_ip(getattr(self, name)):
                raise ValueError("invalid %s: %r" % (name, getattr(self, name)))
        if not self.dns or not all(is_valid_ip(d) for d in self.dns):
            raise ValueError("invalid DNS list")
        if ip_to_int(self.pool_start) > ip_to_int(self.pool_end):
            raise ValueError("pool_start is greater than pool_end")
        if self.lease_time < 2:
            raise ValueError("lease_time must be >= 2 seconds")
        for mac, ip in self.reservations.items():
            if not is_valid_mac(mac) or not is_valid_ip(ip):
                raise ValueError("bad reservation %s -> %s" % (mac, ip))

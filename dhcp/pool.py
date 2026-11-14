"""Address pool and lease database (no networking in here, so it is easy to unit-test)."""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

from .utils import int_to_ip, ip_to_int


@dataclass
class Lease:
    mac: str
    ip: str
    start: float
    expiry: float
    static: bool = False
    hostname: str = ""

    def remaining(self, now: float) -> int:
        return max(0, int(self.expiry - now))


class LeasePool:
    def __init__(self, start: str, end: str, lease_time: int, offer_hold: int = 10,
                 decline_hold: int = 60, reservations: Optional[Dict[str, str]] = None,
                 clock: Callable[[], float] = time.time):
        self.lo, self.hi = ip_to_int(start), ip_to_int(end)
        self.lease_time, self.offer_hold, self.decline_hold = lease_time, offer_hold, decline_hold
        self.reservations = dict(reservations or {})
        self.clock = clock
        self.leases: Dict[str, Lease] = {}
        self.offers: Dict[str, Lease] = {}
        self.declined: Dict[str, float] = {}      # ip -> quarantine expiry
        self._lock = threading.RLock()

    # ---------- internals ----------
    def _expire(self) -> None:
        now = self.clock()
        for table in (self.leases, self.offers):
            for mac in [m for m, l in table.items() if l.expiry <= now]:
                del table[mac]
        for ip in [i for i, e in self.declined.items() if e <= now]:
            del self.declined[ip]

    def _in_range(self, ip: str) -> bool:
        return self.lo <= ip_to_int(ip) <= self.hi

    def _taken_by_other(self, ip: str, mac: str) -> bool:
        if ip in self.declined:
            return True
        if any(l.ip == ip and m != mac for m, l in self.leases.items()):
            return True
        if any(l.ip == ip and m != mac for m, l in self.offers.items()):
            return True
        return any(rip == ip and rmac != mac for rmac, rip in self.reservations.items())

    # ---------- DHCP operations ----------
    def offer(self, mac: str, requested: Optional[str] = None, hostname: str = "") -> Optional[str]:
        """Pick an address for a DISCOVER and hold it for offer_hold seconds."""
        with self._lock:
            self._expire()
            ip = None
            if mac in self.reservations:
                ip = self.reservations[mac]
            elif mac in self.leases:
                ip = self.leases[mac].ip
            elif mac in self.offers:
                ip = self.offers[mac].ip
            elif requested and self._in_range(requested) and not self._taken_by_other(requested, mac):
                ip = requested
            else:
                for i in range(self.lo, self.hi + 1):
                    cand = int_to_ip(i)
                    if not self._taken_by_other(cand, mac):
                        ip = cand
                        break
            if ip is None:
                return None
            now = self.clock()
            self.offers[mac] = Lease(mac, ip, now, now + self.offer_hold, mac in self.reservations, hostname=hostname)
            return ip

    def commit(self, mac: str, ip: str, hostname: str = "") -> Optional[Lease]:
        """Validate a REQUEST; return the new Lease (-> ACK) or None (-> NAK)."""
        with self._lock:
            self._expire()
            ok = False
            if mac in self.offers and self.offers[mac].ip == ip:
                ok = True                                         # SELECTING
            elif mac in self.leases and self.leases[mac].ip == ip:
                ok = True                                         # RENEWING / REBINDING
            elif mac not in self.offers and mac not in self.leases:
                ok = (self._in_range(ip) or self.reservations.get(mac) == ip) \
                    and not self._taken_by_other(ip, mac)         # INIT-REBOOT
            if not ok:
                return None
            self.offers.pop(mac, None)
            now = self.clock()
            lease = Lease(mac, ip, now, now + self.lease_time, mac in self.reservations, hostname=hostname)
            self.leases[mac] = lease
            return lease

    def release(self, mac: str) -> bool:
        with self._lock:
            self.offers.pop(mac, None)
            return self.leases.pop(mac, None) is not None

    def decline(self, mac: str, ip: str) -> None:
        with self._lock:
            self.offers.pop(mac, None)
            self.leases.pop(mac, None)
            self.declined[ip] = self.clock() + self.decline_hold

    # ---------- views ----------
    def snapshot(self) -> List[Lease]:
        with self._lock:
            self._expire()
            return sorted(self.leases.values(), key=lambda l: ip_to_int(l.ip))

    def offers_snapshot(self) -> List[Lease]:
        with self._lock:
            self._expire()
            return sorted(self.offers.values(), key=lambda l: ip_to_int(l.ip))

    def stats(self) -> Dict[str, int]:
        with self._lock:
            self._expire()
            size = self.hi - self.lo + 1
            return {"size": size, "leased": len(self.leases), "offered": len(self.offers),
                    "declined": len(self.declined)}

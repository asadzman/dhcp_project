"""In-memory ARP Cache Table with TTL support."""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class ArpEntry:
    ip: str
    mac: str
    updated_at: float
    ttl: float = 300.0  # seconds
    static: bool = False

    @property
    def is_expired(self) -> bool:
        if self.static:
            return False
        return (time.time() - self.updated_at) > self.ttl


class ArpTable:
    def __init__(self, default_ttl: float = 300.0):
        self.default_ttl = default_ttl
        self._entries: Dict[str, ArpEntry] = {}  # ip -> ArpEntry
        self._lock = threading.RLock()

    def update(self, ip: str, mac: str, static: bool = False, ttl: Optional[float] = None) -> ArpEntry:
        """Add or refresh an ARP cache mapping."""
        with self._lock:
            entry = ArpEntry(
                ip=ip,
                mac=mac,
                updated_at=time.time(),
                ttl=ttl if ttl is not None else self.default_ttl,
                static=static,
            )
            self._entries[ip] = entry
            return entry

    def lookup(self, ip: str) -> Optional[str]:
        """Look up MAC by IP. Returns None if absent or expired."""
        with self._lock:
            entry = self._entries.get(ip)
            if entry is None:
                return None
            if entry.is_expired:
                del self._entries[ip]
                return None
            return entry.mac

    def remove(self, ip: str) -> bool:
        """Delete an IP mapping."""
        with self._lock:
            return self._entries.pop(ip, None) is not None

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()

    def snapshot(self) -> List[ArpEntry]:
        """Return non-expired entries sorted by IP."""
        with self._lock:
            now = time.time()
            alive = []
            for ip in list(self._entries.keys()):
                entry = self._entries[ip]
                if entry.is_expired:
                    del self._entries[ip]
                else:
                    alive.append(entry)
            return sorted(alive, key=lambda e: e.ip)

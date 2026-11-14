"""ARP Networking Engine: UDP socket communication, live packet handling, and table resolution."""
from __future__ import annotations

import socket
import threading
import time
from typing import Callable, Dict, List, Optional, Tuple

from dhcp.capture import PacketCapture
from dhcp.eventlog import EventLog
from .constants import ArpOpcode
from .packet import (ArpPacket, new_arp_probe, new_arp_reply, new_arp_request,
                     new_gratuitous_arp)
from .table import ArpTable

DEFAULT_ARP_PORT = 6868


class ArpEngine:
    def __init__(self, mac: str, ip: str, port: int = DEFAULT_ARP_PORT,
                 peers: Optional[List[Tuple[str, int]]] = None,
                 log: Optional[EventLog] = None, capture: Optional[PacketCapture] = None,
                 table: Optional[ArpTable] = None):
        self.mac = mac
        self.ip = ip
        self.port = port
        self.peers = list(peers or [])
        self.log = log or EventLog()
        self.capture = capture
        self.table = table or ArpTable()
        self.sock: Optional[socket.socket] = None
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._waiters: Dict[str, threading.Event] = {}
        self._lock = threading.RLock()

    def start(self) -> None:
        with self._lock:
            if self._running:
                return
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind(("0.0.0.0", self.port))
            self.sock.settimeout(0.3)
            self.port = self.sock.getsockname()[1]
            self._running = True
            self._thread = threading.Thread(target=self._serve, name="arp-engine", daemon=True)
            self._thread.start()
            self.log("ARP node started on UDP port %d | IP: %s | MAC: %s" % (self.port, self.ip, self.mac))

    def stop(self) -> None:
        with self._lock:
            self._running = False
            if self._thread:
                self._thread.join(timeout=1.0)
                self._thread = None
            if self.sock:
                try:
                    self.sock.close()
                except Exception:
                    pass
                self.sock = None
            self.log("ARP node stopped")

    @property
    def running(self) -> bool:
        return self._running

    def add_peer(self, host: str, port: int) -> None:
        with self._lock:
            addr = (host, port)
            if addr not in self.peers:
                self.peers.append(addr)

    def _serve(self) -> None:
        while self._running:
            try:
                data, addr = self.sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                pkt = ArpPacket.decode(data)
            except ValueError:
                continue

            me = self.sock.getsockname()
            if self.capture:
                self.capture.add_arp(data, addr, me, "rx", pkt)

            self.handle(pkt, addr)

    def handle(self, pkt: ArpPacket, src_addr: Tuple[str, int]) -> None:
        # Ignore our own loopback transmissions if received
        if pkt.sender_mac == self.mac:
            return

        # Standard ARP Snooping: update local cache with the sender's mapping
        if pkt.sender_ip != "0.0.0.0":
            self.table.update(pkt.sender_ip, pkt.sender_mac)

        if pkt.op == int(ArpOpcode.REQUEST):
            if pkt.is_probe:
                self.log("ARP <- PROBE from %s checking IP %s" % (pkt.sender_mac, pkt.target_ip))
                # If someone probes our IP, answer to claim ownership and defend the IP!
                if pkt.target_ip == self.ip:
                    self.log("ARP -> DEFENDING: address collision! Replying to probe from %s" % pkt.sender_mac)
                    self.send_reply(pkt.sender_mac, pkt.target_ip, src_addr)
            elif pkt.is_gratuitous:
                self.log("ARP <- GRATUITOUS announcement: %s is at %s (cache updated)" % (pkt.sender_ip, pkt.sender_mac))
            else:
                self.log("ARP <- Who has %s? Tell %s [%s]" % (pkt.target_ip, pkt.sender_ip, pkt.sender_mac))
                # If query is asking for our IP, reply!
                if pkt.target_ip == self.ip:
                    self.log("ARP -> Answering query: %s is at %s" % (self.ip, self.mac))
                    self.send_reply(pkt.sender_mac, pkt.sender_ip, src_addr)

        elif pkt.op == int(ArpOpcode.REPLY):
            self.log("ARP <- REPLY: %s is at %s" % (pkt.sender_ip, pkt.sender_mac))
            # Wake up any thread waiting for this resolution
            with self._lock:
                ev = self._waiters.get(pkt.sender_ip)
                if ev:
                    ev.set()

    def _broadcast(self, pkt: ArpPacket) -> None:
        if not self.sock:
            return
        raw = pkt.encode()
        me = self.sock.getsockname()
        destinations = list(self.peers) or [("127.0.0.1", DEFAULT_ARP_PORT)]
        for dst in destinations:
            if dst == me:
                continue
            try:
                self.sock.sendto(raw, dst)
                if self.capture:
                    self.capture.add_arp(raw, me, dst, "tx", pkt)
            except Exception:
                pass

    def send_request(self, target_ip: str) -> None:
        """Broadcast an ARP Who-has request."""
        pkt = new_arp_request(self.mac, self.ip, target_ip)
        self.log("ARP -> Broadcast Who has %s? Tell %s [%s]" % (target_ip, self.ip, self.mac))
        self._broadcast(pkt)

    def send_reply(self, target_mac: str, target_ip: str, peer_addr: Optional[Tuple[str, int]] = None) -> None:
        """Send an ARP reply."""
        if not self.sock:
            return
        pkt = new_arp_reply(self.mac, self.ip, target_mac, target_ip)
        raw = pkt.encode()
        me = self.sock.getsockname()
        dst = peer_addr or (self.peers[0] if self.peers else ("127.0.0.1", DEFAULT_ARP_PORT))
        try:
            self.sock.sendto(raw, dst)
            self.log("ARP -> Reply to %s [%s]: %s is at %s" % (target_ip, target_mac, self.ip, self.mac))
            if self.capture:
                self.capture.add_arp(raw, me, dst, "tx", pkt)
        except Exception:
            pass

    def send_probe(self, target_ip: str) -> None:
        """Broadcast an RFC 5227 Address Conflict Detection Probe."""
        pkt = new_arp_probe(self.mac, target_ip)
        self.log("ARP -> Broadcast PROBE for %s (ACD / DAD)" % target_ip)
        self._broadcast(pkt)

    def send_gratuitous(self) -> None:
        """Broadcast an RFC 5227 Gratuitous ARP announcement."""
        pkt = new_gratuitous_arp(self.mac, self.ip)
        self.log("ARP -> Broadcast GRATUITOUS announcement for %s [%s]" % (self.ip, self.mac))
        self._broadcast(pkt)

    def query(self, target_ip: str, timeout: float = 1.0) -> Optional[str]:
        """Query for a MAC address; blocks until resolved or timeout."""
        mac = self.table.lookup(target_ip)
        if mac:
            return mac
        ev = threading.Event()
        with self._lock:
            self._waiters[target_ip] = ev
        try:
            self.send_request(target_ip)
            ev.wait(timeout)
            return self.table.lookup(target_ip)
        finally:
            with self._lock:
                self._waiters.pop(target_ip, None)

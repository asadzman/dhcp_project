"""DHCP client state machine (INIT -> SELECTING -> REQUESTING -> BOUND -> RENEWING)."""
from __future__ import annotations

import random
import socket
import threading
import time
from typing import Callable, Optional, Tuple

from .capture import PacketCapture
from .constants import LOOPBACK, SERVER_PORT, MsgType, Opt
from .eventlog import EventLog
from .packet import DhcpPacket, new_request_packet

INIT, SELECTING, REQUESTING, BOUND, RENEWING = "INIT", "SELECTING", "REQUESTING", "BOUND", "RENEWING"


class DhcpClient:
    def __init__(self, mac: str, name: Optional[str] = None,
                 server_addr: Tuple[str, int] = (LOOPBACK, SERVER_PORT),
                 log: Optional[EventLog] = None, timeout: float = 1.5, retries: int = 3,
                 auto_renew: bool = True, on_change: Optional[Callable[["DhcpClient"], None]] = None,
                 capture: Optional[PacketCapture] = None):
        self.mac, self.name = mac, name or mac
        self.server_addr, self.log = server_addr, log or EventLog()
        self.timeout, self.retries, self.auto_renew = timeout, retries, auto_renew
        self.on_change = on_change
        self.capture = capture
        self.state = INIT
        self.ip: Optional[str] = None
        self.subnet_mask = self.router = self.dns = self.server_id = None
        self.lease_time = 0
        self.t1 = 0
        self.bound_at = 0.0
        self._timer: Optional[threading.Timer] = None
        self._lock = threading.Lock()       # one DHCP transaction at a time

    # ---------- helpers ----------
    def _set_state(self, st: str) -> None:
        self.state = st
        if self.on_change:
            self.on_change(self)

    def lease_remaining(self) -> int:
        return max(0, int(self.lease_time - (time.time() - self.bound_at))) if self.ip else 0

    def _new_socket(self) -> socket.socket:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("0.0.0.0", 0))
        s.settimeout(0.2)
        return s

    def _exchange(self, sock: socket.socket, pkt: DhcpPacket, want) -> Optional[DhcpPacket]:
        """Send pkt, wait for a reply with the same xid; retransmit on timeout."""
        for attempt in range(1, self.retries + 1):
            raw = pkt.encode()
            sock.sendto(raw, self.server_addr)
            self._cap(raw, sock, "tx")
            self.log("%s -> %s%s" % (self.name, pkt.summary(), "" if attempt == 1 else "  (retry %d)" % attempt))
            deadline = time.time() + self.timeout
            while time.time() < deadline:
                try:
                    data, _ = sock.recvfrom(4096)
                except socket.timeout:
                    continue
                try:
                    rep = DhcpPacket.decode(data)
                except ValueError:
                    continue
                if rep.xid == pkt.xid and rep.msg_type in want:
                    self._cap(data, sock, "rx")
                    self.log("%s <- %s" % (self.name, rep.summary()))
                    return rep
        return None

    def _cap(self, raw: bytes, sock: socket.socket, direction: str) -> None:
        if self.capture:
            me, srv = sock.getsockname(), self.server_addr
            src, dst = (me, srv) if direction == "tx" else (srv, me)
            self.capture.add(raw, src, dst, direction, self.server_id)

    def set_auto_renew(self, on: bool) -> None:
        self.auto_renew = on
        if not on:
            self._cancel_timer()
        elif self.ip and self.t1 > 0:
            self._schedule_renew()

    def _bind(self, ack: DhcpPacket) -> None:
        self.ip = ack.yiaddr
        self.subnet_mask, self.router = ack.get_ip(Opt.SUBNET_MASK), ack.get_ip(Opt.ROUTER)
        self.dns, self.server_id = ack.get_ip(Opt.DNS), ack.get_ip(Opt.SERVER_ID)
        self.lease_time = ack.get_u32(Opt.LEASE_TIME) or 0
        self.t1 = ack.get_u32(Opt.RENEWAL_T1) or self.lease_time // 2
        self.bound_at = time.time()
        self._set_state(BOUND)
        self.log("%s BOUND ip=%s mask=%s gw=%s dns=%s lease=%ds T1=%ds"
                 % (self.name, self.ip, self.subnet_mask, self.router, self.dns, self.lease_time, self.t1))
        self._schedule_renew()

    def _lose_lease(self) -> None:
        self._cancel_timer()
        self.ip = None
        self.lease_time = 0
        self._set_state(INIT)

    # ---------- DORA ----------
    def obtain(self) -> bool:
        """Blocking DISCOVER/OFFER/REQUEST/ACK. Returns True when bound."""
        with self._lock:
            sock, xid = self._new_socket(), random.getrandbits(32)
            try:
                self._set_state(SELECTING)
                offer = self._exchange(sock, new_request_packet(xid, self.mac, MsgType.DISCOVER), {MsgType.OFFER})
                if offer is None:
                    self._set_state(INIT)
                    self.log("%s: no OFFER received (server down or pool exhausted)" % self.name)
                    return False
                self._set_state(REQUESTING)
                req = new_request_packet(xid, self.mac, MsgType.REQUEST)
                req.set_ip(Opt.REQUESTED_IP, offer.yiaddr)
                req.options[Opt.SERVER_ID] = offer.options[Opt.SERVER_ID]
                rep = self._exchange(sock, req, {MsgType.ACK, MsgType.NAK})
                if rep is None or rep.msg_type == MsgType.NAK:
                    self._set_state(INIT)
                    self.log("%s: request %s" % (self.name, "NAKed" if rep else "timed out"))
                    return False
                self._bind(rep)
                return True
            finally:
                sock.close()

    def obtain_async(self) -> None:
        threading.Thread(target=self.obtain, daemon=True).start()

    # ---------- renew / release ----------
    def renew(self) -> bool:
        with self._lock:
            if not self.ip:
                self.log("%s: no lease to renew" % self.name)
                return False
            sock = self._new_socket()
            try:
                self._set_state(RENEWING)
                req = new_request_packet(random.getrandbits(32), self.mac, MsgType.REQUEST)
                req.ciaddr = self.ip
                rep = self._exchange(sock, req, {MsgType.ACK, MsgType.NAK})
                if rep is not None and rep.msg_type == MsgType.ACK:
                    self._bind(rep)
                    return True
                self.log("%s: renewal failed, lease lost" % self.name)
                self._lose_lease()
                return False
            finally:
                sock.close()

    def renew_async(self) -> None:
        threading.Thread(target=self.renew, daemon=True).start()

    def _send_once(self, pkt: DhcpPacket) -> None:
        sock = self._new_socket()
        try:
            raw = pkt.encode()
            sock.sendto(raw, self.server_addr)
            self._cap(raw, sock, "tx")
            self.log("%s -> %s" % (self.name, pkt.summary()))
        finally:
            sock.close()

    def release(self) -> None:
        with self._lock:
            if not self.ip:
                return
            pkt = new_request_packet(random.getrandbits(32), self.mac, MsgType.RELEASE)
            pkt.ciaddr = self.ip
            pkt.set_ip(Opt.SERVER_ID, self.server_id or "0.0.0.0")
            self._send_once(pkt)
            self._lose_lease()

    def decline(self) -> None:
        """Tell the server the address is already in use (e.g. found by an ARP probe)."""
        with self._lock:
            if not self.ip:
                return
            pkt = new_request_packet(random.getrandbits(32), self.mac, MsgType.DECLINE)
            pkt.set_ip(Opt.REQUESTED_IP, self.ip)
            pkt.set_ip(Opt.SERVER_ID, self.server_id or "0.0.0.0")
            self._send_once(pkt)
            self._lose_lease()

    # ---------- automatic renewal at T1 ----------
    def _schedule_renew(self) -> None:
        self._cancel_timer()
        if self.auto_renew and self.t1 > 0:
            self._timer = threading.Timer(self.t1, self.renew)
            self._timer.daemon = True
            self._timer.start()

    def _cancel_timer(self) -> None:
        if self._timer:
            self._timer.cancel()
            self._timer = None

    def shutdown(self) -> None:
        self._cancel_timer()

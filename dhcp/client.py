"""DHCP client state machine (INIT -> SELECTING -> REQUESTING -> BOUND -> RENEWING)."""
from __future__ import annotations

import random
import socket
import threading
import time
from typing import Callable, List, Optional, Tuple, Union

from .capture import PacketCapture
from .constants import LOOPBACK, SERVER_PORT, MsgType, Opt
from .eventlog import EventLog
from .packet import DhcpPacket, new_request_packet

INIT, SELECTING, REQUESTING, BOUND, RENEWING, REBINDING = (
    "INIT", "SELECTING", "REQUESTING", "BOUND", "RENEWING", "REBINDING"
)


class DhcpClient:
    def __init__(self, mac: str, name: Optional[str] = None,
                 server_addr: Union[Tuple[str, int], List[Tuple[str, int]]] = (LOOPBACK, SERVER_PORT),
                 log: Optional[EventLog] = None, timeout: float = 1.5, retries: int = 3,
                 auto_renew: bool = True, on_change: Optional[Callable[["DhcpClient"], None]] = None,
                 capture: Optional[PacketCapture] = None):
        self.mac, self.name = mac, name or mac
        if isinstance(server_addr, list):
            self.server_addrs = list(server_addr)
            self.server_addr = self.server_addrs[0] if self.server_addrs else (LOOPBACK, SERVER_PORT)
        else:
            self.server_addr = server_addr
            self.server_addrs = [server_addr]
        self.log = log or EventLog()
        self.timeout, self.retries, self.auto_renew = timeout, retries, auto_renew
        self.on_change = on_change
        self.capture = capture
        self.state = INIT
        self.ip: Optional[str] = None
        self.subnet_mask = self.router = self.dns = self.server_id = None
        self.domain_name: Optional[str] = None
        self.broadcast_addr: Optional[str] = None
        self.lease_time = 0
        self.t1 = 0
        self.t2 = 0
        self.bound_at = 0.0
        self._timer: Optional[threading.Timer] = None
        self._t2_timer: Optional[threading.Timer] = None
        self._expiry_timer: Optional[threading.Timer] = None
        self.arp_checker: Optional[Callable[[str], bool]] = None
        self.on_gratuitous_arp: Optional[Callable[[str, str], None]] = None
        self._lock = threading.RLock()       # re-entrant lock for transactions

    def set_arp_checker(self, fn: Optional[Callable[[str], bool]]) -> None:
        """Register a callback (e.g. from an ARP module) to test for address conflict."""
        self.arp_checker = fn

    def set_gratuitous_arp_handler(self, fn: Optional[Callable[[str, str], None]]) -> None:
        """Register a callback to broadcast gratuitous ARP after binding."""
        self.on_gratuitous_arp = fn

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

    def _collect_offers(self, sock: socket.socket, pkt: DhcpPacket) -> List[Tuple[DhcpPacket, Tuple[str, int]]]:
        """Broadcast DISCOVER to all configured servers and collect competing offers (RFC 2131 §4.4.1)."""
        offers: List[Tuple[DhcpPacket, Tuple[str, int]]] = []
        for attempt in range(1, self.retries + 1):
            raw = pkt.encode()
            for srv in self.server_addrs:
                sock.sendto(raw, srv)
                self._cap(raw, sock, "tx", srv)
            self.log("%s -> %s%s" % (self.name, pkt.summary(), "" if attempt == 1 else "  (retry %d)" % attempt))
            deadline = time.time() + self.timeout
            window_end: Optional[float] = None
            while time.time() < deadline:
                if window_end is not None and time.time() > window_end:
                    break
                try:
                    data, src_addr = sock.recvfrom(4096)
                except socket.timeout:
                    continue
                try:
                    rep = DhcpPacket.decode(data)
                except ValueError:
                    continue
                if rep.xid == pkt.xid and rep.msg_type == MsgType.OFFER:
                    self._cap(data, sock, "rx", src_addr)
                    sid = rep.get_ip(Opt.SERVER_ID) or src_addr[0]
                    self.log("%s <- OFFER yiaddr=%s from server %s (%s:%d)" % (self.name, rep.yiaddr, sid, src_addr[0], src_addr[1]))
                    offers.append((rep, src_addr))
                    if len(offers) >= len(self.server_addrs):
                        break
                    if window_end is None and len(self.server_addrs) > 1:
                        window_end = time.time() + 0.15
            if offers:
                break
        return offers

    def _exchange(self, sock: socket.socket, pkt: DhcpPacket, want) -> Optional[DhcpPacket]:
        """Send pkt to all configured servers, wait for a matching reply; retransmit on timeout."""
        for attempt in range(1, self.retries + 1):
            raw = pkt.encode()
            for srv in self.server_addrs:
                sock.sendto(raw, srv)
                self._cap(raw, sock, "tx", srv)
            self.log("%s -> %s%s" % (self.name, pkt.summary(), "" if attempt == 1 else "  (retry %d)" % attempt))
            deadline = time.time() + self.timeout
            while time.time() < deadline:
                try:
                    data, src_addr = sock.recvfrom(4096)
                except socket.timeout:
                    continue
                try:
                    rep = DhcpPacket.decode(data)
                except ValueError:
                    continue
                if rep.xid == pkt.xid and rep.msg_type in want:
                    self._cap(data, sock, "rx", src_addr)
                    self.log("%s <- %s" % (self.name, rep.summary()))
                    return rep
        return None

    def _cap(self, raw: bytes, sock: socket.socket, direction: str,
             target_addr: Optional[Tuple[str, int]] = None) -> None:
        if self.capture:
            me = sock.getsockname()
            srv = target_addr or self.server_addr
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
        self.domain_name = ack.get_str(Opt.DOMAIN_NAME)
        self.broadcast_addr = ack.get_ip(Opt.BROADCAST_ADDR)
        self.lease_time = ack.get_u32(Opt.LEASE_TIME) or 0
        self.t1 = ack.get_u32(Opt.RENEWAL_T1) or self.lease_time // 2
        self.t2 = ack.get_u32(Opt.REBINDING_T2) or int(self.lease_time * 0.875)
        self.bound_at = time.time()
        self._set_state(BOUND)
        self.log("%s BOUND ip=%s mask=%s gw=%s dns=%s domain=%s lease=%ds T1=%ds T2=%ds"
                 % (self.name, self.ip, self.subnet_mask, self.router, self.dns,
                    self.domain_name, self.lease_time, self.t1, self.t2))
        self._schedule_renew()

    def _lose_lease(self) -> None:
        self._cancel_timers()
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
                pkt = new_request_packet(xid, self.mac, MsgType.DISCOVER, host_name=self.name)
                offers = self._collect_offers(sock, pkt)
                if not offers:
                    self._set_state(INIT)
                    self.log("%s: no OFFER received (server down or pool exhausted)" % self.name)
                    return False
                if len(offers) > 1:
                    competing = ["%s (%s)" % (o.yiaddr, o.get_ip(Opt.SERVER_ID) or src[0]) for o, src in offers]
                    chosen_offer, chosen_src = offers[0]
                    chosen_sid = chosen_offer.get_ip(Opt.SERVER_ID) or chosen_src[0]
                    self.log("%s: Received %d competing offers [%s] -> Selected %s via Option 54"
                             % (self.name, len(offers), ", ".join(competing), chosen_sid))
                else:
                    chosen_offer, chosen_src = offers[0]
                self._set_state(REQUESTING)
                req = new_request_packet(xid, self.mac, MsgType.REQUEST, host_name=self.name)
                req.set_ip(Opt.REQUESTED_IP, chosen_offer.yiaddr)
                req.options[Opt.SERVER_ID] = chosen_offer.options[Opt.SERVER_ID]
                rep = self._exchange(sock, req, {MsgType.ACK, MsgType.NAK})
                if rep is None or rep.msg_type == MsgType.NAK:
                    self._set_state(INIT)
                    self.log("%s: request %s" % (self.name, "NAKed" if rep else "timed out"))
                    return False

                # RFC 2131 3.1.5: ARP probe check for IP collision
                offered_ip = rep.yiaddr
                if self.arp_checker and self.arp_checker(offered_ip):
                    self.log("%s: ARP probe detected IP collision on %s! Sending DECLINE..." % (self.name, offered_ip))
                    self.ip = offered_ip
                    self.server_id = rep.get_ip(Opt.SERVER_ID)
                    self.decline()
                    return False

                self._bind(rep)
                if self.on_gratuitous_arp:
                    self.on_gratuitous_arp(self.mac, self.ip)
                return True
            finally:
                sock.close()

    def obtain_async(self) -> None:
        threading.Thread(target=self.obtain, daemon=True).start()

    # ---------- renew / rebind / release / inform ----------
    def renew(self) -> bool:
        with self._lock:
            if not self.ip:
                self.log("%s: no lease to renew" % self.name)
                return False
            sock = self._new_socket()
            try:
                self._set_state(RENEWING)
                req = new_request_packet(random.getrandbits(32), self.mac, MsgType.REQUEST, host_name=self.name)
                req.ciaddr = self.ip
                rep = self._exchange(sock, req, {MsgType.ACK, MsgType.NAK})
                if rep is not None and rep.msg_type == MsgType.ACK:
                    self._bind(rep)
                    return True
                self.log("%s: renewal at T1 failed" % self.name)
                if not self.auto_renew:
                    self._lose_lease()
                return False
            finally:
                sock.close()

    def renew_async(self) -> None:
        threading.Thread(target=self.renew, daemon=True).start()

    def rebind(self) -> bool:
        """RFC 2131 T2 Rebinding: broadcast REQUEST to any DHCP server."""
        with self._lock:
            if not self.ip:
                return False
            sock = self._new_socket()
            try:
                self._set_state(REBINDING)
                req = new_request_packet(random.getrandbits(32), self.mac, MsgType.REQUEST, host_name=self.name)
                req.ciaddr = self.ip
                rep = self._exchange(sock, req, {MsgType.ACK, MsgType.NAK})
                if rep is not None and rep.msg_type == MsgType.ACK:
                    self._bind(rep)
                    return True
                self.log("%s: rebinding at T2 failed" % self.name)
                return False
            finally:
                sock.close()

    def rebind_async(self) -> None:
        threading.Thread(target=self.rebind, daemon=True).start()

    def inform(self, current_ip: Optional[str] = None) -> bool:
        """RFC 2131 DHCPINFORM: Request configuration parameters for an existing IP."""
        with self._lock:
            sock, xid = self._new_socket(), random.getrandbits(32)
            try:
                pkt = new_request_packet(xid, self.mac, MsgType.INFORM, host_name=self.name)
                pkt.ciaddr = current_ip or self.ip or "0.0.0.0"
                rep = self._exchange(sock, pkt, {MsgType.ACK})
                if rep:
                    self.subnet_mask = rep.get_ip(Opt.SUBNET_MASK)
                    self.router = rep.get_ip(Opt.ROUTER)
                    self.dns = rep.get_ip(Opt.DNS)
                    self.domain_name = rep.get_str(Opt.DOMAIN_NAME)
                    self.broadcast_addr = rep.get_ip(Opt.BROADCAST_ADDR)
                    self.server_id = rep.get_ip(Opt.SERVER_ID)
                    self.log("%s: INFORM success - DNS: %s, Router: %s, Domain: %s"
                             % (self.name, self.dns, self.router, self.domain_name))
                    return True
                self.log("%s: INFORM timed out" % self.name)
                return False
            finally:
                sock.close()

    def inform_async(self, current_ip: Optional[str] = None) -> None:
        threading.Thread(target=self.inform, args=(current_ip,), daemon=True).start()

    def _send_once(self, pkt: DhcpPacket) -> None:
        sock = self._new_socket()
        try:
            raw = pkt.encode()
            for srv in self.server_addrs:
                sock.sendto(raw, srv)
                self._cap(raw, sock, "tx", srv)
            self.log("%s -> %s" % (self.name, pkt.summary()))
        finally:
            sock.close()

    def release(self) -> None:
        with self._lock:
            if not self.ip:
                return
            pkt = new_request_packet(random.getrandbits(32), self.mac, MsgType.RELEASE, host_name=self.name)
            pkt.ciaddr = self.ip
            pkt.set_ip(Opt.SERVER_ID, self.server_id or "0.0.0.0")
            self._send_once(pkt)
            self._lose_lease()

    def decline(self) -> None:
        """Tell the server the address is already in use (e.g. found by an ARP probe)."""
        with self._lock:
            if not self.ip:
                return
            pkt = new_request_packet(random.getrandbits(32), self.mac, MsgType.DECLINE, host_name=self.name)
            pkt.set_ip(Opt.REQUESTED_IP, self.ip)
            pkt.set_ip(Opt.SERVER_ID, self.server_id or "0.0.0.0")
            self._send_once(pkt)
            self._lose_lease()

    # ---------- automatic renewal at T1 & T2 ----------
    def _schedule_renew(self) -> None:
        self._cancel_timers()
        if not self.auto_renew or not self.ip:
            return
        if self.t1 > 0:
            self._timer = threading.Timer(self.t1, self.renew)
            self._timer.daemon = True
            self._timer.start()
        if self.t2 > self.t1:
            self._t2_timer = threading.Timer(self.t2, self.rebind)
            self._t2_timer.daemon = True
            self._t2_timer.start()
        if self.lease_time > 0:
            self._expiry_timer = threading.Timer(self.lease_time, self._on_lease_expired)
            self._expiry_timer.daemon = True
            self._expiry_timer.start()

    def _on_lease_expired(self) -> None:
        self.log("%s: lease expired!" % self.name)
        self._lose_lease()

    def _cancel_timers(self) -> None:
        for t in (self._timer, self._t2_timer, self._expiry_timer):
            if t:
                t.cancel()
        self._timer = self._t2_timer = self._expiry_timer = None

    def _cancel_timer(self) -> None:
        self._cancel_timers()

    def shutdown(self) -> None:
        self._cancel_timers()

"""DHCP server: UDP socket loop + protocol logic on top of LeasePool."""
from __future__ import annotations

import socket
import threading
from typing import Optional

from .capture import PacketCapture
from .config import ServerConfig
from .constants import BOOTREQUEST, MsgType, Opt
from .eventlog import EventLog
from .packet import DhcpPacket, new_reply_packet
from .pool import LeasePool


class DhcpServer:
    def __init__(self, config: ServerConfig, log: Optional[EventLog] = None,
                 capture: Optional[PacketCapture] = None):
        config.validate()
        self.config = config
        self.log = log or EventLog()
        self.capture = capture
        self.pool = LeasePool(config.pool_start, config.pool_end, config.lease_time,
                              config.offer_hold, config.decline_hold, config.reservations)
        self.sock: Optional[socket.socket] = None
        self.port = config.port
        self._thread: Optional[threading.Thread] = None
        self._running = False

    # ---------- lifecycle ----------
    def start(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.config.host, self.config.port))
        self.sock.settimeout(0.3)
        self.port = self.sock.getsockname()[1]
        self._running = True
        self._thread = threading.Thread(target=self._serve, name="dhcp-server", daemon=True)
        self._thread.start()
        c = self.config
        self.log("SERVER listening on UDP %s:%d | pool %s-%s | lease %ds"
                 % (c.host, self.port, c.pool_start, c.pool_end, c.lease_time))

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=1)
        if self.sock:
            self.sock.close()
            self.sock = None
        self.log("SERVER stopped")

    @property
    def running(self) -> bool:
        return self._running

    # ---------- main loop ----------
    def _serve(self) -> None:
        while self._running:
            try:
                data, addr = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                pkt = DhcpPacket.decode(data)
            except ValueError:
                continue
            if pkt.op != BOOTREQUEST:
                continue
            me = self.sock.getsockname()
            self.log("SERVER <- " + pkt.summary())
            if self.capture:
                self.capture.add(data, addr, me, "rx", self.config.server_ip)
            reply = self.handle(pkt)
            if reply is not None:
                out = reply.encode()
                self.sock.sendto(out, addr)
                self.log("SERVER -> " + reply.summary())
                if self.capture:
                    self.capture.add(out, me, addr, "tx", self.config.server_ip)

    # ---------- protocol logic ----------
    def handle(self, pkt: DhcpPacket) -> Optional[DhcpPacket]:
        t = pkt.msg_type
        if t == MsgType.DISCOVER:
            return self._on_discover(pkt)
        if t == MsgType.REQUEST:
            return self._on_request(pkt)
        if t == MsgType.INFORM:
            return self._on_inform(pkt)
        if t == MsgType.RELEASE:
            if self.pool.release(pkt.chaddr):
                self.log("SERVER: %s released %s" % (pkt.chaddr, pkt.ciaddr))
        elif t == MsgType.DECLINE:
            ip = pkt.get_ip(Opt.REQUESTED_IP)
            if ip:
                self.pool.decline(pkt.chaddr, ip)
                self.log("SERVER: %s declined %s (address quarantined)" % (pkt.chaddr, ip))
        return None

    def _fill_config_options(self, reply: DhcpPacket) -> DhcpPacket:
        c = self.config
        reply.set_u32(Opt.LEASE_TIME, c.lease_time)
        reply.set_u32(Opt.RENEWAL_T1, c.lease_time // 2)
        reply.set_u32(Opt.REBINDING_T2, c.lease_time * 7 // 8)
        reply.set_ip(Opt.SUBNET_MASK, c.subnet_mask)
        reply.set_ip(Opt.ROUTER, c.router)
        reply.set_ip(Opt.DNS, *c.dns)
        if c.domain_name:
            reply.set_str(Opt.DOMAIN_NAME, c.domain_name)
        if c.broadcast_addr:
            reply.set_ip(Opt.BROADCAST_ADDR, c.broadcast_addr)
        return reply

    def _on_discover(self, pkt: DhcpPacket) -> Optional[DhcpPacket]:
        hostname = pkt.host_name or ""
        ip = self.pool.offer(pkt.chaddr, pkt.get_ip(Opt.REQUESTED_IP), hostname=hostname)
        if ip is None:
            self.log("SERVER: pool exhausted, no OFFER for %s" % pkt.chaddr)
            return None
        return self._fill_config_options(new_reply_packet(pkt, MsgType.OFFER, self.config.server_ip, ip))

    def _on_request(self, pkt: DhcpPacket) -> Optional[DhcpPacket]:
        sid = pkt.get_ip(Opt.SERVER_ID)
        if sid and sid != self.config.server_ip:
            self.pool.offers.pop(pkt.chaddr, None)        # client picked another server
            self.log("SERVER: %s selected another server (%s) -> released held offer" % (pkt.chaddr, sid))
            return None
        ip = pkt.get_ip(Opt.REQUESTED_IP) or (pkt.ciaddr if pkt.ciaddr != "0.0.0.0" else None)
        hostname = pkt.host_name or ""
        lease = self.pool.commit(pkt.chaddr, ip, hostname=hostname) if ip else None
        if lease is None:
            return new_reply_packet(pkt, MsgType.NAK, self.config.server_ip)
        return self._fill_config_options(new_reply_packet(pkt, MsgType.ACK, self.config.server_ip, lease.ip))

    def _on_inform(self, pkt: DhcpPacket) -> Optional[DhcpPacket]:
        # RFC 2131 Section 4.3.5: client has externally configured IP, wants parameters
        reply = new_reply_packet(pkt, MsgType.ACK, self.config.server_ip, yiaddr="0.0.0.0")
        reply.ciaddr = pkt.ciaddr
        self.log("SERVER: INFORM from %s (%s) -> sending configuration parameters" % (pkt.chaddr, pkt.ciaddr))
        return self._fill_config_options(reply)

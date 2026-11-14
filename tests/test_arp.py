import os
import tempfile
import time
import unittest

from arp import (ArpEngine, ArpOpcode, ArpPacket, ArpTable, new_arp_probe,
                 new_arp_reply, new_arp_request, new_gratuitous_arp)
from dhcp.capture import PacketCapture


class ArpTests(unittest.TestCase):
    def test_arp_request_roundtrip(self):
        pkt = new_arp_request("02:00:5e:01:02:03", "192.168.1.50", "192.168.1.1")
        raw = pkt.encode()
        self.assertEqual(len(raw), 28)
        decoded = ArpPacket.decode(raw)
        self.assertEqual(decoded.op, ArpOpcode.REQUEST)
        self.assertEqual(decoded.sender_mac, "02:00:5e:01:02:03")
        self.assertEqual(decoded.sender_ip, "192.168.1.50")
        self.assertEqual(decoded.target_ip, "192.168.1.1")
        self.assertEqual(decoded.target_mac, "00:00:00:00:00:00")
        self.assertFalse(decoded.is_probe)
        self.assertFalse(decoded.is_gratuitous)

    def test_arp_reply_roundtrip(self):
        pkt = new_arp_reply("02:00:5e:aa:bb:cc", "192.168.1.1", "02:00:5e:01:02:03", "192.168.1.50")
        decoded = ArpPacket.decode(pkt.encode())
        self.assertEqual(decoded.op, ArpOpcode.REPLY)
        self.assertEqual(decoded.sender_ip, "192.168.1.1")
        self.assertEqual(decoded.target_mac, "02:00:5e:01:02:03")

    def test_arp_probe(self):
        probe = new_arp_probe("02:00:5e:11:22:33", "192.168.1.100")
        decoded = ArpPacket.decode(probe.encode())
        self.assertTrue(decoded.is_probe)
        self.assertEqual(decoded.sender_ip, "0.0.0.0")
        self.assertEqual(decoded.target_ip, "192.168.1.100")

    def test_gratuitous_arp(self):
        garp = new_gratuitous_arp("02:00:5e:11:22:33", "192.168.1.100")
        decoded = ArpPacket.decode(garp.encode())
        self.assertTrue(decoded.is_gratuitous)
        self.assertEqual(decoded.sender_ip, decoded.target_ip)

    def test_arp_table_lookup_and_expiration(self):
        tbl = ArpTable(default_ttl=10.0)
        tbl.update("192.168.1.10", "02:00:5e:00:00:10")
        self.assertEqual(tbl.lookup("192.168.1.10"), "02:00:5e:00:00:10")
        self.assertIsNone(tbl.lookup("192.168.1.99"))

        # Test expiration
        tbl.update("192.168.1.20", "02:00:5e:00:00:20", ttl=-1.0)
        self.assertIsNone(tbl.lookup("192.168.1.20"))

    def test_arp_engine_query_and_resolution(self):
        cap_a, cap_b = PacketCapture(), PacketCapture()
        node_a = ArpEngine("02:00:5e:00:00:01", "192.168.1.10", port=0, capture=cap_a)
        node_b = ArpEngine("02:00:5e:00:00:02", "192.168.1.20", port=0, capture=cap_b)
        node_a.start()
        node_b.start()
        try:
            node_a.add_peer("127.0.0.1", node_b.port)
            node_b.add_peer("127.0.0.1", node_a.port)

            resolved_mac = node_a.query("192.168.1.20", timeout=1.0)
            self.assertEqual(resolved_mac, "02:00:5e:00:00:02")
            # Verify Node A's cache recorded Node B
            self.assertEqual(node_a.table.lookup("192.168.1.20"), "02:00:5e:00:00:02")
            # Verify Node B snooped Node A's mapping from the request
            self.assertEqual(node_b.table.lookup("192.168.1.10"), "02:00:5e:00:00:01")
            # Verify packets were captured
            self.assertGreaterEqual(len(cap_a.snapshot()), 2)
            self.assertEqual(cap_a.snapshot()[0].proto, "ARP")
        finally:
            node_a.stop()
            node_b.stop()

    def test_arp_pcap_export(self):
        cap = PacketCapture()
        node = ArpEngine("02:00:5e:00:00:01", "192.168.1.10", port=0, capture=cap)
        node.start()
        try:
            node.send_gratuitous()
            time.sleep(0.05)
            self.assertEqual(len(cap.snapshot()), 1)
            with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tf:
                path = tf.name
            try:
                count = cap.export_pcap(path)
                self.assertEqual(count, 1)
                with open(path, "rb") as f:
                    data = f.read()
                # Libpcap global header (24 bytes) + packet header (16 bytes) + frame
                # Frame: Ethernet (14 bytes) -> EtherType is at offset 24 + 16 + 12 = 52
                ethertype = data[52:54]
                self.assertEqual(ethertype, b"\x08\x06")  # EtherType 0x0806 is ARP!
            finally:
                if os.path.exists(path):
                    os.remove(path)
        finally:
            node.stop()


if __name__ == "__main__":
    unittest.main()

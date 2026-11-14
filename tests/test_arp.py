import unittest
from arp import (ArpOpcode, ArpPacket, ArpTable, new_arp_probe, new_arp_reply,
                 new_arp_request, new_gratuitous_arp)


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


if __name__ == "__main__":
    unittest.main()

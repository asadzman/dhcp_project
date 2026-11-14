import unittest
from dhcp.constants import MsgType, Opt
from dhcp.packet import DhcpPacket, new_request_packet


class PacketTests(unittest.TestCase):
    def test_roundtrip(self):
        p = new_request_packet(0xDEADBEEF, "02:00:5e:01:02:03", MsgType.DISCOVER)
        p.set_ip(Opt.REQUESTED_IP, "10.0.0.7").set_u32(Opt.LEASE_TIME, 3600)
        q = DhcpPacket.decode(p.encode())
        self.assertEqual(q.xid, 0xDEADBEEF)
        self.assertEqual(q.chaddr, "02:00:5e:01:02:03")
        self.assertEqual(q.msg_type, MsgType.DISCOVER)
        self.assertEqual(q.get_ip(Opt.REQUESTED_IP), "10.0.0.7")
        self.assertEqual(q.get_u32(Opt.LEASE_TIME), 3600)

    def test_fixed_header_size_and_cookie(self):
        raw = new_request_packet(1, "02:00:5e:00:00:01", MsgType.DISCOVER).encode()
        self.assertEqual(raw[236:240], b"\x63\x82\x53\x63")
        self.assertEqual(raw[-1], 255)

    def test_garbage_rejected(self):
        with self.assertRaises(ValueError):
            DhcpPacket.decode(b"hello")

    def test_multiple_dns(self):
        p = new_request_packet(1, "02:00:5e:00:00:01", MsgType.OFFER).set_ip(Opt.DNS, "1.1.1.1", "8.8.8.8")
        self.assertEqual(DhcpPacket.decode(p.encode()).get_ips(Opt.DNS), ["1.1.1.1", "8.8.8.8"])

    def test_hostname_and_domain_options(self):
        p = new_request_packet(123, "02:00:5e:11:22:33", MsgType.REQUEST, host_name="Lab-PC")
        p.set_str(Opt.DOMAIN_NAME, "college.edu")
        decoded = DhcpPacket.decode(p.encode())
        self.assertEqual(decoded.host_name, "Lab-PC")
        self.assertEqual(decoded.get_str(Opt.DOMAIN_NAME), "college.edu")


if __name__ == "__main__":
    unittest.main()

import unittest
from dhcp import PacketCapture
from dhcp.constants import MsgType, Opt
from dhcp.dissect import dissect, hex_lines, hex_col
from dhcp.packet import new_request_packet, new_reply_packet


def walk(nodes):
    for n in nodes:
        yield n
        yield from walk(n.children)


class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.cap = PacketCapture()
        self.req = new_request_packet(0x1234ABCD, "02:00:5e:00:00:01", MsgType.DISCOVER)
        self.cp1 = self.cap.add(self.req.encode(), ("127.0.0.1", 5000), ("127.0.0.1", 6767), "rx", "192.168.1.1")
        offer = new_reply_packet(self.req, MsgType.OFFER, "192.168.1.1", "192.168.1.100")
        offer.set_u32(Opt.LEASE_TIME, 30)
        self.cp2 = self.cap.add(offer.encode(), ("127.0.0.1", 6767), ("127.0.0.1", 5000), "tx", "192.168.1.1")

    def test_emulated_addresses(self):
        self.assertEqual((self.cp1.src, self.cp1.dst, self.cp1.sport, self.cp1.dport),
                         ("0.0.0.0", "255.255.255.255", 68, 67))
        self.assertEqual((self.cp2.src, self.cp2.dst, self.cp2.sport, self.cp2.dport),
                         ("192.168.1.1", "255.255.255.255", 67, 68))   # broadcast flag set

    def test_numbering_info_and_filter_text(self):
        self.assertEqual([c.no for c in self.cap.snapshot()], [1, 2])
        self.assertIn("Discover", self.cp1.info)
        self.assertIn("0x1234abcd", self.cp1.haystack())

    def test_dissect_tree(self):
        labels = [n.label for n in walk(dissect(self.cp2))]
        self.assertTrue(any(l.startswith("Dynamic Host Configuration Protocol (Offer)") for l in labels))
        self.assertIn("Transaction ID: 0x1234abcd", labels)
        self.assertIn("Your (client) IP address: 192.168.1.100", labels)
        self.assertIn("Option: (51) IP Address Lease Time", labels)

    def test_byte_ranges_match_raw(self):
        for n in walk(dissect(self.cp2)):
            if n.label.startswith("Transaction ID"):
                self.assertEqual(self.cp2.raw[n.start:n.start + n.length].hex(), "1234abcd")

    def test_hex_dump_columns(self):
        line = hex_lines(self.cp1.raw)[0]
        i = 4  # first byte of xid
        self.assertEqual(line[hex_col(i):hex_col(i) + 2], "%02x" % self.cp1.raw[i])

    def test_clear(self):
        self.cap.clear()
        self.assertEqual(self.cap.snapshot(), [])


if __name__ == "__main__":
    unittest.main()

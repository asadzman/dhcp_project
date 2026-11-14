"""Server and clients talking over real UDP sockets on loopback."""
import time
import unittest
from dhcp import DhcpClient, DhcpServer, ServerConfig
from dhcp.client import BOUND, INIT


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        cfg = ServerConfig(pool_start="192.168.5.10", pool_end="192.168.5.11", lease_time=4, port=0)
        self.server = DhcpServer(cfg)
        self.server.start()
        self.addr = ("127.0.0.1", self.server.port)

    def tearDown(self):
        self.server.stop()

    def client(self, n, **kw):
        return DhcpClient("02:00:5e:00:00:%02x" % n, "PC%d" % n, self.addr, timeout=0.4, retries=2, **kw)

    def test_dora_gives_lease(self):
        c = self.client(1, auto_renew=False)
        self.assertTrue(c.obtain())
        self.assertEqual((c.state, c.ip), (BOUND, "192.168.5.10"))
        self.assertEqual(c.subnet_mask, "255.255.255.0")
        self.assertEqual(c.dns, "8.8.8.8")
        self.assertEqual(len(self.server.pool.snapshot()), 1)

    def test_two_clients_different_ips_then_exhaustion(self):
        cs = [self.client(i, auto_renew=False) for i in (1, 2, 3)]
        self.assertTrue(cs[0].obtain()); self.assertTrue(cs[1].obtain())
        self.assertNotEqual(cs[0].ip, cs[1].ip)
        self.assertFalse(cs[2].obtain())
        self.assertEqual(cs[2].state, INIT)

    def test_release_frees_ip(self):
        a, b = self.client(1, auto_renew=False), self.client(2, auto_renew=False)
        a.obtain(); old = a.ip; a.release()
        time.sleep(0.2)
        self.assertEqual(a.state, INIT)
        self.assertEqual(len(self.server.pool.snapshot()), 0)
        self.assertTrue(b.obtain())

    def test_manual_renew_extends_lease(self):
        c = self.client(1, auto_renew=False)
        c.obtain(); first = c.bound_at; time.sleep(0.3)
        self.assertTrue(c.renew())
        self.assertGreater(c.bound_at, first)
        self.assertEqual(c.ip, "192.168.5.10")

    def test_auto_renew_at_t1(self):
        c = self.client(1, auto_renew=True)      # lease 4s -> T1 = 2s
        c.obtain(); first = c.bound_at
        time.sleep(2.6)
        self.assertGreater(c.bound_at, first)
        c.shutdown()

    def test_server_down_times_out(self):
        self.server.stop()
        c = self.client(9, auto_renew=False)
        self.assertFalse(c.obtain())
        self.server.start()                       # so tearDown() is happy

    def test_decline_quarantines_address(self):
        a = self.client(1, auto_renew=False)
        a.obtain(); bad = a.ip; a.decline(); time.sleep(0.2)
        b = self.client(2, auto_renew=False)
        b.obtain()
        self.assertNotEqual(b.ip, bad)

    def test_renew_after_expiry_regrants_if_free(self):
        c = self.client(1, auto_renew=False)
        c.obtain()
        time.sleep(4.3)                           # lease (4s) expired on the server
        self.assertTrue(c.renew())                # address still free -> re-granted
        self.assertEqual(c.ip, "192.168.5.10")

    def test_renew_naked_if_address_taken(self):
        c, d = self.client(1, auto_renew=False), self.client(2, auto_renew=False)
        c.obtain()
        time.sleep(4.3)
        self.assertTrue(d.obtain())               # d takes the expired .10
        self.assertEqual(d.ip, "192.168.5.10")
        self.assertFalse(c.renew())               # NAK
        self.assertEqual(c.state, INIT)


if __name__ == "__main__":
    unittest.main()

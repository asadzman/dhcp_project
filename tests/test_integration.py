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

    def test_hostname_saved_in_lease(self):
        c = self.client(5, auto_renew=False)
        self.assertTrue(c.obtain())
        leases = self.server.pool.snapshot()
        self.assertEqual(len(leases), 1)
        self.assertEqual(leases[0].hostname, "PC5")

    def test_dhcp_inform(self):
        c = self.client(6, auto_renew=False)
        self.assertTrue(c.inform("192.168.5.88"))
        self.assertEqual(c.dns, "8.8.8.8")
        self.assertEqual(c.domain_name, "lab.local")
        # INFORM must not consume an address from the lease pool
        self.assertEqual(len(self.server.pool.snapshot()), 0)

    def test_arp_probe_conflict_triggers_auto_decline(self):
        c = self.client(7, auto_renew=False)
        # Simulate ARP conflict detection returning True (address is collision)
        c.set_arp_checker(lambda ip: True)
        self.assertFalse(c.obtain())
        self.assertEqual(c.state, INIT)
        time.sleep(0.1)
        # Address should now be quarantined in server pool declined table
        stats = self.server.pool.stats()
        self.assertEqual(stats["declined"], 1)

    def test_multiple_competing_servers_selection(self):
        # Create a second competing DHCP server with a separate subnet
        cfg2 = ServerConfig(server_ip="192.168.9.1", pool_start="192.168.9.10", pool_end="192.168.9.20",
                            lease_time=4, port=0)
        server2 = DhcpServer(cfg2)
        server2.start()
        try:
            addr2 = ("127.0.0.1", server2.port)
            # Client broadcasts DISCOVER to BOTH servers
            c = DhcpClient("02:00:5e:00:00:99", "MultiClient",
                           server_addr=[self.addr, addr2], timeout=0.5, retries=2, auto_renew=False)
            self.assertTrue(c.obtain())
            self.assertEqual(c.state, BOUND)
            # One server must have granted the lease, and the unchosen server must have released its offer
            srv1_leases = len(self.server.pool.snapshot())
            srv2_leases = len(server2.pool.snapshot())
            self.assertEqual(srv1_leases + srv2_leases, 1)
            # Check that unchosen server did not hold onto a dangling offer
            self.assertEqual(len(server2.pool.offers_snapshot()) if srv1_leases == 1 else len(self.server.pool.offers_snapshot()), 0)
        finally:
            server2.stop()


if __name__ == "__main__":
    unittest.main()

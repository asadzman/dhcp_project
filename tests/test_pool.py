import unittest
from dhcp.pool import LeasePool


class FakeClock:
    def __init__(self): self.t = 1000.0
    def __call__(self): return self.t


class PoolTests(unittest.TestCase):
    def setUp(self):
        self.clk = FakeClock()
        self.pool = LeasePool("10.0.0.10", "10.0.0.12", lease_time=60, offer_hold=5, decline_hold=30,
                              reservations={"aa:aa:aa:aa:aa:aa": "10.0.0.99"}, clock=self.clk)

    def lease(self, mac):
        ip = self.pool.offer(mac)
        return ip, self.pool.commit(mac, ip) if ip else None

    def test_sequential_allocation_and_exhaustion(self):
        ips = [self.lease("02:00:00:00:00:0%d" % i)[0] for i in range(3)]
        self.assertEqual(ips, ["10.0.0.10", "10.0.0.11", "10.0.0.12"])
        self.assertIsNone(self.pool.offer("02:00:00:00:00:09"))

    def test_same_client_gets_same_ip(self):
        a = self.lease("02:00:00:00:00:01")[0]
        self.assertEqual(self.pool.offer("02:00:00:00:00:01"), a)

    def test_expiry_frees_address(self):
        self.lease("02:00:00:00:00:01")
        self.clk.t += 61
        self.assertEqual(self.pool.snapshot(), [])
        self.assertEqual(self.pool.offer("02:00:00:00:00:02"), "10.0.0.10")

    def test_offer_hold_expires(self):
        self.pool.offer("02:00:00:00:00:01")
        self.clk.t += 6
        self.assertEqual(self.pool.stats()["offered"], 0)

    def test_reservation(self):
        ip, lease = self.lease("aa:aa:aa:aa:aa:aa")
        self.assertEqual(ip, "10.0.0.99")
        self.assertTrue(lease.static)

    def test_commit_without_offer_is_nak(self):
        self.pool.offer("02:00:00:00:00:01")                       # holds .10
        self.assertIsNone(self.pool.commit("02:00:00:00:00:02", "10.0.0.10"))

    def test_init_reboot(self):
        self.assertIsNotNone(self.pool.commit("02:00:00:00:00:05", "10.0.0.11"))

    def test_release_and_decline(self):
        ip, _ = self.lease("02:00:00:00:00:01")
        self.assertTrue(self.pool.release("02:00:00:00:00:01"))
        ip2, _ = self.lease("02:00:00:00:00:02")
        self.pool.decline("02:00:00:00:00:02", ip2)
        self.assertNotEqual(self.pool.offer("02:00:00:00:00:03"), ip2)
        self.clk.t += 31
        self.assertEqual(self.pool.offer("02:00:00:00:00:04"), ip2)

    def test_requested_ip_honoured(self):
        self.assertEqual(self.pool.offer("02:00:00:00:00:01", "10.0.0.12"), "10.0.0.12")


if __name__ == "__main__":
    unittest.main()

"""DHCP SERVER application: configuration, lease table and a Wireshark-style live capture."""
import random
import threading
import time
import tkinter as tk
from tkinter import messagebox, ttk

from dhcp import DhcpServer, EventLog, PacketCapture, ServerConfig
from dhcp.constants import SERVER_PORT

from .capture_view import CaptureView
from .widgets import LogView, labeled_entry, make_table, refill


class ServerApp:
    def __init__(self, root):
        self.root = root
        root.title("DHCP Server")
        root.geometry("1180x760")
        self.server = None
        self.capture = PacketCapture()
        self.log = EventLog()

        # ---- toolbar ----
        tb = ttk.Frame(root)
        tb.pack(fill="x", padx=8, pady=6)
        self.btn = ttk.Button(tb, text="Start server", command=self.toggle)
        self.btn.pack(side="left")
        self.dot = tk.Label(tb, text="\u25cf", fg="#c00", font=("Arial", 16))
        self.dot.pack(side="left", padx=(10, 2))
        self.status = ttk.Label(tb, text="Stopped")
        self.status.pack(side="left")
        self.stats = ttk.Label(tb, text="")
        self.stats.pack(side="right")

        nb = ttk.Notebook(root)
        nb.pack(fill="both", expand=True, padx=6, pady=(0, 6))

        # ---- tab 1: capture ----
        self.view = CaptureView(nb, self.capture)
        nb.add(self.view, text="  Packet Capture  ")

        # ---- tab 2: leases ----
        lt = ttk.Frame(nb)
        nb.add(lt, text="  Leases  ")
        self.table = make_table(lt, [("mac", "Client MAC", 150), ("ip", "IP address", 120),
                                     ("host", "Host Name", 110), ("left", "Expires in (s)", 90),
                                     ("kind", "State", 110)], height=10)
        self.table.pack(fill="x", padx=6, pady=6)
        bar = ttk.Frame(lt)
        bar.pack(fill="x", padx=6)
        ttk.Button(bar, text="Revoke selected lease", command=self.revoke).pack(side="left")
        ttk.Button(bar, text="Simulate Starvation Attack", command=self.simulate_starvation).pack(side="left", padx=8)
        ttk.Label(lt, text="Server events").pack(anchor="w", padx=6, pady=(10, 0))
        self.events = LogView(lt, height=12)
        self.events.pack(fill="both", expand=True, padx=6, pady=6)
        self.log.subscribe(self.events.push)

        # ---- tab 3: configuration ----
        cf = ttk.Frame(nb)
        nb.add(cf, text="  Configuration  ")
        g = ttk.LabelFrame(cf, text="Server settings (applied on next Start)")
        g.pack(anchor="nw", padx=10, pady=10)
        self.f = {}
        rows = [("Listen address", "127.0.0.1", "host"), ("UDP port", str(SERVER_PORT), "port"),
                ("Server identifier", "192.168.1.1", "sid"), ("Subnet mask", "255.255.255.0", "mask"),
                ("Pool start", "192.168.1.100", "start"), ("Pool end", "192.168.1.110", "end"),
                ("Default router", "192.168.1.1", "gw"), ("DNS servers (comma)", "8.8.8.8,1.1.1.1", "dns"),
                ("Domain name", "lab.local", "domain"), ("Broadcast address", "192.168.1.255", "bcast"),
                ("Lease time (s)", "30", "lease"), ("Offer hold (s)", "10", "hold"),
                ("Reservations MAC=IP;MAC=IP", "", "resv")]
        for r, (label, default, key) in enumerate(rows):
            self.f[key] = labeled_entry(g, label, default, r, 0, 34)
        ttk.Label(cf, foreground="#555", justify="left",
                  text="Tip: use 127.0.0.1 to test on one PC. Use 0.0.0.0 to serve clients on other PCs in the lab\n"
                       "(they must enter this PC's IP in their Client app).").pack(anchor="w", padx=12)

        self._tick()
        root.protocol("WM_DELETE_WINDOW", self._close)

    # ---------- actions ----------
    def toggle(self):
        if self.server:
            self.server.stop()
            self.server = None
            self.btn.config(text="Start server")
            self.dot.config(fg="#c00")
            self.status.config(text="Stopped")
            return
        try:
            f = {k: e.get().strip() for k, e in self.f.items()}
            resv = dict(x.split("=") for x in f["resv"].split(";") if x.strip())
            cfg = ServerConfig(server_ip=f["sid"], pool_start=f["start"], pool_end=f["end"],
                               subnet_mask=f["mask"], router=f["gw"],
                               dns=[d.strip() for d in f["dns"].split(",") if d.strip()],
                               domain_name=f.get("domain", "lab.local"),
                               broadcast_addr=f.get("bcast", "192.168.1.255"),
                               lease_time=int(f["lease"]), offer_hold=int(f["hold"]),
                               reservations=resv, host=f["host"], port=int(f["port"]))
            self.server = DhcpServer(cfg, self.log, self.capture)
            self.server.start()
        except (ValueError, OSError) as ex:
            self.server = None
            return messagebox.showerror("Cannot start server", str(ex))
        self.btn.config(text="Stop server")
        self.dot.config(fg="#0a0")
        self.status.config(text="Listening on UDP %s:%d" % (cfg.host, cfg.port))

    def simulate_starvation(self):
        if not self.server or not self.server.running:
            return messagebox.showwarning("Starvation Demo", "Please start the server first.")

        def _flood():
            import socket
            from dhcp.constants import MsgType
            from dhcp.packet import new_request_packet
            from dhcp.utils import random_mac
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            srv_addr = (self.server.config.host, self.server.port)
            self.log("DEMO: Launching simulated DHCP starvation attack (20 rapid DISCOVERs)...")
            for i in range(20):
                mac = random_mac()
                pkt = new_request_packet(random.getrandbits(32), mac, MsgType.DISCOVER, host_name=f"Attacker-{i+1}")
                sock.sendto(pkt.encode(), srv_addr)
                time.sleep(0.04)
            sock.close()
            self.log("DEMO: Starvation flood completed. Check the pool exhaustion stats!")

        threading.Thread(target=_flood, daemon=True).start()

    def revoke(self):
        sel = self.table.selection()
        if self.server and sel:
            mac = self.table.item(sel[0])["values"][0]
            self.server.pool.release(str(mac))
            self.log("SERVER: lease of %s revoked by administrator" % mac)

    def _tick(self):
        self.view.pump()
        self.events.pump()
        if self.server:
            now = time.time()
            rows = [(l.mac, l.ip, l.hostname or "-", l.remaining(now), "static lease" if l.static else "leased")
                    for l in self.server.pool.snapshot()]
            rows += [(l.mac, l.ip, l.hostname or "-", l.remaining(now), "offered (pending)")
                     for l in self.server.pool.offers_snapshot()]
            refill(self.table, rows)
            s = self.server.pool.stats()
            self.stats.config(text="Pool: %d / %d leased   |   %d offered   |   %d quarantined"
                              % (s["leased"], s["size"], s["offered"], s["declined"]))
        else:
            refill(self.table, [])
            self.stats.config(text="")
        self.root.after(250, self._tick)

    def _close(self):
        if self.server:
            self.server.stop()
        self.root.destroy()


def run():
    root = tk.Tk()
    ServerApp(root)
    root.mainloop()

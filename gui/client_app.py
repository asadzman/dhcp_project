"""DHCP CLIENT application: obtain / renew / release / decline an address and watch the exchange."""
import time
import tkinter as tk
from tkinter import messagebox, ttk

from arp import ArpTable
from dhcp import DhcpClient, EventLog, PacketCapture
from dhcp.client import BOUND, INIT, REBINDING, REQUESTING, RENEWING, SELECTING
from dhcp.constants import SERVER_PORT
from dhcp.utils import is_valid_mac, random_mac

from .capture_view import CaptureView
from .widgets import LogView, labeled_entry, make_table, refill

STATE_COLORS = {INIT: "#9aa0a6", SELECTING: "#3b78d8", REQUESTING: "#e0a800",
                BOUND: "#1e9e4a", RENEWING: "#8e44ad", REBINDING: "#d35400"}


class ClientApp:
    def __init__(self, root):
        self.root = root
        root.title("DHCP Client")
        root.geometry("1100x780")
        self.capture, self.log = PacketCapture(), EventLog()
        self.arp_table = ArpTable(default_ttl=300.0)
        self.client = None

        # ---- settings ----
        sf = ttk.LabelFrame(root, text="Client settings")
        sf.pack(fill="x", padx=8, pady=6)
        self.e_server = labeled_entry(sf, "DHCP server (host:port)", "127.0.0.1:%d" % SERVER_PORT, 0, 0, 22)
        self.e_name = labeled_entry(sf, "Host name", "PC-1", 0, 2, 14)
        self.e_mac = labeled_entry(sf, "MAC address", random_mac(), 1, 0, 22)
        ttk.Button(sf, text="Random MAC", command=self._rand_mac).grid(row=1, column=2, sticky="w", padx=3)
        self.auto = tk.BooleanVar(value=True)
        ttk.Checkbutton(sf, text="Auto-renew at T1", variable=self.auto, command=self._toggle_auto).grid(
            row=1, column=3, padx=6)
        self.sim_conflict = tk.BooleanVar(value=False)
        ttk.Checkbutton(sf, text="Simulate ARP Conflict (DAD)", variable=self.sim_conflict).grid(
            row=1, column=4, padx=6)

        # ---- state strip ----
        st = ttk.LabelFrame(root, text="Client state machine")
        st.pack(fill="x", padx=8, pady=4)
        self.state_lbls = {}
        states = (INIT, SELECTING, REQUESTING, BOUND, RENEWING, REBINDING)
        for i, s in enumerate(states):
            l = tk.Label(st, text=s, width=12, pady=6, bg="#e4e4e4", fg="#555", font=("Arial", 9, "bold"))
            l.grid(row=0, column=i * 2, padx=2, pady=6)
            self.state_lbls[s] = l
            if i < len(states) - 1:
                ttk.Label(st, text="\u2192").grid(row=0, column=i * 2 + 1)

        # ---- buttons + lease info ----
        mid = ttk.Frame(root)
        mid.pack(fill="x", padx=8)
        bf = ttk.LabelFrame(mid, text="Actions")
        bf.pack(side="left", fill="y", padx=(0, 6))
        for text, fn in (("Obtain IP  (DORA)", self.obtain), ("Renew lease", self.renew),
                         ("Release lease", self.release), ("Decline address", self.decline),
                         ("Send INFORM (Config)", self.inform)):
            ttk.Button(bf, text=text, width=22, command=fn).pack(padx=8, pady=3)

        lf = ttk.LabelFrame(mid, text="Current lease")
        lf.pack(side="left", fill="both", expand=True)
        self.vars = {k: tk.StringVar(value="-") for k in ("ip", "mask", "gw", "dns", "domain", "sid", "lease", "left")}
        for r, (k, label) in enumerate((("ip", "IP address"), ("mask", "Subnet mask"), ("gw", "Default gateway"),
                                        ("dns", "DNS server"), ("domain", "Domain name"), ("sid", "DHCP server"),
                                        ("lease", "Lease / T1 / T2"))):
            col_group = r // 4
            row_idx = r % 4
            ttk.Label(lf, text=label + ":").grid(row=row_idx, column=col_group * 2, sticky="e", padx=6, pady=2)
            ttk.Label(lf, textvariable=self.vars[k], font=("Courier", 10, "bold")).grid(
                row=row_idx, column=col_group * 2 + 1, sticky="w", padx=6)
        ttk.Label(lf, text="Time left:").grid(row=4, column=0, sticky="e", padx=6, pady=4)
        self.bar = ttk.Progressbar(lf, length=260, maximum=100)
        self.bar.grid(row=4, column=1, columnspan=3, sticky="w")
        ttk.Label(lf, textvariable=self.vars["left"]).grid(row=4, column=4, sticky="w", padx=6)

        # ---- capture / log ----
        nb = ttk.Notebook(root)
        nb.pack(fill="both", expand=True, padx=8, pady=8)
        self.view = CaptureView(nb, self.capture)
        nb.add(self.view, text="  Packet Capture  ")

        tab_arp = ttk.Frame(nb)
        nb.add(tab_arp, text="  ARP Cache Table  ")
        self.arp_view = make_table(tab_arp, [("ip", "IP Address", 140), ("mac", "MAC Address", 160),
                                             ("type", "Type", 100), ("ttl", "TTL Remaining", 120)], height=10)
        self.arp_view.pack(fill="both", expand=True, padx=6, pady=6)

        self.events = LogView(nb, height=12)
        nb.add(self.events, text="  Event log  ")
        self.log.subscribe(self.events.push)

        self._tick()
        root.protocol("WM_DELETE_WINDOW", self._close)

    # ---------- helpers ----------
    def _rand_mac(self):
        self.e_mac.delete(0, "end")
        self.e_mac.insert(0, random_mac())

    def _ensure_client(self):
        mac, name = self.e_mac.get().strip(), self.e_name.get().strip() or "client"
        raw_srv = self.e_server.get().strip()
        addrs = []
        try:
            for part in raw_srv.split(","):
                part = part.strip()
                if not part:
                    continue
                if ":" in part:
                    host, port = part.rsplit(":", 1)
                    addrs.append((host.strip(), int(port.strip())))
                else:
                    addrs.append((part, SERVER_PORT))
        except ValueError:
            messagebox.showerror("Server", "Use host:port or comma-separated list, e.g. 127.0.0.1:6767, 127.0.0.1:6768")
            return None
        if not addrs:
            messagebox.showerror("Server", "Please specify at least one server address.")
            return None
        if not is_valid_mac(mac):
            messagebox.showerror("MAC", "Use format 02:00:5e:12:34:56")
            return None
        c = self.client
        if c and (c.mac != mac or getattr(c, "server_addrs", [c.server_addr]) != addrs or c.name != name):
            if c.ip:
                c.release()
            c.shutdown()
            c = None
        if c is None:
            c = self.client = DhcpClient(mac, name, server_addr=addrs, log=self.log,
                                         auto_renew=self.auto.get(), capture=self.capture)
        c.set_arp_checker(lambda ip: True if self.sim_conflict.get() else False)
        return c

    def obtain(self):
        c = self._ensure_client()
        if c:
            if c.ip:
                messagebox.showinfo("DHCP", "Already bound. Use Renew or Release.")
            else:
                c.obtain_async()

    def inform(self):
        c = self._ensure_client()
        if c:
            c.inform_async()

    def renew(self):
        if self.client and self.client.ip:
            self.client.renew_async()
        else:
            messagebox.showinfo("DHCP", "No lease to renew.")

    def release(self):
        if self.client and self.client.ip:
            self.client.release()

    def decline(self):
        if self.client and self.client.ip:
            self.client.decline()

    def _toggle_auto(self):
        if self.client:
            self.client.set_auto_renew(self.auto.get())

    def _tick(self):
        self.view.pump()
        self.events.pump()
        c = self.client
        state = c.state if c else INIT
        for s, l in self.state_lbls.items():
            on = (s == state)
            l.config(bg=STATE_COLORS[s] if on else "#e4e4e4", fg="white" if on else "#555")
        if c and (c.ip or c.subnet_mask):
            left = c.lease_remaining()
            self.vars["ip"].set(c.ip or "(unassigned)")
            self.vars["mask"].set(c.subnet_mask or "-")
            self.vars["gw"].set(c.router or "-")
            self.vars["dns"].set(c.dns or "-")
            self.vars["domain"].set(c.domain_name or "-")
            self.vars["sid"].set(c.server_id or "-")
            self.vars["lease"].set("%ds / %ds / %ds" % (c.lease_time, c.t1, c.t2) if c.lease_time else "-")
            self.vars["left"].set("%d s" % left if c.lease_time else "-")
            self.bar["value"] = 100.0 * left / c.lease_time if c.lease_time else 0
        else:
            for v in self.vars.values():
                v.set("-")
            self.bar["value"] = 0

        now = time.time()
        arp_rows = []
        if c and c.ip:
            if c.router and not self.arp_table.lookup(c.router):
                self.arp_table.update(c.router, "02:00:5e:fe:00:01", static=True)
            if c.server_id and not self.arp_table.lookup(c.server_id):
                self.arp_table.update(c.server_id, "02:00:5e:fe:00:02", static=True)
        for entry in self.arp_table.snapshot():
            ttl_str = "Static (Permanent)" if entry.static else "%ds" % max(0, int(entry.ttl - (now - entry.updated_at)))
            arp_rows.append((entry.ip, entry.mac, "Static" if entry.static else "Dynamic", ttl_str))
        refill(self.arp_view, arp_rows)

        self.root.after(250, self._tick)

    def _close(self):
        if self.client:
            if self.client.ip:
                self.client.release()
            self.client.shutdown()
        self.root.destroy()


def run():
    root = tk.Tk()
    ClientApp(root)
    root.mainloop()

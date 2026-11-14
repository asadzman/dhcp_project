"""ARP Protocol Application: Live cache table, Who-has queries, Gratuitous ARP, and Wireshark capture."""
from __future__ import annotations

import time
import tkinter as tk
from tkinter import messagebox, ttk

from arp import ArpEngine, ArpTable, DEFAULT_ARP_PORT
from dhcp.capture import PacketCapture
from dhcp.eventlog import EventLog
from dhcp.utils import is_valid_ip, is_valid_mac, random_mac
from .capture_view import CaptureView
from .widgets import LogView, labeled_entry, make_table, refill


class ArpApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title("ARP Protocol Inspector & Manager (RFC 826 / RFC 5227)")
        root.geometry("1120x760")
        self.engine: Optional[ArpEngine] = None
        self.table = ArpTable(default_ttl=120.0)
        self.capture = PacketCapture()
        self.log = EventLog()

        # ---- settings toolbar ----
        sf = ttk.LabelFrame(root, text="Node configuration")
        sf.pack(fill="x", padx=8, pady=6)
        self.e_ip = labeled_entry(sf, "My IP Address", "192.168.1.50", 0, 0, 16)
        self.e_mac = labeled_entry(sf, "My MAC Address", random_mac(), 0, 2, 20)
        ttk.Button(sf, text="Random MAC", command=self._rand_mac).grid(row=0, column=4, sticky="w", padx=4)

        self.e_port = labeled_entry(sf, "UDP Listen Port", str(DEFAULT_ARP_PORT), 1, 0, 16)
        self.e_peers = labeled_entry(sf, "Broadcast Peers (host:port,...)", "127.0.0.1:6869, 127.0.0.1:6870", 1, 2, 32)

        self.btn_toggle = ttk.Button(sf, text="Start ARP Node", command=self.toggle_engine)
        self.btn_toggle.grid(row=1, column=4, padx=6, pady=4)
        self.dot = tk.Label(sf, text="\u25cf", fg="#c00", font=("Arial", 16))
        self.dot.grid(row=1, column=5)

        # ---- action controls ----
        act_frame = ttk.LabelFrame(root, text="Interactive ARP operations")
        act_frame.pack(fill="x", padx=8, pady=4)

        # Query (Who-has)
        ttk.Label(act_frame, text="Target IP:").pack(side="left", padx=(8, 2))
        self.e_target = ttk.Entry(act_frame, width=15)
        self.e_target.insert(0, "192.168.1.1")
        self.e_target.pack(side="left", padx=4)
        ttk.Button(act_frame, text="Query (Who-Has)", command=self.send_query).pack(side="left", padx=4)

        # Gratuitous & Probe
        ttk.Button(act_frame, text="Send Gratuitous ARP", command=self.send_gratuitous).pack(side="left", padx=8)
        ttk.Button(act_frame, text="Send ARP Probe (DAD)", command=self.send_probe).pack(side="left", padx=4)

        # Static mapping adder
        ttk.Separator(act_frame, orient="vertical").pack(side="left", fill="y", padx=10)
        ttk.Button(act_frame, text="Add Static Mapping", command=self.add_static_dialog).pack(side="left", padx=6)

        # ---- tabs ----
        nb = ttk.Notebook(root)
        nb.pack(fill="both", expand=True, padx=8, pady=6)

        # Tab 1: ARP Table
        tab_tbl = ttk.Frame(nb)
        nb.add(tab_tbl, text="  ARP Cache Table  ")
        self.table_view = make_table(tab_tbl, [("ip", "IP Address", 140), ("mac", "MAC Address", 160),
                                              ("kind", "Type", 100), ("ttl", "TTL Remaining", 120)], height=12)
        self.table_view.pack(fill="both", expand=True, padx=6, pady=6)
        tbl_bar = ttk.Frame(tab_tbl)
        tbl_bar.pack(fill="x", padx=6, pady=4)
        ttk.Button(tbl_bar, text="Delete selected entry", command=self.delete_selected).pack(side="left", padx=4)
        ttk.Button(tbl_bar, text="Clear ARP Table", command=self.clear_table).pack(side="left", padx=4)

        # Tab 2: Packet Capture
        self.cap_view = CaptureView(nb, self.capture)
        nb.add(self.cap_view, text="  Packet Capture (Wireshark View)  ")

        # Tab 3: Event Log
        tab_log = ttk.Frame(nb)
        nb.add(tab_log, text="  Event Log  ")
        self.events = LogView(tab_log, height=14)
        self.events.pack(fill="both", expand=True, padx=6, pady=6)
        self.log.subscribe(self.events.push)

        self._tick()
        root.protocol("WM_DELETE_WINDOW", self._close)

    def _rand_mac(self):
        self.e_mac.delete(0, "end")
        self.e_mac.insert(0, random_mac())

    def toggle_engine(self):
        if self.engine and self.engine.running:
            self.engine.stop()
            self.engine = None
            self.btn_toggle.config(text="Start ARP Node")
            self.dot.config(fg="#c00")
            return

        ip = self.e_ip.get().strip()
        mac = self.e_mac.get().strip()
        try:
            port = int(self.e_port.get().strip())
        except ValueError:
            return messagebox.showerror("Error", "Invalid UDP port.")

        if not is_valid_ip(ip):
            return messagebox.showerror("Error", "Invalid IP address.")
        if not is_valid_mac(mac):
            return messagebox.showerror("Error", "Invalid MAC address.")

        peers = []
        raw_peers = self.e_peers.get().strip()
        if raw_peers:
            for p in raw_peers.split(","):
                p = p.strip()
                if ":" in p:
                    h, pt = p.rsplit(":", 1)
                    peers.append((h.strip(), int(pt.strip())))

        self.engine = ArpEngine(mac=mac, ip=ip, port=port, peers=peers,
                                log=self.log, capture=self.capture, table=self.table)
        try:
            self.engine.start()
            self.btn_toggle.config(text="Stop ARP Node")
            self.dot.config(fg="#0a0")
        except Exception as e:
            self.engine = None
            messagebox.showerror("Failed to start", str(e))

    def send_query(self):
        if not self.engine or not self.engine.running:
            return messagebox.showwarning("Warning", "Please start the ARP Node first.")
        target = self.e_target.get().strip()
        if not is_valid_ip(target):
            return messagebox.showerror("Error", "Invalid target IP address.")
        self.engine.send_request(target)

    def send_gratuitous(self):
        if not self.engine or not self.engine.running:
            return messagebox.showwarning("Warning", "Please start the ARP Node first.")
        self.engine.send_gratuitous()

    def send_probe(self):
        if not self.engine or not self.engine.running:
            return messagebox.showwarning("Warning", "Please start the ARP Node first.")
        target = self.e_target.get().strip()
        if not is_valid_ip(target):
            return messagebox.showerror("Error", "Invalid target IP address.")
        self.engine.send_probe(target)

    def add_static_dialog(self):
        dlg = tk.Toplevel(self.root)
        dlg.title("Add Static ARP Entry")
        dlg.geometry("340x160")
        e_ip = labeled_entry(dlg, "IP Address", "192.168.1.1", 0, 0, 18)
        e_mac = labeled_entry(dlg, "MAC Address", "02:00:5e:00:00:01", 1, 0, 18)

        def _save():
            ip_val, mac_val = e_ip.get().strip(), e_mac.get().strip()
            if not is_valid_ip(ip_val) or not is_valid_mac(mac_val):
                return messagebox.showerror("Error", "Invalid IP or MAC.", parent=dlg)
            self.table.update(ip_val, mac_val, static=True)
            self.log("ADMIN: added static ARP entry: %s -> %s" % (ip_val, mac_val))
            dlg.destroy()

        ttk.Button(dlg, text="Save Entry", command=_save).grid(row=2, column=1, pady=12, sticky="e")

    def delete_selected(self):
        sel = self.table_view.selection()
        if not sel:
            return
        item = self.table_view.item(sel[0])
        ip = item["values"][0]
        self.table.remove(ip)
        self.log("ADMIN: deleted ARP entry for %s" % ip)

    def clear_table(self):
        self.table.clear()
        self.log("ADMIN: cleared entire ARP cache table")

    def _tick(self):
        self.cap_view.pump()
        self.events.pump()
        now = time.time()
        rows = []
        for entry in self.table.snapshot():
            ttl_str = "Permanent (Static)" if entry.static else ("%ds" % max(0, int(entry.ttl - (now - entry.updated_at))))
            rows.append((entry.ip, entry.mac, "Static" if entry.static else "Dynamic", ttl_str))
        refill(self.table_view, rows)
        self.root.after(300, self._tick)

    def _close(self):
        if self.engine:
            self.engine.stop()
        self.root.destroy()


def run():
    root = tk.Tk()
    ArpApp(root)
    root.mainloop()


if __name__ == "__main__":
    run()

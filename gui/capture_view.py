"""Wireshark-like capture widget: packet list (top), protocol tree (bottom-left), hex dump (bottom-right).
Selecting a field in the tree highlights its bytes in the hex dump."""
import csv
import queue
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from dhcp.dissect import Node, ascii_col, dissect, hex_col, hex_lines

COLORS = {"Discover": "#dbe9ff", "Offer": "#d8f5d0", "Request": "#fff1b8", "ACK": "#b9eeb9",
          "NAK": "#ffc2c2", "Release": "#e3e3e3", "Decline": "#ffd6ad", "Inform": "#e6d6ff",
          "ARP": "#faf0d7"}
COLUMNS = [("no", "No.", 50), ("time", "Time", 80), ("src", "Source", 120), ("dst", "Destination", 135),
           ("proto", "Protocol", 70), ("len", "Length", 60), ("info", "Info", 360)]


class CaptureView(ttk.Frame):
    def __init__(self, parent, capture):
        super().__init__(parent)
        self.capture = capture
        self._q = queue.Queue()
        capture.subscribe(self._q.put)                 # thread-safe hand-off to the GUI thread
        self._shown = 0
        self._node_ranges = {}
        self._current = None

        # ---- toolbar (filter bar) ----
        bar = ttk.Frame(self)
        bar.pack(fill="x", padx=4, pady=3)
        ttk.Label(bar, text="Filter:").pack(side="left")
        self.filter_var = tk.StringVar()
        ent = ttk.Entry(bar, textvariable=self.filter_var, width=34)
        ent.pack(side="left", padx=4)
        ent.bind("<Return>", lambda e: self.rebuild())
        ttk.Button(bar, text="Apply", command=self.rebuild).pack(side="left")
        ttk.Button(bar, text="Clear filter", command=lambda: (self.filter_var.set(""), self.rebuild())).pack(side="left", padx=2)
        ttk.Label(bar, text='e.g.  offer   02:00:5e   0x1a2b',
                  foreground="#666").pack(side="left", padx=6)
        ttk.Button(bar, text="Export PCAP", command=self.export_pcap).pack(side="right", padx=2)
        ttk.Button(bar, text="Export CSV", command=self.export).pack(side="right", padx=2)
        ttk.Button(bar, text="Clear capture", command=self.clear).pack(side="right", padx=2)
        self.autoscroll = tk.BooleanVar(value=True)
        ttk.Checkbutton(bar, text="Auto-scroll", variable=self.autoscroll).pack(side="right", padx=6)

        # ---- panes ----
        outer = ttk.PanedWindow(self, orient="vertical")
        outer.pack(fill="both", expand=True, padx=4)

        lf = ttk.Frame(outer)
        self.lst = ttk.Treeview(lf, columns=[c[0] for c in COLUMNS], show="headings", height=9, selectmode="browse")
        for k, t, w in COLUMNS:
            self.lst.heading(k, text=t)
            self.lst.column(k, width=w, anchor="w", stretch=(k == "info"))
        sb = ttk.Scrollbar(lf, command=self.lst.yview)
        self.lst.config(yscrollcommand=sb.set)
        self.lst.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        for name, col in COLORS.items():
            self.lst.tag_configure(name, background=col, foreground="#000")
        self.lst.bind("<<TreeviewSelect>>", self._on_pick_packet)
        outer.add(lf, weight=3)

        inner = ttk.PanedWindow(outer, orient="horizontal")
        df = ttk.Frame(inner)
        self.det = ttk.Treeview(df, show="tree", selectmode="browse")
        dsb = ttk.Scrollbar(df, command=self.det.yview)
        self.det.config(yscrollcommand=dsb.set)
        self.det.pack(side="left", fill="both", expand=True)
        dsb.pack(side="right", fill="y")
        self.det.bind("<<TreeviewSelect>>", self._on_pick_field)
        inner.add(df, weight=3)

        hf = ttk.Frame(inner)
        self.hex = tk.Text(hf, width=74, height=10, font=("Courier", 10), state="disabled", wrap="none",
                           bg="#fdfdfd")
        hsb = ttk.Scrollbar(hf, command=self.hex.yview)
        self.hex.config(yscrollcommand=hsb.set)
        self.hex.pack(side="left", fill="both", expand=True)
        hsb.pack(side="right", fill="y")
        self.hex.tag_configure("hl", background="#2f6fdb", foreground="white")
        inner.add(hf, weight=2)
        outer.add(inner, weight=4)

        self.status = ttk.Label(self, text="Packets: 0   Displayed: 0", anchor="w")
        self.status.pack(fill="x", padx=6, pady=2)

    # ---------- feeding ----------
    def pump(self):
        """Call regularly from the GUI thread."""
        changed = False
        try:
            while True:
                cp = self._q.get_nowait()
                if self._matches(cp):
                    self._insert(cp)
                changed = True
        except queue.Empty:
            pass
        if changed:
            self._update_status()

    def _terms(self):
        return self.filter_var.get().lower().split()

    def _matches(self, cp):
        h = cp.haystack()
        return all(t in h for t in self._terms())

    def _insert(self, cp):
        t = cp.type_name if cp.proto != "ARP" else "ARP"
        self.lst.insert("", "end", iid=str(cp.no), tags=(t,),
                        values=(cp.no, "%.6f" % cp.rel_time, cp.src, cp.dst, cp.proto, cp.length, cp.info))
        self._shown += 1
        if self.autoscroll.get():
            self.lst.see(str(cp.no))

    def rebuild(self):
        self.lst.delete(*self.lst.get_children())
        self._shown = 0
        while not self._q.empty():          # anything queued is already in capture.packets
            try: self._q.get_nowait()
            except queue.Empty: break
        for cp in self.capture.snapshot():
            if self._matches(cp):
                self._insert(cp)
        self._update_status()

    def clear(self):
        self.capture.clear()
        self.rebuild()
        self._show_packet(None)

    def _update_status(self):
        self.status.config(text="Packets: %d   Displayed: %d" % (len(self.capture.packets), self._shown))

    # ---------- details ----------
    def _on_pick_packet(self, _e=None):
        sel = self.lst.selection()
        self._show_packet(self.capture.get(int(sel[0])) if sel else None)

    def _show_packet(self, cp):
        self._current = cp
        self.det.delete(*self.det.get_children())
        self._node_ranges.clear()
        self.hex.config(state="normal")
        self.hex.delete("1.0", "end")
        if cp:
            for n in dissect(cp):
                self._add_node("", n, depth=0)
            self.hex.insert("end", "\n".join(hex_lines(cp.raw)))
            self.hex.insert("end", "\n\n(DHCP payload = UDP payload, %d bytes)" % cp.length)
        self.hex.config(state="disabled")

    def _add_node(self, parent, node: Node, depth):
        iid = self.det.insert(parent, "end", text=node.label,
                              open=node.label.startswith("Dynamic Host") and depth == 0)
        if node.start >= 0:
            self._node_ranges[iid] = (node.start, node.length)
        for c in node.children:
            self._add_node(iid, c, depth + 1)

    def _on_pick_field(self, _e=None):
        self.hex.config(state="normal")
        self.hex.tag_remove("hl", "1.0", "end")
        sel = self.det.selection()
        if sel and sel[0] in self._node_ranges:
            start, length = self._node_ranges[sel[0]]
            for i in range(start, start + length):
                line = i // 16 + 1
                for col in (hex_col(i), ascii_col(i)):
                    self.hex.tag_add("hl", "%d.%d" % (line, col), "%d.%d" % (line, col + (2 if col == hex_col(i) else 1)))
            self.hex.see("%d.0" % (start // 16 + 1))
        self.hex.config(state="disabled")

    # ---------- export ----------
    def export_pcap(self):
        path = filedialog.asksaveasfilename(defaultextension=".pcap",
                                            filetypes=[("Wireshark PCAP", "*.pcap"), ("All files", "*.*")])
        if not path:
            return
        try:
            n = self.capture.export_pcap(path)
            messagebox.showinfo("Export PCAP", "Saved %d packet(s) to:\n%s\n\nYou can now open this file in Wireshark!" % (n, path))
        except Exception as e:
            messagebox.showerror("Export PCAP Error", str(e))

    def export(self):
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if not path:
            return
        with open(path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow([c[1] for c in COLUMNS])
            for cp in self.capture.snapshot():
                if self._matches(cp):
                    w.writerow([cp.no, "%.6f" % cp.rel_time, cp.src, cp.dst, "DHCP", cp.length, cp.info])
        messagebox.showinfo("Export", "Saved " + path)

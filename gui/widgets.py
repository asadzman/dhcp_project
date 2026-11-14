"""Reusable Tkinter building blocks."""
import queue
import tkinter as tk
from tkinter import ttk


def make_table(parent, columns, height=7):
    """columns: [(key, heading, width), ...] -> Treeview"""
    tree = ttk.Treeview(parent, columns=[c[0] for c in columns], show="headings", height=height)
    for key, text, width in columns:
        tree.heading(key, text=text)
        tree.column(key, width=width, anchor="w")
    return tree


def refill(tree, rows):
    """Replace the rows but keep the selected row index."""
    sel = tree.selection()
    idx = tree.index(sel[0]) if sel else None
    tree.delete(*tree.get_children())
    for r in rows:
        tree.insert("", "end", values=r)
    kids = tree.get_children()
    if idx is not None and idx < len(kids):
        tree.selection_set(kids[idx])


def labeled_entry(parent, label, default, row, col=0, width=16):
    ttk.Label(parent, text=label).grid(row=row, column=col, sticky="e", padx=3, pady=2)
    e = ttk.Entry(parent, width=width)
    e.insert(0, default)
    e.grid(row=row, column=col + 1, padx=3, pady=2, sticky="w")
    return e


class LogView(ttk.Frame):
    """Dark console fed from any thread through a queue."""

    def __init__(self, parent, height=14):
        super().__init__(parent)
        self._q = queue.Queue()
        self.text = tk.Text(self, height=height, state="disabled", bg="#111", fg="#8f8", font=("Courier", 9))
        sb = ttk.Scrollbar(self, command=self.text.yview)
        self.text.config(yscrollcommand=sb.set)
        self.text.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

    def push(self, line):               # thread-safe
        self._q.put(line)

    def clear(self):
        self.text.config(state="normal")
        self.text.delete("1.0", "end")
        self.text.config(state="disabled")

    def pump(self):                     # call from the GUI thread
        try:
            while True:
                line = self._q.get_nowait()
                self.text.config(state="normal")
                self.text.insert("end", line + "\n")
                self.text.see("end")
                self.text.config(state="disabled")
        except queue.Empty:
            pass

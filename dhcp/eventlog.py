"""Tiny publish/subscribe logger so the server, client and GUI stay decoupled."""
import threading
import time


class EventLog:
    def __init__(self, echo: bool = False):
        self.echo = echo
        self._subs = []
        self._lock = threading.Lock()

    def subscribe(self, fn):
        with self._lock:
            self._subs.append(fn)

    def __call__(self, msg: str):
        line = "[%s] %s" % (time.strftime("%H:%M:%S"), msg)
        if self.echo:
            print(line, flush=True)
        with self._lock:
            subs = list(self._subs)
        for fn in subs:
            fn(line)

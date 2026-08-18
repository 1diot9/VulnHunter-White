"""Shared 429 cooldown only — inflight LLM threads are gated by llm_thread.py."""

from __future__ import annotations

import threading
import time
from contextlib import contextmanager
from typing import Iterator

from ..config import settings


class LlmRequestGate:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._cooldown_until = 0.0

    def note_rate_limit(self, retry_after: float | None = None) -> None:
        sleep_sec = float(retry_after or settings.rate_limit_sleep_sec)
        with self._lock:
            self._cooldown_until = max(self._cooldown_until, time.time() + max(0.0, sleep_sec))

    def cooldown_remaining(self) -> float:
        with self._lock:
            return max(0.0, self._cooldown_until - time.time())

    def _wait_until(self, deadline: float, cancel_event: threading.Event | None) -> bool:
        while True:
            if cancel_event is not None and cancel_event.is_set():
                return False
            remaining = deadline - time.time()
            if remaining <= 0:
                return True
            time.sleep(min(0.5, remaining))

    def acquire(self, cancel_event: threading.Event | None = None) -> bool:
        """Wait out a shared 429 cooldown; do not serialize inflight requests."""
        while True:
            with self._lock:
                wait_until = self._cooldown_until
            if not self._wait_until(wait_until, cancel_event):
                return False
            with self._lock:
                if time.time() >= self._cooldown_until:
                    return True

    def release(self) -> None:
        return


llm_gate = LlmRequestGate()


@contextmanager
def llm_slot(cancel_event: threading.Event | None = None) -> Iterator[bool]:
    ok = llm_gate.acquire(cancel_event)
    try:
        yield ok
    finally:
        if ok:
            llm_gate.release()

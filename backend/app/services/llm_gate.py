"""Per-endpoint LLM cooldown (429 / quota / auth / 5xx).

Inflight Agent slots are gated by llm_thread.py; this module only tracks
health/cooldown state shared with the pool scheduler.
"""

from __future__ import annotations

import json
import threading
import time
from contextlib import contextmanager
from typing import Iterator, Literal

ErrorKind = Literal["rate_limit", "quota", "auth", "transient"]

# Cooldown policy (seconds)
_RATE_LIMIT_BASE = 30.0
_RATE_LIMIT_CAP = 90.0
_QUOTA_COOLDOWN = 5 * 60.0
_TRANSIENT_COOLDOWN = 10.0


def compact_llm_error(message: str, kind: str = "") -> str:
    """Prefer provider `error.message` over a raw JSON body."""
    text = (message or "").strip()
    extracted = _extract_provider_message(text) if text else ""
    return (extracted or text or kind)[:240]


def _extract_provider_message(text: str) -> str:
    brace = text.find("{")
    if brace < 0:
        return ""
    try:
        obj = json.loads(text[brace:])
    except json.JSONDecodeError:
        return ""
    return _walk_error_message(obj)


def _walk_error_message(obj: object) -> str:
    if isinstance(obj, str):
        return obj.strip()
    if not isinstance(obj, dict):
        return ""
    err = obj.get("error")
    if isinstance(err, str) and err.strip():
        return err.strip()
    if isinstance(err, dict):
        for key in ("message", "msg"):
            val = err.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip()
    for key in ("message", "msg", "detail"):
        val = obj.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return ""


class EndpointHealth:
    __slots__ = ("cooldown_until", "disabled", "last_error", "error_kind", "rate_limit_strikes")

    def __init__(self) -> None:
        self.cooldown_until = 0.0
        self.disabled = False
        self.last_error = ""
        self.error_kind = ""
        self.rate_limit_strikes = 0


class LlmRequestGate:
    """Per-endpoint cooldown registry."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._by_id: dict[str, EndpointHealth] = {}

    def reset(self) -> None:
        with self._lock:
            self._by_id.clear()

    def clear_on_settings_save(self) -> None:
        """Drop cooldowns/disables after settings change."""
        self.reset()

    def _health(self, endpoint_id: str) -> EndpointHealth:
        h = self._by_id.get(endpoint_id)
        if h is None:
            h = EndpointHealth()
            self._by_id[endpoint_id] = h
        return h

    def note_error(
        self,
        endpoint_id: str,
        kind: ErrorKind,
        *,
        retry_after: float | None = None,
        message: str = "",
    ) -> float:
        """Record an error for ``endpoint_id``. Returns cooldown seconds applied."""
        eid = (endpoint_id or "").strip() or "_default"
        now = time.time()
        with self._lock:
            h = self._health(eid)
            h.error_kind = kind
            h.last_error = compact_llm_error(message, kind)
            if kind == "auth":
                h.disabled = True
                h.cooldown_until = float("inf")
                return float("inf")
            if kind == "quota":
                sleep_sec = _QUOTA_COOLDOWN
                h.rate_limit_strikes = 0
            elif kind == "transient":
                sleep_sec = _TRANSIENT_COOLDOWN
            else:
                # rate_limit
                h.rate_limit_strikes += 1
                if retry_after is not None and retry_after > 0:
                    sleep_sec = float(retry_after)
                else:
                    sleep_sec = min(
                        _RATE_LIMIT_CAP,
                        _RATE_LIMIT_BASE * (2 ** max(0, h.rate_limit_strikes - 1)),
                    )
            h.cooldown_until = max(h.cooldown_until, now + max(0.0, sleep_sec))
            return sleep_sec

    def note_rate_limit(
        self,
        retry_after: float | None = None,
        *,
        endpoint_id: str = "",
        message: str = "",
    ) -> None:
        """Backward-compatible entry; prefers per-endpoint when id is set."""
        self.note_error(
            endpoint_id or "_default",
            "rate_limit",
            retry_after=retry_after,
            message=message or "rate_limit",
        )

    def note_success(self, endpoint_id: str) -> None:
        eid = (endpoint_id or "").strip()
        if not eid:
            return
        now = time.time()
        with self._lock:
            h = self._by_id.get(eid)
            if h is None:
                return
            h.rate_limit_strikes = 0
            if not h.disabled and now >= h.cooldown_until:
                h.last_error = ""
                h.error_kind = ""

    def is_available(self, endpoint_id: str, *, now: float | None = None) -> bool:
        eid = (endpoint_id or "").strip() or "_default"
        t = now if now is not None else time.time()
        with self._lock:
            h = self._by_id.get(eid)
            if h is None:
                return True
            if h.disabled:
                return False
            return t >= h.cooldown_until

    def cooldown_remaining(self, endpoint_id: str = "") -> float:
        eid = (endpoint_id or "").strip() or "_default"
        now = time.time()
        with self._lock:
            h = self._by_id.get(eid)
            if h is None:
                return 0.0
            if h.disabled:
                return float("inf") if h.cooldown_until == float("inf") else max(0.0, h.cooldown_until - now)
            return max(0.0, h.cooldown_until - now)

    def earliest_available_at(self, endpoint_ids: list[str]) -> float:
        """Earliest time any listed endpoint becomes available (inf if all disabled)."""
        now = time.time()
        soonest = float("inf")
        with self._lock:
            for eid in endpoint_ids:
                h = self._by_id.get(eid)
                if h is None:
                    return now
                if h.disabled:
                    continue
                soonest = min(soonest, h.cooldown_until)
        return soonest if soonest != float("inf") else now

    def snapshot(self, endpoint_ids: list[str] | None = None) -> dict[str, dict[str, float | str | bool]]:
        now = time.time()
        with self._lock:
            ids = endpoint_ids if endpoint_ids is not None else list(self._by_id.keys())
            out: dict[str, dict[str, float | str | bool]] = {}
            for eid in ids:
                h = self._by_id.get(eid) or EndpointHealth()
                cd = 0.0
                if h.disabled:
                    cd = float("inf") if h.cooldown_until == float("inf") else max(0.0, h.cooldown_until - now)
                else:
                    cd = max(0.0, h.cooldown_until - now)
                out[eid] = {
                    "cooldown_sec": cd if cd != float("inf") else -1.0,
                    "disabled": h.disabled,
                    "last_error": h.last_error,
                    "error_kind": h.error_kind,
                }
            return out


llm_gate = LlmRequestGate()


@contextmanager
def llm_slot(cancel_event: threading.Event | None = None) -> Iterator[bool]:
    """No longer serializes inflight requests; only respects cancel."""
    if cancel_event is not None and cancel_event.is_set():
        yield False
        return
    yield True

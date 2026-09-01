"""Per-endpoint FIFO limiter for LLM-interacting agent threads.

Each AgentLoop occupies one slot on one Base URL for the session duration.
Capacity is the sum of per-endpoint max_inflight. On 429/quota the session can
rebind to another healthy endpoint without releasing the global wait queue.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Iterator

from ..config import settings
from .llm_gate import llm_gate

DEFAULT_LLM_THREAD_LIMIT = 6
_ANON_ENDPOINT_ID = "_anon"


@dataclass
class SlotHandle:
    endpoint_id: str
    ticket: int


@dataclass
class _EndpointBucket:
    id: str
    base_url: str
    api_key: str
    cap: int
    used: int = 0
    model: str = ""


def _read_pool_from_settings() -> list[dict[str, Any]]:
    try:
        from .llm_settings import pool_endpoints_resolved

        pool = pool_endpoints_resolved()
        if pool:
            return [
                {
                    "id": ep.id,
                    "base_url": ep.base_url,
                    "api_key": ep.api_key,
                    "model": ep.model,
                    "max_inflight": ep.max_inflight,
                }
                for ep in pool
            ]
    except Exception:  # noqa: BLE001
        pass
    try:
        from .llm_settings import get_settings_row

        row = get_settings_row()
        n = getattr(row, "llm_thread_limit", None)
        limit = max(1, int(n)) if n is not None else DEFAULT_LLM_THREAD_LIMIT
        url = (getattr(row, "default_base_url", None) or "").strip() or "https://api.openai.com/v1"
        key = (getattr(row, "default_api_key", None) or "").strip()
        model = (getattr(row, "default_model", None) or "").strip()
        return [
            {
                "id": "ep-1",
                "base_url": url,
                "api_key": key,
                "model": model,
                "max_inflight": limit,
            }
        ]
    except Exception:  # noqa: BLE001
        pass
    return [
        {
            "id": "ep-1",
            "base_url": "https://api.openai.com/v1",
            "api_key": "",
            "model": "",
            "max_inflight": max(
                1, int(getattr(settings, "llm_thread_limit", None) or DEFAULT_LLM_THREAD_LIMIT)
            ),
        }
    ]


def _log_system(
    project_id: int | None,
    phase: str,
    role: str,
    text: str,
) -> None:
    if not project_id:
        return
    try:
        from .live_log import live_log

        live_log.system(project_id, text, phase=phase or None, role=role or None)
    except Exception:  # noqa: BLE001
        pass


class LlmThreadLimiter:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._cond = threading.Condition(self._lock)
        self._queue: deque[int] = deque()
        self._next_ticket = 0
        self._buckets: dict[str, _EndpointBucket] = {}
        self._order: list[str] = []
        self._override: int | None = None
        self._loaded = False
        self._handles: dict[int, str] = {}  # ticket -> endpoint_id while held

    def reset(self) -> None:
        """Drop inflight/waiters. Tests and process isolation only."""
        with self._cond:
            self._queue.clear()
            self._next_ticket = 0
            self._buckets.clear()
            self._order.clear()
            self._override = None
            self._loaded = False
            self._handles.clear()
            self._cond.notify_all()
        llm_gate.reset()

    def set_limit_override(self, n: int | None) -> None:
        """Test hook: force a single anonymous bucket with capacity n."""
        with self._cond:
            if n is None:
                self._override = None
            else:
                self._override = max(1, int(n))
                self._buckets = {
                    _ANON_ENDPOINT_ID: _EndpointBucket(
                        id=_ANON_ENDPOINT_ID,
                        base_url="",
                        api_key="",
                        cap=self._override,
                        used=self._total_used_locked(),
                    )
                }
                self._order = [_ANON_ENDPOINT_ID]
                self._loaded = True
            self._cond.notify_all()

    def refresh_limit(self, n: int | None = None) -> int:
        """Legacy: set single-bucket capacity (compat for older callers/tests)."""
        if n is None:
            self.refresh_pool()
            return self.current_limit()
        limit = max(1, int(n))
        with self._cond:
            if len(self._order) == 1:
                bid = self._order[0]
                self._buckets[bid].cap = limit
            elif not self._order:
                self._buckets = {
                    "ep-1": _EndpointBucket(
                        id="ep-1", base_url="", api_key="", cap=limit, used=0
                    )
                }
                self._order = ["ep-1"]
            self._loaded = True
            self._cond.notify_all()
        return limit

    def refresh_pool(self, endpoints: list[Any] | None = None) -> int:
        """Reload caps from settings or provided endpoint list; clear cooldowns."""
        llm_gate.clear_on_settings_save()
        if endpoints is None:
            raw = _read_pool_from_settings()
        else:
            raw = []
            for ep in endpoints:
                if hasattr(ep, "id"):
                    raw.append(
                        {
                            "id": str(getattr(ep, "id", "") or ""),
                            "base_url": str(getattr(ep, "base_url", "") or ""),
                            "api_key": "",
                            "model": str(getattr(ep, "model", "") or ""),
                            "max_inflight": int(getattr(ep, "max_inflight", DEFAULT_LLM_THREAD_LIMIT) or DEFAULT_LLM_THREAD_LIMIT),
                        }
                    )
                elif isinstance(ep, dict):
                    raw.append(ep)
        if not raw:
            raw = _read_pool_from_settings()

        with self._cond:
            old_used = {bid: b.used for bid, b in self._buckets.items()}
            new_buckets: dict[str, _EndpointBucket] = {}
            new_order: list[str] = []
            for item in raw:
                eid = str(item.get("id") or "").strip()
                if not eid:
                    continue
                cap = max(1, int(item.get("max_inflight") or DEFAULT_LLM_THREAD_LIMIT))
                # Preserve api_key/base_url/model from resolved pool when available
                key = str(item.get("api_key") or "")
                url = str(item.get("base_url") or "")
                model = str(item.get("model") or "").strip()
                if not key or not url or not model:
                    try:
                        from .llm_settings import pool_endpoints_resolved

                        for pe in pool_endpoints_resolved():
                            if pe.id == eid:
                                key = key or pe.api_key
                                url = url or pe.base_url
                                model = model or pe.model
                                break
                    except Exception:  # noqa: BLE001
                        pass
                used = min(old_used.get(eid, 0), cap)
                new_buckets[eid] = _EndpointBucket(
                    id=eid, base_url=url, api_key=key, cap=cap, used=used, model=model
                )
                new_order.append(eid)
            if not new_buckets:
                new_buckets = {
                    "ep-1": _EndpointBucket(
                        id="ep-1",
                        base_url="",
                        api_key="",
                        cap=DEFAULT_LLM_THREAD_LIMIT,
                        used=0,
                    )
                }
                new_order = ["ep-1"]
            self._buckets = new_buckets
            self._order = new_order
            self._override = None
            self._loaded = True
            self._cond.notify_all()
            return self._limit_locked()

    def _ensure_loaded(self) -> None:
        with self._lock:
            if self._loaded or self._override is not None:
                return
            self._loaded = True
        self.refresh_pool()

    def _total_used_locked(self) -> int:
        return sum(b.used for b in self._buckets.values())

    def _limit_locked(self) -> int:
        if self._override is not None and not self._buckets:
            return self._override
        return max(1, sum(b.cap for b in self._buckets.values()) or DEFAULT_LLM_THREAD_LIMIT)

    def current_limit(self) -> int:
        self._ensure_loaded()
        with self._lock:
            return self._limit_locked()

    def snapshot(self) -> tuple[int, int, int]:
        """Return (used, limit, waiting)."""
        self._ensure_loaded()
        with self._lock:
            return self._total_used_locked(), self._limit_locked(), len(self._queue)

    def detailed_snapshot(self) -> dict[str, Any]:
        self._ensure_loaded()
        health = llm_gate.snapshot(list(self._order) if self._order else None)
        with self._lock:
            endpoints = []
            for eid in self._order:
                b = self._buckets[eid]
                h = health.get(eid) or {}
                cd = float(h.get("cooldown_sec") or 0.0)
                endpoints.append(
                    {
                        "id": eid,
                        "base_url": b.base_url,
                        "used": b.used,
                        "limit": b.cap,
                        "cooldown_sec": 0.0 if cd < 0 else cd,
                        "last_error": str(h.get("last_error") or ""),
                        "error_kind": str(h.get("error_kind") or ""),
                        "disabled": bool(h.get("disabled")),
                    }
                )
            return {
                "used": self._total_used_locked(),
                "limit": self._limit_locked(),
                "waiting": len(self._queue),
                "endpoints": endpoints,
            }

    def endpoint_creds(self, endpoint_id: str) -> tuple[str, str, str]:
        """Return (base_url, api_key, model) for a bound endpoint."""
        self._ensure_loaded()
        with self._lock:
            b = self._buckets.get(endpoint_id)
            if b is None:
                return "", "", ""
            return b.base_url, b.api_key, b.model

    def get_endpoint(self, endpoint_id: str) -> _EndpointBucket | None:
        self._ensure_loaded()
        with self._lock:
            return self._buckets.get(endpoint_id)

    def _pick_endpoint_locked(self, *, prefer: str | None = None) -> str | None:
        """Pick a healthy endpoint with remaining capacity, spreading load evenly.

        Chooses the lowest utilization (used/cap), then the lowest inflight count.
        ``prefer`` is a tie-breaker only: a sticky first endpoint is not filled to
        capacity before other pools are used.
        """
        now = time.time()
        best_id: str | None = None
        best_key: tuple[float, int, int, int] | None = None
        for idx, eid in enumerate(self._order):
            b = self._buckets[eid]
            if b.used >= b.cap:
                continue
            if not llm_gate.is_available(eid, now=now):
                continue
            util = b.used / b.cap
            sticky = 0 if (prefer and eid == prefer) else 1
            key = (util, b.used, sticky, idx)
            if best_key is None or key < best_key:
                best_key = key
                best_id = eid
        return best_id

    def _wait_deadline_locked(self) -> float:
        ids = list(self._order)
        return llm_gate.earliest_available_at(ids)

    def acquire(
        self,
        cancel_event: threading.Event | None = None,
        *,
        project_id: int | None = None,
        phase: str = "",
        role: str = "",
        prefer_endpoint: str | None = None,
    ) -> SlotHandle | None:
        self._ensure_loaded()
        logged_wait = False
        acquired = False
        handle: SlotHandle | None = None
        with self._cond:
            ticket = self._next_ticket
            self._next_ticket += 1
            self._queue.append(ticket)
        try:
            while True:
                granted = False
                pending_log: str | None = None
                used = limit = waiting = 0
                endpoint_id = ""
                with self._cond:
                    if cancel_event is not None and cancel_event.is_set():
                        return None
                    limit = self._limit_locked()
                    used = self._total_used_locked()
                    waiting = len(self._queue)
                    at_front = bool(self._queue and self._queue[0] == ticket)
                    pick = self._pick_endpoint_locked(prefer=prefer_endpoint) if at_front else None
                    if at_front and pick is not None:
                        self._queue.popleft()
                        self._buckets[pick].used += 1
                        self._handles[ticket] = pick
                        acquired = True
                        granted = True
                        endpoint_id = pick
                        used, waiting = self._total_used_locked(), len(self._queue)
                        self._cond.notify_all()
                    else:
                        if not logged_wait:
                            logged_wait = True
                            if at_front and pick is None:
                                pending_log = (
                                    f"LLM 端点均不可用或已满（占用 {used}/{limit}，排队 {waiting}），等待冷却或名额"
                                )
                            else:
                                pending_log = (
                                    f"LLM 总线程已满（占用 {used}/{limit}，排队 {waiting}），等待按顺序放行"
                                )
                        # Wait for slot release, cooldown end, or cancel
                        deadline = self._wait_deadline_locked()
                        now = time.time()
                        timeout = 0.25
                        if deadline > now and deadline != float("inf"):
                            timeout = min(0.5, max(0.05, deadline - now))
                        self._cond.wait(timeout=timeout)
                if granted:
                    handle = SlotHandle(endpoint_id=endpoint_id, ticket=ticket)
                    if logged_wait:
                        _log_system(
                            project_id,
                            phase,
                            role,
                            f"已获得 LLM 线程名额（端点 {endpoint_id}，占用 {used}/{limit}，排队 {waiting}），开始本轮",
                        )
                    return handle
                if pending_log:
                    _log_system(project_id, phase, role, pending_log)
        finally:
            if not acquired:
                with self._cond:
                    try:
                        self._queue.remove(ticket)
                    except ValueError:
                        pass
                    self._cond.notify_all()

    def rebind(
        self,
        handle: SlotHandle,
        *,
        cancel_event: threading.Event | None = None,
        project_id: int | None = None,
        phase: str = "",
        role: str = "",
        reason: str = "",
    ) -> SlotHandle | None:
        """Move an acquired slot to another healthy endpoint. Waits if pool is cold."""
        self._ensure_loaded()
        if handle is None:
            return None
        logged = False
        wait_started = time.time()
        while True:
            with self._cond:
                if cancel_event is not None and cancel_event.is_set():
                    return None
                current = self._handles.get(handle.ticket)
                if current is None:
                    # Slot already released
                    return None
                pick = self._pick_endpoint_locked(prefer=None)
                if pick is not None and pick != current:
                    # Transfer occupancy
                    if current in self._buckets:
                        self._buckets[current].used = max(0, self._buckets[current].used - 1)
                    self._buckets[pick].used += 1
                    self._handles[handle.ticket] = pick
                    self._cond.notify_all()
                    new_handle = SlotHandle(endpoint_id=pick, ticket=handle.ticket)
                    url = self._buckets[pick].base_url
                    _log_system(
                        project_id,
                        phase,
                        role,
                        f"改走端点 {pick}（{url}）"
                        + (f"，因 {reason}" if reason else ""),
                    )
                    return new_handle
                if pick == current:
                    # Same endpoint still best (e.g. only one) — keep sticky
                    return handle
                # No healthy endpoint with capacity
                any_not_disabled = any(
                    llm_gate.is_available(eid) or llm_gate.cooldown_remaining(eid) != float("inf")
                    for eid in self._order
                )
                if not any_not_disabled:
                    return None
                # Cap wait so callers can surface rate_limit_exhausted
                if time.time() - wait_started > 120:
                    return None
                if not logged:
                    logged = True
                    used, limit = self._total_used_locked(), self._limit_locked()
                    msg = f"LLM 池暂无可用端点（占用 {used}/{limit}）"
                    if reason:
                        msg += f"，因 {reason}"
                    msg += "，等待冷却或名额"
                    pending = msg
                else:
                    pending = None
                deadline = self._wait_deadline_locked()
                now = time.time()
                timeout = 0.25
                if deadline > now and deadline != float("inf"):
                    timeout = min(0.5, max(0.05, deadline - now))
                self._cond.wait(timeout=timeout)
            if pending:
                _log_system(project_id, phase, role, pending)

    def release(self, handle: SlotHandle | None = None) -> None:
        with self._cond:
            if handle is not None:
                eid = self._handles.pop(handle.ticket, None)
                if eid and eid in self._buckets:
                    self._buckets[eid].used = max(0, self._buckets[eid].used - 1)
            else:
                # Legacy release without handle: decrement any over-used bucket
                for eid in self._order:
                    b = self._buckets[eid]
                    if b.used > 0:
                        b.used -= 1
                        break
            self._cond.notify_all()

    def pick_idle_endpoint(self) -> str | None:
        """Select the least-loaded healthy endpoint (no slot taken)."""
        self._ensure_loaded()
        with self._lock:
            return self._pick_endpoint_locked()


llm_thread_limiter = LlmThreadLimiter()


@contextmanager
def llm_thread_slot(
    cancel_event: threading.Event | None = None,
    *,
    project_id: int | None = None,
    phase: str = "",
    role: str = "",
    prefer_endpoint: str | None = None,
) -> Iterator[SlotHandle | None]:
    handle = llm_thread_limiter.acquire(
        cancel_event,
        project_id=project_id,
        phase=phase,
        role=role,
        prefer_endpoint=prefer_endpoint,
    )
    try:
        yield handle
    finally:
        if handle is not None:
            llm_thread_limiter.release(handle)


@contextmanager
def llm_slot(cancel_event: threading.Event | None = None) -> Iterator[bool]:
    """Deprecated shim: no longer serializes requests; always True unless cancelled."""
    if cancel_event is not None and cancel_event.is_set():
        yield False
        return
    yield True

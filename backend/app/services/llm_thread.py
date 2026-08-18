"""Global FIFO limiter for LLM-interacting agent threads.

Every AgentLoop (recon / worker / fix / reviewer / verifier) occupies one slot
for the duration of a session. Inflight work across all projects cannot exceed
the configured limit; extra work waits in arrival order.
"""

from __future__ import annotations

import threading
from collections import deque
from contextlib import contextmanager
from typing import Iterator

from ..config import settings

DEFAULT_LLM_THREAD_LIMIT = 6


def _read_limit_from_settings() -> int:
    try:
        from .llm_settings import get_settings_row

        row = get_settings_row()
        n = getattr(row, "llm_thread_limit", None)
        if n is not None:
            return max(1, int(n))
    except Exception:  # noqa: BLE001
        pass
    return max(1, int(getattr(settings, "llm_thread_limit", None) or DEFAULT_LLM_THREAD_LIMIT))


def _log_system(
    project_id: int | None,
    phase: str,
    role: str,
    text: str,
) -> None:
    if project_id is None:
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
        self._used = 0
        self._queue: deque[int] = deque()
        self._next_ticket = 0
        self._cached_limit = DEFAULT_LLM_THREAD_LIMIT
        self._override: int | None = None
        self._loaded = False

    def reset(self) -> None:
        """Drop inflight/waiters. Tests and process isolation only."""
        with self._cond:
            self._used = 0
            self._queue.clear()
            self._next_ticket = 0
            self._override = None
            self._cached_limit = DEFAULT_LLM_THREAD_LIMIT
            self._loaded = False
            self._cond.notify_all()

    def set_limit_override(self, n: int | None) -> None:
        with self._cond:
            self._override = None if n is None else max(1, int(n))
            self._cond.notify_all()

    def refresh_limit(self, n: int | None = None) -> int:
        if n is None:
            n = _read_limit_from_settings()
        limit = max(1, int(n))
        with self._cond:
            self._cached_limit = limit
            self._loaded = True
            self._cond.notify_all()
        return limit

    def _ensure_loaded(self) -> None:
        with self._lock:
            if self._loaded or self._override is not None:
                return
            self._loaded = True
        self.refresh_limit()

    def current_limit(self) -> int:
        with self._lock:
            return self._limit_locked()

    def snapshot(self) -> tuple[int, int, int]:
        """Return (used, limit, waiting)."""
        with self._lock:
            return self._used, self._limit_locked(), len(self._queue)

    def _limit_locked(self) -> int:
        if self._override is not None:
            return self._override
        return max(1, int(self._cached_limit or DEFAULT_LLM_THREAD_LIMIT))

    def acquire(
        self,
        cancel_event: threading.Event | None = None,
        *,
        project_id: int | None = None,
        phase: str = "",
        role: str = "",
    ) -> bool:
        self._ensure_loaded()
        logged_wait = False
        acquired = False
        with self._cond:
            ticket = self._next_ticket
            self._next_ticket += 1
            self._queue.append(ticket)
        try:
            while True:
                granted = False
                pending_log: str | None = None
                used = limit = waiting = 0
                with self._cond:
                    if cancel_event is not None and cancel_event.is_set():
                        return False
                    limit = self._limit_locked()
                    if self._used < limit and self._queue and self._queue[0] == ticket:
                        self._queue.popleft()
                        self._used += 1
                        acquired = True
                        granted = True
                        used, waiting = self._used, len(self._queue)
                        self._cond.notify_all()
                    else:
                        used, waiting = self._used, len(self._queue)
                        if not logged_wait:
                            logged_wait = True
                            pending_log = (
                                f"LLM 总线程已满（占用 {used}/{limit}，排队 {waiting}），等待按顺序放行"
                            )
                        else:
                            pending_log = None
                        self._cond.wait(timeout=0.25)
                if granted:
                    if logged_wait:
                        _log_system(
                            project_id,
                            phase,
                            role,
                            f"已获得 LLM 线程名额（占用 {used}/{limit}，排队 {waiting}），开始本轮",
                        )
                    return True
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

    def release(self) -> None:
        with self._cond:
            self._used = max(0, self._used - 1)
            self._cond.notify_all()


llm_thread_limiter = LlmThreadLimiter()


@contextmanager
def llm_thread_slot(
    cancel_event: threading.Event | None = None,
    *,
    project_id: int | None = None,
    phase: str = "",
    role: str = "",
) -> Iterator[bool]:
    ok = llm_thread_limiter.acquire(
        cancel_event, project_id=project_id, phase=phase, role=role
    )
    try:
        yield ok
    finally:
        if ok:
            llm_thread_limiter.release()

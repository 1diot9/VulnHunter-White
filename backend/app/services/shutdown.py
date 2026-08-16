"""Process-wide shutdown flag so long-lived SSE can drop before Uvicorn waits forever.

Uvicorn's graceful shutdown waits for HTTP connections to close *before* it
cancels request tasks. An infinite SSE generator therefore deadlocks reload
unless it notices SIGTERM/SIGINT itself (and `--timeout-graceful-shutdown`
is set as a backstop).
"""

from __future__ import annotations

import asyncio
import signal
import threading
from typing import Any

_flag = threading.Event()


def reset() -> None:
    _flag.clear()


def request_shutdown() -> None:
    _flag.set()


def is_shutting_down() -> bool:
    return _flag.is_set()


async def wait_or_shutdown(seconds: float) -> bool:
    """Sleep up to `seconds`. Return True if shutdown was requested."""
    deadline = asyncio.get_running_loop().time() + max(0.0, seconds)
    while True:
        if _flag.is_set():
            return True
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            return _flag.is_set()
        await asyncio.sleep(min(0.1, remaining))


def _is_uvicorn_exit_handler(handler: Any) -> bool:
    fn = getattr(handler, "__func__", handler)
    return getattr(fn, "__name__", "") == "handle_exit"


def install_signal_bridge() -> None:
    """Wrap Uvicorn's already-installed exit handlers so SSE sees SIGTERM immediately."""
    if threading.current_thread() is not threading.main_thread():
        return
    handled: list[signal.Signals] = [signal.SIGINT, signal.SIGTERM]
    sigbreak = getattr(signal, "SIGBREAK", None)
    if sigbreak is not None:
        handled.append(sigbreak)
    for sig in handled:
        try:
            prev = signal.getsignal(sig)
        except (OSError, ValueError, AttributeError):
            continue
        if not _is_uvicorn_exit_handler(prev):
            continue

        def _wrap(previous: Any) -> Any:
            def handler(signum: int, frame: Any) -> None:
                request_shutdown()
                previous(signum, frame)

            return handler

        try:
            signal.signal(sig, _wrap(prev))
        except (OSError, ValueError):
            continue

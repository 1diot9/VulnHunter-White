from __future__ import annotations

import asyncio
import threading
import time

from fastapi.testclient import TestClient

from app.services.shutdown import is_shutting_down, request_shutdown, reset, wait_or_shutdown


def test_wait_or_shutdown_returns_immediately_when_flag_set():
    reset()
    request_shutdown()

    async def _run() -> bool:
        started = time.monotonic()
        stopped = await wait_or_shutdown(5)
        elapsed = time.monotonic() - started
        return stopped and elapsed < 0.5

    assert asyncio.run(_run()) is True
    assert is_shutting_down() is True
    reset()
    assert is_shutting_down() is False


def test_sse_stream_exits_on_shutdown(tmp_env, project):
    from app.main import app

    reset()
    with TestClient(app) as client:
        threading.Timer(0.2, request_shutdown).start()
        started = time.monotonic()
        with client.stream("GET", f"/api/projects/{project}/stream") as resp:
            assert resp.status_code == 200
            assert "text/event-stream" in resp.headers["content-type"]
            body = b"".join(resp.iter_bytes())
        assert time.monotonic() - started < 3
        assert b"retry:" in body or b"data:" in body

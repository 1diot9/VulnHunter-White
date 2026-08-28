"""Per-endpoint LLM thread limiter: FIFO queue + sticky/rebind across Base URLs."""

from __future__ import annotations

import threading
import time

from app.agent.loop import AgentLoop, LoopResult
from app.services.llm_gate import llm_gate
from app.services.llm_thread import (
    DEFAULT_LLM_THREAD_LIMIT,
    LlmThreadLimiter,
    llm_thread_limiter,
    llm_thread_slot,
)
from app.services import pipeline


def _wait_until(pred, timeout: float = 2.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if pred():
            return True
        time.sleep(0.02)
    return False


def test_default_limit_is_six():
    assert DEFAULT_LLM_THREAD_LIMIT == 6
    lim = LlmThreadLimiter()
    lim.set_limit_override(6)
    assert lim.current_limit() == 6


def test_fifo_releases_waiters_in_arrival_order():
    lim = LlmThreadLimiter()
    lim.set_limit_override(1)
    order: list[str] = []
    hold_a = threading.Event()

    def hold() -> None:
        h = lim.acquire()
        assert h is not None
        order.append("a")
        hold_a.wait(timeout=3)
        lim.release(h)

    def waiter(name: str) -> None:
        h = lim.acquire()
        assert h is not None
        order.append(name)
        lim.release(h)

    t_a = threading.Thread(target=hold)
    t_a.start()
    assert _wait_until(lambda: lim.snapshot()[0] == 1)

    t_b = threading.Thread(target=waiter, args=("b",))
    t_b.start()
    assert _wait_until(lambda: lim.snapshot()[2] == 1)

    t_c = threading.Thread(target=waiter, args=("c",))
    t_c.start()
    assert _wait_until(lambda: lim.snapshot()[2] == 2)

    hold_a.set()
    t_a.join(timeout=3)
    t_b.join(timeout=3)
    t_c.join(timeout=3)
    assert order == ["a", "b", "c"]
    assert lim.snapshot() == (0, 1, 0)


def test_cancel_while_queued_does_not_take_slot():
    lim = LlmThreadLimiter()
    lim.set_limit_override(1)
    h0 = lim.acquire()
    assert h0 is not None
    cancel = threading.Event()
    result: list[object] = []

    def waiter() -> None:
        result.append(lim.acquire(cancel))

    t = threading.Thread(target=waiter)
    t.start()
    assert _wait_until(lambda: lim.snapshot()[2] == 1)
    cancel.set()
    t.join(timeout=3)
    assert result == [None]
    assert lim.snapshot() == (1, 1, 0)
    lim.release(h0)
    assert lim.snapshot() == (0, 1, 0)


def test_raising_limit_unblocks_queue():
    lim = LlmThreadLimiter()
    lim.set_limit_override(1)
    h0 = lim.acquire()
    assert h0 is not None
    got: list[bool] = []

    def waiter() -> None:
        h = lim.acquire()
        got.append(h is not None)
        if h is not None:
            lim.release(h)

    t = threading.Thread(target=waiter)
    t.start()
    assert _wait_until(lambda: lim.snapshot()[2] == 1)
    lim.set_limit_override(2)
    t.join(timeout=3)
    assert got == [True]
    lim.release(h0)
    assert lim.snapshot() == (0, 2, 0)


def test_acquire_releases_after_exception():
    lim = LlmThreadLimiter()
    lim.set_limit_override(2)

    def _slot() -> None:
        h = lim.acquire()
        try:
            if h is None:
                return
            raise RuntimeError("boom")
        finally:
            if h is not None:
                lim.release(h)

    try:
        _slot()
    except RuntimeError:
        pass
    assert lim.snapshot()[0] == 0


def test_multi_endpoint_parallel_capacity():
    lim = LlmThreadLimiter()
    lim.refresh_pool(
        [
            {"id": "ep-a", "base_url": "https://a.example/v1", "api_key": "ka", "max_inflight": 2},
            {"id": "ep-b", "base_url": "https://b.example/v1", "api_key": "kb", "max_inflight": 3},
        ]
    )
    assert lim.current_limit() == 5
    handles = []
    for _ in range(5):
        h = lim.acquire()
        assert h is not None
        handles.append(h)
    assert lim.snapshot()[0] == 5
    ids = {h.endpoint_id for h in handles}
    assert ids == {"ep-a", "ep-b"}
    # Prefer remaining capacity: ep-a cap 2, ep-b cap 3
    assert sum(1 for h in handles if h.endpoint_id == "ep-a") == 2
    assert sum(1 for h in handles if h.endpoint_id == "ep-b") == 3
    for h in handles:
        lim.release(h)
    assert lim.snapshot()[0] == 0


def test_rebind_moves_off_cooled_endpoint():
    lim = LlmThreadLimiter()
    lim.refresh_pool(
        [
            {"id": "ep-a", "base_url": "https://a.example/v1", "api_key": "ka", "max_inflight": 1},
            {"id": "ep-b", "base_url": "https://b.example/v1", "api_key": "kb", "max_inflight": 1},
        ]
    )
    h = lim.acquire(prefer_endpoint="ep-a")
    assert h is not None
    assert h.endpoint_id == "ep-a"
    llm_gate.note_error("ep-a", "rate_limit", retry_after=60, message="429")
    rebound = lim.rebind(h, reason="429")
    assert rebound is not None
    assert rebound.endpoint_id == "ep-b"
    assert lim.snapshot()[0] == 1
    snap = lim.detailed_snapshot()
    by_id = {ep["id"]: ep for ep in snap["endpoints"]}
    assert by_id["ep-a"]["used"] == 0
    assert by_id["ep-a"]["cooldown_sec"] > 0
    assert by_id["ep-a"]["last_error"] == "429"
    assert by_id["ep-a"]["error_kind"] == "rate_limit"
    assert by_id["ep-b"]["used"] == 1
    lim.release(rebound)


def test_cooldown_on_one_endpoint_does_not_block_other():
    lim = LlmThreadLimiter()
    lim.refresh_pool(
        [
            {"id": "ep-a", "base_url": "https://a.example/v1", "api_key": "ka", "max_inflight": 1},
            {"id": "ep-b", "base_url": "https://b.example/v1", "api_key": "kb", "max_inflight": 1},
        ]
    )
    llm_gate.note_error("ep-a", "rate_limit", retry_after=120, message="429")
    h = lim.acquire()
    assert h is not None
    assert h.endpoint_id == "ep-b"
    lim.release(h)


def test_agent_loop_run_occupies_one_slot(tmp_env, project, monkeypatch):
    llm_thread_limiter.set_limit_override(1)
    held = threading.Event()
    release = threading.Event()

    def fake_loop(self) -> LoopResult:
        held.set()
        release.wait(timeout=3)
        return LoopResult(ok=True, state=self.state)

    monkeypatch.setattr(AgentLoop, "_run_loop", fake_loop)
    run_id = pipeline._new_phase_run(project, "worker", "worker")
    loop = AgentLoop(
        project_id=project,
        role="worker",
        phase="worker",
        system_prompt="sys",
        user_prompt="u",
        phase_run_id=run_id,
        stop_when=lambda st: True,
    )

    t = threading.Thread(target=loop.run)
    t.start()
    assert held.wait(timeout=3)
    assert llm_thread_limiter.snapshot()[0] == 1

    second_started = threading.Event()
    second_got: list[bool] = []

    def second() -> None:
        second_started.set()
        with llm_thread_slot() as handle:
            second_got.append(handle is not None)

    t2 = threading.Thread(target=second)
    t2.start()
    assert second_started.wait(timeout=3)
    assert _wait_until(lambda: llm_thread_limiter.snapshot()[2] >= 1)
    release.set()
    t.join(timeout=3)
    t2.join(timeout=3)
    assert second_got == [True]
    assert llm_thread_limiter.snapshot()[0] == 0

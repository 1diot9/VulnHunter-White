"""Global LLM thread limiter: FIFO queue across recon / worker / reviewer sessions."""

from __future__ import annotations

import threading
import time

from app.agent.loop import AgentLoop, LoopResult
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
    assert lim.current_limit() == 6


def test_fifo_releases_waiters_in_arrival_order():
    lim = LlmThreadLimiter()
    lim.set_limit_override(1)
    order: list[str] = []
    hold_a = threading.Event()

    def hold() -> None:
        assert lim.acquire() is True
        order.append("a")
        hold_a.wait(timeout=3)
        lim.release()

    def waiter(name: str) -> None:
        assert lim.acquire() is True
        order.append(name)
        lim.release()

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
    assert lim.acquire() is True
    cancel = threading.Event()
    result: list[bool] = []

    def waiter() -> None:
        result.append(lim.acquire(cancel))

    t = threading.Thread(target=waiter)
    t.start()
    assert _wait_until(lambda: lim.snapshot()[2] == 1)
    cancel.set()
    t.join(timeout=3)
    assert result == [False]
    assert lim.snapshot() == (1, 1, 0)
    lim.release()
    assert lim.snapshot() == (0, 1, 0)


def test_raising_limit_unblocks_queue():
    lim = LlmThreadLimiter()
    lim.set_limit_override(1)
    assert lim.acquire() is True
    got: list[bool] = []

    def waiter() -> None:
        got.append(lim.acquire())
        lim.release()

    t = threading.Thread(target=waiter)
    t.start()
    assert _wait_until(lambda: lim.snapshot()[2] == 1)
    lim.set_limit_override(2)
    t.join(timeout=3)
    assert got == [True]
    lim.release()
    assert lim.snapshot() == (0, 2, 0)


def test_acquire_releases_after_exception():
    lim = LlmThreadLimiter()
    lim.set_limit_override(2)

    def _slot() -> None:
        ok = lim.acquire()
        try:
            if not ok:
                return
            raise RuntimeError("boom")
        finally:
            if ok:
                lim.release()

    try:
        _slot()
    except RuntimeError:
        pass
    assert lim.snapshot()[0] == 0


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
        with llm_thread_slot() as ok:
            second_got.append(ok)

    t2 = threading.Thread(target=second)
    t2.start()
    assert second_started.wait(timeout=3)
    assert _wait_until(lambda: llm_thread_limiter.snapshot()[2] >= 1)
    release.set()
    t.join(timeout=3)
    t2.join(timeout=3)
    assert second_got == [True]
    assert llm_thread_limiter.snapshot()[0] == 0

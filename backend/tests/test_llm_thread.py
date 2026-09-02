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
    # Spread by utilization until both are full: ep-a cap 2, ep-b cap 3
    assert sum(1 for h in handles if h.endpoint_id == "ep-a") == 2
    assert sum(1 for h in handles if h.endpoint_id == "ep-b") == 3
    for h in handles:
        lim.release(h)
    assert lim.snapshot()[0] == 0


def test_acquire_spreads_evenly_even_when_preferring_first():
    """New sessions must not fill the sticky first endpoint before using others."""
    lim = LlmThreadLimiter()
    lim.refresh_pool(
        [
            {"id": "ep-a", "base_url": "https://a.example/v1", "api_key": "ka", "max_inflight": 4},
            {"id": "ep-b", "base_url": "https://b.example/v1", "api_key": "kb", "max_inflight": 4},
            {"id": "ep-c", "base_url": "https://c.example/v1", "api_key": "kc", "max_inflight": 4},
        ]
    )
    handles = [lim.acquire(prefer_endpoint="ep-a") for _ in range(6)]
    assert all(h is not None for h in handles)
    counts = {"ep-a": 0, "ep-b": 0, "ep-c": 0}
    for h in handles:
        counts[h.endpoint_id] += 1
    assert counts == {"ep-a": 2, "ep-b": 2, "ep-c": 2}
    # Intermediate prefix must already be spread, not 4-on-a then overflow
    prefix = [h.endpoint_id for h in handles[:3]]
    assert set(prefix) == {"ep-a", "ep-b", "ep-c"}
    for h in handles:
        lim.release(h)
    assert lim.snapshot()[0] == 0


def test_prefer_wins_only_when_loads_are_equal():
    lim = LlmThreadLimiter()
    lim.refresh_pool(
        [
            {"id": "ep-a", "base_url": "https://a.example/v1", "api_key": "ka", "max_inflight": 4},
            {"id": "ep-b", "base_url": "https://b.example/v1", "api_key": "kb", "max_inflight": 4},
        ]
    )
    h0 = lim.acquire(prefer_endpoint="ep-b")
    assert h0 is not None and h0.endpoint_id == "ep-b"
    h1 = lim.acquire(prefer_endpoint="ep-b")
    assert h1 is not None and h1.endpoint_id == "ep-a"
    lim.release(h0)
    lim.release(h1)


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


def _expire_cooldown(eid: str) -> None:
    with llm_gate._lock:
        h = llm_gate._by_id.get(eid)
        if h is not None:
            h.cooldown_until = 0.0


def test_quota_exhausted_not_picked_when_other_endpoint_free():
    """Idle quota endpoints must not win by lowest utilization."""
    lim = LlmThreadLimiter()
    lim.refresh_pool(
        [
            {"id": "ep-1", "base_url": "https://a.example/v1", "api_key": "ka", "max_inflight": 4},
            {"id": "ep-2", "base_url": "https://b.example/v1", "api_key": "kb", "max_inflight": 4},
        ]
    )
    busy = lim.acquire(prefer_endpoint="ep-1")
    assert busy is not None and busy.endpoint_id == "ep-1"
    llm_gate.note_error("ep-2", "quota", message="insufficient_quota")
    _expire_cooldown("ep-2")
    assert llm_gate.is_available("ep-2")
    assert llm_gate.last_error_kind("ep-2") == "quota"
    h = lim.acquire()
    assert h is not None
    assert h.endpoint_id == "ep-1"
    idle = lim.pick_idle_endpoint()
    assert idle == "ep-1"
    lim.release(h)
    lim.release(busy)


def test_quota_exhausted_is_last_resort_when_others_full():
    lim = LlmThreadLimiter()
    lim.refresh_pool(
        [
            {"id": "ep-1", "base_url": "https://a.example/v1", "api_key": "ka", "max_inflight": 1},
            {"id": "ep-2", "base_url": "https://b.example/v1", "api_key": "kb", "max_inflight": 1},
        ]
    )
    llm_gate.note_error("ep-2", "quota", message="insufficient_quota")
    _expire_cooldown("ep-2")
    h1 = lim.acquire()
    assert h1 is not None and h1.endpoint_id == "ep-1"
    h2 = lim.acquire()
    assert h2 is not None and h2.endpoint_id == "ep-2"
    lim.release(h1)
    lim.release(h2)


def test_rebind_wait_false_returns_none_when_no_other_endpoint():
    lim = LlmThreadLimiter()
    lim.refresh_pool(
        [
            {"id": "ep-1", "base_url": "https://a.example/v1", "api_key": "ka", "max_inflight": 1},
        ]
    )
    h = lim.acquire()
    assert h is not None
    llm_gate.note_error("ep-1", "quota", message="insufficient_quota")
    rebound = lim.rebind(h, reason="额度用尽", wait=False)
    assert rebound is None
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


def _followup_pool(monkeypatch):
    from contextlib import contextmanager

    from app.services.llm_settings import PoolEndpoint, ResolvedLlm
    import app.services.llm_settings as llm_settings
    import app.services.vuln_followup as vf

    llm_thread_limiter.reset()
    llm_thread_limiter.refresh_pool(
        [
            {
                "id": "ep-1",
                "base_url": "https://a.example/v1",
                "api_key": "ka",
                "model": "m",
                "max_inflight": 2,
            },
            {
                "id": "ep-2",
                "base_url": "https://b.example/v1",
                "api_key": "kb",
                "model": "m",
                "max_inflight": 2,
            },
        ]
    )
    eps = [
        PoolEndpoint(id="ep-1", base_url="https://a.example/v1", api_key="ka", model="m", max_inflight=2),
        PoolEndpoint(id="ep-2", base_url="https://b.example/v1", api_key="kb", model="m", max_inflight=2),
    ]
    monkeypatch.setattr(
        vf,
        "resolve_llm",
        lambda *a, **k: ResolvedLlm(
            base_url="https://a.example/v1",
            wire_api="chat",
            model="m",
            api_key="ka",
            source="test",
            endpoint_id="ep-1",
        ),
    )
    monkeypatch.setattr(llm_settings, "pool_endpoints_resolved", lambda: eps)
    seen: list[str] = []

    class _Resp:
        def __init__(self, status, body=b"", lines=None):
            self.status_code = status
            self._body = body
            self._lines = lines or []
            self.headers = {}

        def read(self):
            return self._body

        def iter_lines(self):
            yield from self._lines

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    class _Client:
        def stream(self, method, url, headers=None, json=None):
            seen.append(url)
            if "b.example" in url:
                return _Resp(
                    429,
                    b'{"error":{"message":"You exceeded your current quota","type":"insufficient_quota"}}',
                )
            return _Resp(
                200,
                lines=[
                    'data: {"choices":[{"message":{"content":"ok-from-ep-1"}}]}',
                    "data: [DONE]",
                ],
            )

    @contextmanager
    def fake_client(timeout=None):
        yield _Client()

    monkeypatch.setattr(vf, "chat_http_client", fake_client)
    return seen


def test_call_reviewer_llm_fails_over_quota_endpoint(monkeypatch):
    from app.services.vuln_followup import _call_reviewer_llm

    seen = _followup_pool(monkeypatch)
    busy = llm_thread_limiter.acquire(prefer_endpoint="ep-1")
    assert busy is not None and busy.endpoint_id == "ep-1"
    try:
        answer = _call_reviewer_llm(1, [{"role": "user", "content": "q"}])
        assert answer == "ok-from-ep-1"
        assert any("b.example" in u for u in seen)
        assert any("a.example" in u for u in seen)
        assert llm_gate.last_error_kind("ep-2") == "quota"
    finally:
        llm_thread_limiter.release(busy)
        llm_thread_limiter.reset()


def test_call_reviewer_llm_skips_known_quota_endpoint(monkeypatch):
    from app.services.vuln_followup import _call_reviewer_llm

    seen = _followup_pool(monkeypatch)
    llm_gate.note_error("ep-2", "quota", message="insufficient_quota")
    _expire_cooldown("ep-2")
    try:
        answer = _call_reviewer_llm(1, [{"role": "user", "content": "q"}])
        assert answer == "ok-from-ep-1"
        assert seen
        assert all("a.example" in u for u in seen)
        assert not any("b.example" in u for u in seen)
    finally:
        llm_thread_limiter.reset()

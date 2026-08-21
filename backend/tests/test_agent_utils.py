from __future__ import annotations

import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import httpx
import pytest

from app.agent.compression import (
    attach_todo_list,
    estimate_tokens,
    format_todo_list_block,
    needs_compress,
)
from app.agent.loop import (
    AgentLoop,
    _content_text,
    _is_rate_limit_response,
    _looks_like_rate_limit,
    _reasoning_text,
)
from app.config import settings
from app.services.http_client import (
    FallbackClient,
    chat_http_client,
    chat_http_timeout,
    http_client,
    is_proxy_unavailable,
    proxy_is_skipped,
    proxy_tcp_reachable,
    proxy_url,
    reset_proxy_skip,
)
from app.services.llm_gate import LlmRequestGate


def test_looks_like_rate_limit():
    assert _looks_like_rate_limit("Error: 429 Too Many Requests")
    assert _looks_like_rate_limit('{"type":"rate_limit_exceeded"}')
    assert _looks_like_rate_limit("rate limit exceeded, please retry")
    assert not _looks_like_rate_limit("HTTP 200 OK")
    assert not _looks_like_rate_limit("port 429 is open")


def test_is_rate_limit_response_ignores_200_and_5xx():
    assert _is_rate_limit_response(429, "nope") is True
    assert _is_rate_limit_response(400, '{"type":"rate_limit_exceeded"}') is True
    assert _is_rate_limit_response(200, '{"type":"rate_limit_exceeded"}') is False
    assert _is_rate_limit_response(502, "rate limit exceeded") is False


def test_estimate_tokens():
    n = estimate_tokens([{"role": "user", "content": "abcd" * 100}])
    assert n >= 50


def test_estimate_tokens_counts_cjk_heavier():
    ascii_n = estimate_tokens([{"role": "user", "content": "abcd" * 100}])
    cjk_n = estimate_tokens([{"role": "user", "content": "汉字" * 100}])
    assert cjk_n > ascii_n


def test_estimate_tokens_includes_tools_schema():
    msgs = [{"role": "user", "content": "hi"}]
    tools = [{"function": {"name": "Read", "description": "y" * 400}}]
    assert estimate_tokens(msgs, tools) > estimate_tokens(msgs)


def test_needs_compress(monkeypatch):
    monkeypatch.setattr(settings, "context_compress_ratio", 0.01)
    msgs = [{"role": "user", "content": "hello world " * 200}]
    assert needs_compress(msgs, context_window=100) is True


def test_needs_compress_uses_last_prompt_tokens(monkeypatch):
    monkeypatch.setattr(settings, "context_compress_ratio", 0.85)
    msgs = [{"role": "user", "content": "hi"}]
    assert needs_compress(msgs, 1000, last_prompt_tokens=900) is True
    assert needs_compress(msgs, 1000, last_prompt_tokens=10) is False


def test_needs_compress_includes_tools(monkeypatch):
    monkeypatch.setattr(settings, "context_compress_ratio", 0.5)
    msgs = [{"role": "user", "content": "hi"}]
    tools = [{"function": {"name": "X", "description": "y" * 4000}}]
    assert needs_compress(msgs, context_window=1000, tools=tools) is True


def test_format_todo_list_block():
    assert format_todo_list_block(None) == ""
    assert format_todo_list_block([]) == ""
    block = format_todo_list_block(
        [
            {"id": "1", "content": "回推 sink", "status": "in_progress"},
            {"id": "2", "content": "写 poc 草案", "status": "pending"},
        ]
    )
    assert block.startswith("## TodoList")
    assert "- [in_progress] 1: 回推 sink" in block
    assert "- [pending] 2: 写 poc 草案" in block


def test_attach_todo_list_appends_once():
    todos = [{"id": "1", "content": "追 source", "status": "pending"}]
    once = attach_todo_list("已完成入口分析", todos)
    assert "已完成入口分析" in once
    assert "## TodoList" in once
    assert "追 source" in once
    twice = attach_todo_list(once, todos)
    assert twice.count("## TodoList") == 1


def test_compress_appends_todolist(tmp_env, project):
    loop = AgentLoop(
        project_id=project,
        role="worker",
        phase="worker",
        system_prompt="sys",
        user_prompt="task",
        worker_id="w1",
    )
    loop.state["todos"] = [
        {"id": "1", "content": "回推 sink", "status": "in_progress"},
        {"id": "2", "content": "写 poc 草案", "status": "pending"},
    ]
    out = loop._compress(
        [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "task"},
            {"role": "assistant", "content": "working"},
        ],
        force_summary="已看完入口",
    )
    user = out[1]["content"]
    assert "已看完入口" in user
    assert "## TodoList" in user
    assert "回推 sink" in user
    assert "写 poc 草案" in user


def test_compress_skips_empty_todolist(tmp_env, project):
    loop = AgentLoop(
        project_id=project,
        role="worker",
        phase="worker",
        system_prompt="sys",
        user_prompt="task",
        worker_id="w1",
    )
    out = loop._compress(
        [{"role": "user", "content": "task"}],
        force_summary="已看完入口",
    )
    assert "TodoList" not in out[1]["content"]


def test_compress_reads_todolist_from_workspace_file(tmp_env, project):
    from app.tools import ToolContext, registry

    ctx = ToolContext(project_id=project, role="worker", phase="worker", worker_id="w1")
    registry.dispatch(
        ctx,
        "TodoWrite",
        {"todos": [{"id": "9", "content": "文件中的待办", "status": "pending"}]},
    )
    loop = AgentLoop(
        project_id=project,
        role="worker",
        phase="worker",
        system_prompt="sys",
        user_prompt="task",
        worker_id="w1",
    )
    out = loop._compress(
        [{"role": "user", "content": "task"}],
        force_summary="压缩摘要",
    )
    assert "文件中的待办" in out[1]["content"]


def test_chat_http_timeout_scales_and_caps(monkeypatch):
    monkeypatch.setattr(settings, "chat_connect_timeout", 30.0)
    monkeypatch.setattr(settings, "chat_read_timeout_min", 180.0)
    monkeypatch.setattr(settings, "chat_read_timeout_max", 600.0)
    t = chat_http_timeout(1800, est_tokens=80_000)
    assert t.connect == 30.0
    assert t.read == 600.0
    short = chat_http_timeout(40, est_tokens=80_000)
    assert short.read == 35.0
    mid = chat_http_timeout(1800, est_tokens=1000)
    assert mid.read == 180.0


def _has_proxy_transport(client) -> bool:
    return any(transport is not None for transport in client._mounts.values())


def test_chat_http_client_direct_ignores_env_and_tool_proxy(tmp_env, monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:19999")
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:19999")
    monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:19999")
    monkeypatch.setattr(settings, "http_proxy", "http://127.0.0.1:19999")
    monkeypatch.setattr(settings, "https_proxy", "http://127.0.0.1:19999")
    monkeypatch.setattr(settings, "chat_proxy", "")
    with chat_http_client() as client:
        assert client.trust_env is False
        assert not _has_proxy_transport(client)


def test_http_client_uses_settings_page_proxy(tmp_env):
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as client:
        assert proxy_url() is None
        client.put("/api/settings", json={"http_proxy": "http://127.0.0.1:19999"})
        assert proxy_url() == "http://127.0.0.1:19999"
        with http_client() as hc:
            assert _has_proxy_transport(hc)
        client.put("/api/settings", json={"http_proxy": ""})
        assert proxy_url() is None


def test_chat_http_client_uses_explicit_chat_proxy(tmp_env, monkeypatch):
    monkeypatch.setattr(settings, "chat_proxy", "http://127.0.0.1:19998")
    with chat_http_client() as client:
        assert client.trust_env is False
        assert _has_proxy_transport(client)


def test_is_proxy_unavailable_classifies_transport_errors():
    req = httpx.Request("GET", "https://example.invalid/")
    assert is_proxy_unavailable(httpx.ProxyError("bad proxy")) is True
    assert is_proxy_unavailable(httpx.ConnectError("connection refused")) is True
    assert is_proxy_unavailable(httpx.ConnectTimeout("connect timed out")) is True
    assert is_proxy_unavailable(httpx.ReadTimeout("read timed out")) is False
    assert is_proxy_unavailable(httpx.TimeoutException("generic timeout")) is False
    assert is_proxy_unavailable(httpx.HTTPStatusError("boom", request=req, response=httpx.Response(502))) is False


def _closed_tcp_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = int(s.getsockname()[1])
    s.close()
    return port


def _start_local_http() -> tuple[HTTPServer, str]:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):  # noqa: A003
            return

    httpd = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    host, port = httpd.server_address[:2]
    return httpd, f"http://{host}:{port}/"


def test_fallback_client_uses_direct_when_proxy_down():
    reset_proxy_skip()
    httpd, url = _start_local_http()
    proxy = f"http://127.0.0.1:{_closed_tcp_port()}"
    try:
        assert proxy_tcp_reachable(proxy, timeout=0.5) is False
        started = time.monotonic()
        with FallbackClient(timeout=3.0, follow_redirects=True, trust_env=False, proxy=proxy) as client:
            r = client.get(url)
            with client.stream("GET", url) as streamed:
                body = streamed.read()
        elapsed = time.monotonic() - started
        assert r.status_code == 200
        assert r.text == "ok"
        assert streamed.status_code == 200
        assert body == b"ok"
        assert proxy_is_skipped(proxy)
        assert elapsed < 10.0
        with FallbackClient(timeout=3.0, follow_redirects=True, trust_env=False, proxy=proxy) as client:
            r = client.get(url)
        assert r.status_code == 200
        assert r.text == "ok"
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_http_client_falls_back_when_settings_proxy_down(tmp_env):
    from fastapi.testclient import TestClient

    from app.main import app

    reset_proxy_skip()
    httpd, url = _start_local_http()
    proxy = f"http://127.0.0.1:{_closed_tcp_port()}"
    try:
        with TestClient(app) as api:
            api.put("/api/settings", json={"http_proxy": proxy, "chat_proxy": proxy})
            with http_client(timeout=3.0) as hc:
                r = hc.get(url)
            assert r.status_code == 200
            assert r.text == "ok"
            reset_proxy_skip()
            with chat_http_client(timeout=3.0) as hc:
                r = hc.get(url)
            assert r.status_code == 200
            assert r.text == "ok"
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_direct_client_still_raises_when_origin_down():
    reset_proxy_skip()
    dead = f"http://127.0.0.1:{_closed_tcp_port()}/"
    with http_client(timeout=2.0) as client:
        with pytest.raises((httpx.ConnectError, httpx.ConnectTimeout)):
            client.get(dead)


def test_llm_gate_rate_limit_sets_cooldown(monkeypatch):
    monkeypatch.setattr(settings, "rate_limit_sleep_sec", 90)
    gate = LlmRequestGate()
    before = gate._cooldown_until
    gate.note_rate_limit(12)
    assert gate._cooldown_until >= before + 11
    assert gate.cooldown_remaining() > 0


def test_llm_gate_acquire_does_not_serialize():
    gate = LlmRequestGate()
    assert gate.acquire() is True
    assert gate.acquire() is True
    gate.release()
    gate.release()


def test_content_and_reasoning_text():
    assert _content_text({"content": "hello"}) == "hello"
    assert _content_text({"content": [{"type": "text", "text": "a"}, {"text": "b"}]}) == "a\nb"
    assert _reasoning_text({"reasoning_content": "think"}) == "think"
    assert _reasoning_text({"reasoning": {"content": "r"}}) == "r"

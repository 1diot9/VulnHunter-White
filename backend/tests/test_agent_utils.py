from __future__ import annotations

from app.agent.compression import estimate_tokens, needs_compress
from app.agent.loop import (
    _content_text,
    _is_rate_limit_response,
    _looks_like_rate_limit,
    _reasoning_text,
)
from app.config import settings
from app.services.http_client import chat_http_client, chat_http_timeout
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


def test_chat_http_client_direct_ignores_env_and_tool_proxy(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:10808")
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:10808")
    monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:10808")
    monkeypatch.setattr(settings, "http_proxy", "http://127.0.0.1:10808")
    monkeypatch.setattr(settings, "https_proxy", "http://127.0.0.1:10808")
    monkeypatch.setattr(settings, "chat_proxy", "")
    with chat_http_client() as client:
        assert client.trust_env is False
        assert not _has_proxy_transport(client)


def test_chat_http_client_uses_explicit_chat_proxy(monkeypatch):
    monkeypatch.setattr(settings, "chat_proxy", "http://127.0.0.1:9999")
    with chat_http_client() as client:
        assert client.trust_env is False
        assert _has_proxy_transport(client)


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

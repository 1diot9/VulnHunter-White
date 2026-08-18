from __future__ import annotations

import json

import pytest

from app.agent.chat_stream import (
    ChatStreamCancelled,
    ChatStreamEmpty,
    ChatStreamProviderError,
    assemble_chat_completion,
    consume_chat_stream,
    parse_sse_line,
)
from app.agent.loop import AgentLoop, AuthError, RateLimitError, _sanitize_chat_messages
from app.services.llm_settings import ResolvedLlm


def test_parse_sse_line_done_and_comments():
    assert parse_sse_line("") is None
    assert parse_sse_line(": keep-alive") is None
    done = parse_sse_line("data: [DONE]")
    assert done is not None and done is not parse_sse_line("data: {}")
    payload = parse_sse_line('data: {"choices":[]}')
    assert payload == {"choices": []}
    raw = parse_sse_line('{"choices":[{"message":{"content":"hi"}}]}')
    assert raw["choices"][0]["message"]["content"] == "hi"


def test_assemble_content_and_reasoning():
    chunks = [
        {"id": "c1", "model": "glm-5.2", "choices": [{"delta": {"role": "assistant", "reasoning_content": "think "}}]},
        {"choices": [{"delta": {"reasoning_content": "more"}}]},
        {"choices": [{"delta": {"content": "hello "}}]},
        {"choices": [{"delta": {"content": "world"}, "finish_reason": "stop"}]},
        {"usage": {"prompt_tokens": 10, "completion_tokens": 4, "total_tokens": 14}, "choices": []},
    ]
    out = assemble_chat_completion(chunks)
    msg = out["choices"][0]["message"]
    assert msg["content"] == "hello world"
    assert msg["reasoning_content"] == "think more"
    assert out["usage"]["prompt_tokens"] == 10
    assert out["choices"][0]["finish_reason"] == "stop"


def test_assemble_tool_call_fragments():
    chunks = [
        {
            "choices": [
                {
                    "delta": {
                        "tool_calls": [
                            {
                                "index": 0,
                                "id": "call_1",
                                "type": "function",
                                "function": {"name": "Read", "arguments": ""},
                            }
                        ]
                    }
                }
            ]
        },
        {"choices": [{"delta": {"tool_calls": [{"index": 0, "function": {"arguments": "{\"path\""}}]}}]},
        {
            "choices": [
                {
                    "delta": {"tool_calls": [{"index": 0, "function": {"arguments": ":\"a.java\"}"}}]},
                    "finish_reason": "tool_calls",
                }
            ]
        },
    ]
    out = assemble_chat_completion(chunks)
    tc = out["choices"][0]["message"]["tool_calls"][0]
    assert tc["id"] == "call_1"
    assert tc["function"]["name"] == "Read"
    assert json.loads(tc["function"]["arguments"]) == {"path": "a.java"}


def test_consume_stops_at_done_and_skips_keepalive():
    lines = [
        ": ping",
        'data: {"choices":[{"delta":{"content":"ab"}}]}',
        "",
        "data: [DONE]",
        'data: {"choices":[{"delta":{"content":"ignored"}}]}',
    ]
    out = consume_chat_stream(lines)
    assert out["choices"][0]["message"]["content"] == "ab"


def test_consume_full_json_passthrough():
    payload = {
        "choices": [{"message": {"role": "assistant", "content": "pong"}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 2, "completion_tokens": 1, "total_tokens": 3},
    }
    out = consume_chat_stream([json.dumps(payload)])
    assert out["choices"][0]["message"]["content"] == "pong"
    assert out["usage"]["completion_tokens"] == 1


def test_consume_empty_and_provider_error():
    with pytest.raises(ChatStreamEmpty):
        consume_chat_stream(["", ": c"])
    with pytest.raises(ChatStreamProviderError):
        consume_chat_stream(['data: {"error":{"message":"rate limit exceeded"}}'])


def test_consume_cancel():
    def lines():
        yield 'data: {"choices":[{"delta":{"content":"x"}}]}'
        yield 'data: {"choices":[{"delta":{"content":"y"}}]}'

    n = {"i": 0}

    def cancel_check():
        n["i"] += 1
        return n["i"] > 1

    with pytest.raises(ChatStreamCancelled):
        consume_chat_stream(lines(), cancel_check=cancel_check)


def test_consume_first_payload_callback():
    seen = []
    consume_chat_stream(
        [": a", 'data: {"choices":[{"delta":{"content":"z"}}]}', "data: [DONE]"],
        on_first_payload=lambda: seen.append(1),
    )
    assert seen == [1]


class _FakeResponse:
    def __init__(self, status_code=200, headers=None, lines=None, body=b""):
        self.status_code = status_code
        self.headers = headers or {}
        self._lines = lines or []
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def iter_lines(self):
        yield from self._lines

    def read(self):
        return self._body


class _FakeClient:
    def __init__(self, response: _FakeResponse):
        self.response = response
        self.captured = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def stream(self, method, url, headers=None, json=None):
        self.captured = {"method": method, "url": url, "json": json, "headers": headers}
        return self.response


def _loop(monkeypatch, client: _FakeClient) -> AgentLoop:
    monkeypatch.setattr("app.agent.loop.chat_http_client", lambda timeout=None: client)
    monkeypatch.setattr("app.agent.loop.live_log.system", lambda *a, **k: None)
    monkeypatch.setattr("app.agent.loop.llm_gate.note_rate_limit", lambda retry_after=None: None)
    return AgentLoop(
        project_id=1,
        role="worker",
        phase="worker",
        system_prompt="s",
        user_prompt="u",
        llm=ResolvedLlm(
            base_url="http://llm.test/v1",
            wire_api="chat",
            model="glm-5.2",
            api_key="k",
            source="test",
        ),
    )


def test_chat_streams_and_assembles(monkeypatch):
    resp = _FakeResponse(
        lines=[
            'data: {"choices":[{"delta":{"content":"hi"}}]}',
            'data: {"usage":{"prompt_tokens":3,"completion_tokens":1,"total_tokens":4,"prompt_tokens_details":{"cached_tokens":2}}}',
            "data: [DONE]",
        ]
    )
    client = _FakeClient(resp)
    loop = _loop(monkeypatch, client)
    data, usage, retry_after = loop._chat(
        [{"role": "user", "content": "hi"}],
        [],
        remaining=1800,
    )
    assert retry_after is None
    assert data["choices"][0]["message"]["content"] == "hi"
    assert usage["prompt_tokens"] == 3
    assert usage["cached_tokens"] == 2
    assert client.captured["json"]["stream"] is True
    assert client.captured["json"]["stream_options"] == {"include_usage": True}


def test_chat_http_429(monkeypatch):
    resp = _FakeResponse(status_code=429, headers={"retry-after": "7"}, body=b"Too Many Requests")
    loop = _loop(monkeypatch, _FakeClient(resp))
    with pytest.raises(RateLimitError) as ei:
        loop._chat([{"role": "user", "content": "hi"}], [], remaining=1800)
    assert ei.value.retry_after == 7.0


def test_chat_http_401(monkeypatch):
    resp = _FakeResponse(status_code=401, body=b"nope")
    loop = _loop(monkeypatch, _FakeClient(resp))
    with pytest.raises(AuthError):
        loop._chat([{"role": "user", "content": "hi"}], [], remaining=1800)


def test_sanitize_chat_messages_coerces_null_content():
    tool_calls = [
        {
            "id": "call_1",
            "type": "function",
            "function": {"name": "Read", "arguments": '{"path":"a.java"}'},
        }
    ]
    original = [
        {"role": "system", "content": "sys"},
        {"role": "assistant", "content": None, "tool_calls": tool_calls},
        {"role": "tool", "tool_call_id": "call_1"},
        {"role": "assistant", "content": ""},
        {"role": "user", "content": "continue"},
    ]
    out = _sanitize_chat_messages(original)
    assert out[1]["content"] == ""
    assert out[1]["tool_calls"] == tool_calls
    assert out[2]["content"] == ""
    assert out[2]["tool_call_id"] == "call_1"
    assert out[3]["content"] == ""
    assert original[1]["content"] is None
    assert "content" not in original[2]


def test_chat_sends_empty_string_for_null_assistant_content(monkeypatch):
    resp = _FakeResponse(
        lines=[
            'data: {"choices":[{"delta":{"content":"ok"}}]}',
            "data: [DONE]",
        ]
    )
    client = _FakeClient(resp)
    loop = _loop(monkeypatch, client)
    loop._chat(
        [
            {"role": "user", "content": "hi"},
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call_1",
                        "type": "function",
                        "function": {"name": "Read", "arguments": "{}"},
                    }
                ],
            },
            {"role": "tool", "tool_call_id": "call_1", "content": None},
        ],
        [],
        remaining=1800,
    )
    msgs = client.captured["json"]["messages"]
    assert msgs[1]["content"] == ""
    assert msgs[1]["tool_calls"][0]["id"] == "call_1"
    assert msgs[2]["content"] == ""


def test_chat_drops_stream_options_on_400(monkeypatch):
    responses = [
        _FakeResponse(status_code=400, body=b'{"error":"unknown parameter stream_options"}'),
        _FakeResponse(
            lines=[
                'data: {"choices":[{"delta":{"content":"ok"}}]}',
                "data: [DONE]",
            ]
        ),
    ]
    captured = []

    class _SeqClient(_FakeClient):
        def stream(self, method, url, headers=None, json=None):
            captured.append(json)
            return responses[len(captured) - 1]

    loop = _loop(monkeypatch, _SeqClient(responses[0]))
    data, _usage, _ra = loop._chat([{"role": "user", "content": "hi"}], [], remaining=1800)
    assert data["choices"][0]["message"]["content"] == "ok"
    assert "stream_options" in captured[0]
    assert "stream_options" not in captured[1]
    assert captured[1]["stream"] is True


def test_chat_retries_incomplete_chunked_read(monkeypatch):
    logs: list[str] = []

    class _BoomThenOk(_FakeClient):
        def __init__(self):
            super().__init__(
                _FakeResponse(
                    lines=[
                        'data: {"choices":[{"delta":{"content":"ok"}}]}',
                        "data: [DONE]",
                    ]
                )
            )
            self.n = 0

        def stream(self, method, url, headers=None, json=None):
            self.n += 1
            self.captured = {"method": method, "url": url, "json": json, "headers": headers}
            if self.n == 1:

                class _Bad:
                    status_code = 200
                    headers = {}

                    def __enter__(self):
                        return self

                    def __exit__(self, *exc):
                        return False

                    def iter_lines(self):
                        raise RuntimeError(
                            "peer closed connection without sending complete message body "
                            "(incomplete chunked read)"
                        )

                return _Bad()
            return self.response

    client = _BoomThenOk()
    monkeypatch.setattr("app.agent.loop.chat_http_client", lambda timeout=None: client)
    monkeypatch.setattr("app.agent.loop.live_log.system", lambda *a, **k: logs.append(a[-1] if a else k.get("text", "")))
    monkeypatch.setattr("app.agent.loop._interruptible_sleep", lambda *a, **k: 0.0)
    monkeypatch.setattr("app.agent.loop.llm_gate.note_rate_limit", lambda retry_after=None: None)
    loop = AgentLoop(
        project_id=1,
        role="worker",
        phase="worker",
        system_prompt="s",
        user_prompt="u",
        llm=ResolvedLlm(
            base_url="http://llm.test/v1",
            wire_api="chat",
            model="glm-5.2",
            api_key="k",
            source="test",
        ),
    )
    data, _usage, _ra = loop._chat([{"role": "user", "content": "hi"}], [], remaining=1800)
    assert data["choices"][0]["message"]["content"] == "ok"
    assert client.n == 2
    assert any("incomplete chunked read" in t for t in logs)
    assert any("正在重新请求模型（2/3）" in t for t in logs)

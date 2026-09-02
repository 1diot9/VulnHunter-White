from __future__ import annotations

import json

import pytest

from app.agent.anthropic_compat import (
    ANTHROPIC_VERSION,
    anthropic_headers,
    anthropic_message_to_openai,
    anthropic_url,
    assemble_anthropic_stream,
    build_anthropic_body,
    consume_anthropic_stream,
    is_anthropic_wire,
    openai_messages_to_anthropic,
    openai_tools_to_anthropic,
)
from app.agent.chat_stream import ChatStreamProviderError
from app.agent.loop import AgentLoop
from app.services.llm_settings import ResolvedLlm, normalize_wire_api


def test_wire_aliases():
    assert is_anthropic_wire("anthropic")
    assert is_anthropic_wire("messages")
    assert is_anthropic_wire("claude")
    assert not is_anthropic_wire("chat")
    assert normalize_wire_api("messages") == "anthropic"
    assert normalize_wire_api("bogus") == "chat"


def test_headers_and_url():
    headers = anthropic_headers("sk-ant")
    assert headers["x-api-key"] == "sk-ant"
    assert headers["Authorization"] == "Bearer sk-ant"
    assert headers["anthropic-version"] == ANTHROPIC_VERSION
    assert anthropic_url("https://api.anthropic.com/v1") == "https://api.anthropic.com/v1/messages"


def test_openai_tools_to_anthropic():
    tools = [
        {
            "type": "function",
            "function": {
                "name": "Read",
                "description": "read a file",
                "parameters": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]},
            },
        }
    ]
    out = openai_tools_to_anthropic(tools)
    assert out == [
        {
            "name": "Read",
            "description": "read a file",
            "input_schema": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
        }
    ]


def test_messages_split_system_and_merge_tool_results():
    system, msgs = openai_messages_to_anthropic(
        [
            {"role": "system", "content": "you are a helper"},
            {"role": "user", "content": "look at a.java"},
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "toolu_1",
                        "type": "function",
                        "function": {"name": "Read", "arguments": '{"path":"a.java"}'},
                    },
                    {
                        "id": "toolu_2",
                        "type": "function",
                        "function": {"name": "Grep", "arguments": '{"pattern":"sink"}'},
                    },
                ],
            },
            {"role": "tool", "tool_call_id": "toolu_1", "content": '{"ok":true}'},
            {"role": "tool", "tool_call_id": "toolu_2", "content": '{"ok":true,"hits":1}'},
            {"role": "user", "content": "请继续"},
        ]
    )
    assert system == "you are a helper"
    assert msgs[0] == {"role": "user", "content": "look at a.java"}
    assistant = msgs[1]
    assert assistant["role"] == "assistant"
    assert assistant["content"][0]["type"] == "tool_use"
    assert assistant["content"][0]["id"] == "toolu_1"
    assert assistant["content"][0]["input"] == {"path": "a.java"}
    assert assistant["content"][1]["name"] == "Grep"
    follow = msgs[2]
    assert follow["role"] == "user"
    blocks = follow["content"]
    assert [b["type"] for b in blocks] == ["tool_result", "tool_result", "text"]
    assert blocks[0]["tool_use_id"] == "toolu_1"
    assert blocks[2]["text"] == "请继续"


def test_build_anthropic_body_omits_empty_tools():
    body = build_anthropic_body(
        model="claude-sonnet-4-20250514",
        messages=[{"role": "system", "content": "sys"}, {"role": "user", "content": "hi"}],
        tools=[],
        stream=True,
        temperature=0.2,
    )
    assert body["model"] == "claude-sonnet-4-20250514"
    assert body["max_tokens"] == 8192
    assert body["system"] == "sys"
    assert body["messages"] == [{"role": "user", "content": "hi"}]
    assert body["stream"] is True
    assert "tools" not in body


def test_anthropic_message_to_openai_tools_and_usage():
    data = {
        "id": "msg_1",
        "type": "message",
        "role": "assistant",
        "model": "claude-test",
        "content": [
            {"type": "thinking", "thinking": "plan"},
            {"type": "text", "text": "calling"},
            {"type": "tool_use", "id": "toolu_9", "name": "Read", "input": {"path": "a.java"}},
        ],
        "stop_reason": "tool_use",
        "usage": {"input_tokens": 11, "output_tokens": 7, "cache_read_input_tokens": 3},
    }
    out = anthropic_message_to_openai(data)
    msg = out["choices"][0]["message"]
    assert msg["content"] == "calling"
    assert msg["reasoning_content"] == "plan"
    assert msg["tool_calls"][0]["id"] == "toolu_9"
    assert json.loads(msg["tool_calls"][0]["function"]["arguments"]) == {"path": "a.java"}
    assert out["choices"][0]["finish_reason"] == "tool_calls"
    assert out["usage"]["prompt_tokens"] == 11
    assert out["usage"]["completion_tokens"] == 7
    assert out["usage"]["cached_tokens"] == 3


def test_assemble_anthropic_stream_text_and_tool():
    chunks = [
        {
            "type": "message_start",
            "message": {
                "id": "msg_s",
                "model": "claude-test",
                "usage": {"input_tokens": 20, "cache_read_input_tokens": 4},
            },
        },
        {
            "type": "content_block_start",
            "index": 0,
            "content_block": {"type": "text", "text": ""},
        },
        {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "hi "}},
        {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "there"}},
        {"type": "content_block_stop", "index": 0},
        {
            "type": "content_block_start",
            "index": 1,
            "content_block": {"type": "tool_use", "id": "toolu_1", "name": "Read", "input": {}},
        },
        {
            "type": "content_block_delta",
            "index": 1,
            "delta": {"type": "input_json_delta", "partial_json": '{"path":'},
        },
        {
            "type": "content_block_delta",
            "index": 1,
            "delta": {"type": "input_json_delta", "partial_json": '"a.java"}'},
        },
        {"type": "content_block_stop", "index": 1},
        {
            "type": "message_delta",
            "delta": {"stop_reason": "tool_use"},
            "usage": {"output_tokens": 9},
        },
        {"type": "message_stop"},
    ]
    out = assemble_anthropic_stream(chunks)
    msg = out["choices"][0]["message"]
    assert msg["content"] == "hi there"
    tc = msg["tool_calls"][0]
    assert tc["id"] == "toolu_1"
    assert json.loads(tc["function"]["arguments"]) == {"path": "a.java"}
    assert out["choices"][0]["finish_reason"] == "tool_calls"
    assert out["usage"]["prompt_tokens"] == 20
    assert out["usage"]["cached_tokens"] == 4
    assert out["usage"]["completion_tokens"] == 9


def test_consume_anthropic_sse_skips_ping_and_event_lines():
    lines = [
        "event: ping",
        'data: {"type":"ping"}',
        "event: message_start",
        'data: {"type":"message_start","message":{"id":"msg_x","model":"c","usage":{"input_tokens":2}}}',
        "event: content_block_start",
        'data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}',
        "event: content_block_delta",
        'data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"pong"}}',
        "event: message_delta",
        'data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":1}}',
        "event: message_stop",
        'data: {"type":"message_stop"}',
    ]
    out = consume_anthropic_stream(lines)
    assert out["choices"][0]["message"]["content"] == "pong"
    assert out["choices"][0]["finish_reason"] == "stop"


def test_consume_anthropic_full_message_json():
    payload = {
        "type": "message",
        "role": "assistant",
        "content": [{"type": "text", "text": "pong"}],
        "stop_reason": "end_turn",
        "usage": {"input_tokens": 1, "output_tokens": 1},
    }
    out = consume_anthropic_stream([json.dumps(payload)])
    assert out["choices"][0]["message"]["content"] == "pong"


def test_consume_anthropic_provider_error():
    with pytest.raises(ChatStreamProviderError):
        consume_anthropic_stream(
            ['data: {"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}']
        )


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


def test_chat_uses_anthropic_messages_endpoint(tmp_env, monkeypatch):
    resp = _FakeResponse(
        lines=[
            'data: {"type":"message_start","message":{"id":"msg_1","usage":{"input_tokens":5}}}',
            'data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}',
            'data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"ok"}}',
            'data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":1}}',
            'data: {"type":"message_stop"}',
        ]
    )
    client = _FakeClient(resp)
    monkeypatch.setattr("app.agent.loop.chat_http_client", lambda timeout=None: client)
    monkeypatch.setattr("app.agent.loop.live_log.system", lambda *a, **k: None)
    monkeypatch.setattr("app.agent.loop.llm_gate.note_rate_limit", lambda retry_after=None: None)
    loop = AgentLoop(
        project_id=1,
        role="worker",
        phase="worker",
        system_prompt="s",
        user_prompt="u",
        llm=ResolvedLlm(
            base_url="https://api.anthropic.com/v1",
            wire_api="anthropic",
            model="claude-test",
            api_key="sk-ant",
            source="test",
        ),
    )
    tools = [
        {
            "type": "function",
            "function": {"name": "Read", "description": "r", "parameters": {"type": "object", "properties": {}}},
        }
    ]
    data, usage, retry_after = loop._chat(
        [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "hi"},
        ],
        tools,
        remaining=1800,
    )
    assert retry_after is None
    assert data["choices"][0]["message"]["content"] == "ok"
    assert usage["prompt_tokens"] == 5
    assert usage["completion_tokens"] == 1
    assert client.captured["url"].endswith("/messages")
    assert client.captured["headers"]["x-api-key"] == "sk-ant"
    body = client.captured["json"]
    assert body["stream"] is True
    assert "stream_options" not in body
    assert body["system"] == "sys"
    assert body["messages"][0]["role"] == "user"
    assert body["tools"][0]["name"] == "Read"
    assert body["max_tokens"] == 8192

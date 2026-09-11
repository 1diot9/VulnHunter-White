from __future__ import annotations

import json

import pytest

from app.agent.chat_stream import ChatStreamEmpty, ChatStreamProviderError
from app.agent.loop import AgentLoop
from app.agent.responses_compat import (
    assemble_responses_stream,
    build_responses_body,
    consume_responses_stream,
    is_responses_wire,
    openai_messages_to_responses,
    openai_tools_to_responses,
    responses_headers,
    responses_to_openai,
    responses_url,
)
from app.services.llm_settings import ResolvedLlm, normalize_wire_api


def test_wire_aliases():
    assert is_responses_wire("responses")
    assert is_responses_wire("response")
    assert is_responses_wire("openai-responses")
    assert not is_responses_wire("chat")
    assert not is_responses_wire("anthropic")
    assert normalize_wire_api("response") == "responses"
    assert normalize_wire_api("openai-responses") == "responses"


def test_headers_and_url():
    headers = responses_headers("sk-test")
    assert headers["Authorization"] == "Bearer sk-test"
    assert headers["Content-Type"] == "application/json"
    assert responses_url("https://api.openai.com/v1") == "https://api.openai.com/v1/responses"


def test_openai_tools_to_responses():
    tools = [
        {
            "type": "function",
            "function": {
                "name": "Read",
                "description": "read a file",
                "parameters": {
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                    "required": ["path"],
                },
            },
        }
    ]
    out = openai_tools_to_responses(tools)
    assert out == [
        {
            "type": "function",
            "name": "Read",
            "description": "read a file",
            "parameters": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
        }
    ]


def test_messages_split_system_and_tool_results():
    instructions, items = openai_messages_to_responses(
        [
            {"role": "system", "content": "you are a helper"},
            {"role": "user", "content": "look at a.java"},
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call_1",
                        "type": "function",
                        "function": {"name": "Read", "arguments": '{"path":"a.java"}'},
                    }
                ],
            },
            {"role": "tool", "tool_call_id": "call_1", "content": '{"ok":true}'},
            {"role": "user", "content": "请继续"},
        ]
    )
    assert instructions == "you are a helper"
    assert items[0] == {"role": "user", "content": "look at a.java"}
    assert items[1]["type"] == "function_call"
    assert items[1]["call_id"] == "call_1"
    assert items[1]["name"] == "Read"
    assert json.loads(items[1]["arguments"]) == {"path": "a.java"}
    assert items[2] == {
        "type": "function_call_output",
        "call_id": "call_1",
        "output": '{"ok":true}',
    }
    assert items[3] == {"role": "user", "content": "请继续"}


def test_build_responses_body_omits_empty_tools():
    body = build_responses_body(
        model="gpt-4.1",
        messages=[{"role": "system", "content": "sys"}, {"role": "user", "content": "hi"}],
        tools=[],
        stream=True,
        temperature=0.2,
    )
    assert body["model"] == "gpt-4.1"
    assert body["instructions"] == "sys"
    assert body["input"] == [{"role": "user", "content": "hi"}]
    assert body["stream"] is True
    assert body["temperature"] == 0.2
    assert "tools" not in body
    assert "max_output_tokens" not in body
    assert "stream_options" not in body


def test_build_responses_body_tools_and_max_tokens():
    body = build_responses_body(
        model="gpt-5",
        messages=[{"role": "user", "content": "hi"}],
        tools=[
            {
                "type": "function",
                "function": {
                    "name": "Read",
                    "description": "r",
                    "parameters": {"type": "object", "properties": {}},
                },
            }
        ],
        max_output_tokens=16,
        temperature=0.2,
    )
    assert "temperature" not in body
    assert body["max_output_tokens"] == 16
    assert body["tools"][0]["name"] == "Read"
    assert body["tool_choice"] == "auto"


def test_responses_to_openai_tools_and_usage():
    data = {
        "id": "resp_1",
        "object": "response",
        "status": "completed",
        "model": "gpt-test",
        "output": [
            {
                "type": "reasoning",
                "summary": [{"type": "summary_text", "text": "plan"}],
            },
            {
                "type": "message",
                "role": "assistant",
                "content": [{"type": "output_text", "text": "calling"}],
            },
            {
                "type": "function_call",
                "id": "fc_9",
                "call_id": "call_9",
                "name": "Read",
                "arguments": '{"path":"a.java"}',
            },
        ],
        "usage": {
            "input_tokens": 11,
            "output_tokens": 7,
            "total_tokens": 18,
            "input_tokens_details": {"cached_tokens": 3},
        },
    }
    out = responses_to_openai(data)
    msg = out["choices"][0]["message"]
    assert msg["content"] == "calling"
    assert msg["reasoning_content"] == "plan"
    assert msg["tool_calls"][0]["id"] == "call_9"
    assert json.loads(msg["tool_calls"][0]["function"]["arguments"]) == {"path": "a.java"}
    assert out["choices"][0]["finish_reason"] == "tool_calls"
    assert out["usage"]["prompt_tokens"] == 11
    assert out["usage"]["completion_tokens"] == 7
    assert out["usage"]["cached_tokens"] == 3


def test_assemble_responses_stream_text_and_tool():
    chunks = [
        {
            "type": "response.created",
            "response": {"id": "resp_s", "model": "gpt-test", "status": "in_progress"},
        },
        {
            "type": "response.output_item.added",
            "output_index": 0,
            "item": {
                "id": "msg_1",
                "type": "message",
                "role": "assistant",
                "content": [],
            },
        },
        {
            "type": "response.output_text.delta",
            "output_index": 0,
            "delta": "hi ",
        },
        {
            "type": "response.output_text.delta",
            "output_index": 0,
            "delta": "there",
        },
        {
            "type": "response.output_item.added",
            "output_index": 1,
            "item": {
                "id": "fc_1",
                "type": "function_call",
                "call_id": "call_1",
                "name": "Read",
                "arguments": "",
            },
        },
        {
            "type": "response.function_call_arguments.delta",
            "output_index": 1,
            "delta": '{"path":',
        },
        {
            "type": "response.function_call_arguments.delta",
            "output_index": 1,
            "delta": '"a.java"}',
        },
    ]
    out = assemble_responses_stream(chunks)
    msg = out["choices"][0]["message"]
    assert msg["content"] == "hi there"
    tc = msg["tool_calls"][0]
    assert tc["id"] == "call_1"
    assert json.loads(tc["function"]["arguments"]) == {"path": "a.java"}
    assert out["choices"][0]["finish_reason"] == "tool_calls"


def test_assemble_prefers_completed_event():
    chunks = [
        {"type": "response.output_text.delta", "delta": "partial"},
        {
            "type": "response.completed",
            "response": {
                "id": "resp_done",
                "object": "response",
                "status": "completed",
                "output": [
                    {
                        "type": "message",
                        "role": "assistant",
                        "content": [{"type": "output_text", "text": "final"}],
                    }
                ],
                "usage": {"input_tokens": 4, "output_tokens": 1},
            },
        },
    ]
    out = assemble_responses_stream(chunks)
    assert out["choices"][0]["message"]["content"] == "final"
    assert out["usage"]["prompt_tokens"] == 4


def test_consume_responses_sse_skips_event_lines():
    lines = [
        "event: response.created",
        'data: {"type":"response.created","response":{"id":"resp_x","status":"in_progress"}}',
        "event: response.output_text.delta",
        'data: {"type":"response.output_text.delta","output_index":0,"delta":"pong"}',
        "event: response.completed",
        (
            'data: {"type":"response.completed","response":{"id":"resp_x","object":"response",'
            '"status":"completed","output":[{"type":"message","role":"assistant",'
            '"content":[{"type":"output_text","text":"pong"}]}],'
            '"usage":{"input_tokens":2,"output_tokens":1}}}'
        ),
    ]
    out = consume_responses_stream(lines)
    assert out["choices"][0]["message"]["content"] == "pong"
    assert out["choices"][0]["finish_reason"] == "stop"


def test_consume_responses_full_json():
    payload = {
        "id": "resp_1",
        "object": "response",
        "status": "completed",
        "output": [
            {
                "type": "message",
                "role": "assistant",
                "content": [{"type": "output_text", "text": "pong"}],
            }
        ],
        "usage": {"input_tokens": 1, "output_tokens": 1},
    }
    out = consume_responses_stream([json.dumps(payload)])
    assert out["choices"][0]["message"]["content"] == "pong"


def test_consume_responses_provider_error():
    with pytest.raises(ChatStreamProviderError):
        consume_responses_stream(
            ['data: {"type":"error","error":{"message":"Overloaded"}}']
        )


def test_assemble_created_only_is_empty():
    with pytest.raises(ChatStreamEmpty):
        assemble_responses_stream(
            [{"type": "response.created", "response": {"id": "resp_x", "status": "in_progress"}}]
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


def test_chat_uses_responses_endpoint(tmp_env, monkeypatch):
    resp = _FakeResponse(
        lines=[
            'data: {"type":"response.output_text.delta","delta":"ok"}',
            (
                'data: {"type":"response.completed","response":{"id":"resp_1","object":"response",'
                '"status":"completed","model":"gpt-test",'
                '"output":[{"type":"message","role":"assistant",'
                '"content":[{"type":"output_text","text":"ok"}]}],'
                '"usage":{"input_tokens":5,"output_tokens":1}}}'
            ),
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
            base_url="https://api.openai.com/v1",
            wire_api="responses",
            model="gpt-test",
            api_key="sk-test",
            source="test",
        ),
    )
    tools = [
        {
            "type": "function",
            "function": {
                "name": "Read",
                "description": "r",
                "parameters": {"type": "object", "properties": {}},
            },
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
    assert client.captured["url"].endswith("/responses")
    assert client.captured["headers"]["Authorization"] == "Bearer sk-test"
    body = client.captured["json"]
    assert body["stream"] is True
    assert "stream_options" not in body
    assert body["instructions"] == "sys"
    assert body["input"][0]["role"] == "user"
    assert body["tools"][0]["name"] == "Read"
    assert body["tools"][0]["type"] == "function"
    assert "function" not in body["tools"][0]

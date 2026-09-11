"""Convert OpenAI-style chat payloads to the Responses API and back.

Internal checkpoints stay Chat Completions-shaped (system / assistant.tool_calls /
role=tool). Requests to wire_api=responses use POST /responses with instructions,
input items, and function / function_call_output tools. Streaming events are folded
back into a chat.completions object so the agent loop does not need a second path.
"""

from __future__ import annotations

import json
from typing import Any, Callable, Iterable

from .chat_stream import (
    ChatStreamEmpty,
    ChatStreamProviderError,
    assemble_chat_completion,
    iter_sse_payloads,
)
from .llm_compat import prepare_responses_body

_COMPLETE_EVENTS = frozenset(
    {"response.completed", "response.incomplete", "response.failed"}
)
_STATUS_FINISH = {
    "incomplete": "length",
    "failed": "stop",
    "cancelled": "stop",
}


def is_responses_wire(wire_api: str | None) -> bool:
    return (wire_api or "").strip().lower() in {"responses", "response", "openai-responses"}


def responses_url(base_url: str) -> str:
    return (base_url or "").rstrip("/") + "/responses"


def responses_headers(api_key: str) -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    key = (api_key or "").strip()
    if key:
        headers["Authorization"] = f"Bearer {key}"
    return headers


def openai_tools_to_responses(tools: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for item in tools or []:
        if not isinstance(item, dict):
            continue
        fn = item.get("function") if isinstance(item.get("function"), dict) else item
        name = str(fn.get("name") or "").strip()
        if not name:
            continue
        schema = fn.get("parameters") if isinstance(fn.get("parameters"), dict) else None
        if not schema:
            schema = {"type": "object", "properties": {}}
        else:
            schema = dict(schema)
            schema.setdefault("type", "object")
            if schema.get("type") == "object":
                schema.setdefault("properties", {})
        tool: dict[str, Any] = {
            "type": "function",
            "name": name,
            "description": str(fn.get("description") or ""),
            "parameters": schema,
        }
        if fn.get("strict") is True:
            tool["strict"] = True
        out.append(tool)
    return out


def _content_to_text(content: Any) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, dict):
        return str(content.get("text") or content.get("content") or json.dumps(content, ensure_ascii=False))
    if isinstance(content, list):
        parts: list[str] = []
        for part in content:
            if isinstance(part, str) and part:
                parts.append(part)
            elif isinstance(part, dict):
                text = str(part.get("text") or part.get("content") or "")
                if text:
                    parts.append(text)
        return "\n".join(parts)
    return str(content)


def _tool_arguments(raw: Any) -> str:
    if raw is None:
        return "{}"
    if isinstance(raw, str):
        return raw or "{}"
    if isinstance(raw, dict):
        return json.dumps(raw, ensure_ascii=False)
    return json.dumps(raw, ensure_ascii=False)


def openai_messages_to_responses(
    messages: list[dict[str, Any]] | None,
) -> tuple[str | None, list[dict[str, Any]]]:
    """Split system text into instructions and convert turns to Responses input items."""
    system_parts: list[str] = []
    converted: list[dict[str, Any]] = []
    for raw in messages or []:
        if not isinstance(raw, dict):
            continue
        role = str(raw.get("role") or "").strip()
        if role == "system":
            text = _content_to_text(raw.get("content")).strip()
            if text:
                system_parts.append(text)
            continue
        if role == "tool":
            converted.append(
                {
                    "type": "function_call_output",
                    "call_id": str(raw.get("tool_call_id") or raw.get("id") or "tool"),
                    "output": _content_to_text(raw.get("content")) or "",
                }
            )
            continue
        if role == "assistant":
            text = _content_to_text(raw.get("content"))
            if text.strip():
                item: dict[str, Any] = {"role": "assistant", "content": text}
                reasoning = raw.get("reasoning_content")
                if isinstance(reasoning, str) and reasoning.strip():
                    item["reasoning_content"] = reasoning
                converted.append(item)
            for tc in raw.get("tool_calls") or []:
                if not isinstance(tc, dict):
                    continue
                fn = tc.get("function") if isinstance(tc.get("function"), dict) else {}
                name = str(fn.get("name") or "").strip()
                call_id = str(tc.get("id") or name or "tool")
                converted.append(
                    {
                        "type": "function_call",
                        "id": call_id,
                        "call_id": call_id,
                        "name": name,
                        "arguments": _tool_arguments(fn.get("arguments")),
                    }
                )
            continue
        if role in ("user", "developer"):
            text = _content_to_text(raw.get("content"))
            if not text.strip():
                continue
            converted.append({"role": role, "content": text})
    if not converted:
        converted.append({"role": "user", "content": "(empty)"})
    instructions = "\n\n".join(system_parts) if system_parts else None
    return instructions, converted


def build_responses_body(
    *,
    model: str,
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]] | None = None,
    stream: bool = False,
    temperature: float | None = None,
    max_output_tokens: int | None = None,
) -> dict[str, Any]:
    instructions, converted = openai_messages_to_responses(messages)
    body: dict[str, Any] = {
        "model": model,
        "input": converted,
    }
    if instructions:
        body["instructions"] = instructions
    converted_tools = openai_tools_to_responses(tools)
    if converted_tools:
        body["tools"] = converted_tools
        body["tool_choice"] = "auto"
    if stream:
        body["stream"] = True
    if max_output_tokens is not None:
        body["max_output_tokens"] = max(1, int(max_output_tokens))
    prepare_responses_body(body, model, temperature=temperature)
    return body


def _delta_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return str(value.get("text") or value.get("content") or value.get("delta") or "")
    return ""


def _usage_from_responses(raw: dict[str, Any] | None) -> dict[str, Any]:
    src = raw if isinstance(raw, dict) else {}
    prompt = int(src.get("input_tokens") or src.get("prompt_tokens") or 0)
    completion = int(src.get("output_tokens") or src.get("completion_tokens") or 0)
    details = src.get("input_tokens_details") if isinstance(src.get("input_tokens_details"), dict) else {}
    cached = int(
        details.get("cached_tokens")
        or src.get("cached_tokens")
        or 0
    )
    usage: dict[str, Any] = {
        "prompt_tokens": prompt,
        "completion_tokens": completion,
        "total_tokens": int(src.get("total_tokens") or (prompt + completion)),
    }
    if cached:
        usage["cached_tokens"] = cached
        usage["prompt_tokens_details"] = {"cached_tokens": cached}
    return usage


def _text_from_content(content: Any) -> tuple[str, str]:
    if isinstance(content, str):
        return content, ""
    if not isinstance(content, list):
        return _content_to_text(content), ""
    texts: list[str] = []
    reasoning: list[str] = []
    for part in content:
        if isinstance(part, str) and part:
            texts.append(part)
            continue
        if not isinstance(part, dict):
            continue
        ptype = str(part.get("type") or "")
        text = str(part.get("text") or part.get("content") or "")
        if ptype in ("reasoning", "reasoning_text", "summary_text"):
            if text:
                reasoning.append(text)
            continue
        if text:
            texts.append(text)
    return "".join(texts), "".join(reasoning)


def _reasoning_from_item(item: dict[str, Any]) -> str:
    parts: list[str] = []
    summary = item.get("summary")
    if isinstance(summary, list):
        for block in summary:
            if isinstance(block, dict):
                text = str(block.get("text") or block.get("content") or "")
                if text:
                    parts.append(text)
            elif isinstance(block, str) and block:
                parts.append(block)
    text = str(item.get("text") or item.get("content") or "")
    if text and not isinstance(item.get("content"), (list, dict)):
        parts.append(text)
    elif isinstance(item.get("content"), list):
        _text, extra = _text_from_content(item.get("content"))
        if extra:
            parts.append(extra)
        elif _text:
            parts.append(_text)
    return "".join(parts)


def _finish_reason(payload: dict[str, Any], tool_calls: list[Any]) -> str | None:
    status = str(payload.get("status") or "")
    details = payload.get("incomplete_details") if isinstance(payload.get("incomplete_details"), dict) else {}
    reason = str(details.get("reason") or "")
    if reason == "max_output_tokens" or status == "incomplete":
        return "length"
    if tool_calls:
        return "tool_calls"
    mapped = _STATUS_FINISH.get(status)
    if mapped:
        return mapped
    if status in ("completed", ""):
        return "stop"
    return status or "stop"


def unwrap_responses_payload(data: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(data, dict):
        return None
    if isinstance(data.get("output"), list) or data.get("object") == "response":
        return data
    nested = data.get("response")
    if isinstance(nested, dict) and (
        isinstance(nested.get("output"), list) or nested.get("object") == "response"
    ):
        return nested
    return None


def looks_like_responses_payload(data: dict[str, Any] | None) -> bool:
    if not isinstance(data, dict):
        return False
    if unwrap_responses_payload(data) is not None:
        return True
    ctype = str(data.get("type") or "")
    return ctype.startswith("response.")


def responses_to_openai(data: dict[str, Any]) -> dict[str, Any]:
    """Map a non-stream Responses object (or completed event) to chat.completions."""
    if not isinstance(data, dict):
        return {
            "choices": [
                {"index": 0, "finish_reason": None, "message": {"role": "assistant", "content": None}}
            ]
        }
    if isinstance(data.get("choices"), list):
        return data
    payload = unwrap_responses_payload(data) or data
    output = payload.get("output") if isinstance(payload.get("output"), list) else []
    texts: list[str] = []
    reasoning: list[str] = []
    tool_calls: list[dict[str, Any]] = []
    for i, item in enumerate(output):
        if not isinstance(item, dict):
            continue
        itype = str(item.get("type") or "")
        if itype in ("message", "output_text") or item.get("role") == "assistant":
            text, extra = _text_from_content(item.get("content") if "content" in item else item.get("text"))
            if itype == "output_text" and not text:
                text = str(item.get("text") or "")
            if extra:
                reasoning.append(extra)
            if text:
                texts.append(text)
            continue
        if itype == "function_call":
            call_id = str(item.get("call_id") or item.get("id") or f"call_{i}")
            tool_calls.append(
                {
                    "id": call_id,
                    "type": "function",
                    "function": {
                        "name": str(item.get("name") or ""),
                        "arguments": _tool_arguments(item.get("arguments")),
                    },
                }
            )
            continue
        if itype == "reasoning":
            thought = _reasoning_from_item(item)
            if thought:
                reasoning.append(thought)
    if not texts and isinstance(payload.get("output_text"), str) and payload["output_text"]:
        texts.append(payload["output_text"])
    message: dict[str, Any] = {
        "role": "assistant",
        "content": "".join(texts) or None,
    }
    if reasoning:
        message["reasoning_content"] = "".join(reasoning)
    if tool_calls:
        message["tool_calls"] = tool_calls
    out: dict[str, Any] = {
        "id": payload.get("id") or data.get("id"),
        "model": payload.get("model") or data.get("model"),
        "object": "chat.completion",
        "choices": [
            {
                "index": 0,
                "finish_reason": _finish_reason(payload, tool_calls),
                "message": message,
            }
        ],
        "usage": _usage_from_responses(
            payload.get("usage") if isinstance(payload.get("usage"), dict) else data.get("usage")
        ),
    }
    return out


def _slot(slots: dict[int, dict[str, Any]], index: int) -> dict[str, Any]:
    return slots.setdefault(
        index,
        {
            "kind": "",
            "id": "",
            "call_id": "",
            "name": "",
            "text_parts": [],
            "arg_parts": [],
            "arguments": "",
            "reasoning_parts": [],
        },
    )


def _apply_output_item(slots: dict[int, dict[str, Any]], index: int, item: dict[str, Any]) -> None:
    slot = _slot(slots, index)
    itype = str(item.get("type") or slot.get("kind") or "")
    if itype:
        slot["kind"] = itype
    if item.get("id"):
        slot["id"] = str(item["id"])
    if item.get("call_id"):
        slot["call_id"] = str(item["call_id"])
    if item.get("name"):
        slot["name"] = str(item["name"])
    if itype == "function_call" or item.get("arguments") is not None:
        args = item.get("arguments")
        if args not in (None, ""):
            slot["arguments"] = _tool_arguments(args)
    if itype in ("message", "output_text") or item.get("role") == "assistant":
        text, extra = _text_from_content(item.get("content") if "content" in item else item.get("text"))
        if itype == "output_text" and not text:
            text = str(item.get("text") or "")
        if text:
            slot["text_parts"] = [text]
        if extra:
            slot["reasoning_parts"] = [extra]
    if itype == "reasoning":
        thought = _reasoning_from_item(item)
        if thought:
            slot["reasoning_parts"] = [thought]


def assemble_responses_stream(chunks: Iterable[dict[str, Any]]) -> dict[str, Any]:
    items = [c for c in chunks if isinstance(c, dict)]
    if any(isinstance(c.get("choices"), list) for c in items):
        return assemble_chat_completion(items)

    slots: dict[int, dict[str, Any]] = {}
    finish_reason: str | None = None
    usage: dict[str, Any] = {}
    meta: dict[str, Any] = {}
    complete: dict[str, Any] | None = None

    for chunk in items:
        ctype = str(chunk.get("type") or "")
        err = chunk.get("error")
        if ctype in ("error", "response.failed") or err:
            payload = unwrap_responses_payload(chunk) or chunk
            nested_err = payload.get("error") if isinstance(payload.get("error"), dict) else err
            raise ChatStreamProviderError(nested_err or chunk)
        payload = unwrap_responses_payload(chunk)
        if payload is not None:
            if payload.get("id"):
                meta["id"] = payload["id"]
            if payload.get("model"):
                meta["model"] = payload["model"]
            if isinstance(payload.get("usage"), dict) and payload["usage"]:
                usage = _usage_from_responses(payload["usage"])
            if ctype in _COMPLETE_EVENTS or payload.get("status") in (
                "completed",
                "incomplete",
                "failed",
            ):
                complete = payload
                continue
            if ctype in ("response.created", "response.in_progress"):
                continue
            if ctype == "" and isinstance(payload.get("output"), list) and payload.get("status"):
                complete = payload
                continue

        if ctype in (
            "response.created",
            "response.in_progress",
            "response.content_part.done",
            "response.output_item.delta",
        ):
            continue

        try:
            idx = int(chunk.get("output_index") if chunk.get("output_index") is not None else 0)
        except (TypeError, ValueError):
            idx = 0

        if ctype == "response.output_item.added":
            item = chunk.get("item") if isinstance(chunk.get("item"), dict) else {}
            _apply_output_item(slots, idx, item)
            continue
        if ctype == "response.output_item.done":
            item = chunk.get("item") if isinstance(chunk.get("item"), dict) else {}
            _apply_output_item(slots, idx, item)
            continue
        if ctype in ("response.output_text.delta", "response.text.delta"):
            text = _delta_text(chunk.get("delta"))
            if text:
                slot = _slot(slots, idx)
                slot["kind"] = slot["kind"] or "message"
                slot["text_parts"].append(text)
            continue
        if ctype == "response.output_text.done":
            text = str(chunk.get("text") or "")
            if text:
                slot = _slot(slots, idx)
                slot["kind"] = slot["kind"] or "message"
                slot["text_parts"] = [text]
            continue
        if ctype == "response.function_call_arguments.delta":
            slot = _slot(slots, idx)
            slot["kind"] = "function_call"
            delta = chunk.get("delta")
            if isinstance(delta, dict):
                slot["arg_parts"].append(_tool_arguments(delta) if delta else "")
            else:
                slot["arg_parts"].append(str(delta or ""))
            continue
        if ctype == "response.function_call_arguments.done":
            slot = _slot(slots, idx)
            slot["kind"] = "function_call"
            args = chunk.get("arguments")
            if args not in (None, ""):
                slot["arguments"] = _tool_arguments(args)
            continue
        if ctype in (
            "response.reasoning_summary_text.delta",
            "response.reasoning_text.delta",
        ):
            text = _delta_text(chunk.get("delta"))
            if text:
                _slot(slots, idx)["reasoning_parts"].append(text)
            continue
        if ctype == "response.content_part.added":
            part = chunk.get("part") if isinstance(chunk.get("part"), dict) else {}
            ptype = str(part.get("type") or "")
            text = str(part.get("text") or "")
            if ptype in ("output_text", "text") and text:
                slot = _slot(slots, idx)
                slot["kind"] = slot["kind"] or "message"
                slot["text_parts"].append(text)
            elif ptype in ("reasoning", "reasoning_text", "summary_text") and text:
                _slot(slots, idx)["reasoning_parts"].append(text)
            continue

    if complete is not None and str(complete.get("status") or "") in (
        "completed",
        "incomplete",
        "failed",
    ):
        return responses_to_openai(complete)

    if not slots:
        raise ChatStreamEmpty()

    content_parts: list[str] = []
    reasoning_parts: list[str] = []
    tool_calls: list[dict[str, Any]] = []
    for idx in sorted(slots):
        slot = slots[idx]
        kind = slot.get("kind") or ""
        if kind == "function_call" or slot.get("name") or slot.get("call_id"):
            args = slot.get("arguments") or "".join(slot.get("arg_parts") or [])
            name = str(slot.get("name") or "")
            call_id = str(slot.get("call_id") or slot.get("id") or name or f"call_{idx}")
            tool_calls.append(
                {
                    "id": call_id,
                    "type": "function",
                    "function": {"name": name, "arguments": args or "{}"},
                }
            )
            continue
        content_parts.extend(str(p) for p in (slot.get("text_parts") or []) if p)
        reasoning_parts.extend(str(p) for p in (slot.get("reasoning_parts") or []) if p)

    message: dict[str, Any] = {
        "role": "assistant",
        "content": "".join(content_parts) or None,
    }
    if reasoning_parts:
        message["reasoning_content"] = "".join(reasoning_parts)
    if tool_calls:
        message["tool_calls"] = tool_calls
        if not finish_reason:
            finish_reason = "tool_calls"
    elif not finish_reason:
        finish_reason = "stop"
    out: dict[str, Any] = {
        **meta,
        "object": "chat.completion",
        "choices": [{"index": 0, "finish_reason": finish_reason, "message": message}],
    }
    if usage:
        out["usage"] = usage
    return out


def consume_responses_stream(
    lines: Iterable[Any],
    *,
    cancel_check: Callable[[], bool] | None = None,
    on_first_payload: Callable[[], None] | None = None,
) -> dict[str, Any]:
    chunks: list[dict[str, Any]] = []
    first = True
    for payload in iter_sse_payloads(lines, cancel_check=cancel_check):
        if payload.get("type") == "ping":
            continue
        if first:
            first = False
            if on_first_payload:
                on_first_payload()
        chunks.append(payload)
    if not chunks:
        raise ChatStreamEmpty()
    if len(chunks) == 1 and isinstance(chunks[0].get("choices"), list):
        return assemble_chat_completion(chunks)
    if len(chunks) == 1 and unwrap_responses_payload(chunks[0]) is not None:
        err = chunks[0].get("error")
        if err:
            raise ChatStreamProviderError(err)
        return responses_to_openai(chunks[0])
    if any(isinstance(c.get("choices"), list) for c in chunks):
        return assemble_chat_completion(chunks)
    return assemble_responses_stream(chunks)

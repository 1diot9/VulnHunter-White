"""Convert OpenAI-style chat payloads to Anthropic Messages API and back.

Internal checkpoints stay Chat Completions-shaped (system / assistant.tool_calls /
role=tool). Requests to wire_api=anthropic use POST /messages with system, tool_use,
and tool_result blocks. Streaming events are folded back into a chat.completions
object so the agent loop does not need a second tool-call path.
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

ANTHROPIC_VERSION = "2023-06-01"
DEFAULT_MAX_TOKENS = 8192
_STOP_REASON = {
    "end_turn": "stop",
    "stop_sequence": "stop",
    "pause_turn": "stop",
    "refusal": "stop",
    "tool_use": "tool_calls",
    "max_tokens": "length",
}


def is_anthropic_wire(wire_api: str | None) -> bool:
    return (wire_api or "").strip().lower() in {"anthropic", "messages", "claude"}


def anthropic_url(base_url: str) -> str:
    return (base_url or "").rstrip("/") + "/messages"


def anthropic_headers(api_key: str) -> dict[str, str]:
    """Official Claude uses x-api-key; many gateways only accept Bearer. Send both."""
    headers = {
        "Content-Type": "application/json",
        "anthropic-version": ANTHROPIC_VERSION,
    }
    key = (api_key or "").strip()
    if key:
        headers["x-api-key"] = key
        headers["Authorization"] = f"Bearer {key}"
    return headers


def openai_tools_to_anthropic(tools: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
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
        out.append(
            {
                "name": name,
                "description": str(fn.get("description") or ""),
                "input_schema": schema,
            }
        )
    return out


def _content_to_text(content: Any) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, dict):
        return json.dumps(content, ensure_ascii=False)
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


def _as_blocks(content: Any) -> list[dict[str, Any]]:
    if content is None or content == "":
        return []
    if isinstance(content, str):
        return [{"type": "text", "text": content}]
    if isinstance(content, list):
        blocks: list[dict[str, Any]] = []
        for part in content:
            if isinstance(part, str) and part:
                blocks.append({"type": "text", "text": part})
            elif isinstance(part, dict) and part.get("type"):
                blocks.append(part)
            elif isinstance(part, dict):
                text = str(part.get("text") or part.get("content") or "")
                if text:
                    blocks.append({"type": "text", "text": text})
        return blocks
    return [{"type": "text", "text": str(content)}]


def _merge_content(left: Any, right: Any) -> Any:
    merged = _as_blocks(left) + _as_blocks(right)
    if not merged:
        return ""
    if all(b.get("type") == "text" for b in merged):
        return "\n\n".join(str(b.get("text") or "") for b in merged if b.get("text"))
    return merged


def _parse_tool_input(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if raw is None or raw == "":
        return {}
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def _assistant_blocks(message: dict[str, Any]) -> list[dict[str, Any]]:
    blocks = _as_blocks(message.get("content"))
    for tc in message.get("tool_calls") or []:
        if not isinstance(tc, dict):
            continue
        fn = tc.get("function") if isinstance(tc.get("function"), dict) else {}
        name = str(fn.get("name") or "").strip()
        tool_id = str(tc.get("id") or name or "tool")
        blocks.append(
            {
                "type": "tool_use",
                "id": tool_id,
                "name": name,
                "input": _parse_tool_input(fn.get("arguments")),
            }
        )
    return [b for b in blocks if b.get("type") != "text" or (b.get("text") or "").strip()]


def _has_payload(content: Any) -> bool:
    if isinstance(content, str):
        return bool(content.strip())
    if isinstance(content, list):
        return bool(content)
    return bool(content)


def _ensure_alternating(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for msg in messages:
        role = msg.get("role")
        content = msg.get("content")
        if role not in ("user", "assistant"):
            continue
        if not _has_payload(content):
            continue
        if out and out[-1].get("role") == role:
            out[-1]["content"] = _merge_content(out[-1].get("content"), content)
        else:
            out.append({"role": role, "content": content})
    if out and out[0].get("role") != "user":
        out.insert(0, {"role": "user", "content": "(continue)"})
    if not out:
        out.append({"role": "user", "content": "(empty)"})
    return out


def openai_messages_to_anthropic(
    messages: list[dict[str, Any]] | None,
) -> tuple[str | None, list[dict[str, Any]]]:
    """Split system text and convert user/assistant/tool turns to Messages API."""
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
            block = {
                "type": "tool_result",
                "tool_use_id": str(raw.get("tool_call_id") or raw.get("id") or "tool"),
                "content": _content_to_text(raw.get("content")) or "",
            }
            if converted and converted[-1].get("role") == "user":
                converted[-1]["content"] = _merge_content(converted[-1].get("content"), [block])
            else:
                converted.append({"role": "user", "content": [block]})
            continue
        if role == "assistant":
            blocks = _assistant_blocks(raw)
            if not blocks:
                continue
            if all(b.get("type") == "text" for b in blocks):
                converted.append(
                    {
                        "role": "assistant",
                        "content": "\n".join(str(b.get("text") or "") for b in blocks if b.get("text")),
                    }
                )
            else:
                converted.append({"role": "assistant", "content": blocks})
            continue
        if role == "user":
            text = _content_to_text(raw.get("content"))
            if not text.strip():
                continue
            converted.append({"role": "user", "content": text})
    system = "\n\n".join(system_parts) if system_parts else None
    return system, _ensure_alternating(converted)


def build_anthropic_body(
    *,
    model: str,
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]] | None = None,
    stream: bool = False,
    temperature: float | None = None,
    max_tokens: int = DEFAULT_MAX_TOKENS,
) -> dict[str, Any]:
    system, converted = openai_messages_to_anthropic(messages)
    body: dict[str, Any] = {
        "model": model,
        "max_tokens": max(1, int(max_tokens)),
        "messages": converted,
    }
    if system:
        body["system"] = system
    converted_tools = openai_tools_to_anthropic(tools)
    if converted_tools:
        body["tools"] = converted_tools
    if stream:
        body["stream"] = True
    if temperature is not None:
        body["temperature"] = temperature
    return body


def _map_stop_reason(reason: Any) -> str | None:
    if reason is None or reason == "":
        return None
    text = str(reason)
    return _STOP_REASON.get(text, text)


def _usage_from_anthropic(raw: dict[str, Any] | None) -> dict[str, Any]:
    src = raw if isinstance(raw, dict) else {}
    prompt = int(src.get("input_tokens") or src.get("prompt_tokens") or 0)
    completion = int(src.get("output_tokens") or src.get("completion_tokens") or 0)
    cached = int(src.get("cache_read_input_tokens") or src.get("cached_tokens") or 0)
    usage: dict[str, Any] = {
        "prompt_tokens": prompt,
        "completion_tokens": completion,
        "total_tokens": prompt + completion,
    }
    if cached:
        usage["cached_tokens"] = cached
        usage["prompt_tokens_details"] = {"cached_tokens": cached}
    return usage


def anthropic_message_to_openai(data: dict[str, Any]) -> dict[str, Any]:
    """Map a non-stream Messages response (or type=message event) to chat.completions."""
    if not isinstance(data, dict):
        return {"choices": [{"index": 0, "finish_reason": None, "message": {"role": "assistant", "content": None}}]}
    if isinstance(data.get("choices"), list):
        return data
    payload = data.get("message") if isinstance(data.get("message"), dict) and data.get("type") == "message_start" else data
    content_blocks = payload.get("content") if isinstance(payload.get("content"), list) else []
    texts: list[str] = []
    reasoning: list[str] = []
    tool_calls: list[dict[str, Any]] = []
    for i, block in enumerate(content_blocks):
        if not isinstance(block, dict):
            continue
        btype = block.get("type")
        if btype == "text":
            texts.append(str(block.get("text") or ""))
        elif btype == "tool_use":
            inp = block.get("input") if isinstance(block.get("input"), dict) else {}
            tool_calls.append(
                {
                    "id": str(block.get("id") or f"toolu_{i}"),
                    "type": "function",
                    "function": {
                        "name": str(block.get("name") or ""),
                        "arguments": json.dumps(inp, ensure_ascii=False),
                    },
                }
            )
        elif btype in ("thinking", "redacted_thinking"):
            thinking = str(block.get("thinking") or block.get("content") or "")
            if thinking:
                reasoning.append(thinking)
    message: dict[str, Any] = {
        "role": "assistant",
        "content": "".join(texts) or None,
    }
    if reasoning:
        message["reasoning_content"] = "".join(reasoning)
    if tool_calls:
        message["tool_calls"] = tool_calls
    usage_src = payload.get("usage") if isinstance(payload.get("usage"), dict) else data.get("usage")
    out: dict[str, Any] = {
        "id": payload.get("id") or data.get("id"),
        "model": payload.get("model") or data.get("model"),
        "object": "chat.completion",
        "choices": [
            {
                "index": 0,
                "finish_reason": _map_stop_reason(payload.get("stop_reason") or data.get("stop_reason")),
                "message": message,
            }
        ],
        "usage": _usage_from_anthropic(usage_src if isinstance(usage_src, dict) else {}),
    }
    return out


def assemble_anthropic_stream(chunks: Iterable[dict[str, Any]]) -> dict[str, Any]:
    content_parts: list[str] = []
    reasoning_parts: list[str] = []
    tool_slots: dict[int, dict[str, Any]] = {}
    finish_reason: str | None = None
    usage: dict[str, Any] = {}
    meta: dict[str, Any] = {}
    saw_message_event = False
    items = [c for c in chunks if isinstance(c, dict)]
    if any(isinstance(c.get("choices"), list) for c in items):
        return assemble_chat_completion(items)

    for chunk in items:
        if not isinstance(chunk, dict):
            continue
        ctype = chunk.get("type")
        if ctype == "ping":
            continue
        err = chunk.get("error")
        if ctype == "error" or err:
            raise ChatStreamProviderError(err or chunk)
        if ctype == "message" and isinstance(chunk.get("content"), list):
            return anthropic_message_to_openai(chunk)
        if ctype == "message_start":
            saw_message_event = True
            msg = chunk.get("message") if isinstance(chunk.get("message"), dict) else {}
            if msg.get("id"):
                meta["id"] = msg["id"]
            if msg.get("model"):
                meta["model"] = msg["model"]
            if isinstance(msg.get("usage"), dict):
                usage.update(_usage_from_anthropic(msg["usage"]))
            continue
        if ctype == "content_block_start":
            saw_message_event = True
            try:
                idx = int(chunk.get("index") if chunk.get("index") is not None else 0)
            except (TypeError, ValueError):
                idx = 0
            block = chunk.get("content_block") if isinstance(chunk.get("content_block"), dict) else {}
            btype = block.get("type")
            if btype == "tool_use":
                tool_slots[idx] = {
                    "id": str(block.get("id") or ""),
                    "name": str(block.get("name") or ""),
                    "json_parts": [],
                    "input": block.get("input") if isinstance(block.get("input"), dict) else {},
                }
            elif btype in ("thinking", "redacted_thinking"):
                thinking = str(block.get("thinking") or "")
                if thinking:
                    reasoning_parts.append(thinking)
            elif btype == "text":
                text = str(block.get("text") or "")
                if text:
                    content_parts.append(text)
            continue
        if ctype == "content_block_delta":
            saw_message_event = True
            try:
                idx = int(chunk.get("index") if chunk.get("index") is not None else 0)
            except (TypeError, ValueError):
                idx = 0
            delta = chunk.get("delta") if isinstance(chunk.get("delta"), dict) else {}
            dtype = delta.get("type")
            if dtype == "text_delta":
                content_parts.append(str(delta.get("text") or ""))
            elif dtype == "input_json_delta":
                slot = tool_slots.setdefault(
                    idx,
                    {"id": "", "name": "", "json_parts": [], "input": {}},
                )
                slot["json_parts"].append(str(delta.get("partial_json") or ""))
            elif dtype == "thinking_delta":
                reasoning_parts.append(str(delta.get("thinking") or ""))
            continue
        if ctype == "message_delta":
            saw_message_event = True
            delta = chunk.get("delta") if isinstance(chunk.get("delta"), dict) else {}
            mapped = _map_stop_reason(delta.get("stop_reason"))
            if mapped:
                finish_reason = mapped
            if isinstance(chunk.get("usage"), dict):
                extra = _usage_from_anthropic(chunk["usage"])
                if extra.get("completion_tokens"):
                    usage["completion_tokens"] = extra["completion_tokens"]
                usage["total_tokens"] = int(usage.get("prompt_tokens") or 0) + int(
                    usage.get("completion_tokens") or 0
                )
            continue
        if ctype in ("content_block_stop", "message_stop"):
            saw_message_event = True
            continue

    if not saw_message_event and not content_parts and not tool_slots:
        raise ChatStreamEmpty()

    tool_calls: list[dict[str, Any]] = []
    for idx in sorted(tool_slots):
        slot = tool_slots[idx]
        args = "".join(slot.get("json_parts") or [])
        if not args and slot.get("input"):
            args = json.dumps(slot["input"], ensure_ascii=False)
        name = str(slot.get("name") or "")
        tool_calls.append(
            {
                "id": str(slot.get("id") or name or f"toolu_{idx}"),
                "type": "function",
                "function": {"name": name, "arguments": args or "{}"},
            }
        )
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
    out: dict[str, Any] = {
        **meta,
        "object": "chat.completion",
        "choices": [{"index": 0, "finish_reason": finish_reason, "message": message}],
    }
    if usage:
        out["usage"] = usage
    return out


def consume_anthropic_stream(
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
    if len(chunks) == 1 and chunks[0].get("type") == "message":
        err = chunks[0].get("error")
        if err:
            raise ChatStreamProviderError(err)
        return anthropic_message_to_openai(chunks[0])
    if any(isinstance(c.get("choices"), list) for c in chunks):
        return assemble_chat_completion(chunks)
    return assemble_anthropic_stream(chunks)

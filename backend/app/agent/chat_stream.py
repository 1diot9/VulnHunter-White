"""OpenAI-compatible Chat Completions SSE parse + assemble."""

from __future__ import annotations

import json
from typing import Any, Callable, Iterable, Iterator

_DONE = object()
_REASONING_KEYS = ("reasoning_content", "reasoning", "thinking")


class ChatStreamError(Exception):
    """Stream failed; caller maps this onto TransientError / RateLimitError."""


class ChatStreamCancelled(ChatStreamError):
    pass


class ChatStreamEmpty(ChatStreamError):
    def __init__(self) -> None:
        super().__init__("empty stream")


class ChatStreamProviderError(ChatStreamError):
    def __init__(self, payload: Any) -> None:
        self.payload = payload
        super().__init__(_error_message(payload))


def _error_message(payload: Any) -> str:
    if isinstance(payload, dict):
        for key in ("message", "msg", "error"):
            val = payload.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip()
            if isinstance(val, dict):
                nested = _error_message(val)
                if nested:
                    return nested
        return json.dumps(payload, ensure_ascii=False)[:300]
    return str(payload)[:300]


def _as_text(line: Any) -> str:
    if line is None:
        return ""
    if isinstance(line, bytes):
        return line.decode("utf-8", errors="replace")
    return str(line)


def parse_sse_line(line: Any) -> Any:
    """Return dict payload, _DONE, or None (comment / blank / ignore)."""
    text = _as_text(line).strip()
    if not text or text.startswith(":"):
        return None
    if text.startswith("data:"):
        data = text[5:].strip()
        if data == "[DONE]":
            return _DONE
        if not data:
            return None
        try:
            return json.loads(data)
        except json.JSONDecodeError as e:
            raise ChatStreamError(f"invalid SSE JSON: {e}") from e
    if text.startswith("{"):
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return None
    return None


def _append_reasoning(parts: list[str], obj: dict[str, Any]) -> None:
    for key in _REASONING_KEYS:
        val = obj.get(key)
        if isinstance(val, str) and val:
            parts.append(val)
            return
        if isinstance(val, dict):
            text = str(val.get("content") or val.get("text") or "")
            if text:
                parts.append(text)
                return


def _merge_tool_call(slots: dict[int, dict[str, Any]], tc: dict[str, Any], fallback_index: int) -> None:
    try:
        idx = int(tc.get("index")) if tc.get("index") is not None else fallback_index
    except (TypeError, ValueError):
        idx = fallback_index
    slot = slots.setdefault(
        idx,
        {"id": "", "type": "function", "function": {"name": "", "arguments": ""}},
    )
    if tc.get("id"):
        slot["id"] = str(tc["id"])
    if tc.get("type"):
        slot["type"] = str(tc["type"])
    fn = tc.get("function") if isinstance(tc.get("function"), dict) else {}
    name = fn.get("name")
    if isinstance(name, str) and name:
        existing = slot["function"]["name"]
        if not existing:
            slot["function"]["name"] = name
        elif name.startswith(existing):
            slot["function"]["name"] = name
        elif not existing.startswith(name):
            slot["function"]["name"] += name
    args = fn.get("arguments")
    if isinstance(args, str) and args:
        slot["function"]["arguments"] += args


def _merge_delta(
    content_parts: list[str],
    reasoning_parts: list[str],
    tool_slots: dict[int, dict[str, Any]],
    delta: dict[str, Any],
) -> None:
    content = delta.get("content")
    if isinstance(content, str) and content:
        content_parts.append(content)
    elif isinstance(content, list):
        for part in content:
            if isinstance(part, str) and part:
                content_parts.append(part)
            elif isinstance(part, dict):
                text = str(part.get("text") or part.get("content") or "")
                if text:
                    content_parts.append(text)
    _append_reasoning(reasoning_parts, delta)
    tool_calls = delta.get("tool_calls")
    if isinstance(tool_calls, list):
        for i, tc in enumerate(tool_calls):
            if isinstance(tc, dict):
                _merge_tool_call(tool_slots, tc, i)


def assemble_chat_completion(chunks: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Fold SSE chunks into a non-stream chat.completions payload."""
    content_parts: list[str] = []
    reasoning_parts: list[str] = []
    tool_slots: dict[int, dict[str, Any]] = {}
    finish_reason: str | None = None
    usage: dict[str, Any] = {}
    meta: dict[str, Any] = {}

    for chunk in chunks:
        if not isinstance(chunk, dict):
            continue
        if chunk.get("error"):
            raise ChatStreamProviderError(chunk.get("error"))
        for key in ("id", "object", "model", "created"):
            if key in chunk and chunk[key] is not None:
                meta[key] = chunk[key]
        if isinstance(chunk.get("usage"), dict) and chunk["usage"]:
            usage = chunk["usage"]
        choices = chunk.get("choices")
        if not isinstance(choices, list):
            continue
        for choice in choices:
            if not isinstance(choice, dict):
                continue
            fr = choice.get("finish_reason")
            if fr:
                finish_reason = str(fr)
            message = choice.get("message")
            if isinstance(message, dict):
                _merge_delta(content_parts, reasoning_parts, tool_slots, message)
            delta = choice.get("delta")
            if isinstance(delta, dict):
                _merge_delta(content_parts, reasoning_parts, tool_slots, delta)

    message: dict[str, Any] = {
        "role": "assistant",
        "content": "".join(content_parts) or None,
    }
    if reasoning_parts:
        message["reasoning_content"] = "".join(reasoning_parts)
    if tool_slots:
        message["tool_calls"] = [tool_slots[i] for i in sorted(tool_slots)]
        for tc in message["tool_calls"]:
            if not tc.get("id"):
                tc["id"] = tc["function"]["name"] or "tool"

    out: dict[str, Any] = {
        **meta,
        "choices": [{"index": 0, "finish_reason": finish_reason, "message": message}],
    }
    if usage:
        out["usage"] = usage
    return out


def iter_sse_payloads(
    lines: Iterable[Any],
    *,
    cancel_check: Callable[[], bool] | None = None,
    on_first_payload: Callable[[], None] | None = None,
) -> Iterator[dict[str, Any]]:
    saw_first = False
    for line in lines:
        if cancel_check and cancel_check():
            raise ChatStreamCancelled("cancelled")
        parsed = parse_sse_line(line)
        if parsed is None:
            continue
        if parsed is _DONE:
            return
        if not isinstance(parsed, dict):
            continue
        if not saw_first:
            saw_first = True
            if on_first_payload:
                on_first_payload()
        yield parsed


def consume_chat_stream(
    lines: Iterable[Any],
    *,
    cancel_check: Callable[[], bool] | None = None,
    on_first_payload: Callable[[], None] | None = None,
) -> dict[str, Any]:
    chunks = list(
        iter_sse_payloads(
            lines,
            cancel_check=cancel_check,
            on_first_payload=on_first_payload,
        )
    )
    if not chunks:
        raise ChatStreamEmpty()
    if len(chunks) == 1 and isinstance((chunks[0].get("choices") or [None])[0], dict):
        choice = chunks[0]["choices"][0]
        if isinstance(choice.get("message"), dict) and "delta" not in choice:
            err = chunks[0].get("error")
            if err:
                raise ChatStreamProviderError(err)
            return chunks[0]
    return assemble_chat_completion(chunks)

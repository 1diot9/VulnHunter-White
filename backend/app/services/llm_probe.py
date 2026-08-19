"""List remote models and ping chat / Anthropic Messages for settings UI."""

from __future__ import annotations

import json
import time
from typing import Any

import httpx

from ..agent.anthropic_compat import (
    anthropic_headers,
    anthropic_message_to_openai,
    anthropic_url,
    build_anthropic_body,
    is_anthropic_wire,
)
from ..schemas import LlmModelListOut, LlmProbeIn, LlmTestOut
from .http_client import chat_http_client
from .llm_settings import resolve_probe_target

_PROBE_TIMEOUT = 30.0


def _headers(api_key: str, wire_api: str = "chat") -> dict[str, str]:
    if is_anthropic_wire(wire_api):
        return anthropic_headers(api_key)
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    return headers


def _short_error(text: str, limit: int = 400) -> str:
    t = " ".join((text or "").split())
    if len(t) > limit:
        return t[: limit - 1] + "…"
    return t


def _http_error(status: int, body: str) -> str:
    snippet = _short_error(body)
    if status == 401:
        return "401 密钥无效，请检查 API Key"
    if status == 403:
        return "403 无权限访问该接口，请检查 API Key 或模型权限"
    if status == 404:
        return "404 接口不存在，请确认 Base URL 是否包含 /v1"
    if status == 429:
        return "429 请求过于频繁，请稍后再试"
    if snippet:
        return f"HTTP {status}: {snippet}"
    return f"HTTP {status}"


def _transport_error(exc: Exception) -> str:
    if isinstance(exc, httpx.TimeoutException):
        return "请求超时，请检查 Base URL、代理或网络"
    if isinstance(exc, httpx.ConnectError):
        return "无法连接 Base URL，请检查地址与代理"
    return _short_error(str(exc) or exc.__class__.__name__)


def _extract_model_ids(payload: Any) -> list[str]:
    if isinstance(payload, dict):
        if isinstance(payload.get("data"), list):
            items = payload["data"]
        elif isinstance(payload.get("models"), list):
            items = payload["models"]
        else:
            items = []
    elif isinstance(payload, list):
        items = payload
    else:
        items = []

    ids: list[str] = []
    seen: set[str] = set()
    for item in items:
        if isinstance(item, str):
            mid = item.strip()
        elif isinstance(item, dict):
            mid = str(item.get("id") or item.get("name") or "").strip()
        else:
            continue
        if mid and mid not in seen:
            seen.add(mid)
            ids.append(mid)
    ids.sort(key=str.lower)
    return ids


def _provider_error(data: Any) -> str | None:
    if not isinstance(data, dict) or not data.get("error"):
        return None
    err = data["error"]
    if isinstance(err, dict):
        return _short_error(str(err.get("message") or err))
    return _short_error(str(err))


def _choice_text(data: dict[str, Any]) -> str:
    choices = data.get("choices")
    if not isinstance(choices, list) or not choices:
        return ""
    first = choices[0]
    if not isinstance(first, dict):
        return ""
    message = first.get("message") or {}
    content = message.get("content") if isinstance(message, dict) else None
    if isinstance(content, list):
        parts: list[str] = []
        for part in content:
            if isinstance(part, str):
                parts.append(part)
            elif isinstance(part, dict):
                parts.append(str(part.get("text") or part.get("content") or ""))
        content = "".join(parts)
    if content is None:
        content = first.get("text") or ""
    return _short_error(str(content).strip(), 200)


def list_models(body: LlmProbeIn) -> LlmModelListOut:
    base_url, api_key, _model, wire_api = resolve_probe_target(
        base_url=body.base_url,
        api_key=body.api_key,
        model=body.model,
        wire_api=body.wire_api,
    )
    url = base_url + "/models"
    started = time.perf_counter()
    try:
        with chat_http_client(timeout=_PROBE_TIMEOUT) as client:
            r = client.get(url, headers=_headers(api_key, wire_api))
    except Exception as e:  # noqa: BLE001
        return LlmModelListOut(ok=False, error=_transport_error(e))

    latency = int((time.perf_counter() - started) * 1000)
    if r.status_code >= 400:
        return LlmModelListOut(ok=False, latency_ms=latency, error=_http_error(r.status_code, r.text))
    try:
        data = r.json()
    except (ValueError, json.JSONDecodeError):
        return LlmModelListOut(ok=False, latency_ms=latency, error="响应不是 JSON，请确认 Base URL")
    err = _provider_error(data)
    if err:
        return LlmModelListOut(ok=False, latency_ms=latency, error=err)
    models = _extract_model_ids(data)
    if not models:
        return LlmModelListOut(
            ok=False,
            latency_ms=latency,
            error=(
                "未解析到模型列表，请确认该接口兼容 GET /models"
                + ("（Anthropic Messages）" if is_anthropic_wire(wire_api) else "（OpenAI）")
            ),
        )
    return LlmModelListOut(ok=True, models=models, count=len(models), latency_ms=latency)


def test_connectivity(body: LlmProbeIn) -> LlmTestOut:
    base_url, api_key, model, wire_api = resolve_probe_target(
        base_url=body.base_url,
        api_key=body.api_key,
        model=body.model,
        wire_api=body.wire_api,
    )
    if not model:
        return LlmTestOut(ok=False, error="请填写模型名")
    if not api_key:
        return LlmTestOut(ok=False, model=model, error="未配置 API Key")

    probe_messages = [{"role": "user", "content": "Reply with the single word pong."}]
    if is_anthropic_wire(wire_api):
        url = anthropic_url(base_url)
        payload = build_anthropic_body(model=model, messages=probe_messages, max_tokens=16)
        headers = _headers(api_key, wire_api)
    else:
        url = base_url + "/chat/completions"
        payload = {
            "model": model,
            "messages": probe_messages,
            "max_tokens": 16,
        }
        headers = _headers(api_key, wire_api)
    started = time.perf_counter()
    try:
        with chat_http_client(timeout=_PROBE_TIMEOUT) as client:
            r = client.post(url, headers=headers, json=payload)
    except Exception as e:  # noqa: BLE001
        return LlmTestOut(ok=False, model=model, error=_transport_error(e))

    latency = int((time.perf_counter() - started) * 1000)
    if r.status_code >= 400:
        return LlmTestOut(
            ok=False,
            model=model,
            latency_ms=latency,
            error=_http_error(r.status_code, r.text),
        )
    try:
        data = r.json()
    except (ValueError, json.JSONDecodeError):
        return LlmTestOut(ok=False, model=model, latency_ms=latency, error="响应不是 JSON")
    if not isinstance(data, dict):
        return LlmTestOut(ok=False, model=model, latency_ms=latency, error="响应格式无法识别")
    err = _provider_error(data)
    if err:
        return LlmTestOut(ok=False, model=model, latency_ms=latency, error=err)
    if is_anthropic_wire(wire_api) or data.get("type") == "message":
        data = anthropic_message_to_openai(data)
    reply = _choice_text(data)
    return LlmTestOut(ok=True, model=model, latency_ms=latency, reply=reply or None)

"""Per-model Chat Completions / Anthropic request tweaks.

Domestic and thinking models often lock sampling or reject extra OpenAI fields.
Profiles omit those fields up front; HTTP 400 still drops the cited parameter
and retries (same idea as AutoPoc's Chat gateway not forwarding unknown extras).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

_REASONING_KEYS = ("reasoning_content", "reasoning", "thinking")
_NEVER_DROP = frozenset({"model", "messages", "tools", "stream", "tool_choice"})
_DROP_ON_400 = (
    "temperature",
    "top_p",
    "n",
    "presence_penalty",
    "frequency_penalty",
    "stream_options",
    "reasoning_effort",
    "max_tokens",
    "max_completion_tokens",
    "parallel_tool_calls",
    "stop",
    "logit_bias",
    "tool_choice",
)

# Kimi K3 / K2.5+ lock sampling. temperature=0.2 → HTTP 400.
_KIMI_FIXED = re.compile(
    r"(?:^|[-./_])kimi-k(?:3|2\.(?:5|6|7))(?:[-.].*)?$",
    re.IGNORECASE,
)
_DEEPSEEK_REASONER = re.compile(
    r"(?:^|[-./_])(?:deepseek-reasoner|deepseek-r1)(?:[-.].*)?$",
    re.IGNORECASE,
)
_OPENAI_REASONING = re.compile(
    r"(?:^|[-./_])(?:o1|o3|o4-mini|gpt-5)(?:[-.].*)?$",
    re.IGNORECASE,
)
_CLAUDE_NO_TEMP = re.compile(
    r"(?:^|[-./_])claude-opus-4-[6-9](?:[-.].*)?$",
    re.IGNORECASE,
)
_GLM_THINKING = re.compile(
    r"(?:^|[-./_])glm-(?:4\.[5-9]|5)(?:[-.].*)?$",
    re.IGNORECASE,
)
_QWEN_THINKING = re.compile(
    r"(?:^|[-./_])(?:qwen3|qwq)(?:[-.].*)?$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ModelProfile:
    omit_temperature: bool = False
    preserve_reasoning: bool = False
    prefer_max_completion_tokens: bool = False


def model_slug(model: str | None) -> str:
    return (model or "").strip().split("/")[-1].strip()


def model_profile(model: str | None) -> ModelProfile:
    slug = model_slug(model)
    if not slug:
        return ModelProfile()
    if _KIMI_FIXED.search(slug):
        return ModelProfile(
            omit_temperature=True,
            preserve_reasoning=True,
            prefer_max_completion_tokens=True,
        )
    if _DEEPSEEK_REASONER.search(slug):
        return ModelProfile(omit_temperature=True, preserve_reasoning=True)
    if _OPENAI_REASONING.search(slug):
        return ModelProfile(omit_temperature=True, prefer_max_completion_tokens=True)
    if _CLAUDE_NO_TEMP.search(slug):
        return ModelProfile(omit_temperature=True)
    if _GLM_THINKING.search(slug) or _QWEN_THINKING.search(slug):
        return ModelProfile(preserve_reasoning=True)
    return ModelProfile()


def uses_fixed_sampling(model: str | None) -> bool:
    return model_profile(model).omit_temperature


def preserves_assistant_reasoning(model: str | None) -> bool:
    """Thinking models that need the full assistant message, including reasoning_content."""
    return model_profile(model).preserve_reasoning


def sampling_temperature(model: str | None, temperature: float | None) -> float | None:
    """Return temperature to send, or None to omit the field."""
    if temperature is None or model_profile(model).omit_temperature:
        return None
    return temperature


def apply_temperature(body: dict[str, Any], model: str | None, temperature: float | None) -> None:
    value = sampling_temperature(model, temperature)
    if value is None:
        body.pop("temperature", None)
    else:
        body["temperature"] = value


def prepare_chat_body(
    body: dict[str, Any],
    model: str | None,
    *,
    temperature: float | None = None,
) -> dict[str, Any]:
    """Apply per-model omissions / renames on a Chat Completions body."""
    profile = model_profile(model)
    if temperature is not None or profile.omit_temperature:
        apply_temperature(body, model, temperature)
    if profile.prefer_max_completion_tokens and "max_tokens" in body:
        body["max_completion_tokens"] = body.pop("max_tokens")
    return body


def param_to_drop(body: dict[str, Any], error_text: str | None) -> str | None:
    """Pick a request field to strip after HTTP 400, if the provider named it."""
    err = (error_text or "").lower()
    for key in _DROP_ON_400:
        if key in _NEVER_DROP:
            continue
        if key in body and key in err:
            return key
    if body.get("stream_options"):
        return "stream_options"
    return None


def strip_reasoning_fields(message: dict[str, Any]) -> dict[str, Any]:
    out = dict(message)
    for key in _REASONING_KEYS:
        out.pop(key, None)
    return out

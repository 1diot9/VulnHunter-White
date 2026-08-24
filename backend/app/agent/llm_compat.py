"""Per-model Chat Completions / Anthropic request tweaks."""

from __future__ import annotations

import re
from typing import Any

# Kimi K3 / K2.5+ lock sampling server-side. Passing temperature=0.2 (our default)
# returns HTTP 400: Parameter 'temperature'=0.2 is not supported.
_FIXED_SAMPLING = re.compile(
    r"(?:^|[-./_])kimi-k(?:3|2\.(?:5|6|7))(?:[-.].*)?$",
    re.IGNORECASE,
)
_REASONING_KEYS = ("reasoning_content", "reasoning", "thinking")


def model_slug(model: str | None) -> str:
    return (model or "").strip().split("/")[-1].strip()


def uses_fixed_sampling(model: str | None) -> bool:
    slug = model_slug(model)
    return bool(slug and _FIXED_SAMPLING.search(slug))


def sampling_temperature(model: str | None, temperature: float | None) -> float | None:
    """Return temperature to send, or None to omit the field."""
    if temperature is None or uses_fixed_sampling(model):
        return None
    return temperature


def apply_temperature(body: dict[str, Any], model: str | None, temperature: float | None) -> None:
    value = sampling_temperature(model, temperature)
    if value is None:
        body.pop("temperature", None)
    else:
        body["temperature"] = value


def preserves_assistant_reasoning(model: str | None) -> bool:
    """Kimi K2.5+ / K3 require the full assistant message, including reasoning_content."""
    return uses_fixed_sampling(model)


def strip_reasoning_fields(message: dict[str, Any]) -> dict[str, Any]:
    out = dict(message)
    for key in _REASONING_KEYS:
        out.pop(key, None)
    return out

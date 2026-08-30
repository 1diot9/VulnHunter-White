"""Per-vuln harness verification depth: sink / module / integration (L3)."""

from __future__ import annotations

from typing import Any

HARNESS_DEPTH_SINK = "sink"
HARNESS_DEPTH_MODULE = "module"
HARNESS_DEPTH_INTEGRATION = "integration"

HARNESS_DEPTH_LABELS: dict[str, str] = {
    HARNESS_DEPTH_SINK: "函数级",
    HARNESS_DEPTH_MODULE: "模块链",
    HARNESS_DEPTH_INTEGRATION: "集成",
}

ALLOWED_HARNESS_DEPTHS = frozenset(HARNESS_DEPTH_LABELS)

_HARNESS_DEPTH_ALIASES: dict[str, str] = {
    "sink": HARNESS_DEPTH_SINK,
    "function": HARNESS_DEPTH_SINK,
    "函数": HARNESS_DEPTH_SINK,
    "函数级": HARNESS_DEPTH_SINK,
    "module": HARNESS_DEPTH_MODULE,
    "chain": HARNESS_DEPTH_MODULE,
    "模块": HARNESS_DEPTH_MODULE,
    "模块链": HARNESS_DEPTH_MODULE,
    "integration": HARNESS_DEPTH_INTEGRATION,
    "integrate": HARNESS_DEPTH_INTEGRATION,
    "集成": HARNESS_DEPTH_INTEGRATION,
    "l3": HARNESS_DEPTH_INTEGRATION,
}

INTEGRATION_RUNTIME_SANDBOX = "sandbox"
INTEGRATION_RUNTIME_HOST_FALLBACK = "host_fallback"
ALLOWED_INTEGRATION_RUNTIMES = frozenset(
    {INTEGRATION_RUNTIME_SANDBOX, INTEGRATION_RUNTIME_HOST_FALLBACK}
)


def normalize_harness_depth(raw: Any, *, default: str = HARNESS_DEPTH_SINK) -> str:
    text = str(raw or "").strip()
    if not text:
        return default
    key = text.lower().replace("-", "_")
    compact = "".join(text.split())
    if key in ALLOWED_HARNESS_DEPTHS:
        return key
    found = (
        _HARNESS_DEPTH_ALIASES.get(key)
        or _HARNESS_DEPTH_ALIASES.get(text)
        or _HARNESS_DEPTH_ALIASES.get(compact)
        or _HARNESS_DEPTH_ALIASES.get(compact.lower())
    )
    return found if found in ALLOWED_HARNESS_DEPTHS else default


def parse_harness_depth(raw: Any) -> str:
    if raw is None or str(raw).strip() == "":
        return HARNESS_DEPTH_SINK
    found = normalize_harness_depth(raw, default="")
    if found not in ALLOWED_HARNESS_DEPTHS:
        allowed = "、".join(f"{k}（{v}）" for k, v in HARNESS_DEPTH_LABELS.items())
        raise ValueError(f"harness_depth 无效：{raw!r}。允许：{allowed}")
    return found


def harness_depth_label(depth: str | None) -> str | None:
    key = (depth or "").strip()
    if not key:
        return None
    return HARNESS_DEPTH_LABELS.get(key)


def is_integration_depth(depth: str | None) -> bool:
    return normalize_harness_depth(depth) == HARNESS_DEPTH_INTEGRATION

"""Project audit target kind: web app vs library/component vs mixed."""

from __future__ import annotations

from typing import Any

TARGET_KIND_WEB = "web"
TARGET_KIND_LIBRARY = "library"
TARGET_KIND_MIXED = "mixed"
DEFAULT_TARGET_KIND = TARGET_KIND_WEB
ALLOWED_TARGET_KINDS = frozenset(
    {TARGET_KIND_WEB, TARGET_KIND_LIBRARY, TARGET_KIND_MIXED}
)
TARGET_KIND_EDITABLE_STATUSES = frozenset({"paused", "completed"})

TARGET_KIND_LABELS: dict[str, str] = {
    TARGET_KIND_WEB: "Web 应用",
    TARGET_KIND_LIBRARY: "组件库",
    TARGET_KIND_MIXED: "混合",
}

_TARGET_KIND_ALIASES: dict[str, str] = {
    "web": TARGET_KIND_WEB,
    "app": TARGET_KIND_WEB,
    "application": TARGET_KIND_WEB,
    "webapp": TARGET_KIND_WEB,
    "web_app": TARGET_KIND_WEB,
    "web应用": TARGET_KIND_WEB,
    "web 应用": TARGET_KIND_WEB,
    "应用": TARGET_KIND_WEB,
    "library": TARGET_KIND_LIBRARY,
    "lib": TARGET_KIND_LIBRARY,
    "component": TARGET_KIND_LIBRARY,
    "组件": TARGET_KIND_LIBRARY,
    "组件库": TARGET_KIND_LIBRARY,
    "库": TARGET_KIND_LIBRARY,
    "mixed": TARGET_KIND_MIXED,
    "hybrid": TARGET_KIND_MIXED,
    "混合": TARGET_KIND_MIXED,
}

_INITIAL_HINTS: dict[str, str] = {
    TARGET_KIND_WEB: "按 Web 应用审计：HTTP/非 HTTP 入口为 source，正向或回推到 sink。",
    TARGET_KIND_LIBRARY: (
        "按组件库审计：公开 API / 解析器 / SPI 为调用方可控入口；"
        "划清信任边界；验证以 harness 为主；FOFA/站点指纹可省略。"
    ),
    TARGET_KIND_MIXED: (
        "混合仓：优先挖库核心（api/core/parser/codec）；"
        "demo/sample/examples/示例 Web 降权或薄扫；验证默认偏 harness。"
    ),
}


def normalize_target_kind(raw: Any, *, default: str = DEFAULT_TARGET_KIND) -> str:
    s = str(raw or "").strip()
    if not s:
        return default
    key = s.lower().replace("-", "_")
    compact = "".join(s.split())
    if key in ALLOWED_TARGET_KINDS:
        return key
    return (
        _TARGET_KIND_ALIASES.get(key)
        or _TARGET_KIND_ALIASES.get(s)
        or _TARGET_KIND_ALIASES.get(compact)
        or _TARGET_KIND_ALIASES.get(compact.lower())
        or default
    )


def try_parse_target_kind(raw: Any) -> str | None:
    """Return a valid kind or None. Does not fall back to the default."""
    if raw is None:
        return None
    s = str(raw).strip()
    if not s:
        return None
    key = s.lower().replace("-", "_")
    compact = "".join(s.split())
    if key in ALLOWED_TARGET_KINDS:
        return key
    found = (
        _TARGET_KIND_ALIASES.get(key)
        or _TARGET_KIND_ALIASES.get(s)
        or _TARGET_KIND_ALIASES.get(compact)
        or _TARGET_KIND_ALIASES.get(compact.lower())
    )
    return found if found in ALLOWED_TARGET_KINDS else None


def parse_target_kind(raw: Any) -> str:
    """Raise if the caller provided an invalid explicit kind."""
    if raw is None or str(raw).strip() == "":
        return DEFAULT_TARGET_KIND
    found = try_parse_target_kind(raw)
    if found in ALLOWED_TARGET_KINDS:
        return found
    allowed = "、".join(
        f"{k}（{TARGET_KIND_LABELS[k]}）"
        for k in (TARGET_KIND_WEB, TARGET_KIND_LIBRARY, TARGET_KIND_MIXED)
    )
    raise ValueError(f"审计对象无效，可选：{allowed}")


def target_kind_label(raw: Any) -> str:
    kind = normalize_target_kind(raw)
    return TARGET_KIND_LABELS.get(kind, TARGET_KIND_LABELS[DEFAULT_TARGET_KIND])


def initial_hint(raw: Any) -> str:
    kind = normalize_target_kind(raw)
    return _INITIAL_HINTS.get(kind, _INITIAL_HINTS[DEFAULT_TARGET_KIND])


def is_component_target(raw: Any) -> bool:
    """True for library or mixed (non-pure-web)."""
    return normalize_target_kind(raw) in {TARGET_KIND_LIBRARY, TARGET_KIND_MIXED}


def create_verify_defaults(raw: Any) -> dict[str, Any]:
    """Suggested verify settings when creating a project of this kind.

    Callers should only apply these when the client did not explicitly
    set dynamic_verify_mode / verifier_enabled.
    """
    if is_component_target(raw):
        return {"dynamic_verify_mode": "harness", "verifier_enabled": False}
    return {"dynamic_verify_mode": "off", "verifier_enabled": False}

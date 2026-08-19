"""Mining path flags: heuristic file-based Worker, fast sink scan, historical-vuln bypass."""

from __future__ import annotations

from typing import Any

MINING_PATH_EDITABLE_STATUSES = frozenset({"paused", "completed"})

# Per-vuln origin (SubmitVuln); orthogonal to project enable flags.
MINING_PATH_HEURISTIC = "heuristic"
MINING_PATH_FAST = "fast"
MINING_PATH_BYPASS = "bypass"
ALLOWED_MINING_PATHS = frozenset(
    {MINING_PATH_HEURISTIC, MINING_PATH_FAST, MINING_PATH_BYPASS}
)
MINING_PATH_LABELS = {
    MINING_PATH_HEURISTIC: "启发式挖掘",
    MINING_PATH_FAST: "快速扫描",
    MINING_PATH_BYPASS: "历史漏洞绕过",
}
_ROLE_TO_MINING_PATH = {
    "worker": MINING_PATH_HEURISTIC,
    "fast_worker": MINING_PATH_FAST,
    "bypass_worker": MINING_PATH_BYPASS,
}

# Lite heuristic only injects weight-100 user-controlled entries
# (HTTP and non-HTTP: WebSocket / RPC / MQ / callbacks).
HEURISTIC_LITE_WEIGHT = 100


class MiningPathError(ValueError):
    """Invalid mining-path combination."""


def normalize_mining_path(raw: Any) -> str | None:
    if raw is None:
        return None
    s = str(raw).strip().lower()
    return s if s in ALLOWED_MINING_PATHS else None


def mining_path_from_role(role: str | None) -> str | None:
    return _ROLE_TO_MINING_PATH.get((role or "").strip().lower())


def mining_path_display(raw: Any) -> str | None:
    key = normalize_mining_path(raw)
    return MINING_PATH_LABELS.get(key) if key else None


def normalize_flag(raw: Any, *, default: bool) -> bool:
    if raw is None:
        return default
    if isinstance(raw, bool):
        return raw
    s = str(raw).strip().lower()
    if s in {"1", "true", "yes", "on"}:
        return True
    if s in {"0", "false", "no", "off"}:
        return False
    return default


def parse_mining_paths(
    *,
    heuristic_enabled: Any = None,
    fast_enabled: Any = None,
    bypass_enabled: Any = None,
    default_heuristic: bool = True,
    default_fast: bool = False,
    default_bypass: bool = False,
) -> tuple[bool, bool, bool]:
    heuristic = normalize_flag(heuristic_enabled, default=default_heuristic)
    fast = normalize_flag(fast_enabled, default=default_fast)
    bypass = normalize_flag(bypass_enabled, default=default_bypass)
    if not heuristic and not fast and not bypass:
        raise MiningPathError("请至少开启启发式挖掘、快速扫描或历史漏洞绕过其中一条路径")
    return heuristic, fast, bypass


def parse_heuristic_lite(raw: Any = None, *, default: bool = False) -> bool:
    return normalize_flag(raw, default=default)


def heuristic_lite_active(*, heuristic_enabled: bool, heuristic_lite: bool) -> bool:
    return bool(heuristic_enabled) and bool(heuristic_lite)


def mining_path_label(
    *,
    heuristic_enabled: bool,
    fast_enabled: bool,
    bypass_enabled: bool = False,
    heuristic_lite: bool = False,
) -> str:
    parts: list[str] = []
    if heuristic_enabled:
        parts.append("启发式轻量" if heuristic_lite else "启发式挖掘")
    if fast_enabled:
        parts.append("快速扫描")
    if bypass_enabled:
        parts.append("历史漏洞绕过")
    return " + ".join(parts) or "启发式挖掘"

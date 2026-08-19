"""Project dynamic-verify mode: off / lab (Docker target) / harness (local sandbox)."""

from __future__ import annotations

from typing import Any

VERIFY_MODE_OFF = "off"
VERIFY_MODE_LAB = "lab"
VERIFY_MODE_HARNESS = "harness"
DEFAULT_VERIFY_MODE = VERIFY_MODE_OFF
ALLOWED_VERIFY_MODES = frozenset({VERIFY_MODE_OFF, VERIFY_MODE_LAB, VERIFY_MODE_HARNESS})

VERIFY_MODE_LABELS: dict[str, str] = {
    VERIFY_MODE_OFF: "关闭",
    VERIFY_MODE_LAB: "靶场动态",
    VERIFY_MODE_HARNESS: "局部验证",
}

_VERIFY_MODE_ALIASES: dict[str, str] = {
    "off": VERIFY_MODE_OFF,
    "none": VERIFY_MODE_OFF,
    "static": VERIFY_MODE_OFF,
    "关闭": VERIFY_MODE_OFF,
    "仅静态": VERIFY_MODE_OFF,
    "lab": VERIFY_MODE_LAB,
    "docker": VERIFY_MODE_LAB,
    "dynamic": VERIFY_MODE_LAB,
    "靶场": VERIFY_MODE_LAB,
    "靶场动态": VERIFY_MODE_LAB,
    "动态验证": VERIFY_MODE_LAB,
    "harness": VERIFY_MODE_HARNESS,
    "sandbox": VERIFY_MODE_HARNESS,
    "local": VERIFY_MODE_HARNESS,
    "局部": VERIFY_MODE_HARNESS,
    "局部验证": VERIFY_MODE_HARNESS,
}

EVIDENCE_STATIC = "static_only"
EVIDENCE_DYNAMIC = "dynamic"
EVIDENCE_MCP = "mcp"
EVIDENCE_HARNESS = "harness"
ALLOWED_EVIDENCE_LEVELS = frozenset(
    {EVIDENCE_STATIC, EVIDENCE_DYNAMIC, EVIDENCE_MCP, EVIDENCE_HARNESS}
)

_EVIDENCE_ALIASES: dict[str, str] = {
    "static_only": EVIDENCE_STATIC,
    "static": EVIDENCE_STATIC,
    "仅静态": EVIDENCE_STATIC,
    "dynamic": EVIDENCE_DYNAMIC,
    "mcp": EVIDENCE_MCP,
    "harness": EVIDENCE_HARNESS,
    "局部验证": EVIDENCE_HARNESS,
    "局部": EVIDENCE_HARNESS,
}


def normalize_verify_mode(raw: Any, *, default: str = DEFAULT_VERIFY_MODE) -> str:
    s = str(raw or "").strip()
    if not s:
        return default
    key = s.lower().replace("-", "_")
    compact = "".join(s.split())
    if key in ALLOWED_VERIFY_MODES:
        return key
    return (
        _VERIFY_MODE_ALIASES.get(key)
        or _VERIFY_MODE_ALIASES.get(s)
        or _VERIFY_MODE_ALIASES.get(compact)
        or _VERIFY_MODE_ALIASES.get(compact.lower())
        or default
    )


def parse_verify_mode(raw: Any) -> str:
    if raw is None or str(raw).strip() == "":
        return DEFAULT_VERIFY_MODE
    found = normalize_verify_mode(raw, default="")
    if found not in ALLOWED_VERIFY_MODES:
        allowed = "、".join(f"{k}（{VERIFY_MODE_LABELS[k]}）" for k in (VERIFY_MODE_OFF, VERIFY_MODE_LAB, VERIFY_MODE_HARNESS))
        raise ValueError(f"dynamic_verify_mode 无效，可选: {allowed}")
    return found


def resolve_verify_mode(
    *,
    mode: Any = None,
    enabled: Any = None,
    current_mode: Any = None,
    current_enabled: Any = None,
    manual_lab: Any = None,
    manual_lab_prompt: Any = None,
) -> str:
    """Prefer explicit mode; map the legacy boolean; keep current harness/lab when only re-enabling.

    Creating with only ``manual_lab`` / prompt (old API) and no verify fields implies 靶场动态.
    """
    explicit_mode = mode is not None and str(mode).strip() != ""
    if explicit_mode:
        chosen = parse_verify_mode(mode)
    else:
        cur = project_verify_mode_values(current_mode, current_enabled)
        if enabled is None:
            chosen = cur
        elif bool(enabled):
            chosen = cur if cur != VERIFY_MODE_OFF else VERIFY_MODE_LAB
        else:
            chosen = VERIFY_MODE_OFF
    wants_manual = bool(manual_lab) or bool(str(manual_lab_prompt or "").strip())
    # Create schema defaults enabled=False when omitted; treat that plus manual_lab as 靶场动态.
    if wants_manual and chosen == VERIFY_MODE_OFF and not explicit_mode:
        return VERIFY_MODE_LAB
    return chosen


def project_verify_mode_values(mode: Any, enabled: Any) -> str:
    """Derive mode from stored columns. Legacy rows may only have the boolean set."""
    normalized = normalize_verify_mode(mode, default=VERIFY_MODE_OFF)
    if normalized != VERIFY_MODE_OFF:
        return normalized
    if bool(enabled):
        return VERIFY_MODE_LAB
    return VERIFY_MODE_OFF


def project_verify_mode(proj: Any) -> str:
    if proj is None:
        return VERIFY_MODE_OFF
    return project_verify_mode_values(
        getattr(proj, "dynamic_verify_mode", None),
        getattr(proj, "dynamic_verify_enabled", False),
    )


def verify_mode_enabled(mode: str) -> bool:
    return normalize_verify_mode(mode) != VERIFY_MODE_OFF


def is_lab_mode(mode: str) -> bool:
    return normalize_verify_mode(mode) == VERIFY_MODE_LAB


def is_harness_mode(mode: str) -> bool:
    return normalize_verify_mode(mode) == VERIFY_MODE_HARNESS


def verify_mode_label(mode: str) -> str:
    return VERIFY_MODE_LABELS.get(normalize_verify_mode(mode), VERIFY_MODE_LABELS[DEFAULT_VERIFY_MODE])


def apply_verify_mode(proj: Any, mode: str) -> str:
    normalized = normalize_verify_mode(mode)
    proj.dynamic_verify_mode = normalized
    proj.dynamic_verify_enabled = normalized != VERIFY_MODE_OFF
    return normalized


def project_is_harness(project_id: int) -> bool:
    from .models import Project, SessionLocal

    with SessionLocal() as db:
        proj = db.get(Project, int(project_id))
        return is_harness_mode(project_verify_mode(proj))


def normalize_evidence_level(raw: Any) -> str | None:
    s = str(raw or "").strip()
    if not s:
        return None
    key = s.lower().replace("-", "_")
    compact = "".join(s.split())
    if key in ALLOWED_EVIDENCE_LEVELS:
        return key
    found = (
        _EVIDENCE_ALIASES.get(key)
        or _EVIDENCE_ALIASES.get(s)
        or _EVIDENCE_ALIASES.get(compact)
        or _EVIDENCE_ALIASES.get(compact.lower())
    )
    return found if found in ALLOWED_EVIDENCE_LEVELS else None


def coerce_evidence_level(raw: Any, *, mode: str) -> str:
    """Map requested evidence onto the project's verify mode."""
    normalized_mode = normalize_verify_mode(mode)
    evidence = normalize_evidence_level(raw)
    if not evidence:
        if normalized_mode == VERIFY_MODE_LAB:
            return EVIDENCE_DYNAMIC
        if normalized_mode == VERIFY_MODE_HARNESS:
            return EVIDENCE_HARNESS
        return EVIDENCE_STATIC
    if normalized_mode == VERIFY_MODE_OFF and evidence != EVIDENCE_STATIC:
        return EVIDENCE_STATIC
    if normalized_mode == VERIFY_MODE_LAB and evidence == EVIDENCE_HARNESS:
        return EVIDENCE_STATIC
    if normalized_mode == VERIFY_MODE_HARNESS and evidence in (EVIDENCE_DYNAMIC, EVIDENCE_MCP):
        return EVIDENCE_STATIC
    return evidence


def default_evidence_for_mode(mode: str) -> str:
    return coerce_evidence_level(None, mode=mode)

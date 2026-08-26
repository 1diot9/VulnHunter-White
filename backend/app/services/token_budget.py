"""Per-project LLM token budget: input + output, pause when the cap is reached."""

from __future__ import annotations

from typing import Any

from sqlalchemy import func

from ..models import Project, SessionLocal, TokenUsage

# 0 = unlimited. Upper bound keeps JSON / Form values in a sane integer range.
MAX_TOKEN_USAGE_CAP = 1_000_000_000_000


def parse_max_token_usage(raw: Any, *, default: int = 0) -> int:
    """Non-negative integer; 0 means unlimited. Empty / None uses default."""
    if raw is None:
        return default
    if isinstance(raw, bool):
        raise ValueError("max_token_usage 必须是非负整数，0 表示不限制")
    if isinstance(raw, str):
        text = raw.strip()
        if not text:
            return default
        if text.startswith("+"):
            text = text[1:]
        if not text.isdigit():
            raise ValueError("max_token_usage 必须是非负整数，0 表示不限制")
        n = int(text)
    elif isinstance(raw, int):
        n = raw
    elif isinstance(raw, float) and raw.is_integer():
        n = int(raw)
    else:
        raise ValueError("max_token_usage 必须是非负整数，0 表示不限制")
    if n < 0:
        raise ValueError("max_token_usage 不能为负数")
    if n > MAX_TOKEN_USAGE_CAP:
        raise ValueError(f"max_token_usage 过大，最多 {MAX_TOKEN_USAGE_CAP}")
    return n


def project_token_spend(db, project_id: int) -> int:
    """Sum of billed input + output tokens for a project (cached is already in input)."""
    row = (
        db.query(
            func.coalesce(func.sum(TokenUsage.tokens_input), 0),
            func.coalesce(func.sum(TokenUsage.tokens_output), 0),
        )
        .filter(TokenUsage.project_id == project_id)
        .one()
    )
    return int(row[0] or 0) + int(row[1] or 0)


def token_budget_status(project_id: int) -> tuple[bool, int, int]:
    """Return (over_budget, used_input_plus_output, limit). limit=0 means unlimited."""
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        limit = int(getattr(proj, "max_token_usage", 0) or 0) if proj else 0
        used = project_token_spend(db, project_id)
    over = bool(limit > 0 and used >= limit)
    return over, used, limit


def token_budget_block_reason(project_id: int) -> str | None:
    """Human-readable reason if resume / new LLM work should be refused."""
    over, used, limit = token_budget_status(project_id)
    if not over:
        return None
    return (
        f"已达到 Token 上限（已用 {used} / 上限 {limit}，输入+输出），"
        "请在项目配置中提高上限后再续跑"
    )


def maybe_pause_for_token_budget(project_id: int) -> bool:
    """Pause the whole project when spend hits the cap. Idempotent if already paused."""
    over, used, limit = token_budget_status(project_id)
    if not over:
        return False
    from .pipeline import get_phase_states, request_pause

    if get_phase_states(project_id).get("project_paused"):
        return True
    request_pause(
        project_id,
        reason=(
            f"已达到 Token 上限（已用 {used} / 上限 {limit}，输入+输出），已自动暂停"
        ),
    )
    return bool(get_phase_states(project_id).get("project_paused"))

"""Soft duplicate reminders for SubmitVuln / ConfirmVuln (no hard block).

First call with a suspected sibling returns a reminder. A later call may pass
``confirm_not_duplicate=true``, but only after that same session already saw the
reminder for the same fingerprint.
"""

from __future__ import annotations

from typing import Any

from .root_cause import canonical_root_cause_key

# Live reports that count as merge / dedup candidates
_LIVE_STATUSES = frozenset({"pending_review", "confirmed", "static_only", "returned"})

_STATE_KEY = "duplicate_soft_warned"
_PARAM = "confirm_not_duplicate"


def _file_norm(path: str | None) -> str:
    return (path or "").replace("\\", "/").strip().lower()


def _truthy(raw: Any) -> bool:
    if isinstance(raw, bool):
        return raw
    if raw is None:
        return False
    text = str(raw).strip().lower()
    return text in {"1", "true", "yes", "y", "on"}


def fingerprint(
    *,
    tool: str,
    file_path: str | None,
    vuln_type: str | None,
    root_cause_key: str | None,
    exclude_vuln_id: int | None = None,
) -> str:
    """Stable key for session-scoped soft-ack tracking."""
    parts = [
        tool,
        _file_norm(file_path),
        (vuln_type or "").strip().lower(),
        canonical_root_cause_key(root_cause_key),
        str(exclude_vuln_id or 0),
    ]
    return "|".join(parts)


def _candidate_public(row: Any) -> dict[str, Any]:
    return {
        "vuln_id": int(row.id),
        "title": row.title,
        "status": row.status,
        "vuln_type": row.vuln_type,
        "file_path": row.file_path,
        "line_no": row.line_no,
        "root_cause_key": row.root_cause_key,
        "submission_tier": getattr(row, "submission_tier", None),
        "merged_into_id": getattr(row, "merged_into_id", None),
    }


def find_suspected_duplicates(
    db: Any,
    *,
    project_id: int,
    file_path: str | None,
    vuln_type: str | None,
    root_cause_key: str | None,
    exclude_vuln_id: int | None = None,
) -> list[dict[str, Any]]:
    """Same file+type or same normalized root_cause_key among live reports."""
    from ..models import Vuln

    path = _file_norm(file_path)
    vtype = (vuln_type or "").strip().lower()
    key = canonical_root_cause_key(root_cause_key)
    if not path and not key:
        return []

    q = db.query(Vuln).filter(Vuln.project_id == project_id, Vuln.status.in_(tuple(_LIVE_STATUSES)))
    if exclude_vuln_id is not None:
        q = q.filter(Vuln.id != int(exclude_vuln_id))
    rows = q.order_by(Vuln.id.asc()).all()

    out: list[dict[str, Any]] = []
    seen: set[int] = set()
    for row in rows:
        same_file_type = bool(
            path and vtype and _file_norm(row.file_path) == path and (row.vuln_type or "").strip().lower() == vtype
        )
        same_key = bool(key and canonical_root_cause_key(row.root_cause_key) == key)
        if not (same_file_type or same_key):
            continue
        if int(row.id) in seen:
            continue
        seen.add(int(row.id))
        item = _candidate_public(row)
        reasons: list[str] = []
        if same_file_type:
            reasons.append("same_file_type")
        if same_key:
            reasons.append("same_root_cause_key")
        item["match_reasons"] = reasons
        out.append(item)
    return out


def soft_duplicate_gate(
    ctx: Any,
    args: dict[str, Any],
    *,
    tool: str,
    file_path: str | None,
    vuln_type: str | None,
    root_cause_key: str | None,
    exclude_vuln_id: int | None = None,
    action_hint: str,
) -> dict[str, Any] | None:
    """Return an error payload if the call should be soft-blocked; else None."""
    from ..models import SessionLocal

    with SessionLocal() as db:
        candidates = find_suspected_duplicates(
            db,
            project_id=ctx.project_id,
            file_path=file_path,
            vuln_type=vuln_type,
            root_cause_key=root_cause_key,
            exclude_vuln_id=exclude_vuln_id,
        )
    if not candidates:
        return None

    token = fingerprint(
        tool=tool,
        file_path=file_path,
        vuln_type=vuln_type,
        root_cause_key=root_cause_key,
        exclude_vuln_id=exclude_vuln_id,
    )
    warned: dict[str, Any] = ctx.state.setdefault(_STATE_KEY, {})
    want_confirm = _truthy(args.get(_PARAM))

    if want_confirm and not warned.get(token):
        return {
            "ok": False,
            "error": (
                f"{_PARAM}=true 仅在本会话已因疑似重复被提醒过一次后才可传入；"
                "请先不带该参数调用一次，按返回的 candidates 复查 SearchOldVuln / MergeIntoVuln，"
                "确认仍要继续后再带上。"
            ),
            "need_confirm_not_duplicate": True,
            "confirm_param": _PARAM,
            "candidates": candidates,
            "duplicate_soft_gate": True,
        }

    if want_confirm and warned.get(token):
        # One-shot ack: clear so a later identical submit needs a fresh reminder.
        warned.pop(token, None)
        return None

    warned[token] = True
    ids = ", ".join(f"#{c['vuln_id']}" for c in candidates[:8])
    return {
        "ok": False,
        "error": (
            f"疑似与已有漏洞重复（{ids}）：同 file_path+vuln_type 或同 root_cause_key。"
            f"请 SearchOldVuln 复查，优先{action_hint}。"
            f"若确认危害/鉴权不同、确需单独提交，再次调用并传 {_PARAM}=true。"
        ),
        "need_confirm_not_duplicate": True,
        "confirm_param": _PARAM,
        "candidates": candidates,
        "duplicate_soft_gate": True,
        "hint": (
            "不要在未复查时直接带确认参数；确认参数只对「本会话已提醒过的同一指纹」生效。"
        ),
    }

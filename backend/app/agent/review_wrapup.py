"""Reviewer wrap-up grace: extend wall-clock once when verified and finishing docs."""

from __future__ import annotations

import re
from typing import Any

# How many recent tool dispatches to inspect for wrap-up (TodoWrite ignored).
RECENT_WINDOW = 3

# Seconds of remaining budget at/below which we may grant grace (also when <= 0).
GRACE_REMAINING_THRESHOLD = 120.0

WRAPUP_TOOL_NAMES = frozenset(
    {
        "Write",
        "Read",
        "ReadCveRecord",
        "SetCveRecordField",
        "ConfirmVuln",
    }
)

# At least one of these (or Write under vulns/) must appear in the recent window.
DOC_WRITE_TOOLS = frozenset({"Write", "SetCveRecordField"})

IGNORE_TOOLS = frozenset({"TodoWrite"})

# ConfirmVuln rejected because packaging/docs are incomplete — still counts as verified.
_CONFIRM_DOC_GATE_HINTS = (
    "漏洞代码",
    "Write 报告后再 Confirm",
    "advisory",
    "Vulnerable code",
    "harness_output",
    "harness 输出",
    "禁止写死",
    "须含",
    "缺段",
)

_POC_PY_RE = re.compile(r"(?:^|[/\\\s])poc\.py\b", re.IGNORECASE)
_VULN_PATH_RE = re.compile(r"(?:^|[/\\])vulns[/\\](\d+)[/\\]", re.IGNORECASE)


def _norm_path(path: Any) -> str:
    return str(path or "").replace("\\", "/").lstrip("./")


def path_under_vuln(path: Any, vuln_id: int | None) -> bool:
    """True when path is under vulns/{id}/ (or any vulns/N/ if vuln_id is None)."""
    text = _norm_path(path)
    if not text:
        return False
    m = _VULN_PATH_RE.search(text)
    if not m:
        # Also accept relative forms like vulns/12/report.md at start
        m = re.match(r"vulns/(\d+)/", text, re.IGNORECASE)
    if not m:
        return False
    if vuln_id is None:
        return True
    try:
        return int(m.group(1)) == int(vuln_id)
    except (TypeError, ValueError):
        return False


def _command_runs_poc(command: Any) -> bool:
    return bool(_POC_PY_RE.search(str(command or "")))


def _confirm_doc_gate_rejection(result: dict[str, Any] | None) -> bool:
    if not isinstance(result, dict) or result.get("ok") is not False:
        return False
    err = str(result.get("error") or "")
    if not err:
        return False
    lower = err.lower()
    for hint in _CONFIRM_DOC_GATE_HINTS:
        if hint.lower() in lower or hint in err:
            return True
    return False


def _paths_from_args(args: dict[str, Any] | None) -> list[str]:
    if not isinstance(args, dict):
        return []
    out: list[str] = []
    raw = args.get("path")
    if raw not in (None, ""):
        out.append(str(raw))
    paths = args.get("paths")
    if isinstance(paths, list):
        out.extend(str(p) for p in paths if p not in (None, ""))
    elif paths not in (None, ""):
        out.append(str(paths))
    return out


def is_wrapup_tool(
    name: str,
    args: dict[str, Any] | None,
    *,
    vuln_id: int | None,
) -> bool:
    """Whether a successful tool call counts as wrap-up activity."""
    tool = str(name or "").strip()
    if tool in IGNORE_TOOLS:
        return False
    if tool in ("ReadCveRecord", "SetCveRecordField", "ConfirmVuln"):
        return True
    if tool in ("Read", "Write"):
        paths = _paths_from_args(args)
        if not paths:
            return False
        return all(path_under_vuln(p, vuln_id) for p in paths)
    return False


def is_doc_write_tool(
    name: str,
    args: dict[str, Any] | None,
    *,
    vuln_id: int | None,
) -> bool:
    tool = str(name or "").strip()
    if tool == "SetCveRecordField":
        return True
    if tool == "Write":
        paths = _paths_from_args(args)
        return bool(paths) and all(path_under_vuln(p, vuln_id) for p in paths)
    return False


def ensure_wrapup_state(state: dict[str, Any]) -> dict[str, Any]:
    """Normalize wrap-up tracking keys on agent state (mutates and returns)."""
    state.setdefault("review_verified", False)
    state.setdefault("review_wrote_docs", False)
    state.setdefault("review_wrapup_grace_used", False)
    recent = state.get("review_recent_tools")
    if not isinstance(recent, list):
        state["review_recent_tools"] = []
    return state


def note_tool_for_wrapup(
    state: dict[str, Any],
    *,
    name: str,
    arguments: dict[str, Any] | None,
    result: dict[str, Any] | None,
    vuln_id: int | None,
) -> None:
    """Update wrap-up tracking after a reviewer tool dispatch."""
    ensure_wrapup_state(state)
    tool = str(name or "").strip()
    if not tool or tool in IGNORE_TOOLS:
        return

    args = arguments if isinstance(arguments, dict) else {}
    res = result if isinstance(result, dict) else {}
    ok = bool(res.get("ok"))

    if tool == "RunCode" and ok:
        state["review_verified"] = True
    elif tool in ("Bash", "PowerShell") and ok and _command_runs_poc(args.get("command")):
        state["review_verified"] = True
    elif tool == "ConfirmVuln" and _confirm_doc_gate_rejection(res):
        state["review_verified"] = True

    if ok and is_doc_write_tool(tool, args, vuln_id=vuln_id):
        state["review_wrote_docs"] = True

    # Track successful dispatches for recent-window checks.
    # ConfirmVuln doc-gate failures still count as wrap-up activity.
    track = False
    if ok:
        track = True
    elif tool == "ConfirmVuln" and _confirm_doc_gate_rejection(res):
        track = True
    if not track:
        return

    entry = {
        "name": tool,
        "wrapup": is_wrapup_tool(tool, args, vuln_id=vuln_id),
        "doc_write": is_doc_write_tool(tool, args, vuln_id=vuln_id),
    }
    recent: list[dict[str, Any]] = list(state.get("review_recent_tools") or [])
    recent.append(entry)
    # Keep a little extra history beyond the window for debugging/resume.
    state["review_recent_tools"] = recent[-12:]


def recent_tools_are_wrapup(state: dict[str, Any], *, window: int = RECENT_WINDOW) -> bool:
    """True when the last ``window`` tracked tools are all wrap-up and include a doc write."""
    ensure_wrapup_state(state)
    recent: list[dict[str, Any]] = list(state.get("review_recent_tools") or [])
    if len(recent) < window:
        # Fewer than window: require all of them wrap-up + at least one doc write.
        if not recent:
            return False
        slice_ = recent
    else:
        slice_ = recent[-window:]
    if not all(bool(e.get("wrapup")) for e in slice_):
        return False
    if not any(bool(e.get("doc_write")) for e in slice_):
        return False
    return True


def should_grant_wrapup_grace(
    state: dict[str, Any],
    *,
    phase: str,
    remaining: float,
    threshold: float = GRACE_REMAINING_THRESHOLD,
) -> bool:
    """Whether the reviewer loop should extend the deadline once."""
    if str(phase or "") != "reviewer":
        return False
    ensure_wrapup_state(state)
    if state.get("review_wrapup_grace_used"):
        return False
    if float(remaining) > float(threshold):
        return False
    if not recent_tools_are_wrapup(state):
        return False
    # Verified (harness/poc/confirm-doc-gate) OR static wrap-up (wrote docs this round).
    if state.get("review_verified"):
        return True
    if state.get("review_wrote_docs"):
        return True
    return False


def wrapup_grace_nudge(*, verified: bool, grace_sec: int) -> str:
    if verified:
        lead = (
            "系统判定：本条漏洞已验证成功（或已走到 Confirm 文档闸门），"
            "当前处于报告/CVE/Confirm 收尾阶段。"
        )
    else:
        lead = (
            "系统判定：本条审核已进入报告/CVE/Confirm 收尾阶段（本轮已改过漏洞文档）。"
        )
    return (
        f"{lead}"
        f"已为本轮追加一次收尾宽限（{int(grace_sec)} 秒），用尽后仍会超时。"
        "请立刻停止继续打磨文案；未知 CVE 字段用占位符即可。"
        "马上调用 ConfirmVuln（或 MarkFalsePositive）完成本条审核。"
    )


def mark_grace_used(state: dict[str, Any]) -> None:
    ensure_wrapup_state(state)
    state["review_wrapup_grace_used"] = True

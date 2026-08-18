"""Bypass-path tool: FinishBypass."""

from __future__ import annotations

from typing import Any

from ..agent.compression import strip_followup_section
from ..models import BypassTarget, SessionLocal
from ..services.bypass_queue import parse_bypass_ref
from . import ToolSpec, registry
from .sandbox import assert_writable

BYPASS_VERDICTS = frozenset(
    {"bypass_submitted", "still_patched", "unreachable", "incomplete", "intended"}
)


def _injected_bypass_id(ctx) -> int | None:
    raw = getattr(ctx, "file_path", None) or (ctx.state or {}).get("injected_bypass")
    parsed = parse_bypass_ref(str(raw) if raw else "")
    if parsed:
        return parsed
    try:
        return int((ctx.state or {}).get("bypass_id") or 0) or None
    except (TypeError, ValueError):
        return None


def _finish_bypass(ctx, args: dict[str, Any]) -> dict[str, Any]:
    injected = _injected_bypass_id(ctx)
    try:
        bypass_id = int(args.get("bypass_id") or injected or 0)
    except (TypeError, ValueError):
        bypass_id = 0
    if not bypass_id:
        return {"ok": False, "error": "缺少 bypass_id"}
    if injected and bypass_id != injected:
        return {"ok": False, "error": f"只能 FinishBypass 本轮注入的历史漏洞 {injected}"}
    verdict = str(args.get("verdict") or "").strip().lower()
    if verdict not in BYPASS_VERDICTS:
        return {"ok": False, "error": f"verdict 无效，可选: {', '.join(sorted(BYPASS_VERDICTS))}"}
    vuln_id = args.get("vuln_id")
    if verdict == "bypass_submitted":
        submitted = ctx.state.get("submitted_vulns") or []
        if vuln_id in (None, ""):
            if submitted:
                vuln_id = submitted[-1]
            else:
                return {"ok": False, "error": "verdict=bypass_submitted 时必须提供 vuln_id"}
        try:
            vuln_id = int(vuln_id)
        except (TypeError, ValueError):
            return {"ok": False, "error": "vuln_id 必须是整数"}
    else:
        vuln_id = None
    with SessionLocal() as db:
        row = db.get(BypassTarget, bypass_id)
        if not row or row.project_id != ctx.project_id:
            return {"ok": False, "error": "绕过目标不存在"}
        row.status = "done"
        row.verdict = verdict
        row.claimed_by = None
        row.claimed_at = None
        row.vuln_id = vuln_id
        row.agent_reason = str(args.get("reason") or args.get("report") or "")[:2000] or row.agent_reason
        db.commit()
    report = args.get("report") or args.get("summary") or args.get("reason") or ""
    if report:
        round_id = int((ctx.state or {}).get("round_id") or 0)
        path = assert_writable(ctx.project_id, f"workspace/rounds/bypass-round-{round_id}.md")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(strip_followup_section(str(report)), encoding="utf-8")
    ctx.state["bypass_finished"] = True
    ctx.state["round_finished"] = True
    return {"ok": True, "bypass_id": bypass_id, "verdict": verdict, "message": "本轮历史漏洞绕过已结束"}


def register_bypass_tools() -> None:
    registry.register(
        ToolSpec(
            name="FinishBypass",
            description=(
                "结束本轮注入的历史漏洞绕过。必填 verdict："
                "bypass_submitted / still_patched / unreachable / incomplete / intended。"
                "提交了漏洞则带 vuln_id。调用后本轮结束。"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "bypass_id": {"type": "integer"},
                    "verdict": {"type": "string"},
                    "vuln_id": {"type": "integer"},
                    "reason": {"type": "string"},
                    "report": {"type": "string"},
                },
                "required": ["verdict"],
            },
            handler=_finish_bypass,
        )
    )


register_bypass_tools()

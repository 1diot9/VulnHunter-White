"""Fast-scan tools: FinishSinkTriage and FinishSink."""

from __future__ import annotations

from typing import Any

from ..agent.compression import strip_followup_section
from ..models import SessionLocal, Sink
from ..services.sink_queue import apply_triage_decisions, parse_sink_ref
from . import ToolSpec, registry
from .sandbox import assert_writable

SINK_VERDICTS = frozenset({"vuln_submitted", "unreachable", "sanitized", "intended", "noise"})


def _injected_sink_id(ctx) -> int | None:
    raw = getattr(ctx, "file_path", None) or (ctx.state or {}).get("injected_sink")
    parsed = parse_sink_ref(str(raw) if raw else "")
    if parsed:
        return parsed
    try:
        return int((ctx.state or {}).get("sink_id") or 0) or None
    except (TypeError, ValueError):
        return None


def _finish_sink_triage(ctx, args: dict[str, Any]) -> dict[str, Any]:
    decisions = args.get("decisions") or args.get("items") or []
    if not isinstance(decisions, list) or not decisions:
        return {"ok": False, "error": "FinishSinkTriage 需要 decisions 列表"}
    stats = apply_triage_decisions(ctx.project_id, decisions)
    expected = ctx.state.get("triage_batch_ids") or []
    decided = {int(item.get("id") or item.get("sink_id") or 0) for item in decisions if isinstance(item, dict)}
    missing = [sid for sid in expected if int(sid) not in decided]
    if missing:
        return {
            "ok": False,
            "error": f"本批仍有未决策的 Sink: {missing[:8]}",
            **stats,
        }
    ctx.state["triage_batch_finished"] = True
    return {"ok": True, "message": "本批筛选已记录", **stats}


def _finish_sink(ctx, args: dict[str, Any]) -> dict[str, Any]:
    injected = _injected_sink_id(ctx)
    try:
        sink_id = int(args.get("sink_id") or injected or 0)
    except (TypeError, ValueError):
        sink_id = 0
    if not sink_id:
        return {"ok": False, "error": "缺少 sink_id"}
    if injected and sink_id != injected:
        return {"ok": False, "error": f"只能 FinishSink 本轮注入的 Sink {injected}"}
    verdict = str(args.get("verdict") or "").strip().lower()
    if verdict not in SINK_VERDICTS:
        return {"ok": False, "error": f"verdict 无效，可选: {', '.join(sorted(SINK_VERDICTS))}"}
    vuln_id = args.get("vuln_id")
    if verdict == "vuln_submitted":
        submitted = ctx.state.get("submitted_vulns") or []
        if vuln_id in (None, ""):
            if submitted:
                vuln_id = submitted[-1]
            else:
                return {"ok": False, "error": "verdict=vuln_submitted 时必须提供 vuln_id"}
        try:
            vuln_id = int(vuln_id)
        except (TypeError, ValueError):
            return {"ok": False, "error": "vuln_id 必须是整数"}
    else:
        vuln_id = None
    with SessionLocal() as db:
        row = db.get(Sink, sink_id)
        if not row or row.project_id != ctx.project_id:
            return {"ok": False, "error": "Sink 不存在"}
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
        path = assert_writable(ctx.project_id, f"workspace/rounds/fast-round-{round_id}.md")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(strip_followup_section(str(report)), encoding="utf-8")
    ctx.state["sink_finished"] = True
    ctx.state["round_finished"] = True
    return {"ok": True, "sink_id": sink_id, "verdict": verdict, "message": "本轮 Sink 已结束"}


def register_fast_tools() -> None:
    registry.register(
        ToolSpec(
            name="FinishSinkTriage",
            description=(
                "提交本批 Sink 筛选结果。每条必须有 id 与 decision=keep|drop|defer，"
                "可附 reason。禁止读代码或追调用链。高危高置信高权 Sink 不要 drop。"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "decisions": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "id": {"type": "integer"},
                                "sink_id": {"type": "integer"},
                                "decision": {"type": "string"},
                                "reason": {"type": "string"},
                            },
                        },
                    }
                },
                "required": ["decisions"],
            },
            handler=_finish_sink_triage,
        )
    )
    registry.register(
        ToolSpec(
            name="FinishSink",
            description=(
                "结束本轮注入 Sink。必填 verdict："
                "vuln_submitted / unreachable / sanitized / intended / noise。"
                "提交了漏洞则带 vuln_id。调用后本轮结束。"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "sink_id": {"type": "integer"},
                    "verdict": {"type": "string"},
                    "vuln_id": {"type": "integer"},
                    "reason": {"type": "string"},
                    "report": {"type": "string"},
                },
                "required": ["verdict"],
            },
            handler=_finish_sink,
        )
    )


register_fast_tools()

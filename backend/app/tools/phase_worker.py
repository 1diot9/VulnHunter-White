"""Worker-phase tools: SubmitVuln, FinishFile, FinishRound, FinishFix."""

from __future__ import annotations

from typing import Any

from ..models import FileWeight, Project, SessionLocal, Vuln
from ..services.paths import vuln_dir
from ..services.report import write_report_md
from ..vuln_types import normalize_vuln_type, severity_for_type
from . import ToolSpec, registry


REQUIRED_SUBMIT_FIELDS = (
    "title",
    "vuln_type",
    "cwe",
    "file_path",
    "line_no",
    "source_sink",
    "auth_premise",
    "http_request",
    "poc_code",
    "expected_evidence",
)

FINISH_FILE_CONTINUE_MSG = (
    "FinishFile 不等于结束本轮。请继续分析一开始注入的入口文件；"
    "仅当该入口的 source→sink 已完整分析后再调用 FinishRound。"
)
FINISH_FILE_NON_ENTRY_MSG = (
    "已标记非入口文件，本轮未结束。禁止立刻 FinishRound。"
    "请继续分析一开始注入的入口文件及其调用链。"
)
FINISH_FILE_ENTRY_MSG = (
    "已标记本轮注入入口。若其 source→sink 已完整分析，现在可以 FinishRound；"
    "否则继续分析，不要仅因 FinishFile 而结束本轮。"
)
FINISH_ROUND_NEED_FILE = "FinishRound 前本轮必须先调用过 FinishFile"
FINISH_ROUND_NEED_ENTRY = (
    "本轮注入入口 {injected} 尚未 FinishFile，不能结束本轮。"
    "中途 FinishFile 的是非入口文件，请继续分析注入入口；"
    "仅当该入口 source→sink 已完整分析并 FinishFile 后再 FinishRound。"
)


def _norm_audit_path(p: str) -> str:
    p = str(p).replace("\\", "/").lstrip("/")
    if p.startswith("src/"):
        p = p[4:]
    return p


def _injected_path(ctx) -> str | None:
    raw = getattr(ctx, "file_path", None) or (ctx.state or {}).get("injected_file")
    if not raw:
        return None
    return _norm_audit_path(str(raw))


def mining_complete(project_id: int) -> bool:
    """recon_done + all non-skipped files audited + no returned/fixing."""
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        if not proj or not proj.recon_done:
            return False
        left = (
            db.query(FileWeight)
            .filter(
                FileWeight.project_id == project_id,
                FileWeight.skipped.is_(False),
                FileWeight.audited.is_(False),
            )
            .count()
        )
        if left > 0:
            return False
        bounced = (
            db.query(Vuln)
            .filter(
                Vuln.project_id == project_id,
                Vuln.status.in_(("returned", "fixing")),
            )
            .count()
        )
        return bounced == 0


def project_complete_gates(project_id: int) -> bool:
    """Mining done + no pending_review/returned/fixing."""
    if not mining_complete(project_id):
        return False
    with SessionLocal() as db:
        pending = (
            db.query(Vuln)
            .filter(
                Vuln.project_id == project_id,
                Vuln.status.in_(("pending_review", "returned", "fixing")),
            )
            .count()
        )
        return pending == 0


def _submit_vuln(ctx, args: dict[str, Any]) -> dict[str, Any]:
    if ctx.role == "worker" and mining_complete(ctx.project_id):
        return {
            "ok": False,
            "error": "挖掘阶段已完成（文件均已审计且无打回），禁止再 SubmitVuln；修复请走 Fix 流程",
        }
    missing = [f for f in REQUIRED_SUBMIT_FIELDS if args.get(f) in (None, "")]
    if missing:
        return {"ok": False, "error": f"SubmitVuln 缺少必填字段: {', '.join(missing)}"}
    vtype = normalize_vuln_type(str(args.get("vuln_type")))
    severity = severity_for_type(vtype)
    intended = bool(args.get("intended_behavior") or False)
    try:
        line_no = int(args.get("line_no"))
    except (TypeError, ValueError):
        return {"ok": False, "error": "line_no 必须是整数"}

    with SessionLocal() as db:
        vuln = Vuln(
            project_id=ctx.project_id,
            title=str(args["title"]).strip(),
            vuln_type=vtype,
            severity=severity,
            cwe=str(args["cwe"]).strip(),
            file_path=str(args["file_path"]).replace("\\", "/"),
            line_no=line_no,
            source_sink=str(args["source_sink"]),
            auth_premise=str(args["auth_premise"]),
            http_request=str(args["http_request"]),
            poc_code=str(args["poc_code"]),
            expected_evidence=str(args["expected_evidence"]),
            intended_behavior=intended,
            status="pending_review",
        )
        db.add(vuln)
        db.commit()
        db.refresh(vuln)
        vuln_id = vuln.id
        # write artifacts
        vdir = vuln_dir(ctx.project_id, vuln_id)
        report = args.get("report_md") or _default_report(args, vtype, severity)
        write_report_md(vdir / "report.md", report, vuln.created_at)
        (vdir / "request.http").write_text(str(args["http_request"]), encoding="utf-8")
        (vdir / "poc.py").write_text(str(args["poc_code"]), encoding="utf-8")
        vuln.report_path = f"vulns/{vuln_id}/report.md"
        db.commit()

    ctx.state.setdefault("submitted_vulns", []).append(vuln_id)
    # Signal scheduler via shared state
    ctx.state["review_queue_notify"] = True
    return {
        "ok": True,
        "vuln_id": vuln_id,
        "status": "pending_review",
        "message": "已入审核队列，Worker 可继续审计",
    }


def _default_report(args: dict[str, Any], vtype: str, severity: str) -> str:
    return f"""---
title: {args.get('title')}
summary: {args.get('source_sink', '')[:200]}
---

# {args.get('title')}

## 摘要
- 类型：{vtype}
- 严重度：{severity}
- CWE：{args.get('cwe')}
- 位置：{args.get('file_path')}:{args.get('line_no')}

## Source → Sink
{args.get('source_sink')}

## 鉴权前提
{args.get('auth_premise')}

## HTTP 请求包
```http
{args.get('http_request')}
```

## 预期证据
{args.get('expected_evidence')}

## PoC
见同目录 `poc.py`。
"""


def _finish_file_message(ctx, done: list[str]) -> str:
    injected = _injected_path(ctx)
    done_norm = {_norm_audit_path(p) for p in done}
    if injected and done_norm and injected not in done_norm:
        return FINISH_FILE_NON_ENTRY_MSG
    if injected and injected in done_norm:
        return FINISH_FILE_ENTRY_MSG
    return FINISH_FILE_CONTINUE_MSG


def _finish_file(ctx, args: dict[str, Any]) -> dict[str, Any]:
    paths = args.get("paths") or args.get("path") or args.get("files")
    if isinstance(paths, str):
        paths = [paths]
    if not paths:
        return {"ok": False, "error": "缺少 path/paths"}
    done = []
    with SessionLocal() as db:
        for p in paths:
            p = _norm_audit_path(p)
            fw = (
                db.query(FileWeight)
                .filter(FileWeight.project_id == ctx.project_id, FileWeight.path == p)
                .first()
            )
            if not fw:
                continue
            fw.audited = True
            fw.claimed_by = None
            fw.claimed_at = None
            done.append(p)
        db.commit()
    ctx.state.setdefault("finished_files_this_round", [])
    ctx.state["finished_files_this_round"].extend(done)
    return {
        "ok": True,
        "finished": done,
        "count": len(done),
        "message": _finish_file_message(ctx, done),
    }


def _finish_round(ctx, args: dict[str, Any]) -> dict[str, Any]:
    finished = ctx.state.get("finished_files_this_round") or []
    if not finished:
        return {"ok": False, "error": FINISH_ROUND_NEED_FILE}
    injected = _injected_path(ctx)
    if injected:
        finished_norm = {_norm_audit_path(p) for p in finished}
        if injected not in finished_norm:
            return {"ok": False, "error": FINISH_ROUND_NEED_ENTRY.format(injected=injected)}
    report = args.get("report") or args.get("summary") or ""
    if report:
        from .sandbox import assert_writable

        path = assert_writable(ctx.project_id, f"workspace/rounds/round-{ctx.state.get('round_id', 0)}.md")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(str(report), encoding="utf-8")
    ctx.state["round_finished"] = True
    ctx.state["finished_files_this_round"] = []
    return {"ok": True, "message": "本轮审计结束"}


def _finish_fix(ctx, args: dict[str, Any]) -> dict[str, Any]:
    vuln_id = args.get("vuln_id") or ctx.vuln_id
    if not vuln_id:
        return {"ok": False, "error": "缺少 vuln_id"}
    report_md = args.get("report_md")
    with SessionLocal() as db:
        vuln = db.get(Vuln, int(vuln_id))
        if not vuln or vuln.project_id != ctx.project_id:
            return {"ok": False, "error": "漏洞不存在"}
        if vuln.status not in ("returned", "fixing"):
            return {"ok": False, "error": f"仅 status=returned/fixing 可 FinishFix，当前为 {vuln.status}"}
        # optional field updates
        for key in (
            "title",
            "source_sink",
            "auth_premise",
            "http_request",
            "poc_code",
            "expected_evidence",
            "cwe",
        ):
            if args.get(key) is not None:
                setattr(vuln, key, args[key])
        if args.get("line_no") is not None:
            vuln.line_no = int(args["line_no"])
        if args.get("file_path"):
            vuln.file_path = str(args["file_path"])
        if report_md:
            vdir = vuln_dir(ctx.project_id, vuln.id)
            write_report_md(vdir / "report.md", str(report_md), vuln.created_at)
        if args.get("http_request"):
            (vuln_dir(ctx.project_id, vuln.id) / "request.http").write_text(str(args["http_request"]), encoding="utf-8")
        if args.get("poc_code"):
            (vuln_dir(ctx.project_id, vuln.id) / "poc.py").write_text(str(args["poc_code"]), encoding="utf-8")
        vuln.status = "pending_review"
        vuln.return_reason = None
        db.commit()
        vid = vuln.id
    ctx.state["fix_finished"] = True
    return {"ok": True, "vuln_id": vid, "status": "pending_review", "message": "已修改并重新入队"}


def register_worker_tools() -> None:
    registry.register(
        ToolSpec(
            name="SubmitVuln",
            description="提交待审核漏洞（必填字段齐全才入库）",
            parameters={
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "vuln_type": {"type": "string"},
                    "cwe": {"type": "string"},
                    "file_path": {"type": "string"},
                    "line_no": {"type": "integer"},
                    "source_sink": {"type": "string"},
                    "auth_premise": {"type": "string"},
                    "http_request": {"type": "string"},
                    "poc_code": {"type": "string"},
                    "expected_evidence": {"type": "string"},
                    "intended_behavior": {"type": "boolean"},
                    "report_md": {"type": "string"},
                },
                "required": list(REQUIRED_SUBMIT_FIELDS),
            },
            handler=_submit_vuln,
        )
    )
    registry.register(
        ToolSpec(
            name="FinishFile",
            description=(
                "中途标记文件不必再作为后续轮次注入点。沿调用链确认的非入口文件立刻 "
                "FinishFile(paths=[...])，然后继续分析本轮注入入口，禁止立刻 FinishRound。"
                "本轮注入入口仅在 source→sink 查清后再标。不要只标一开始注入的文件。"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "paths": {"type": "array", "items": {"type": "string"}},
                },
            },
            handler=_finish_file,
        )
    )
    registry.register(
        ToolSpec(
            name="FinishRound",
            description=(
                "仅当一开始注入的入口文件已完整分析后结束本轮。"
                "中途 FinishFile 非入口文件后禁止立刻调用；须先 FinishFile 该注入入口。"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "report": {"type": "string"},
                    "summary": {"type": "string"},
                },
            },
            handler=_finish_round,
        )
    )
    registry.register(
        ToolSpec(
            name="FinishFix",
            description="完成打回修改，重新入审核队列",
            parameters={
                "type": "object",
                "properties": {
                    "vuln_id": {"type": "integer"},
                    "report_md": {"type": "string"},
                    "title": {"type": "string"},
                    "source_sink": {"type": "string"},
                    "auth_premise": {"type": "string"},
                    "http_request": {"type": "string"},
                    "poc_code": {"type": "string"},
                    "expected_evidence": {"type": "string"},
                    "cwe": {"type": "string"},
                    "file_path": {"type": "string"},
                    "line_no": {"type": "integer"},
                },
            },
            handler=_finish_fix,
        )
    )


register_worker_tools()

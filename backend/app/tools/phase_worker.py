"""Worker-phase tools: SubmitVuln, FinishFile, FinishRound, FinishFix."""

from __future__ import annotations

from typing import Any

from ..audit_mode import AUDIT_MODE_BOUNTY, bounty_submit_block_reason, normalize_audit_mode
from ..models import FileWeight, Project, SessionLocal, Vuln
from ..services.paths import vuln_dir
from ..services.report import ensure_search_fingerprint_section, write_report_md
from ..vuln_types import PENDING_SEVERITY, normalize_vuln_type
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
    intended = bool(args.get("intended_behavior") or False)
    try:
        line_no = int(args.get("line_no"))
    except (TypeError, ValueError):
        return {"ok": False, "error": "line_no 必须是整数"}

    with SessionLocal() as db:
        proj = db.get(Project, ctx.project_id)
        mode = normalize_audit_mode(None if not proj else proj.audit_mode)
        if mode == AUDIT_MODE_BOUNTY:
            blocked = bounty_submit_block_reason(vtype)
            if blocked:
                return {"ok": False, "error": blocked}
        vuln = Vuln(
            project_id=ctx.project_id,
            title=str(args["title"]).strip(),
            vuln_type=vtype,
            severity=PENDING_SEVERITY,
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
        report = args.get("report_md") or _default_report(args, vtype)
        report = ensure_search_fingerprint_section(
            str(report),
            fofa=args.get("fofa_fingerprint"),
            x=args.get("x_fingerprint"),
            basis=args.get("fingerprint_basis"),
        )
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


def _default_report(args: dict[str, Any], vtype: str) -> str:
    return f"""---
title: {args.get('title')}
summary: {args.get('source_sink', '')[:200]}
---

# {args.get('title')}

## 摘要
- 漏洞技术类型：{vtype}
- 严重度：待 Reviewer 按利用上下文校准（不按类型映射）
- CWE：{args.get('cwe')}
- 位置：{args.get('file_path')}:{args.get('line_no')}

## 漏洞描述
第一段：待根据厂商与产品资料补全系统介绍。

第二段：该漏洞位于 `{args.get('file_path')}:{args.get('line_no')}`，数据流为 {args.get('source_sink')}。

## 漏洞危害
- 已证明危害：{args.get('expected_evidence')}
- 潜在危害：待根据漏洞类型补全。
- SQL 注入须明确：是否能获取 OS-Shell：未验证

## 漏洞厂商全称
暂未明确

## 已知受影响产品及版本
暂未明确

## 漏洞技术细节

### Source → Sink
{args.get('source_sink')}

### 完整 PoC 描述
可运行脚本见同目录 `poc.py`。

```http
{args.get('http_request')}
```

### 触发条件
{args.get('auth_premise')}

## 复现证明

### 基础环境搭建
详见项目文档 `docs/lab.md`。

### 漏洞触发操作
-

### 预期证据
{args.get('expected_evidence')}

### 复现注意事项
-

## 修复方案
-

## 备注
无
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
            report = ensure_search_fingerprint_section(
                str(report_md),
                fofa=args.get("fofa_fingerprint"),
                x=args.get("x_fingerprint"),
                basis=args.get("fingerprint_basis"),
            )
            write_report_md(vdir / "report.md", report, vuln.created_at)
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
            description=(
                "提交待审核漏洞（必填字段齐全才入库）。"
                "仅当默认/官方部署下，攻击者只凭自身权限与 HTTP 输入就能打出可观察有害冲击时才提交；"
                "source→sink 可达但默认环境无冲击、需要额外写文件/独立漏洞/非默认目录布局、"
                "或只是配置/文档/compose 里的默认密码弱口令的不要提交。"
                "不要按漏洞类型填写严重度；入库严重度为 pending，由 Reviewer 校准。"
            ),
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
                    "fofa_fingerprint": {"type": "string"},
                    "x_fingerprint": {"type": "string"},
                    "fingerprint_basis": {"type": "string"},
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
                "须附 report，结构对齐 templates/round-report.md（本轮入口、挖掘方向、已尝试、已排除、建议后续方向）。"
                "中途 FinishFile 非入口文件后禁止立刻调用；须先 FinishFile 该注入入口。"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "report": {
                        "type": "string",
                        "description": (
                            "本轮挖掘摘要（中文），结构对齐 templates/round-report.md，"
                            "须含 ## 本轮入口、## 本轮挖掘方向、## 已尝试、"
                            "## 已排除（后续轮不要再走）、## 建议后续方向。"
                        ),
                    },
                    "summary": {
                        "type": "string",
                        "description": "report 的别名，同样对齐 templates/round-report.md。",
                    },
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
                    "fofa_fingerprint": {"type": "string"},
                    "x_fingerprint": {"type": "string"},
                    "fingerprint_basis": {"type": "string"},
                    "cwe": {"type": "string"},
                    "file_path": {"type": "string"},
                    "line_no": {"type": "integer"},
                },
            },
            handler=_finish_fix,
        )
    )


register_worker_tools()

"""产出漏洞去重：RecordVulnDedup + FinishVulnDedup。"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..models import SessionLocal, Vuln
from ..services.live_log import live_log
from ..services.paths import docs_dir, workspace_dir
from . import ToolSpec, registry
from .common import call_fail

PHASE = "vuln_dedup"
ROLE = "vuln_dedup"
REQUEST_NAME = "vuln-dedup-request.json"
REPORT_REL = "docs/vuln-dedup.md"

VERDICT_KNOWN = "known_public"
VERDICT_UNIQUE = "unique"
VERDICT_UNCERTAIN = "uncertain"
VERDICTS = frozenset({VERDICT_KNOWN, VERDICT_UNIQUE, VERDICT_UNCERTAIN})
SOURCE_PRESENT = "present"
SOURCE_FIXED = "fixed"
SOURCE_UNCERTAIN = "uncertain"
SOURCE_STATUSES = frozenset({SOURCE_PRESENT, SOURCE_FIXED, SOURCE_UNCERTAIN})
SOURCE_STATUS_LABEL = {
    SOURCE_PRESENT: "仍存在",
    SOURCE_FIXED: "已修复",
    SOURCE_UNCERTAIN: "未核实",
}
SKIP_STATUSES = frozenset({"merged"})
FP_KIND_KNOWN_PUBLIC = "known_public"
FP_KIND_SOURCE_FIXED = "source_fixed"

_DEDUP_STATUSES = (
    "pending_review",
    "confirmed",
    "static_only",
    "returned",
    "fixing",
    "false_positive",
)


def request_path(project_id: int) -> Path:
    return workspace_dir(project_id) / REQUEST_NAME


def report_path(project_id: int) -> Path:
    return docs_dir(project_id) / "vuln-dedup.md"


def load_request(project_id: int) -> dict[str, Any]:
    path = request_path(project_id)
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def save_request(project_id: int, payload: dict[str, Any]) -> None:
    path = request_path(project_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)


def resolve_vuln_ids(project_id: int, vuln_ids: list[int] | None) -> list[int]:
    wanted = [int(v) for v in (vuln_ids or []) if int(v) > 0]
    with SessionLocal() as db:
        q = db.query(Vuln).filter(Vuln.project_id == project_id)
        if wanted:
            rows = q.filter(Vuln.id.in_(wanted)).order_by(Vuln.id.asc()).all()
            found = {int(v.id) for v in rows}
            missing = [i for i in wanted if i not in found]
            if missing:
                raise ValueError(f"漏洞不属于本项目或不存在：{missing[:12]}")
        else:
            rows = q.filter(Vuln.status.in_(_DEDUP_STATUSES)).order_by(Vuln.id.asc()).all()
        ids = [int(v.id) for v in rows if (v.status or "") not in SKIP_STATUSES]
    if not ids:
        raise ValueError("没有可去重的产出漏洞")
    return ids


def _iso(ts: Any) -> str:
    if ts is None:
        return ""
    if hasattr(ts, "isoformat"):
        try:
            return ts.isoformat()
        except Exception:  # noqa: BLE001
            return str(ts)
    return str(ts)


def catalog_for_ids(project_id: int, vuln_ids: list[int]) -> list[dict[str, Any]]:
    with SessionLocal() as db:
        rows = (
            db.query(Vuln)
            .filter(Vuln.project_id == project_id, Vuln.id.in_(vuln_ids))
            .order_by(Vuln.id.asc())
            .all()
        )
        by_id = {int(v.id): v for v in rows}
        out: list[dict[str, Any]] = []
        for vid in vuln_ids:
            v = by_id.get(int(vid))
            if not v:
                continue
            out.append(
                {
                    "vuln_id": v.id,
                    "title": v.title,
                    "status": v.status,
                    "vuln_type": v.vuln_type,
                    "cwe": v.cwe,
                    "file_path": v.file_path,
                    "line_no": v.line_no,
                    "source_sink": (v.source_sink or "")[:400],
                    "http_request": (v.http_request or "")[:400],
                    "attack_surface": v.attack_surface,
                    "required_account": v.required_account,
                    "config_premise": v.config_premise,
                    "severity": v.severity,
                    "report_path": v.report_path or f"vulns/{v.id}/report.md",
                    "created_at": _iso(v.created_at),
                }
            )
        return out


def recent_old_vulns(project_id: int, *, limit: int = 20) -> list[dict[str, Any]]:
    from .common import _old_vuln_entries, _public_doc

    entries = list(_old_vuln_entries(project_id))
    entries.sort(key=lambda e: float(e.get("mtime") or 0), reverse=True)
    out: list[dict[str, Any]] = []
    for entry in entries[:limit]:
        item = _public_doc(entry)
        mtime = float(entry.get("mtime") or 0)
        if mtime:
            item["collected_at"] = datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat()
        out.append(item)
    return out


def source_snapshot(project_id: int) -> dict[str, Any]:
    from ..models import Project
    from ..services.ingest import _git_head_sha
    from ..services.paths import src_dir

    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        source_type = (getattr(proj, "source_type", None) or "").strip() if proj else ""
        source_url = (getattr(proj, "source_url", None) or "").strip() if proj else ""
        sync_error = (getattr(proj, "source_sync_error", None) or "").strip() if proj else ""
        sync_notice = (getattr(proj, "source_sync_notice", None) or "").strip() if proj else ""
    head = ""
    src = src_dir(project_id)
    try:
        if (src / ".git").is_dir():
            head = _git_head_sha(src)
    except Exception:  # noqa: BLE001
        head = ""
    return {
        "source_type": source_type or "zip",
        "source_url": source_url,
        "head": head,
        "head_short": head[:7] if head else "",
        "sync_error": sync_error,
        "sync_notice": sync_notice,
    }


def format_source_note(project_id: int, *, attempted_sync: bool = False) -> str:
    snap = source_snapshot(project_id)
    kind = snap["source_type"]
    head = snap["head_short"]
    head_bit = f"当前 src/ 提交 `{head}`。" if head else "当前 src/ 没有可读的 git HEAD。"
    if kind == "github":
        if attempted_sync:
            err = snap["sync_error"]
            notice = snap["sync_notice"]
            if err:
                sync_bit = f"已尝试同步上游但失败（{err}），仍用当前快照。"
            elif notice:
                sync_bit = notice
            else:
                sync_bit = "已检查上游，无新提交或无需更新。"
        else:
            sync_bit = "项目审计进行中，未拉取上游以免打断挖掘；请对照当前 src/。"
        return f"GitHub 项目。{head_bit}{sync_bit} 以该快照判断漏洞是否还在。"
    return f"zip 项目无上游。{head_bit}请对照当前导入的 src/ 判断漏洞是否还在。"


def _dedup_fp_kind(verdict: str, source_status: str) -> str | None:
    if source_status == SOURCE_FIXED:
        return FP_KIND_SOURCE_FIXED
    if verdict == VERDICT_KNOWN:
        return FP_KIND_KNOWN_PUBLIC
    return None


def path_hints_for_catalog(project_id: int, catalog: list[dict[str, Any]]) -> list[dict[str, Any]]:
    from ..services.known_public import find_known_public_matches

    hints: list[dict[str, Any]] = []
    for item in catalog:
        matches = find_known_public_matches(
            project_id,
            title=str(item.get("title") or ""),
            source_sink=str(item.get("source_sink") or ""),
            http_request=str(item.get("http_request") or ""),
            file_path=str(item.get("file_path") or ""),
            vuln_type=str(item.get("vuln_type") or ""),
        )
        if matches:
            hints.append({"vuln_id": item.get("vuln_id"), "candidates": matches})
    return hints


def write_report(project_id: int, results: list[dict[str, Any]], *, notes: str = "") -> Path:
    known = [r for r in results if r.get("verdict") == VERDICT_KNOWN]
    unique = [r for r in results if r.get("verdict") == VERDICT_UNIQUE]
    uncertain = [r for r in results if r.get("verdict") == VERDICT_UNCERTAIN]
    still = [r for r in results if r.get("source_status") == SOURCE_PRESENT]
    gone = [r for r in results if r.get("source_status") == SOURCE_FIXED]
    source_unknown = [r for r in results if r.get("source_status") == SOURCE_UNCERTAIN]
    lines = [
        "# 产出漏洞去重",
        "",
        f"- 已公开同类：{len(known)}",
        f"- 未覆盖新链：{len(unique)}",
        f"- 公开对比证据不足：{len(uncertain)}",
        f"- 最新代码仍存在：{len(still)}",
        f"- 最新代码已修复：{len(gone)}",
        f"- 源码未核实：{len(source_unknown)}",
        "",
    ]
    if notes.strip():
        lines.extend(["## 说明", "", notes.strip(), ""])
    lines.extend(
        [
            "## 逐条结论",
            "",
            "| vuln_id | 公开结论 | 最新代码 | 历史漏洞 | 是否误报 | 原因 |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
    )
    for row in results:
        reason = str(row.get("reason") or "").replace("|", "\\|").replace("\n", " ")
        old = str(row.get("old_title") or "").replace("|", "\\|")
        fp = "是" if row.get("marked_false_positive") else "否"
        src = SOURCE_STATUS_LABEL.get(str(row.get("source_status") or ""), "—")
        lines.append(
            f"| #{row.get('vuln_id')} | {row.get('verdict')} | {src} | {old or '—'} | {fp} | {reason or '—'} |"
        )
    lines.append("")
    path = report_path(project_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def _results(ctx) -> list[dict[str, Any]]:
    raw = ctx.state.setdefault("dedup_results", [])
    if not isinstance(raw, list):
        raw = []
        ctx.state["dedup_results"] = raw
    return raw


def _record_vuln_dedup(ctx, args: dict[str, Any]) -> dict[str, Any]:
    from .phase_reviewer import _commit_false_positive

    try:
        vuln_id = int(args.get("vuln_id") or 0)
    except (TypeError, ValueError):
        return call_fail("vuln_id 必须是整数")
    verdict = str(args.get("verdict") or "").strip()
    source_status = str(args.get("source_status") or "").strip()
    reason = str(args.get("reason") or "").strip()
    old_title = str(args.get("old_title") or args.get("old_vuln_title") or "").strip()
    if vuln_id <= 0:
        return call_fail("缺少 vuln_id")
    if verdict not in VERDICTS:
        return call_fail(f"verdict 须为 {sorted(VERDICTS)}")
    if source_status not in SOURCE_STATUSES:
        return call_fail(f"source_status 须为 {sorted(SOURCE_STATUSES)}（对照最新 src/ 是否还存在）")
    if not reason:
        return call_fail("必须写明对比原因 reason（含历史对比与源码核对）")
    if verdict == VERDICT_KNOWN and not old_title:
        return call_fail("known_public 必须提供 old_title（历史漏洞标题）")

    fp_kind = _dedup_fp_kind(verdict, source_status)
    mark_fp = args.get("mark_false_positive")
    if mark_fp is None:
        mark_fp = fp_kind is not None
    else:
        mark_fp = bool(mark_fp)

    with SessionLocal() as db:
        vuln = db.get(Vuln, vuln_id)
        if not vuln or vuln.project_id != ctx.project_id:
            return call_fail("漏洞不存在")
        if (vuln.status or "") in SKIP_STATUSES:
            return call_fail(f"#{vuln_id} 已合并，不要去重")
        already_fp = vuln.status == "false_positive"
        marked = False
        if mark_fp and fp_kind and not already_fp:
            if fp_kind == FP_KIND_SOURCE_FIXED:
                message = "最新源码已修复，标为误报"
            else:
                message = "已公开同类洞，标为误报"
            out = _commit_false_positive(
                ctx,
                db,
                vuln,
                vuln_id,
                reason,
                message,
                fp_kind=fp_kind,
                end_review=False,
            )
            if not out.get("ok"):
                return out
            marked = True
        status = vuln.status

    row = {
        "vuln_id": vuln_id,
        "verdict": verdict,
        "source_status": source_status,
        "old_title": old_title,
        "reason": reason,
        "marked_false_positive": marked or (bool(fp_kind) and already_fp),
        "status": status,
        "fp_kind": fp_kind if (marked or (bool(fp_kind) and already_fp)) else None,
    }
    results = _results(ctx)
    results[:] = [r for r in results if int(r.get("vuln_id") or 0) != vuln_id]
    results.append(row)
    ctx.state["dedup_results"] = results
    src_label = SOURCE_STATUS_LABEL.get(source_status, source_status)
    live_log.system(
        ctx.project_id,
        f"去重 #{vuln_id} {verdict} / 源码{src_label}"
        + (f" ← {old_title}" if old_title else "")
        + ("，已标误报" if marked else ""),
        phase=PHASE,
        role=ROLE,
    )
    return {"ok": True, **row, "recorded": len(results)}


def _finish_vuln_dedup(ctx, args: dict[str, Any]) -> dict[str, Any]:
    notes = str(args.get("notes") or "").strip()
    if not notes:
        return call_fail("FinishVulnDedup 必须提供 notes")
    results = list(_results(ctx))
    path = write_report(ctx.project_id, results, notes=notes)
    ctx.state["vuln_dedup_done"] = True
    ctx.state["vuln_dedup_notes"] = notes
    rel = REPORT_REL
    known_n = sum(1 for r in results if r.get("verdict") == VERDICT_KNOWN)
    fixed_n = sum(1 for r in results if r.get("source_status") == SOURCE_FIXED)
    live_log.system(
        ctx.project_id,
        f"产出漏洞去重结束：已公开 {known_n}、已修复 {fixed_n} / "
        f"共 {len(results)} 条，报告 {rel}",
        phase=PHASE,
        role=ROLE,
    )
    return {
        "ok": True,
        "done": True,
        "report": rel,
        "path": str(path),
        "count": len(results),
        "known_public": known_n,
        "source_fixed": fixed_n,
    }


registry.register(
    ToolSpec(
        name="RecordVulnDedup",
        description=(
            "记录一条产出的去重结论：相对历史漏洞是否已公开，以及最新 src/ 是否还存在该漏洞。"
            "verdict=known_public 表示同一入口/sink 的已公开同类洞；unique 表示公开文未覆盖；"
            "source_status=fixed 表示最新代码已修复。known_public 或 fixed 默认标误报；"
            "已公开且已修时状态为已修复。"
        ),
        parameters={
            "type": "object",
            "properties": {
                "vuln_id": {"type": "integer"},
                "verdict": {
                    "type": "string",
                    "description": "known_public | unique | uncertain（相对历史漏洞）",
                },
                "source_status": {
                    "type": "string",
                    "description": "present | fixed | uncertain（对照当前 src/ 是否还存在）",
                },
                "reason": {
                    "type": "string",
                    "description": "对比依据：入口/sink/公开文覆盖范围，以及源码核对结果",
                },
                "old_title": {
                    "type": "string",
                    "description": "命中的历史漏洞标题（known_public 必填）",
                },
                "mark_false_positive": {
                    "type": "boolean",
                    "description": "known_public 或 source_status=fixed 时默认 true",
                },
            },
            "required": ["vuln_id", "verdict", "source_status", "reason"],
        },
        handler=_record_vuln_dedup,
    )
)
registry.register(
    ToolSpec(
        name="FinishVulnDedup",
        description="结束产出漏洞去重。全部 vuln_id 都 Record 之后调用；没有历史命中或源码仍在也要 Finish。",
        parameters={
            "type": "object",
            "properties": {
                "notes": {
                    "type": "string",
                    "description": "收工说明：查了几条、已公开几条、无法判断几条",
                },
            },
            "required": ["notes"],
        },
        handler=_finish_vuln_dedup,
    )
)

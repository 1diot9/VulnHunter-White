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
SKIP_STATUSES = frozenset({"merged"})
FP_KIND_KNOWN_PUBLIC = "known_public"

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
    lines = [
        "# 产出漏洞去重",
        "",
        f"- 已公开同类：{len(known)}",
        f"- 未覆盖新链：{len(unique)}",
        f"- 证据不足：{len(uncertain)}",
        "",
    ]
    if notes.strip():
        lines.extend(["## 说明", "", notes.strip(), ""])
    lines.extend(
        [
            "## 逐条结论",
            "",
            "| vuln_id | 结论 | 历史漏洞 | 是否误报 | 原因 |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    for row in results:
        reason = str(row.get("reason") or "").replace("|", "\\|").replace("\n", " ")
        old = str(row.get("old_title") or "").replace("|", "\\|")
        fp = "是" if row.get("marked_false_positive") else "否"
        lines.append(
            f"| #{row.get('vuln_id')} | {row.get('verdict')} | {old or '—'} | {fp} | {reason or '—'} |"
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
    reason = str(args.get("reason") or "").strip()
    old_title = str(args.get("old_title") or args.get("old_vuln_title") or "").strip()
    if vuln_id <= 0:
        return call_fail("缺少 vuln_id")
    if verdict not in VERDICTS:
        return call_fail(f"verdict 须为 {sorted(VERDICTS)}")
    if not reason:
        return call_fail("必须写明对比原因 reason")
    if verdict == VERDICT_KNOWN and not old_title:
        return call_fail("known_public 必须提供 old_title（历史漏洞标题）")

    mark_fp = args.get("mark_false_positive")
    if mark_fp is None:
        mark_fp = verdict == VERDICT_KNOWN
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
        if mark_fp and verdict == VERDICT_KNOWN and not already_fp:
            out = _commit_false_positive(
                ctx,
                db,
                vuln,
                vuln_id,
                reason,
                "已公开同类洞，标为误报",
                fp_kind=FP_KIND_KNOWN_PUBLIC,
                end_review=False,
            )
            if not out.get("ok"):
                return out
            marked = True
        status = vuln.status

    row = {
        "vuln_id": vuln_id,
        "verdict": verdict,
        "old_title": old_title,
        "reason": reason,
        "marked_false_positive": marked or (verdict == VERDICT_KNOWN and already_fp),
        "status": status,
    }
    results = _results(ctx)
    results[:] = [r for r in results if int(r.get("vuln_id") or 0) != vuln_id]
    results.append(row)
    ctx.state["dedup_results"] = results
    live_log.system(
        ctx.project_id,
        f"去重 #{vuln_id} {verdict}"
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
    live_log.system(
        ctx.project_id,
        f"产出漏洞去重结束：已公开 {sum(1 for r in results if r.get('verdict') == VERDICT_KNOWN)} / "
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
        "known_public": sum(1 for r in results if r.get("verdict") == VERDICT_KNOWN),
    }


registry.register(
    ToolSpec(
        name="RecordVulnDedup",
        description=(
            "记录一条产出相对历史漏洞的对比结论。"
            "verdict=known_public 表示同一入口/sink 的已公开同类洞（含 patched CVE），默认标误报；"
            "unique 表示公开文未覆盖的新链；uncertain 表示证据不足、不要误报。"
        ),
        parameters={
            "type": "object",
            "properties": {
                "vuln_id": {"type": "integer"},
                "verdict": {
                    "type": "string",
                    "description": "known_public | unique | uncertain",
                },
                "reason": {"type": "string", "description": "对比依据：入口/sink/公开文覆盖范围"},
                "old_title": {
                    "type": "string",
                    "description": "命中的历史漏洞标题（known_public 必填）",
                },
                "mark_false_positive": {
                    "type": "boolean",
                    "description": "known_public 时默认 true；unique/uncertain 不要标误报",
                },
            },
            "required": ["vuln_id", "verdict", "reason"],
        },
        handler=_record_vuln_dedup,
    )
)
registry.register(
    ToolSpec(
        name="FinishVulnDedup",
        description="结束产出漏洞去重。全部 vuln_id 都 Record 之后调用；没有命中也要 Finish。",
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

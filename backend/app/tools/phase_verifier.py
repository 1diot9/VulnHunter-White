"""Verifier tools: FofaSearch, FinishVerifier."""

from __future__ import annotations

from typing import Any

from ..models import SessionLocal, Vuln
from ..services.fofa import FOFA_DEFAULT_SIZE, FOFA_MAX_SIZE, search as fofa_search
from ..services.paths import vuln_dir
from ..services.report import upsert_report_section
from ..services.verifier import (
    VERIFIER_FAILED,
    VERIFIER_SKIPPED,
    VERIFIER_VERIFIED,
    clip_evidence,
    format_verifier_report,
    internet_test_block_reason,
    verifier_report_path,
    verifier_report_rel,
)
from . import ToolSpec, registry
from .common import call_fail

_REVIEW_HEADING = "## 互联网验证"
_VERDICTS = {
    "success": VERIFIER_VERIFIED,
    "fail": VERIFIER_FAILED,
    "no_targets": VERIFIER_SKIPPED,
    "skipped": VERIFIER_SKIPPED,
}


def _fofa_search(ctx, args: dict[str, Any]) -> dict[str, Any]:
    query = str(args.get("query") or "").strip()
    size = args.get("size", FOFA_DEFAULT_SIZE)
    return fofa_search(query, size=size)


def _finish_verifier(ctx, args: dict[str, Any]) -> dict[str, Any]:
    vuln_id = args.get("vuln_id") or ctx.vuln_id
    if not vuln_id:
        return call_fail("缺少 vuln_id")
    verdict = str(args.get("verdict") or "").strip().lower()
    if verdict not in _VERDICTS:
        return call_fail("verdict 须为 success|fail|no_targets|skipped")
    verified_url = str(args.get("verified_url") or "").strip()
    poc = clip_evidence(args.get("poc"))
    response = clip_evidence(args.get("response"))
    if verdict == "success":
        if not verified_url:
            return call_fail("success 必须提供 verified_url（实际打通的那个同款目标）")
        if not poc:
            return call_fail("success 必须提供 poc（对该目标实际发出的请求或脚本，原样粘贴）")
        if not response:
            return call_fail("success 必须提供 response（该目标的真实 HTTP 响应/回显，原样粘贴）")
        with SessionLocal() as db:
            vuln = db.get(Vuln, int(vuln_id))
            vtype = vuln.vuln_type if vuln else ""
            title = vuln.title if vuln else ""
            http_request = vuln.http_request if vuln else ""
            stored_poc = vuln.poc_code if vuln else ""
            expected = vuln.expected_evidence if vuln else ""
        unsafe = internet_test_block_reason(
            vuln_type=vtype,
            title=title or "",
            http_request=http_request or "",
            poc_code="\n".join(p for p in (stored_poc, poc) if p),
            expected_evidence=expected or "",
        )
        if unsafe:
            return call_fail(unsafe)
    fofa_query = str(args.get("fofa_query") or "").strip()
    notes = str(args.get("notes") or "").strip()
    if not notes:
        return call_fail("必须填写 notes：测了哪些目标、为何成功或失败")
    try:
        tested_count = int(args.get("tested_count") or 0)
    except (TypeError, ValueError):
        tested_count = 0
    status = _VERDICTS[verdict]
    body = format_verifier_report(
        verdict=verdict,
        fofa_query=fofa_query,
        tested_count=tested_count,
        verified_url=verified_url,
        poc=poc,
        response=response,
        notes=notes,
    )
    rel = verifier_report_rel(int(vuln_id))
    report_path = verifier_report_path(ctx.project_id, int(vuln_id))
    report_path.write_text(f"# Verifier · 漏洞 #{int(vuln_id)}\n\n{body}", encoding="utf-8")
    upsert_report_section(vuln_dir(ctx.project_id, int(vuln_id)) / "report.md", _REVIEW_HEADING, body)
    with SessionLocal() as db:
        vuln = db.get(Vuln, int(vuln_id))
        if not vuln or vuln.project_id != ctx.project_id:
            return call_fail("漏洞不存在")
        vuln.verifier_status = status
        vuln.verifier_verified_url = verified_url or None
        vuln.verifier_poc = poc or None
        vuln.verifier_response = response or None
        db.commit()
    ctx.state["verifier_done"] = True
    ctx.state["verifier_verdict"] = verdict
    return {
        "ok": True,
        "vuln_id": int(vuln_id),
        "verdict": verdict,
        "verifier_status": status,
        "verified_url": verified_url or None,
        "report_path": rel,
        "message": "已记录互联网验证结论（目标 / PoC / 响应），本轮结束。",
    }


def register_verifier_tools() -> None:
    registry.register(
        ToolSpec(
            name="FofaSearch",
            description=(
                "只读 FOFA 测绘：用 FOFA 语法圈定同款前台系统，返回命中总量与样本"
                f"（host/ip/port/title/domain/org）。默认 {FOFA_DEFAULT_SIZE} 条，最多 {FOFA_MAX_SIZE} 条。"
                "只查 FOFA，不碰目标。拿到样本后再用 shell 按报告 PoC 逐个复测。"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": 'FOFA 语法，如 title="XX系统" && body="稳定特征"',
                    },
                    "size": {
                        "type": "integer",
                        "description": f"返回样本数，默认 {FOFA_DEFAULT_SIZE}，最大 {FOFA_MAX_SIZE}",
                        "default": FOFA_DEFAULT_SIZE,
                    },
                },
                "required": ["query"],
            },
            handler=_fofa_search,
        )
    )
    registry.register(
        ToolSpec(
            name="FinishVerifier",
            description=(
                "提交互联网验证结论并结束本轮。任一 FOFA 目标按报告复测成功即 verdict=success；"
                "搜到了但都没打通=fail；无样本=no_targets；无 key/网络不可用=skipped。"
                "成功必须带 verified_url、poc（实际发出的请求/脚本）、response（该目标真实响应）。"
                "任意文件删除、DoS、SQL 增删改等会中断或篡改业务的漏洞禁止互联网复测，应 verdict=skipped。"
                "不要在成功后再继续扫。"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "vuln_id": {"type": "integer"},
                    "verdict": {
                        "type": "string",
                        "description": "success | fail | no_targets | skipped",
                    },
                    "verified_url": {
                        "type": "string",
                        "description": "实际打通的同款目标 URL，success 时必填",
                    },
                    "poc": {
                        "type": "string",
                        "description": "对该目标实际发出的请求或脚本（curl/http/python 原样），success 时必填",
                    },
                    "response": {
                        "type": "string",
                        "description": "该目标的真实 HTTP 状态行、关键响应头与正文（原样粘贴），success 时必填",
                    },
                    "fofa_query": {"type": "string", "description": "最终使用的 FOFA 语法"},
                    "tested_count": {"type": "integer", "description": "实际发过复测请求的目标数"},
                    "notes": {"type": "string", "description": "测了哪些目标、为何成功或失败"},
                },
                "required": ["verdict", "notes"],
            },
            handler=_finish_verifier,
        )
    )


register_verifier_tools()

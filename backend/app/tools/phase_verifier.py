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
    dump_verifier_targets,
    format_verifier_report,
    internet_test_block_reason,
    load_project_fofa_cache,
    merge_verifier_targets,
    parse_verifier_targets,
    resolve_fofa_sample,
    save_project_fofa_cache,
    seed_fofa_state,
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
    seed_fofa_state(ctx.state, ctx.project_id)
    cache = load_project_fofa_cache(ctx.project_id)
    if cache is not None:
        ctx.state["fofa_query"] = cache.get("query") or ctx.state.get("fofa_query") or ""
        ctx.state["fofa_targets"] = list(cache.get("sample") or [])
        ctx.state["fofa_cached"] = True
        return {
            "ok": True,
            "cached": True,
            "query": cache.get("query") or "",
            "size": cache.get("size") or 0,
            "returned": cache.get("returned") or len(cache.get("sample") or []),
            "sample": list(cache.get("sample") or []),
            "guidance": (
                "本项目已搜索过 FOFA，结果供全部漏洞共享。不要再搜。"
                "直接按这些目标复测本条漏洞；FinishVerifier.targets 覆盖全部样本，"
                "success 时带上 fofa_query（即这份共享语法）。"
            ),
        }
    query = str(args.get("query") or "").strip()
    size = args.get("size", FOFA_DEFAULT_SIZE)
    out = fofa_search(query, size=size)
    if out.get("ok"):
        sample = list(out.get("sample") or [])
        saved = save_project_fofa_cache(
            ctx.project_id,
            query=str(out.get("query") or query),
            sample=sample,
            size=int(out.get("size") or 0),
        )
        ctx.state["fofa_query"] = saved["query"]
        ctx.state["fofa_targets"] = list(saved["sample"])
        extra = (
            "已写入项目共享缓存 docs/fofa-targets.json，后续漏洞直接复用，禁止再搜。"
            "FinishVerifier.targets 必须覆盖这些样本：已复测标 success/fail，其余标 untested。"
            "success 必须带 fofa_query（本次搜索语法）。任一成功即可结束，不要为了填表继续打。"
        )
        guidance = str(out.get("guidance") or "").strip()
        out["cached"] = False
        out["guidance"] = f"{guidance} {extra}".strip()
    return out


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
    seed_fofa_state(ctx.state, ctx.project_id)
    cached_query, cached_sample = resolve_fofa_sample(ctx.project_id, ctx.state)
    fofa_query = str(args.get("fofa_query") or cached_query or "").strip()
    if verdict == "success" and not fofa_query:
        return call_fail("success 必须提供 fofa_query（FOFA 搜索语法）；优先用本项目共享结果里的语法")
    notes = str(args.get("notes") or "").strip()
    if not notes:
        return call_fail("必须填写 notes：测了哪些目标、为何成功或失败")
    submitted = args.get("targets")
    if submitted is None:
        submitted = args.get("fofa_targets")
    if isinstance(submitted, str):
        submitted = parse_verifier_targets(submitted)
    if not isinstance(submitted, list):
        submitted = []
    targets = merge_verifier_targets(
        fofa_sample=cached_sample or list(ctx.state.get("fofa_targets") or []),
        submitted=submitted,
        verified_url=verified_url,
    )
    if verdict in ("success", "fail") and not targets:
        return call_fail(
            "必须提供 targets：列出 FofaSearch 的全部目标，并标注 status=success|fail|untested"
        )
    try:
        tested_count = int(args.get("tested_count") or 0)
    except (TypeError, ValueError):
        tested_count = 0
    derived = sum(1 for t in targets if t.get("status") in ("success", "fail"))
    if tested_count <= 0:
        tested_count = derived
    status = _VERDICTS[verdict]
    body = format_verifier_report(
        verdict=verdict,
        fofa_query=fofa_query,
        tested_count=tested_count,
        verified_url=verified_url,
        poc=poc,
        response=response,
        notes=notes,
        targets=targets,
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
        vuln.verifier_targets = dump_verifier_targets(targets)
        vuln.verifier_fofa_query = fofa_query or None
        db.commit()
    ctx.state["verifier_done"] = True
    ctx.state["verifier_verdict"] = verdict
    return {
        "ok": True,
        "vuln_id": int(vuln_id),
        "verdict": verdict,
        "verifier_status": status,
        "verified_url": verified_url or None,
        "fofa_query": fofa_query or None,
        "targets": targets,
        "report_path": rel,
        "message": "已记录互联网验证结论（全部 FOFA 目标及成功/失败/未测），本轮结束。",
    }


def register_verifier_tools() -> None:
    registry.register(
        ToolSpec(
            name="FofaSearch",
            description=(
                "只读 FOFA 测绘：用 FOFA 语法圈定同款前台系统，返回命中总量与样本"
                f"（host/ip/port/title/domain/org）。默认 {FOFA_DEFAULT_SIZE} 条，最多 {FOFA_MAX_SIZE} 条。"
                "一个审计项目只搜一次：结果写入 docs/fofa-targets.json，后续漏洞直接复用。"
                "若本项目已有共享结果，本工具立即返回缓存、不再请求 FOFA。只查 FOFA，不碰目标。"
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
                "success/fail 必须用 targets 列出共享 FOFA 的全部结果，并标注 success|fail|untested；"
                "成功还必须带 verified_url、poc、response、fofa_query（FOFA 搜索语法）。不要为了填未测项继续打。"
                "任意文件删除、DoS、SQL 增删改等会中断或篡改业务的漏洞禁止互联网复测，应 verdict=skipped。"
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
                    "targets": {
                        "type": "array",
                        "description": (
                            "FofaSearch 返回的全部目标。每项 host 必填，status 为 success|fail|untested。"
                            "已成功则其余标 untested，不要再测。"
                        ),
                        "items": {
                            "type": "object",
                            "properties": {
                                "host": {"type": "string"},
                                "ip": {"type": "string"},
                                "port": {"type": "string"},
                                "title": {"type": "string"},
                                "protocol": {"type": "string"},
                                "status": {
                                    "type": "string",
                                    "description": "success | fail | untested",
                                },
                                "note": {"type": "string", "description": "失败原因或未测原因"},
                            },
                            "required": ["host", "status"],
                        },
                    },
                    "fofa_query": {
                        "type": "string",
                        "description": "FOFA 搜索语法；success 必填，优先填本项目共享缓存里的那条",
                    },
                    "tested_count": {"type": "integer", "description": "实际发过复测请求的目标数"},
                    "notes": {"type": "string", "description": "测了哪些目标、为何成功或失败"},
                },
                "required": ["verdict", "notes"],
            },
            handler=_finish_verifier,
        )
    )


register_verifier_tools()

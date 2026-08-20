"""Verifier tools: FofaSearch, FinishVerifier."""

from __future__ import annotations

from typing import Any

from ..models import SessionLocal, Vuln
from ..services.fofa import FOFA_DEFAULT_SIZE, FOFA_MAX_PAGES, FOFA_MAX_TARGETS, search as fofa_search
from ..services.paths import vuln_dir
from ..services.asset_proof import format_fofa_rewrite_hint, load_project_fingerprints
from ..services.report import upsert_report_section
from ..services.verifier import (
    FOFA_MAX_ATTEMPTS,
    VERIFIER_FAILED,
    VERIFIER_SKIPPED,
    VERIFIER_SUCCESS_MIN,
    VERIFIER_VERIFIED,
    clip_evidence,
    dump_verifier_targets,
    fofa_cache_expanded,
    fofa_cache_has_targets,
    fofa_can_expand,
    fofa_expand_hint,
    fofa_page,
    fofa_pages_left,
    fofa_search_exhausted,
    format_verifier_report,
    has_verifier_consent,
    internet_harm_reason,
    load_project_fofa_cache,
    merge_fofa_samples,
    merge_verifier_targets,
    park_verifier_ask_user,
    parse_verifier_targets,
    resolve_fofa_sample,
    save_project_fofa_cache,
    seed_fofa_state,
    target_status_counts,
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


def _as_bool(raw: Any) -> bool:
    if isinstance(raw, bool):
        return raw
    return str(raw or "").strip().lower() in {"1", "true", "yes", "on"}


def _cached_fofa_payload(ctx, cache: dict[str, Any], *, guidance: str) -> dict[str, Any]:
    ctx.state["fofa_query"] = cache.get("query") or ctx.state.get("fofa_query") or ""
    ctx.state["fofa_targets"] = list(cache.get("sample") or [])
    ctx.state["fofa_cached"] = True
    page = fofa_page(cache)
    return {
        "ok": True,
        "cached": True,
        "expanded": fofa_cache_expanded(cache),
        "page": page,
        "pages_left": fofa_pages_left(cache),
        "query": cache.get("query") or "",
        "size": cache.get("size") or 0,
        "returned": cache.get("returned") or len(cache.get("sample") or []),
        "sample": list(cache.get("sample") or []),
        "guidance": guidance,
    }


def _expand_fofa_search(ctx, cache: dict[str, Any], args: dict[str, Any]) -> dict[str, Any]:
    if fofa_cache_expanded(cache):
        return _cached_fofa_payload(
            ctx,
            cache,
            guidance=(
                f"本项目已搜满 {FOFA_MAX_PAGES} 轮 FOFA 目标（每轮 {FOFA_DEFAULT_SIZE} 个，"
                f"最多 {FOFA_MAX_TARGETS} 个），不要再搜。"
                f"按现有样本复测：凑满 {VERIFIER_SUCCESS_MIN} 个成功即 FinishVerifier(success)；"
                f"全部测完仍不足则 fail。"
            ),
        )
    query = str(cache.get("query") or args.get("query") or "").strip()
    if not query:
        return call_fail("共享缓存没有 FOFA 语法，无法补搜。请先用项目指纹 FofaSearch。")
    next_page = fofa_page(cache) + 1
    out = fofa_search(query, size=FOFA_DEFAULT_SIZE, page=next_page)
    if not out.get("ok"):
        return out
    incoming = list(out.get("sample") or [])
    merged, new_rows = merge_fofa_samples(cache.get("sample") or [], incoming)
    if not incoming:
        next_page = FOFA_MAX_PAGES
    saved = save_project_fofa_cache(
        ctx.project_id,
        query=query,
        sample=merged,
        size=len(merged),
        attempts=int(cache.get("attempts") or 0),
        attempt_queries=list(cache.get("attempt_queries") or []),
        frozen=True,
        page=next_page,
    )
    ctx.state["fofa_query"] = saved["query"]
    ctx.state["fofa_targets"] = list(saved["sample"])
    ctx.state["fofa_cached"] = False
    pages_left = fofa_pages_left(saved)
    if new_rows:
        extra = (
            f"已补搜第 {next_page}/{FOFA_MAX_PAGES} 轮，新增 {len(new_rows)} 个目标"
            f"（去重后并入共享缓存，共 {len(merged)} 条）。保留此前成功的，只测这些新 host。"
            f"凑满 {VERIFIER_SUCCESS_MIN} 个成功即 FinishVerifier(success)。"
        )
        if pages_left > 0:
            extra += (
                f"本批测完仍不足则继续 FofaSearch(expand=true) 再搜 {FOFA_DEFAULT_SIZE} 个"
                f"（还可补搜 {pages_left} 轮）。"
            )
        else:
            extra += f"已达 {FOFA_MAX_PAGES} 轮上限，全部测完仍不足则 fail。"
    elif not incoming:
        extra = (
            f"FOFA 第 {fofa_page(cache) + 1} 页没有结果，视为已搜完。"
            f"按现有结果：已满 {VERIFIER_SUCCESS_MIN} 个成功则 success，否则 fail。"
        )
    else:
        extra = "本轮补搜没有新的去重目标。"
        if pages_left > 0:
            extra += (
                f"可再 FofaSearch(expand=true) 翻下一页（还可补搜 {pages_left} 轮）；"
                f"若确认没有更多目标：已满 {VERIFIER_SUCCESS_MIN} 个成功则 success，否则继续或 fail。"
            )
        else:
            extra += (
                f"已达 {FOFA_MAX_PAGES} 轮上限。"
                f"已满 {VERIFIER_SUCCESS_MIN} 个成功则 success，否则 fail。"
            )
    guidance = str(out.get("guidance") or "").strip()
    out["ok"] = True
    out["cached"] = False
    out["expanded"] = fofa_cache_expanded(saved)
    out["page"] = saved["page"]
    out["pages_left"] = pages_left
    out["query"] = saved["query"]
    out["size"] = saved["size"]
    out["returned"] = len(saved["sample"])
    out["sample"] = list(saved["sample"])
    out["new_sample"] = new_rows
    out["guidance"] = f"{guidance} {extra}".strip()
    return out


def _fofa_search(ctx, args: dict[str, Any]) -> dict[str, Any]:
    seed_fofa_state(ctx.state, ctx.project_id)
    cache = load_project_fofa_cache(ctx.project_id)
    expand = _as_bool(args.get("expand"))
    if fofa_cache_has_targets(cache) and expand:
        return _expand_fofa_search(ctx, cache, args)
    if fofa_cache_has_targets(cache):
        extra = (
            f"直接按这些目标复测；凑满 {VERIFIER_SUCCESS_MIN} 个成功即可 FinishVerifier(success)，其余 untested。"
            + fofa_expand_hint(cache)
        )
        return _cached_fofa_payload(
            ctx,
            cache,
            guidance=(
                "本项目已搜索过 FOFA 且已有命中，结果供全部漏洞共享。不要为换语法再搜。"
                + extra
                + "FinishVerifier.targets 覆盖全部样本；success 时带上 fofa_query。"
            ),
        )
    if fofa_search_exhausted(cache):
        tried = "；".join((cache or {}).get("attempt_queries") or []) or "（未记录）"
        return {
            "ok": True,
            "cached": True,
            "query": (cache or {}).get("query") or "",
            "size": 0,
            "returned": 0,
            "sample": [],
            "attempts": (cache or {}).get("attempts") or FOFA_MAX_ATTEMPTS,
            "guidance": (
                f"本项目 FOFA 已改写 {FOFA_MAX_ATTEMPTS} 次仍无样本（{tried}）。"
                "不要再搜，FinishVerifier(verdict=no_targets)。"
            ),
        }
    query = str(args.get("query") or "").strip()
    attempted_queries = list((cache or {}).get("attempt_queries") or [])
    if query and query in attempted_queries:
        left = max(0, FOFA_MAX_ATTEMPTS - int((cache or {}).get("attempts") or 0))
        return call_fail(
            "该 FOFA 语法已经搜过且无命中。"
            f"{format_fofa_rewrite_hint(load_project_fingerprints(ctx.project_id), attempted=attempted_queries, left=left)}"
        )
    out = fofa_search(query, size=FOFA_DEFAULT_SIZE, page=1)
    if not out.get("ok"):
        if out.get("account_error"):
            return out
        saved = save_project_fofa_cache(
            ctx.project_id,
            query=query,
            sample=[],
            size=0,
            attempts=int((cache or {}).get("attempts") or 0) + 1,
            attempt_queries=[*attempted_queries, query] if query else attempted_queries,
            frozen=False,
            page=1,
        )
        left = max(0, FOFA_MAX_ATTEMPTS - int(saved.get("attempts") or 0))
        extra = (
            f"语法未通过或接口失败。还可改写 {left} 次；"
            "仍失败则 FinishVerifier(verdict=no_targets)。账号/配额问题用 skipped。"
        )
        guidance = str(out.get("guidance") or "").strip()
        out["guidance"] = f"{guidance} {extra}".strip()
        out["attempts"] = saved["attempts"]
        return out
    sample = list(out.get("sample") or [])
    saved = save_project_fofa_cache(
        ctx.project_id,
        query=str(out.get("query") or query),
        sample=sample,
        size=int(out.get("size") or 0),
        attempts=int((cache or {}).get("attempts") or 0) + 1,
        attempt_queries=[*attempted_queries, query] if query else attempted_queries,
        frozen=bool(sample),
        page=1,
    )
    ctx.state["fofa_query"] = saved["query"]
    ctx.state["fofa_targets"] = list(saved["sample"])
    if sample:
        extra = (
            "已写入项目共享缓存 docs/fofa-targets.json，后续漏洞直接复用，不要为换语法再搜。"
            f"FinishVerifier.targets 必须覆盖这些样本。凑满 {VERIFIER_SUCCESS_MIN} 个成功即可结束，其余 untested。"
            f"{fofa_expand_hint(saved)} success 必须带 fofa_query。"
        )
    else:
        left = max(0, FOFA_MAX_ATTEMPTS - int(saved.get("attempts") or 0))
        extra = (
            "本次 0 条命中，未冻结共享缓存。"
            f"请改写语法再 FofaSearch。"
            f"{format_fofa_rewrite_hint(load_project_fingerprints(ctx.project_id), attempted=saved.get('attempt_queries') or attempted_queries, left=left)}"
            "仍无样本则 FinishVerifier(verdict=no_targets)。"
        )
    guidance = str(out.get("guidance") or "").strip()
    out["cached"] = False
    out["expanded"] = False
    out["page"] = saved["page"]
    out["pages_left"] = fofa_pages_left(saved)
    out["attempts"] = saved["attempts"]
    out["guidance"] = f"{guidance} {extra}".strip()
    return out


def _ask_user(ctx, args: dict[str, Any]) -> dict[str, Any]:
    vuln_id = args.get("vuln_id") or ctx.vuln_id
    if not vuln_id:
        return call_fail("缺少 vuln_id")
    reason = str(args.get("reason") or "").strip()
    question = str(args.get("question") or "").strip()
    out = park_verifier_ask_user(
        ctx.project_id,
        int(vuln_id),
        reason=reason,
        question=question,
    )
    if not out.get("ok"):
        return call_fail(str(out.get("error") or "AskUser 失败"))
    if out.get("already_consented"):
        ctx.state["awaiting_user"] = False
        return out
    ctx.state["awaiting_user"] = True
    ctx.state["ask_user_reason"] = reason
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
    with SessionLocal() as db:
        vuln = db.get(Vuln, int(vuln_id))
        if not vuln or vuln.project_id != ctx.project_id:
            return call_fail("漏洞不存在")
        vtype = vuln.vuln_type or ""
        title = vuln.title or ""
        http_request = vuln.http_request or ""
        stored_poc = vuln.poc_code or ""
        expected = vuln.expected_evidence or ""
        consented = has_verifier_consent(vuln)
        ask_reason = str(vuln.verifier_ask_reason or "").strip()
    harm = internet_harm_reason(
        vuln_type=vtype,
        title=title,
        http_request=http_request,
        poc_code="\n".join(p for p in (stored_poc, poc) if p),
        expected_evidence=expected,
    )
    if verdict == "skipped" and harm and not consented and not ask_reason:
        return call_fail(
            f"可能产生危害的漏洞须先 AskUser 询问用户，不要直接 skipped。原因：{harm}"
        )
    if verdict == "success":
        if not verified_url:
            return call_fail("success 必须提供 verified_url（实际打通的那个同款目标）")
        if not poc:
            return call_fail("success 必须提供 poc（对该目标实际发出的请求或脚本，原样粘贴）")
        if not response:
            return call_fail("success 必须提供 response（该目标的真实 HTTP 响应/回显，原样粘贴）")
        if harm and not consented:
            return call_fail(
                f"可能产生危害的复测须先 AskUser 并由用户同意。原因：{harm}"
            )
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
    success_n, _fail_n, untested_n = target_status_counts(targets)
    cache = load_project_fofa_cache(ctx.project_id)
    if verdict == "success" and success_n < VERIFIER_SUCCESS_MIN:
        if untested_n > 0:
            hint = f"还有 {untested_n} 个未测，请继续复测。"
        elif fofa_can_expand(cache):
            hint = (
                f"当前第 {fofa_page(cache)}/{FOFA_MAX_PAGES} 轮已测完仍不足 {VERIFIER_SUCCESS_MIN} 个成功。"
                f"保留已成功目标，FofaSearch(expand=true) 再搜 {FOFA_DEFAULT_SIZE} 个新目标"
                f"（还可补搜 {fofa_pages_left(cache)} 轮）。"
            )
        else:
            hint = (
                f"已搜满 {FOFA_MAX_PAGES} 轮仍不足 {VERIFIER_SUCCESS_MIN} 个成功，应 verdict=fail，不要标 success。"
            )
        return call_fail(
            f"success 须至少 {VERIFIER_SUCCESS_MIN} 个目标复测成功（当前 {success_n} 个）。{hint}"
        )
    if verdict == "fail":
        if success_n >= VERIFIER_SUCCESS_MIN:
            return call_fail(
                f"已有 {success_n} 个成功，应 verdict=success，不要 fail。"
            )
        if untested_n > 0:
            return call_fail(
                f"还有 {untested_n} 个未测目标，请继续复测；"
                f"本批测完仍不足 {VERIFIER_SUCCESS_MIN} 个成功再补搜或判 fail。"
            )
        if fofa_can_expand(cache):
            return call_fail(
                f"当前第 {fofa_page(cache)}/{FOFA_MAX_PAGES} 轮仍不足 {VERIFIER_SUCCESS_MIN} 个成功。"
                f"保留已成功目标，FofaSearch(expand=true) 再搜 {FOFA_DEFAULT_SIZE} 个新目标后再决定"
                f"（还可补搜 {fofa_pages_left(cache)} 轮，最多 {FOFA_MAX_TARGETS} 个目标）。"
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
                f"（host/ip/port/title/domain/org）。每批 {FOFA_DEFAULT_SIZE} 条。"
                "优先用 docs/app-fingerprints.json 的项目共享指纹。"
                "title/app 与默认页 body 特征各试一条，有命中就停，不要在同一方向反复改写。"
                f"有命中后写入共享缓存给全部漏洞复用；0 条可改写语法再搜，最多 {FOFA_MAX_ATTEMPTS} 次。"
                "若本项目已有命中，默认立即返回缓存、不再请求 FOFA。"
                f"当前这批测完仍不足 {VERIFIER_SUCCESS_MIN} 个成功时，传 expand=true 按同一语法翻页补搜 "
                f"{FOFA_DEFAULT_SIZE} 个新目标（最多 {FOFA_MAX_PAGES} 轮 / {FOFA_MAX_TARGETS} 个目标）。只查 FOFA，不碰目标。"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": 'FOFA 语法。title/app 与 body 特征各试一条，有命中即可',
                    },
                    "size": {
                        "type": "integer",
                        "description": f"每批样本数，固定 {FOFA_DEFAULT_SIZE}",
                        "default": FOFA_DEFAULT_SIZE,
                    },
                    "expand": {
                        "type": "boolean",
                        "description": (
                            f"当前这批测完仍不足 {VERIFIER_SUCCESS_MIN} 个成功时为 true，"
                            f"按已冻结语法再搜 {FOFA_DEFAULT_SIZE} 个新目标；不要改写语法。"
                            f"最多 {FOFA_MAX_PAGES} 轮。"
                        ),
                        "default": False,
                    },
                },
                "required": ["query"],
            },
            handler=_fofa_search,
        )
    )
    registry.register(
        ToolSpec(
            name="AskUser",
            description=(
                "当互联网复测可能中断或篡改对方业务（任意文件删除/上传、DoS、SQL 增删改等）时，"
                "必须先调用本工具询问用户是否继续。调用后本轮挂起，等待用户在「验证确认」页跳过或给出指示；"
                "不要 curl、不要 FinishVerifier(skipped)。用户同意后续跑会带回指示。"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "vuln_id": {"type": "integer"},
                    "reason": {
                        "type": "string",
                        "description": "为何可能产生危害、会打到什么操作（必填）",
                    },
                    "question": {
                        "type": "string",
                        "description": "可选：给用户的补充问题或建议的安全复测方式",
                    },
                },
                "required": ["reason"],
            },
            handler=_ask_user,
        )
    )
    registry.register(
        ToolSpec(
            name="FinishVerifier",
            description=(
                f"提交互联网验证结论并结束本轮。至少 {VERIFIER_SUCCESS_MIN} 个 FOFA 目标按报告复测成功才 verdict=success；"
                f"当前这批测完仍不足则保留成功的、FofaSearch(expand=true) 再搜下一轮"
                f"（最多 {FOFA_MAX_PAGES} 轮 / {FOFA_MAX_TARGETS} 个目标）；"
                f"{FOFA_MAX_PAGES} 轮都测完仍不足=fail；无样本=no_targets；无 key/网络不可用=skipped。"
                "success/fail 必须用 targets 列出共享 FOFA 的全部结果，并标注 success|fail|untested；"
                f"success 时 targets 里至少 {VERIFIER_SUCCESS_MIN} 条 success，并带 verified_url、poc、response、fofa_query。"
                "凑满成功数后其余可标 untested，不要为了填表继续打。"
                "可能产生危害的漏洞须先 AskUser；用户同意前禁止 success；不要用 skipped 代替询问。"
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
                            f"success 须至少 {VERIFIER_SUCCESS_MIN} 条 success；达线后其余可标 untested。"
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

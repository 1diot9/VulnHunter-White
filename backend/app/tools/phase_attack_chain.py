"""Attack-chain phase tools: SubmitAttackChain + IndexAttackChain + FinishAttackChain."""

from __future__ import annotations

import json
import logging
import re
from typing import Any

import yaml

from ..models import AttackChain, Project, SessionLocal, Vuln, utcnow
from ..services.paths import attack_chains_dir, project_root
from ..vuln_types import INTERACTIVE_VULN_TYPES, normalize_vuln_type
from . import ToolSpec, registry
from .common import call_fail

logger = logging.getLogger(__name__)

CONFIRMED_STATUSES = frozenset({"confirmed", "static_only"})
_SLUG_RE = re.compile(r"[^A-Za-z0-9._\u4e00-\u9fff-]+")

VERIFY_STATIC = "static"
VERIFY_VERIFIED = "verified"
VERIFY_SKIPPED_INTERACTION = "skipped_interaction"

VERIFY_STATUS_LABELS = {
    VERIFY_STATIC: "仅静态",
    VERIFY_VERIFIED: "已动态验证",
    VERIFY_SKIPPED_INTERACTION: "需用户交互，跳过动态验证",
}

CHAIN_RUN_TIMEOUT = 180
CHAIN_RUN_FAIL_HINT = (
    "串联脚本须在整条链打通时退出码 0。Write 修好 chain_script 后再次 SubmitAttackChain；"
    "脚本须 argparse 接收 -u/--url 与 --proxy（空则直连），不要写死靶场地址。"
)


def is_attack_chain_enabled(project_id: int) -> bool:
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        return bool(proj and getattr(proj, "attack_chain_enabled", False))


def is_attack_chain_done(project_id: int) -> bool:
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        return bool(proj and getattr(proj, "attack_chain_done", False))


def mark_attack_chain_done(project_id: int, *, reason: str = "") -> None:
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        if not proj:
            return
        proj.attack_chain_done = True
        proj.updated_at = utcnow()
        db.commit()
    from app.services.live_log import live_log as _live

    suffix = f"：{reason}" if reason else ""
    _live.system(project_id, f"攻击链阶段结束{suffix}", phase="attack_chain")


def clear_attack_chain_done(project_id: int) -> None:
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        if not proj:
            return
        proj.attack_chain_done = False
        proj.updated_at = utcnow()
        db.commit()


def attack_chain_prereqs(project_id: int) -> bool:
    """Mining finished and review/fix queue empty. Ignores the done stamp."""
    if not is_attack_chain_enabled(project_id):
        return False
    from .phase_worker import mining_complete

    if not mining_complete(project_id):
        return False
    return review_queue_empty(project_id)


def reclaim_premature_attack_chain_done(project_id: int) -> bool:
    """Undo a done stamp applied before mining/review actually finished."""
    if not is_attack_chain_done(project_id):
        return False
    if attack_chain_prereqs(project_id):
        return False
    clear_attack_chain_done(project_id)
    from app.services.live_log import live_log as _live

    _live.system(
        project_id,
        "攻击链曾在挖掘或审核未结束时收工，已撤回结束标记，全部结束后将重跑串联",
        phase="attack_chain",
    )
    return True


def confirmed_vuln_count(project_id: int) -> int:
    with SessionLocal() as db:
        return (
            db.query(Vuln)
            .filter(
                Vuln.project_id == project_id,
                Vuln.status.in_(tuple(CONFIRMED_STATUSES)),
            )
            .count()
        )


def review_queue_empty(project_id: int) -> bool:
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


def attack_chain_ready(project_id: int) -> bool:
    """Mining done + review queue empty + enabled + not yet done."""
    if is_attack_chain_done(project_id):
        return False
    return attack_chain_prereqs(project_id)


def resolve_attack_chain_lab_url(project_id: int) -> str | None:
    """Return running Docker lab target_url, optionally starting a previously accepted lab."""
    from ..services.lab import (
        lab_bring_up_failed,
        lab_had_docker_lab,
        lab_ready,
        load_env,
        recreate_lab,
    )

    if lab_bring_up_failed(project_id):
        return None
    env = load_env(project_id)
    if lab_ready(env):
        target = str(env.get("target_url") or "").strip()
        return target or None
    if not lab_had_docker_lab(project_id):
        return None
    rec = recreate_lab(project_id, mode="start")
    if not rec.get("ok"):
        return None
    env = load_env(project_id)
    if not lab_ready(env):
        return None
    target = str(env.get("target_url") or "").strip()
    return target or None


def chain_interaction_block(
    project_id: int,
    vuln_ids: list[int],
    *,
    needs_interaction: bool = False,
) -> dict[str, Any] | None:
    """If the chain needs victim/browser interaction, return skip metadata; else None."""
    if needs_interaction:
        return {
            "needs_interaction": True,
            "interactive_vuln_ids": [],
            "reason": "Agent 声明 needs_interaction=true（需受害者浏览器或人工点击等）",
        }
    with SessionLocal() as db:
        rows = (
            db.query(Vuln)
            .filter(Vuln.project_id == project_id, Vuln.id.in_(vuln_ids))
            .all()
        )
        by_id = {v.id: v for v in rows}
    interactive: list[dict[str, Any]] = []
    for vid in vuln_ids:
        row = by_id.get(vid)
        if not row:
            continue
        vtype = normalize_vuln_type(str(row.vuln_type or ""))
        if vtype in INTERACTIVE_VULN_TYPES:
            interactive.append({"vuln_id": vid, "vuln_type": vtype, "title": row.title})
    if not interactive:
        return None
    labels = ", ".join(f"#{x['vuln_id']}({x['vuln_type']})" for x in interactive)
    return {
        "needs_interaction": True,
        "interactive_vuln_ids": [x["vuln_id"] for x in interactive],
        "reason": f"链中含需用户交互的漏洞类型：{labels}（如 XSS/CSRF），跳过靶场动态验证",
    }


def _slug_filename(title: str) -> str:
    raw = (title or "chain").strip()
    slug = _SLUG_RE.sub("-", raw).strip("-._")
    slug = (slug or "chain")[:80]
    if not slug.lower().endswith(".md"):
        slug += ".md"
    return slug


def _parse_vuln_ids(raw: Any) -> list[int] | dict[str, Any]:
    if raw is None:
        return call_fail("缺少 vuln_ids")
    if isinstance(raw, str):
        text = raw.strip()
        if not text:
            return call_fail("vuln_ids 不能为空")
        try:
            raw = json.loads(text)
        except json.JSONDecodeError:
            parts = [p.strip() for p in text.replace(";", ",").split(",") if p.strip()]
            try:
                raw = [int(p.lstrip("#")) for p in parts]
            except ValueError:
                return call_fail("vuln_ids 须为整数数组")
    if not isinstance(raw, list) or not raw:
        return call_fail("vuln_ids 须为至少 2 个已确认漏洞 id 的数组")
    ids: list[int] = []
    seen: set[int] = set()
    for item in raw:
        try:
            vid = int(item)
        except (TypeError, ValueError):
            return call_fail(f"非法 vuln_id: {item!r}")
        if vid in seen:
            continue
        seen.add(vid)
        ids.append(vid)
    if len(ids) < 2:
        return call_fail("攻击链至少需要 2 个不同的已确认漏洞，禁止单洞假链")
    return ids


DETAILED_CHAIN_LIMIT = 3


def _ids_label(vuln_ids: Any) -> str:
    if isinstance(vuln_ids, list):
        parts: list[str] = []
        for x in vuln_ids:
            try:
                parts.append(f"#{int(x)}")
            except (TypeError, ValueError):
                parts.append(str(x))
        return ", ".join(parts)
    if isinstance(vuln_ids, str) and vuln_ids.strip().startswith("["):
        try:
            return _ids_label(json.loads(vuln_ids))
        except json.JSONDecodeError:
            return vuln_ids
    return str(vuln_ids or "")


def _confirm_chain_vulns(project_id: int, raw: Any) -> list[int] | dict[str, Any]:
    parsed = _parse_vuln_ids(raw)
    if isinstance(parsed, dict):
        return parsed
    vuln_ids = parsed
    with SessionLocal() as db:
        rows = (
            db.query(Vuln)
            .filter(Vuln.project_id == project_id, Vuln.id.in_(vuln_ids))
            .all()
        )
        by_id = {v.id: v for v in rows}
        missing = [vid for vid in vuln_ids if vid not in by_id]
        if missing:
            return call_fail(f"漏洞不存在或不属于本项目: {missing}")
        bad_status = [
            vid
            for vid in vuln_ids
            if (by_id[vid].status or "") not in CONFIRMED_STATUSES
        ]
        if bad_status:
            return call_fail(
                f"仅可串联已确认漏洞（confirmed/static_only），以下状态不符: {bad_status}"
            )
    return vuln_ids


def _chain_key(vuln_ids: list[int]) -> str:
    return json.dumps(vuln_ids, ensure_ascii=False)


def _session_chain_keys(ctx) -> set[str]:
    return {str(x) for x in (ctx.state.get("attack_chain_vuln_keys") or [])}


def _remember_chain_key(ctx, vuln_ids: list[int]) -> None:
    keys = list(ctx.state.get("attack_chain_vuln_keys") or [])
    keys.append(_chain_key(vuln_ids))
    ctx.state["attack_chain_vuln_keys"] = keys


def _session_detailed_count(ctx) -> int:
    return len(list(ctx.state.get("attack_chains_detailed") or []))


def _append_state_id(ctx, key: str, chain_id: int) -> None:
    items = list(ctx.state.get(key) or [])
    items.append(chain_id)
    ctx.state[key] = items
    submitted = list(ctx.state.get("attack_chains_submitted") or [])
    submitted.append(chain_id)
    ctx.state["attack_chains_submitted"] = submitted


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


def _load_project_chains(project_id: int) -> list[dict[str, Any]]:
    with SessionLocal() as db:
        rows = (
            db.query(AttackChain)
            .filter(AttackChain.project_id == project_id)
            .order_by(AttackChain.id.asc())
            .all()
        )
        return [
            {
                "title": r.title,
                "vuln_ids": r.vuln_ids,
                "summary": r.summary,
                "report_path": r.report_path,
                "verify_status": getattr(r, "verify_status", None) or VERIFY_STATIC,
                "script_path": getattr(r, "script_path", None),
            }
            for r in rows
        ]


def _is_detailed_row(row: dict[str, Any]) -> bool:
    path = str(row.get("report_path") or "").replace("\\", "/").strip()
    return bool(path) and not path.endswith("/index.md") and path != "docs/attack-chains/index.md"


def _verify_badge(status: str | None) -> str:
    key = (status or VERIFY_STATIC).strip() or VERIFY_STATIC
    label = VERIFY_STATUS_LABELS.get(key, key)
    return f"[{label}]"


def _rebuild_index(project_id: int) -> dict[str, int]:
    chain_dir = attack_chains_dir(project_id)
    rows = _load_project_chains(project_id)
    detailed = [r for r in rows if _is_detailed_row(r)]
    briefs = [r for r in rows if not _is_detailed_row(r)]
    lines = [
        "# 攻击链索引",
        "",
        "详文只保留危害最大、利用最简单的最多 3 条；其余真链见「其他简述」。",
        "有本地 Docker 靶场时，无用户交互的详文链会动态验证并落盘 chain 脚本。",
        "",
        "## 详文",
        "",
    ]
    if not detailed:
        lines.append("（无）")
    else:
        for row in detailed:
            label = _ids_label(row.get("vuln_ids"))
            rel = str(row.get("report_path") or "").replace("\\", "/")
            badge = _verify_badge(str(row.get("verify_status") or ""))
            lines.append(f"- **{row['title']}** {badge}（{label}）→ `{rel}`")
            script = str(row.get("script_path") or "").strip()
            if script:
                lines.append(f"  - 脚本：`{script}`")
            if row.get("summary"):
                lines.append(f"  - {row['summary']}")
    lines.extend(["", "## 其他简述", ""])
    if not briefs:
        lines.append("（无）")
    else:
        for row in briefs:
            label = _ids_label(row.get("vuln_ids"))
            badge = _verify_badge(str(row.get("verify_status") or ""))
            lines.append(f"- **{row['title']}** {badge}（{label}）")
            if row.get("summary"):
                lines.append(f"  - {row['summary']}")
    lines.append("")
    (chain_dir / "index.md").write_text("\n".join(lines), encoding="utf-8")
    return {"detailed": len(detailed), "briefs": len(briefs), "indexed": len(rows)}


def _insert_chain(
    *,
    project_id: int,
    title: str,
    vuln_ids: list[int],
    summary: str,
    report_path: str | None,
    verify_status: str = VERIFY_STATIC,
    script_path: str | None = None,
) -> int:
    with SessionLocal() as db:
        row = AttackChain(
            project_id=project_id,
            title=title,
            vuln_ids=json.dumps(vuln_ids, ensure_ascii=False),
            summary=summary or None,
            report_path=report_path,
            verify_status=verify_status or VERIFY_STATIC,
            script_path=script_path,
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        return int(row.id)


def _run_chain_script(
    project_id: int,
    script: str,
    *,
    target_url: str,
) -> dict[str, Any]:
    from ..services.poc_run import execute_poc_text
    from ..services.poc_script import poc_lab_run_block_reason

    blocked = poc_lab_run_block_reason(script)
    if blocked:
        return {"ok": False, "error": blocked, "hint": CHAIN_RUN_FAIL_HINT}
    logger.info(
        "running attack-chain script project=%s target=%s",
        project_id,
        target_url,
    )
    result = execute_poc_text(
        script,
        target_url=target_url,
        cwd=project_root(project_id),
        timeout=CHAIN_RUN_TIMEOUT,
        project_id=project_id,
    )
    if not result.get("ok"):
        result = dict(result)
        result.setdefault("hint", CHAIN_RUN_FAIL_HINT)
    return result


def _submit_attack_chain(ctx, args: dict[str, Any]) -> dict[str, Any]:
    title = str(args.get("title") or "").strip()
    if not title:
        return call_fail("缺少 title")
    summary = str(args.get("summary") or "").strip()
    steps = str(args.get("steps") or args.get("content") or args.get("body") or "").strip()
    if not steps:
        return call_fail("缺少 steps（多步利用文档正文）")
    parsed = _confirm_chain_vulns(ctx.project_id, args.get("vuln_ids"))
    if isinstance(parsed, dict):
        return parsed
    vuln_ids = parsed
    if _chain_key(vuln_ids) in _session_chain_keys(ctx):
        return call_fail("本轮已提交过相同 vuln_ids 的链，不要重复提交")
    if _session_detailed_count(ctx) >= DETAILED_CHAIN_LIMIT:
        return call_fail(
            f"详文最多 {DETAILED_CHAIN_LIMIT} 条。其余真链请用 IndexAttackChain 写入索引简述，"
            "或在 FinishAttackChain(other_chains=...) 里一次性补交。"
        )

    needs_interaction = _truthy(args.get("needs_interaction"))
    interaction = chain_interaction_block(
        ctx.project_id, vuln_ids, needs_interaction=needs_interaction
    )
    chain_script = str(
        args.get("chain_script") or args.get("script") or args.get("poc_code") or ""
    ).strip()
    lab_url = resolve_attack_chain_lab_url(ctx.project_id)

    verify_status = VERIFY_STATIC
    script_rel: str | None = None
    verify_meta: dict[str, Any] = {}

    if interaction:
        verify_status = VERIFY_SKIPPED_INTERACTION
        verify_meta = {
            "skipped_interaction": True,
            "reason": interaction["reason"],
            "interactive_vuln_ids": interaction.get("interactive_vuln_ids") or [],
        }
        # Optional: still land a script for humans, but do not execute.
        if chain_script:
            pass  # written below with md
    elif lab_url:
        if not chain_script:
            return call_fail(
                "本地 Docker 靶场可用，且本链无需用户交互：须提供 chain_script（可独立运行的 "
                "Python 串联脚本，argparse -u/--url 与 --proxy）。"
                "若链含 XSS/CSRF 等需受害者交互，请传 needs_interaction=true 并跳过脚本。"
            )
        run = _run_chain_script(ctx.project_id, chain_script, target_url=lab_url)
        if not run.get("ok"):
            err = str(run.get("error") or "串联脚本未打通")
            return {
                "ok": False,
                "error": err,
                "hint": run.get("hint") or CHAIN_RUN_FAIL_HINT,
                "target_url": lab_url,
                "exit_code": run.get("exit_code"),
                "stdout": run.get("stdout"),
                "stderr": run.get("stderr"),
                "timed_out": run.get("timed_out"),
            }
        verify_status = VERIFY_VERIFIED
        verify_meta = {
            "verified": True,
            "target_url": lab_url,
            "exit_code": run.get("exit_code"),
            "stdout": run.get("stdout"),
        }

    chain_dir = attack_chains_dir(ctx.project_id)
    name = _slug_filename(title)
    target = chain_dir / name
    n = 2
    stem = target.stem
    while target.exists() or (chain_dir / f"{target.stem}.py").exists():
        target = chain_dir / f"{stem}-{n}.md"
        n += 1

    if chain_script:
        script_path = chain_dir / f"{target.stem}.py"
        script_path.write_text(chain_script if chain_script.endswith("\n") else chain_script + "\n", encoding="utf-8")
        script_rel = f"docs/attack-chains/{script_path.name}"

    meta = {
        "title": title,
        "summary": summary,
        "vuln_ids": vuln_ids,
        "verify_status": verify_status,
    }
    if script_rel:
        meta["script_path"] = script_rel
    if interaction:
        meta["needs_interaction"] = True
    front = yaml.safe_dump(meta, allow_unicode=True, sort_keys=False).strip()
    text = f"---\n{front}\n---\n\n{steps.strip()}\n"
    target.write_text(text, encoding="utf-8")
    rel = f"docs/attack-chains/{target.name}"
    chain_id = _insert_chain(
        project_id=ctx.project_id,
        title=title,
        vuln_ids=vuln_ids,
        summary=summary,
        report_path=rel,
        verify_status=verify_status,
        script_path=script_rel,
    )
    _remember_chain_key(ctx, vuln_ids)
    _append_state_id(ctx, "attack_chains_detailed", chain_id)
    indexed = _rebuild_index(ctx.project_id)
    left = DETAILED_CHAIN_LIMIT - _session_detailed_count(ctx)
    extra = (
        f"还可再写 {left} 条详文。"
        if left > 0
        else "详文已满 3 条，其余真链请 IndexAttackChain 简述。"
    )
    status_label = VERIFY_STATUS_LABELS.get(verify_status, verify_status)
    return {
        "ok": True,
        "chain_id": chain_id,
        "path": rel,
        "script_path": script_rel,
        "kind": "detailed",
        "title": title,
        "vuln_ids": vuln_ids,
        "verify_status": verify_status,
        "verify_status_label": status_label,
        "detailed_count": indexed["detailed"],
        "brief_count": indexed["briefs"],
        "indexed": indexed["indexed"],
        **verify_meta,
        "message": f"已提交攻击链详文（{status_label}）。{extra}",
    }


def _record_brief(ctx, args: dict[str, Any]) -> dict[str, Any]:
    title = str(args.get("title") or "").strip()
    if not title:
        return call_fail("缺少 title")
    summary = str(args.get("summary") or "").strip()
    if not summary:
        return call_fail("简述须提供 summary（一句话写清洞序、怎么接、危害到哪）")
    parsed = _confirm_chain_vulns(ctx.project_id, args.get("vuln_ids"))
    if isinstance(parsed, dict):
        return parsed
    vuln_ids = parsed
    if _chain_key(vuln_ids) in _session_chain_keys(ctx):
        return call_fail("本轮已提交过相同 vuln_ids 的链，不要重复提交")
    needs_interaction = _truthy(args.get("needs_interaction"))
    interaction = chain_interaction_block(
        ctx.project_id, vuln_ids, needs_interaction=needs_interaction
    )
    verify_status = VERIFY_SKIPPED_INTERACTION if interaction else VERIFY_STATIC
    chain_id = _insert_chain(
        project_id=ctx.project_id,
        title=title,
        vuln_ids=vuln_ids,
        summary=summary,
        report_path=None,
        verify_status=verify_status,
        script_path=None,
    )
    _remember_chain_key(ctx, vuln_ids)
    _append_state_id(ctx, "attack_chains_briefs", chain_id)
    indexed = _rebuild_index(ctx.project_id)
    return {
        "ok": True,
        "chain_id": chain_id,
        "path": "docs/attack-chains/index.md",
        "kind": "brief",
        "title": title,
        "vuln_ids": vuln_ids,
        "verify_status": verify_status,
        "verify_status_label": VERIFY_STATUS_LABELS.get(verify_status, verify_status),
        "detailed_count": indexed["detailed"],
        "brief_count": indexed["briefs"],
        "indexed": indexed["indexed"],
        "message": "已写入索引简述，不生成独立详文，不做动态验证。",
    }


def _index_attack_chain(ctx, args: dict[str, Any]) -> dict[str, Any]:
    return _record_brief(ctx, args)


def _parse_other_chains(raw: Any) -> list[dict[str, Any]] | dict[str, Any]:
    if raw in (None, "", [], ()):
        return []
    if isinstance(raw, str):
        text = raw.strip()
        if not text:
            return []
        try:
            raw = json.loads(text)
        except json.JSONDecodeError:
            return call_fail("other_chains 须为对象数组")
    if not isinstance(raw, list):
        return call_fail("other_chains 须为对象数组")
    out: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            return call_fail("other_chains 每项须为对象（title, vuln_ids, summary）")
        out.append(item)
    return out


def _finish_attack_chain(ctx, args: dict[str, Any]) -> dict[str, Any]:
    notes = str(args.get("notes") or args.get("reason") or "").strip()
    parsed = _parse_other_chains(args.get("other_chains") or args.get("briefs"))
    if isinstance(parsed, dict):
        return parsed
    brief_results: list[dict[str, Any]] = []
    for item in parsed:
        result = _record_brief(ctx, item)
        if not result.get("ok"):
            return result
        brief_results.append(result)
    submitted = list(ctx.state.get("attack_chains_submitted") or [])
    detailed_n = _session_detailed_count(ctx)
    brief_n = len(list(ctx.state.get("attack_chains_briefs") or []))
    reason = notes
    if not reason:
        if submitted:
            reason = f"详文 {detailed_n} 条，简述 {brief_n} 条"
        else:
            reason = "无合理串联"
    mark_attack_chain_done(ctx.project_id, reason=reason)
    ctx.state["attack_chain_done"] = True
    return {
        "ok": True,
        "submitted_count": len(submitted),
        "detailed_count": detailed_n,
        "brief_count": brief_n,
        "chain_ids": submitted,
        "other_chain_ids": [r["chain_id"] for r in brief_results],
        "notes": notes,
        "message": "攻击链阶段结束。",
    }


def register_attack_chain_tools() -> None:
    registry.register(
        ToolSpec(
            name="SubmitAttackChain",
            description=(
                "提交一条详文攻击链（最多 3 条）。只用于危害最大、利用最简单的链；"
                "须引用至少 2 个本项目已确认漏洞 id，steps 为多步利用正文。"
                "有本地 Docker 靶场且链无需用户交互时，须传 chain_script；"
                "系统会对靶场执行该脚本，退出码非 0 则拒绝提交。"
                "含 XSS/CSRF 等需受害者交互的链传 needs_interaction=true，跳过动态验证。"
                "其余真链用 IndexAttackChain 简述。"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "vuln_ids": {
                        "type": "array",
                        "items": {"type": "integer"},
                        "description": "按利用顺序排列的已确认漏洞 id，至少 2 个",
                    },
                    "summary": {"type": "string", "description": "一句话摘要"},
                    "steps": {
                        "type": "string",
                        "description": "多步利用 Markdown 正文",
                    },
                    "chain_script": {
                        "type": "string",
                        "description": (
                            "可独立运行的 Python 串联脚本（有 Docker 靶场且无用户交互时必填）。"
                            "须 argparse -u/--url 与 --proxy；成功打通整链退出 0。"
                        ),
                    },
                    "needs_interaction": {
                        "type": "boolean",
                        "description": (
                            "链需要受害者浏览器/人工点击等交互时为 true（如 XSS），"
                            "跳过靶场动态验证；也可由系统根据 vuln_type=xss/stored_xss/csrf 自动判定"
                        ),
                    },
                },
                "required": ["title", "vuln_ids", "steps"],
            },
            handler=_submit_attack_chain,
        )
    )
    registry.register(
        ToolSpec(
            name="IndexAttackChain",
            description=(
                "将未进详文的真链写入索引简述，不生成独立文档，不做动态验证。"
                "summary 须一句话写清洞序、怎么接、危害到哪。"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "vuln_ids": {
                        "type": "array",
                        "items": {"type": "integer"},
                        "description": "按利用顺序排列的已确认漏洞 id，至少 2 个",
                    },
                    "summary": {
                        "type": "string",
                        "description": "一句话简述：洞序、衔接、扩大后的危害",
                    },
                    "needs_interaction": {
                        "type": "boolean",
                        "description": "链需用户交互时可选标记（索引仍只写简述）",
                    },
                },
                "required": ["title", "vuln_ids", "summary"],
            },
            handler=_index_attack_chain,
        )
    )
    registry.register(
        ToolSpec(
            name="FinishAttackChain",
            description=(
                "结束攻击链阶段。找不到合理串联时也必须调用（notes 说明原因），不要硬凑。"
                "other_chains 可一次性补交未进详文的简述。"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "notes": {
                        "type": "string",
                        "description": "收工说明：详文几条、简述几条，或为何没有可串联项",
                    },
                    "other_chains": {
                        "type": "array",
                        "description": "未进详文的其余真链，只写入索引简述",
                        "items": {
                            "type": "object",
                            "properties": {
                                "title": {"type": "string"},
                                "vuln_ids": {
                                    "type": "array",
                                    "items": {"type": "integer"},
                                },
                                "summary": {"type": "string"},
                            },
                            "required": ["title", "vuln_ids", "summary"],
                        },
                    },
                },
                "required": ["notes"],
            },
            handler=_finish_attack_chain,
        )
    )


register_attack_chain_tools()

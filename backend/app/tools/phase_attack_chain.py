"""Attack-chain phase tools: SubmitAttackChain + IndexAttackChain + FinishAttackChain."""

from __future__ import annotations

import json
import re
from typing import Any

import yaml

from ..models import AttackChain, Project, SessionLocal, Vuln, utcnow
from ..services.paths import attack_chains_dir
from . import ToolSpec, registry
from .common import call_fail

CONFIRMED_STATUSES = frozenset({"confirmed", "static_only"})
_SLUG_RE = re.compile(r"[^A-Za-z0-9._\u4e00-\u9fff-]+")


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
            }
            for r in rows
        ]


def _is_detailed_row(row: dict[str, Any]) -> bool:
    path = str(row.get("report_path") or "").replace("\\", "/").strip()
    return bool(path) and not path.endswith("/index.md") and path != "docs/attack-chains/index.md"


def _rebuild_index(project_id: int) -> dict[str, int]:
    chain_dir = attack_chains_dir(project_id)
    rows = _load_project_chains(project_id)
    detailed = [r for r in rows if _is_detailed_row(r)]
    briefs = [r for r in rows if not _is_detailed_row(r)]
    lines = [
        "# 攻击链索引",
        "",
        "详文只保留危害最大、利用最简单的最多 3 条；其余真链见「其他简述」。",
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
            lines.append(f"- **{row['title']}**（{label}）→ `{rel}`")
            if row.get("summary"):
                lines.append(f"  - {row['summary']}")
    lines.extend(["", "## 其他简述", ""])
    if not briefs:
        lines.append("（无）")
    else:
        for row in briefs:
            label = _ids_label(row.get("vuln_ids"))
            lines.append(f"- **{row['title']}**（{label}）")
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
) -> int:
    with SessionLocal() as db:
        row = AttackChain(
            project_id=project_id,
            title=title,
            vuln_ids=json.dumps(vuln_ids, ensure_ascii=False),
            summary=summary or None,
            report_path=report_path,
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        return int(row.id)


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

    chain_dir = attack_chains_dir(ctx.project_id)
    name = _slug_filename(title)
    target = chain_dir / name
    n = 2
    stem = target.stem
    while target.exists():
        target = chain_dir / f"{stem}-{n}.md"
        n += 1

    meta = {
        "title": title,
        "summary": summary,
        "vuln_ids": vuln_ids,
    }
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
    return {
        "ok": True,
        "chain_id": chain_id,
        "path": rel,
        "kind": "detailed",
        "title": title,
        "vuln_ids": vuln_ids,
        "detailed_count": indexed["detailed"],
        "brief_count": indexed["briefs"],
        "indexed": indexed["indexed"],
        "message": f"已提交攻击链详文。{extra}",
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
    chain_id = _insert_chain(
        project_id=ctx.project_id,
        title=title,
        vuln_ids=vuln_ids,
        summary=summary,
        report_path=None,
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
        "detailed_count": indexed["detailed"],
        "brief_count": indexed["briefs"],
        "indexed": indexed["indexed"],
        "message": "已写入索引简述，不生成独立详文。",
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
                "将未进详文的真链写入索引简述，不生成独立文档。"
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

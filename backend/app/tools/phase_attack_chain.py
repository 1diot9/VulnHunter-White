"""Attack-chain phase tools: SubmitAttackChain + FinishAttackChain."""

from __future__ import annotations

import json
import re
from pathlib import Path
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
    if not is_attack_chain_enabled(project_id):
        return False
    if is_attack_chain_done(project_id):
        return False
    from .phase_worker import mining_complete

    if not mining_complete(project_id):
        return False
    return review_queue_empty(project_id)


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


def _rebuild_index(chain_dir: Path) -> int:
    rows: list[tuple[str, str, str]] = []
    for fp in sorted(chain_dir.glob("*.md")):
        if fp.name == "index.md":
            continue
        text = fp.read_text(encoding="utf-8", errors="ignore")
        meta: dict[str, Any] = {}
        if text.lstrip().startswith("---"):
            try:
                from .common import _parse_frontmatter

                meta, _ = _parse_frontmatter(text)
            except Exception:  # noqa: BLE001
                meta = {}
        title = str(meta.get("title") or fp.stem)
        summary = str(meta.get("summary") or "").strip()
        vuln_ids = meta.get("vuln_ids") or []
        if isinstance(vuln_ids, list):
            ids_label = ", ".join(f"#{int(x)}" for x in vuln_ids)
        else:
            ids_label = str(vuln_ids)
        rows.append((title, summary, ids_label))
    lines = ["# 攻击链索引", ""]
    if not rows:
        lines.append("（尚无攻击链）")
    else:
        for title, summary, ids_label in rows:
            lines.append(f"- **{title}**（{ids_label}）")
            if summary:
                lines.append(f"  - {summary}")
    lines.append("")
    (chain_dir / "index.md").write_text("\n".join(lines), encoding="utf-8")
    return len(rows)


def _submit_attack_chain(ctx, args: dict[str, Any]) -> dict[str, Any]:
    title = str(args.get("title") or "").strip()
    if not title:
        return call_fail("缺少 title")
    summary = str(args.get("summary") or "").strip()
    steps = str(args.get("steps") or args.get("content") or args.get("body") or "").strip()
    if not steps:
        return call_fail("缺少 steps（多步利用文档正文）")
    parsed = _parse_vuln_ids(args.get("vuln_ids"))
    if isinstance(parsed, dict):
        return parsed
    vuln_ids = parsed

    with SessionLocal() as db:
        rows = (
            db.query(Vuln)
            .filter(Vuln.project_id == ctx.project_id, Vuln.id.in_(vuln_ids))
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
    indexed = _rebuild_index(chain_dir)

    with SessionLocal() as db:
        row = AttackChain(
            project_id=ctx.project_id,
            title=title,
            vuln_ids=json.dumps(vuln_ids, ensure_ascii=False),
            summary=summary or None,
            report_path=rel,
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        chain_id = int(row.id)

    submitted = list(ctx.state.get("attack_chains_submitted") or [])
    submitted.append(chain_id)
    ctx.state["attack_chains_submitted"] = submitted
    return {
        "ok": True,
        "chain_id": chain_id,
        "path": rel,
        "title": title,
        "vuln_ids": vuln_ids,
        "indexed": indexed,
        "message": "已提交攻击链文档。可继续提交其它链，或调用 FinishAttackChain 结束本阶段。",
    }


def _finish_attack_chain(ctx, args: dict[str, Any]) -> dict[str, Any]:
    notes = str(args.get("notes") or args.get("reason") or "").strip()
    submitted = list(ctx.state.get("attack_chains_submitted") or [])
    mark_attack_chain_done(
        ctx.project_id,
        reason=notes or (f"已提交 {len(submitted)} 条" if submitted else "无合理串联"),
    )
    ctx.state["attack_chain_done"] = True
    return {
        "ok": True,
        "submitted_count": len(submitted),
        "chain_ids": submitted,
        "notes": notes,
        "message": "攻击链阶段结束。",
    }


def register_attack_chain_tools() -> None:
    registry.register(
        ToolSpec(
            name="SubmitAttackChain",
            description=(
                "提交一条多漏洞攻击链。须引用至少 2 个本项目已确认漏洞 id；"
                "steps 为文档正文，说明每步用哪条洞、前置如何被上一步满足、扩大后的危害。"
                "可多次提交；全部完成后调用 FinishAttackChain。"
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
            name="FinishAttackChain",
            description=(
                "结束攻击链阶段。找不到合理串联时也必须调用（notes 说明原因），不要硬凑。"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "notes": {
                        "type": "string",
                        "description": "收工说明：提交了几条链，或为何没有可串联项",
                    },
                },
                "required": ["notes"],
            },
            handler=_finish_attack_chain,
        )
    )


register_attack_chain_tools()

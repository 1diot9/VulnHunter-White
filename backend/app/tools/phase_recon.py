"""Recon-phase tools: MarkSource, MarkWeight, MarkSkip, WriteOldVuln."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from ..models import FileWeight, Project, SessionLocal, Source
from ..services.paths import docs_dir, old_vulns_dir
from . import ToolSpec, registry
from .common import _parse_frontmatter


def _doc_nonempty(path: Path) -> bool:
    return path.exists() and path.stat().st_size > 0


def recon_map_ready(project_id: int) -> bool:
    docs = docs_dir(project_id)
    return _doc_nonempty(docs / "code-map.md") and _doc_nonempty(docs / "auth.md")


def _truthy_meta(val: Any) -> bool:
    if isinstance(val, bool):
        return val
    if val is None:
        return False
    return str(val).strip().lower() in {"1", "true", "yes", "y"}


def _old_vuln_index_path(project_id: int) -> Path:
    return old_vulns_dir(project_id) / "index.md"


def _old_vuln_search_complete(index_path: Path) -> bool:
    if not _doc_nonempty(index_path):
        return False
    text = index_path.read_text(encoding="utf-8", errors="ignore")
    meta, _ = _parse_frontmatter(text)
    return _truthy_meta(meta.get("complete"))


def recon_old_vulns_ready(project_id: int) -> bool:
    """True only after the agent declares search complete — not after the first WriteOldVuln."""
    return _old_vuln_search_complete(_old_vuln_index_path(project_id))


def recon_gates_status(project_id: int) -> dict[str, Any]:
    """Check recon completion gates. Does not mutate DB."""
    docs = docs_dir(project_id)
    map_missing = [
        name
        for name, path in (
            ("code-map.md", docs / "code-map.md"),
            ("auth.md", docs / "auth.md"),
        )
        if not _doc_nonempty(path)
    ]
    old_index = _old_vuln_index_path(project_id)
    old_index_ready = _doc_nonempty(old_index)
    old_done = recon_old_vulns_ready(project_id)
    old_missing = [] if old_index_ready else ["old-vulns/index.md"]
    missing = map_missing + old_missing
    with SessionLocal() as db:
        unmarked = (
            db.query(FileWeight)
            .filter(
                FileWeight.project_id == project_id,
                FileWeight.skipped.is_(False),
                FileWeight.weight.is_(None),
            )
            .count()
        )
        total = db.query(FileWeight).filter(FileWeight.project_id == project_id).count()
    mark_done = unmarked == 0
    errors: list[str] = []
    if map_missing:
        errors.append(f"缺少代码地图/鉴权文档: {', '.join(map_missing)}")
    if old_missing:
        errors.append("缺少历史漏洞索引 old-vulns/index.md；请用 WriteOldVuln 逐条落盘，不要用 Write 攒到最后")
    elif not old_done:
        errors.append(
            "历史漏洞检索尚未结束；逐条 WriteOldVuln 只落盘、不会结束本会话，"
            "检索全部结束后再 WriteOldVuln(done=true)"
        )
    if unmarked > 0:
        errors.append(f"仍有 {unmarked}/{total} 个文件未标记权重（可用 MarkWeight/MarkSkip）")
    subphases = [
        {"id": "map", "label": "代码地图/鉴权", "done": not map_missing},
        {"id": "old_vulns", "label": "历史漏洞", "done": old_done},
        {"id": "mark", "label": "文件盖章", "done": mark_done},
    ]
    return {
        "ok": not errors,
        "missing_docs": missing,
        "missing_map_docs": map_missing,
        "missing_old_vuln_docs": old_missing,
        "unmarked": unmarked,
        "total": total,
        "errors": errors,
        "subphases": subphases,
    }


def recon_gates_met(project_id: int) -> bool:
    return bool(recon_gates_status(project_id).get("ok"))


def recon_docs_ready(project_id: int) -> bool:
    return recon_map_ready(project_id) and recon_old_vulns_ready(project_id)


def recon_subphases(project_id: int, unmarked: int | None = None) -> list[dict[str, Any]]:
    if unmarked is None:
        return list(recon_gates_status(project_id).get("subphases") or [])
    docs = docs_dir(project_id)
    map_done = _doc_nonempty(docs / "code-map.md") and _doc_nonempty(docs / "auth.md")
    old_done = recon_old_vulns_ready(project_id)
    return [
        {"id": "map", "label": "代码地图/鉴权", "done": map_done},
        {"id": "old_vulns", "label": "历史漏洞", "done": old_done},
        {"id": "mark", "label": "文件盖章", "done": unmarked == 0},
    ]


def normalize_weight_path(path: str) -> str:
    p = str(path or "").replace("\\", "/").lstrip("./")
    if p.startswith("src/"):
        p = p[4:]
    return p


def _score_unmarked_path(path: str) -> tuple[int, str]:
    pl = path.lower()
    boost = 0
    for kw in ("controller", "router", "view", "api", "handler", "servlet", "resource"):
        if kw in pl:
            boost -= 10
    return (boost, path)


def pick_unmarked_batch(project_id: int, limit: int) -> list[str]:
    n = max(1, int(limit))
    with SessionLocal() as db:
        rows = (
            db.query(FileWeight)
            .filter(
                FileWeight.project_id == project_id,
                FileWeight.skipped.is_(False),
                FileWeight.weight.is_(None),
            )
            .order_by(FileWeight.path)
            .limit(n)
            .all()
        )
        paths = sorted((r.path for r in rows), key=_score_unmarked_path)
    return paths[:n]


def paths_fully_marked(project_id: int, paths: list[str]) -> bool:
    want = [normalize_weight_path(p) for p in paths if normalize_weight_path(p)]
    if not want:
        return True
    with SessionLocal() as db:
        rows = (
            db.query(FileWeight)
            .filter(FileWeight.project_id == project_id, FileWeight.path.in_(want))
            .all()
        )
        by_path = {r.path: r for r in rows}
        for p in want:
            row = by_path.get(p)
            if row is None:
                return False
            if not row.skipped and row.weight is None:
                return False
    return True


def apply_recon_done(project_id: int) -> bool:
    """Set recon_done if gates are met. Returns True if now done."""
    if not recon_gates_met(project_id):
        return False
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        if not proj:
            return False
        proj.recon_done = True
        if proj.phase == "recon":
            proj.phase = "worker"
        db.commit()
    return True


def _normalize_paths(args: dict[str, Any]) -> list[str]:
    paths = args.get("paths") or args.get("path") or args.get("files")
    if isinstance(paths, str):
        paths = [paths]
    if not paths:
        return []
    return [normalize_weight_path(p) for p in paths if normalize_weight_path(p)]


def _mark_source(ctx, args: dict[str, Any]) -> dict[str, Any]:
    items = args.get("sources") or args.get("items")
    if not items:
        # single form
        file_path = args.get("file") or args.get("file_path") or args.get("path")
        method = args.get("method") or args.get("method_name")
        if file_path and method:
            items = [{"file": file_path, "method": method, "note": args.get("note")}]
    if not items or not isinstance(items, list):
        return {"ok": False, "error": "需要 sources 数组或 file+method"}
    marked = []
    with SessionLocal() as db:
        for it in items:
            if not isinstance(it, dict):
                continue
            fp = str(it.get("file") or it.get("file_path") or it.get("path") or "").replace("\\", "/")
            method = str(it.get("method") or it.get("method_name") or "").strip()
            if not fp or not method:
                continue
            if fp.startswith("src/"):
                fp = fp[4:]
            db.add(
                Source(
                    project_id=ctx.project_id,
                    file_path=fp,
                    method_name=method,
                    note=str(it.get("note") or "") or None,
                )
            )
            fw = (
                db.query(FileWeight)
                .filter(FileWeight.project_id == ctx.project_id, FileWeight.path == fp)
                .first()
            )
            if fw:
                fw.has_source = True
                fw.weight = 100
                fw.skipped = False
            marked.append({"file": fp, "method": method})
        db.commit()
    return {"ok": True, "marked": marked, "count": len(marked)}


def _mark_weight(ctx, args: dict[str, Any]) -> dict[str, Any]:
    paths = _normalize_paths(args)
    weight = args.get("weight")
    if weight is None:
        return {"ok": False, "error": "缺少 weight"}
    try:
        weight = int(weight)
    except (TypeError, ValueError):
        return {"ok": False, "error": "weight 必须是整数"}
    if not paths:
        return {"ok": False, "error": "缺少 path/paths"}
    updated = []
    with SessionLocal() as db:
        for p in paths:
            if p.startswith("src/"):
                p = p[4:]
            fw = (
                db.query(FileWeight)
                .filter(FileWeight.project_id == ctx.project_id, FileWeight.path == p)
                .first()
            )
            if not fw:
                continue
            if fw.has_source:
                fw.weight = 100
            else:
                fw.weight = weight
            fw.skipped = False
            updated.append({"path": p, "weight": fw.weight})
        db.commit()
    return {"ok": True, "updated": updated, "count": len(updated)}


def _mark_skip(ctx, args: dict[str, Any]) -> dict[str, Any]:
    paths = _normalize_paths(args)
    if not paths:
        return {"ok": False, "error": "缺少 path/paths"}
    updated = []
    with SessionLocal() as db:
        for p in paths:
            if p.startswith("src/"):
                p = p[4:]
            fw = (
                db.query(FileWeight)
                .filter(FileWeight.project_id == ctx.project_id, FileWeight.path == p)
                .first()
            )
            if not fw:
                continue
            fw.skipped = True
            fw.weight = 0
            updated.append(p)
        db.commit()
    return {"ok": True, "skipped": updated, "count": len(updated)}


_SLUG_RE = re.compile(r"[^\w.\-\u4e00-\u9fff]+", re.UNICODE)
_WRITE_NOW_HINT = (
    "已落盘。请立即继续下一条/下一批，不要等全部调查完再调用工具。"
    "落盘不会结束本会话；检索全部结束后再 WriteOldVuln(done=true)。"
)
_SEARCH_DONE_HINT = "检索已声明结束，系统将结束本会话。"


def _slug_filename(title: str, cve: str = "") -> str:
    raw = (cve or title or "vuln").strip()
    slug = _SLUG_RE.sub("-", raw).strip("-._")
    slug = (slug or "vuln")[:80]
    if not slug.lower().endswith(".md"):
        slug += ".md"
    return slug


def _iter_old_vuln_files(old_dir: Path):
    old_dir.mkdir(parents=True, exist_ok=True)
    for fp in sorted(old_dir.glob("*.md")):
        if fp.name == "index.md":
            continue
        yield fp


def _find_existing_old_vuln(old_dir: Path, *, title: str, cve: str, filename: str) -> Path | None:
    want_name = filename.replace("\\", "/").split("/")[-1] if filename else ""
    if want_name and not want_name.lower().endswith(".md"):
        want_name += ".md"
    for fp in _iter_old_vuln_files(old_dir):
        if want_name and fp.name.lower() == want_name.lower():
            return fp
        text = fp.read_text(encoding="utf-8", errors="ignore")
        meta, _ = _parse_frontmatter(text)
        doc_title = str(meta.get("title") or fp.stem).strip()
        doc_cve = str(meta.get("cve") or "").strip()
        if title and doc_title == title:
            return fp
        if cve and doc_cve and doc_cve.lower() == cve.lower():
            return fp
        if cve and fp.stem.lower() == cve.lower():
            return fp
    return None


def _rebuild_old_vuln_index(old_dir: Path, *, complete: bool = False) -> int:
    rows: list[str] = []
    for fp in _iter_old_vuln_files(old_dir):
        text = fp.read_text(encoding="utf-8", errors="ignore")
        meta, _ = _parse_frontmatter(text)
        title = str(meta.get("title") or fp.stem).replace("|", "\\|").replace("\n", " ")
        summary = str(meta.get("summary") or "").replace("|", "\\|").replace("\n", " ")
        rows.append(f"| {title} | {summary} | {fp.name} |")
    count = len(rows)
    if not rows:
        rows = ["| （暂无） | 经检索未写入历史漏洞 |  |"]
    body = (
        "---\n"
        "title: 历史漏洞索引\n"
        "summary: 本项目已知历史漏洞列表\n"
        f"complete: {'true' if complete else 'false'}\n"
        "---\n\n"
        "# 历史漏洞索引\n\n"
        "| 标题 | 摘要 | 文件 |\n"
        "|------|------|------|\n"
        + "\n".join(rows)
        + "\n"
    )
    (old_dir / "index.md").write_text(body, encoding="utf-8")
    return count


def _conclude_old_vuln_search(old_dir: Path, *, no_findings: bool, note: str) -> dict[str, Any]:
    count = _rebuild_old_vuln_index(old_dir, complete=True)
    if no_findings and count == 0:
        extra = f"\n\n检索说明：{note}\n" if note else "\n\n经 WebSearch / SearchGHSA 检索，未发现需单独建档的公开历史漏洞。\n"
        index = old_dir / "index.md"
        index.write_text(index.read_text(encoding="utf-8") + extra, encoding="utf-8")
    return {
        "ok": True,
        "no_findings": no_findings,
        "done": True,
        "indexed": count,
        "path": "docs/old-vulns/index.md",
        "hint": _SEARCH_DONE_HINT,
    }


def _write_old_vuln(ctx, args: dict[str, Any]) -> dict[str, Any]:
    no_findings = bool(args.get("no_findings"))
    done = bool(args.get("done") or args.get("complete") or args.get("search_done"))
    conclude = no_findings or done
    title = str(args.get("title") or "").strip()
    old_dir = old_vulns_dir(ctx.project_id)
    old_dir.mkdir(parents=True, exist_ok=True)

    if conclude and (no_findings or not title):
        return _conclude_old_vuln_search(
            old_dir,
            no_findings=no_findings,
            note=str(args.get("note") or "").strip(),
        )

    summary = str(args.get("summary") or "").strip()
    content = args.get("content")
    if content is None:
        content = args.get("body") or args.get("markdown") or ""
    content = str(content)
    if not title:
        return {
            "ok": False,
            "error": "缺少 title。每确认一条历史漏洞立刻调用，不要攒着。检索全部结束后再 WriteOldVuln(done=true)。",
        }
    if not summary:
        return {"ok": False, "error": "缺少 summary"}
    if not content.strip():
        return {"ok": False, "error": "缺少 content（请写入漏洞点/影响版本/补丁等正文）"}

    extra_meta, body = _parse_frontmatter(content) if content.lstrip().startswith("---") else ({}, content)
    if not isinstance(extra_meta, dict):
        extra_meta = {}
    cve = str(args.get("cve") or extra_meta.get("cve") or "").strip()
    cwe = str(args.get("cwe") or extra_meta.get("cwe") or "").strip()
    filename = str(args.get("filename") or args.get("file") or args.get("path") or "").strip()
    meta: dict[str, Any] = {
        "title": title,
        "summary": summary,
        "cve": cve,
        "cwe": cwe,
    }
    for key in ("severity", "component", "affected_version"):
        val = args.get(key) or extra_meta.get(key)
        if val:
            meta[key] = val
    vuln_type = args.get("vuln_type") or extra_meta.get("type") or extra_meta.get("vuln_type")
    if vuln_type:
        meta["type"] = str(vuln_type)

    existing = _find_existing_old_vuln(old_dir, title=title, cve=cve, filename=filename)
    if existing:
        target = existing
        created = False
    else:
        name = filename.replace("\\", "/").split("/")[-1] if filename else _slug_filename(title, cve)
        if not name.lower().endswith(".md"):
            name += ".md"
        target = old_dir / name
        n = 2
        stem = target.stem
        while target.exists():
            target = old_dir / f"{stem}-{n}.md"
            n += 1
        created = True

    front = yaml.safe_dump(meta, allow_unicode=True, sort_keys=False).strip()
    text = f"---\n{front}\n---\n\n{body.strip()}\n"
    target.write_text(text, encoding="utf-8")
    indexed = _rebuild_old_vuln_index(old_dir, complete=conclude)
    rel = f"docs/old-vulns/{target.name}"
    return {
        "ok": True,
        "path": rel,
        "title": title,
        "created": created,
        "indexed": indexed,
        "done": conclude,
        "hint": _SEARCH_DONE_HINT if conclude else _WRITE_NOW_HINT,
    }


def register_recon_tools() -> None:
    registry.register(
        ToolSpec(
            name="MarkSource",
            description="标记一个或多个 HTTP source 点（自动权重 100）。每确认一个入口就立即调用，不要等全部侦察完再批量标记",
            parameters={
                "type": "object",
                "properties": {
                    "sources": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "file": {"type": "string"},
                                "method": {"type": "string"},
                                "note": {"type": "string"},
                            },
                        },
                    },
                    "file": {"type": "string"},
                    "method": {"type": "string"},
                    "note": {"type": "string"},
                },
            },
            handler=_mark_source,
        )
    )
    registry.register(
        ToolSpec(
            name="MarkWeight",
            description="为文件标记审计权重（0-100）。同一类文件用 paths 一次标记，不要逐个调用",
            parameters={
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "paths": {"type": "array", "items": {"type": "string"}},
                    "weight": {"type": "integer"},
                },
                "required": ["weight"],
            },
            handler=_mark_weight,
        )
    )
    registry.register(
        ToolSpec(
            name="MarkSkip",
            description="跳过文件（测试/生成代码等）。判定后立即调用，不要攒到侦察结束",
            parameters={
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "paths": {"type": "array", "items": {"type": "string"}},
                },
            },
            handler=_mark_skip,
        )
    )
    registry.register(
        ToolSpec(
            name="WriteOldVuln",
            description=(
                "立即写入一条历史漏洞到 docs/old-vulns/ 并自动更新 index.md。"
                "每用 WebSearch/SearchGHSA 查到一条就调用；禁止调查完再一次性写入，否则上下文压缩会丢失内容。"
                "逐条落盘不会结束本会话。检索全部结束后设 done=true；确认无公开历史漏洞时设 no_findings=true。"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "title": {"type": "string", "description": "漏洞标题"},
                    "summary": {"type": "string", "description": "一句话摘要"},
                    "content": {"type": "string", "description": "Markdown 正文（影响版本/漏洞点/补丁/参考链接）"},
                    "cve": {"type": "string"},
                    "cwe": {"type": "string"},
                    "severity": {"type": "string"},
                    "vuln_type": {"type": "string"},
                    "component": {"type": "string"},
                    "affected_version": {"type": "string"},
                    "filename": {"type": "string", "description": "可选文件名，默认由 CVE/标题生成"},
                    "done": {
                        "type": "boolean",
                        "description": "检索已全部完成时为 true，声明本会话结束；逐条落盘时不要设",
                    },
                    "no_findings": {
                        "type": "boolean",
                        "description": "已检索且无公开历史漏洞时为 true，写空索引并结束本会话",
                    },
                    "note": {"type": "string", "description": "no_findings 时的检索说明"},
                },
            },
            handler=_write_old_vuln,
        )
    )


register_recon_tools()

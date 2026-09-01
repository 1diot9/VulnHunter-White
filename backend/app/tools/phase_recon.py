"""Recon-phase tools: MarkSource, MarkWeight, MarkSkip, AddSourceExt, WriteOldVuln."""

from __future__ import annotations

import re
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

from ..models import FileWeight, Project, SessionLocal, Source
from ..services.ingest import INDEX_SKIP_NAMES, SOURCE_EXTS, expand_file_index, normalize_source_ext
from ..services.old_vuln_crawl import save_crawl_spec
from ..services.paths import docs_dir, old_vulns_dir
from . import ToolSpec, registry
from .common import (
    _default_fix_status,
    _fix_status_label,
    _normalize_fix_status,
    _normalize_old_vuln_source,
    _parse_frontmatter,
)


def _doc_nonempty(path: Path) -> bool:
    return path.exists() and path.stat().st_size > 0


def recon_map_ready(project_id: int, *, scan: bool = True) -> bool:
    docs = docs_dir(project_id)
    if not (_doc_nonempty(docs / "code-map.md") and _doc_nonempty(docs / "auth.md")):
        return False
    from ..services.decompile_java import business_jar_map_ready

    return business_jar_map_ready(project_id, scan=scan)


# Map/auth refresh: session stays open until FinishReconMap clears the token.
_map_refresh_pending: set[int] = set()


def begin_map_refresh(project_id: int) -> None:
    _map_refresh_pending.add(int(project_id))


def clear_map_refresh(project_id: int) -> None:
    _map_refresh_pending.discard(int(project_id))


def map_refresh_pending(project_id: int) -> bool:
    return int(project_id) in _map_refresh_pending


def recon_map_refresh_ready(project_id: int) -> bool:
    """Ready for a map refresh session: docs present and FinishReconMap called."""
    return (not map_refresh_pending(project_id)) and recon_map_ready(project_id)


def clear_old_vuln_completion(project_id: int) -> dict[str, Any]:
    """Drop complete/llm_complete so old-vuln flow can re-run; keep existing vuln docs."""
    old_dir = old_vulns_dir(project_id)
    old_dir.mkdir(parents=True, exist_ok=True)
    indexed = _rebuild_old_vuln_index(old_dir, complete=False, llm_complete=False)
    return {"ok": True, "indexed": indexed, "complete": False, "llm_complete": False}


def _truthy_meta(val: Any) -> bool:
    if isinstance(val, bool):
        return val
    if val is None:
        return False
    return str(val).strip().lower() in {"1", "true", "yes", "y"}


def _old_vuln_index_path(project_id: int) -> Path:
    return old_vulns_dir(project_id) / "index.md"


def _source_exts_path(project_id: int) -> Path:
    return docs_dir(project_id) / "source-exts.md"


def _old_vuln_index_meta(index_path: Path) -> dict[str, Any]:
    if not _doc_nonempty(index_path):
        return {}
    text = index_path.read_text(encoding="utf-8", errors="ignore")
    meta, _ = _parse_frontmatter(text)
    return meta if isinstance(meta, dict) else {}


def _old_vuln_search_complete(index_path: Path) -> bool:
    return _truthy_meta(_old_vuln_index_meta(index_path).get("complete"))


def _old_vuln_llm_complete(index_path: Path) -> bool:
    meta = _old_vuln_index_meta(index_path)
    return _truthy_meta(meta.get("llm_complete")) or _truthy_meta(meta.get("complete"))


def recon_old_vuln_llm_ready(project_id: int) -> bool:
    """True after the crawler-write pass concludes (WebSearch supplement may still run)."""
    return _old_vuln_llm_complete(_old_vuln_index_path(project_id))


def recon_old_vulns_ready(project_id: int) -> bool:
    """True only after crawler-write + WebSearch supplement both declare complete — not after the first WriteOldVuln."""
    return _old_vuln_search_complete(_old_vuln_index_path(project_id))


def recon_source_ext_ready(project_id: int) -> bool:
    """True only after AddSourceExt(done/none) — not after the first extra-ext ingest."""
    path = _source_exts_path(project_id)
    if not _doc_nonempty(path):
        return False
    text = path.read_text(encoding="utf-8", errors="ignore")
    meta, _ = _parse_frontmatter(text)
    return _truthy_meta(meta.get("complete"))


def _recon_subphase_rows(*, map_done: bool, ext_done: bool, old_done: bool, mark_done: bool) -> list[dict[str, Any]]:
    return [
        {"id": "map", "label": "代码地图/鉴权", "done": map_done},
        {"id": "source_ext", "label": "扩展名", "done": ext_done},
        {"id": "old_vulns", "label": "历史漏洞", "done": old_done},
        {"id": "mark", "label": "文件盖章", "done": mark_done},
    ]


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
    map_docs_ok = not map_missing
    map_done = recon_map_ready(project_id)
    old_index = _old_vuln_index_path(project_id)
    old_index_ready = _doc_nonempty(old_index)
    old_done = recon_old_vulns_ready(project_id)
    old_missing = [] if old_index_ready else ["old-vulns/index.md"]
    ext_done = recon_source_ext_ready(project_id)
    ext_missing = [] if _doc_nonempty(_source_exts_path(project_id)) else ["source-exts.md"]
    missing = map_missing + ext_missing + old_missing
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
    coverage_pending = False
    try:
        from ..services.decompile_java import business_jar_coverage_pending

        coverage_pending = business_jar_coverage_pending(project_id)
    except Exception:  # noqa: BLE001
        coverage_pending = False
    mark_done = unmarked == 0 and not coverage_pending
    errors: list[str] = []
    if map_missing:
        errors.append(f"缺少代码地图/鉴权文档: {', '.join(map_missing)}")
    elif map_docs_ok and not map_done:
        from ..services.decompile_java import bytecode_present

        if bytecode_present(project_id):
            errors.append(
                "存在字节码但尚未结束业务 jar 点名；请 MarkBusinessJar(paths=[...])，"
                "全部点完后 MarkBusinessJar(done=true)，无业务覆盖则 none=true"
            )
    if ext_missing:
        errors.append("尚未检查额外源码扩展名；请用 AddSourceExt 追加模板/映射，或 AddSourceExt(none=true)")
    elif not ext_done:
        errors.append(
            "额外源码扩展名尚未确认结束；AddSourceExt 只入库、不会结束本会话，"
            "确认完毕后 AddSourceExt(done=true)"
        )
    if old_missing:
        errors.append("缺少历史漏洞索引 old-vulns/index.md；请用 WriteOldVuln 逐条落盘，不要用 Write 攒到最后")
    elif not old_done:
        if recon_old_vuln_llm_ready(project_id):
            errors.append(
                "历史漏洞 WebSearch 补漏尚未结束；按产品短名检索公开 CVE/公告后逐条 WriteOldVuln，"
                "全部补漏完再 WriteOldVuln(done=true)"
            )
        else:
            errors.append(
                "历史漏洞爬虫落盘尚未结束；只根据 workspace/ghsa_new.json 逐条 WriteOldVuln，"
                "不要调用 WebSearch。落盘不会结束本会话，本轮结束后再 WriteOldVuln(done=true)"
            )
    if unmarked > 0:
        errors.append(f"仍有 {unmarked}/{total} 个文件未标记权重（可用 MarkWeight/MarkSkip）")
    if coverage_pending:
        errors.append("已点名业务 jar 仍在反编译或尚未入库定权；盖章可继续处理已有文件")
    subphases = _recon_subphase_rows(
        map_done=map_done,
        ext_done=ext_done,
        old_done=old_done,
        mark_done=mark_done,
    )
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
    return _recon_subphase_rows(
        map_done=recon_map_ready(project_id, scan=False),
        ext_done=recon_source_ext_ready(project_id),
        old_done=recon_old_vulns_ready(project_id),
        mark_done=unmarked == 0,
    )


def recon_subphases_for_list(project_id: int, unmarked: int) -> list[dict[str, Any]]:
    """List-card gates: nonempty docs only — no frontmatter parse, no src walk."""
    docs = docs_dir(project_id)
    from ..services.decompile_java import business_jar_map_ready

    map_done = (
        _doc_nonempty(docs / "code-map.md")
        and _doc_nonempty(docs / "auth.md")
        and business_jar_map_ready(project_id, scan=False)
    )
    return _recon_subphase_rows(
        map_done=map_done,
        ext_done=_doc_nonempty(_source_exts_path(project_id)),
        old_done=_doc_nonempty(_old_vuln_index_path(project_id)),
        mark_done=unmarked == 0,
    )


def normalize_weight_path(path: str) -> str:
    """Slash-normalize a file-index path. Do not strip src/ — Maven paths start with src/main.

    Only drop ``./`` prefixes and leading slashes. ``str.lstrip("./")`` would also
    strip a leading dot from hidden names like ``.flattened-pom.xml``.
    """
    p = str(path or "").replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p.lstrip("/")


def weight_path_candidates(path: str) -> list[str]:
    """Exact path first, then with/without a workspace `src/` prefix."""
    p = normalize_weight_path(path)
    if not p:
        return []
    if p.startswith("workspace/"):
        return [p]
    out = [p]
    if p.startswith("src/"):
        rest = p[4:]
        if rest and rest not in out:
            out.append(rest)
    else:
        prefixed = f"src/{p}"
        if prefixed not in out:
            out.append(prefixed)
    return out


def _match_weight_row(path: str, by_path: dict[str, FileWeight]) -> FileWeight | None:
    for candidate in weight_path_candidates(path):
        row = by_path.get(candidate)
        if row is not None:
            return row
    return None


def _load_weight_rows(db, project_id: int, paths: list[str]) -> dict[str, FileWeight]:
    candidates: list[str] = []
    for p in paths:
        candidates.extend(weight_path_candidates(p))
    if not candidates:
        return {}
    rows = (
        db.query(FileWeight)
        .filter(FileWeight.project_id == project_id, FileWeight.path.in_(candidates))
        .all()
    )
    return {r.path: r for r in rows}


def _unmatched_error(unmatched: list[str]) -> str:
    preview = ", ".join(unmatched[:8])
    extra = f" …共 {len(unmatched)} 个" if len(unmatched) > 8 else ""
    return (
        f"未找到文件索引（{len(unmatched)}）: {preview}{extra}。"
        "路径相对 src/（不要重复 src/src）；若文件在磁盘上但扩展名不在默认语言白名单，"
        "等扩展名会话 AddSourceExt 后再标。"
    )


def _score_unmarked_path(path: str) -> tuple[int, str]:
    pl = path.lower()
    boost = 0
    for kw in ("controller", "router", "view", "api", "handler", "servlet", "resource"):
        if kw in pl:
            boost -= 10
    return (boost, path)


def _weight_basename(path: str) -> str:
    return PurePosixPath(str(path or "").replace("\\", "/")).name


def skip_non_source_weight_rows(project_id: int) -> int:
    """Skip hidden/generated index rows so they cannot stall recon marking."""
    n = 0
    with SessionLocal() as db:
        rows = (
            db.query(FileWeight)
            .filter(
                FileWeight.project_id == project_id,
                FileWeight.skipped.is_(False),
                FileWeight.weight.is_(None),
            )
            .all()
        )
        for row in rows:
            name = _weight_basename(row.path).lower()
            if not name.startswith(".") and name not in INDEX_SKIP_NAMES:
                continue
            row.skipped = True
            row.weight = 0
            n += 1
        if n:
            db.commit()
    return n


def has_unmarked_files(project_id: int) -> bool:
    """Cheap existence check; do not sort the unmarked set."""
    with SessionLocal() as db:
        row = (
            db.query(FileWeight.id)
            .filter(
                FileWeight.project_id == project_id,
                FileWeight.skipped.is_(False),
                FileWeight.weight.is_(None),
            )
            .first()
        )
    return row is not None


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
        by_path = _load_weight_rows(db, project_id, want)
        for p in want:
            row = _match_weight_row(p, by_path)
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
        file_path = args.get("file") or args.get("file_path") or args.get("path")
        if file_path:
            items = [{"file": file_path, "method": args.get("method") or args.get("method_name"), "note": args.get("note")}]
    if not items or not isinstance(items, list):
        return {"ok": False, "error": "需要 sources 数组或 file+method"}
    parsed: list[tuple[str, str, str | None]] = []
    for it in items:
        if not isinstance(it, dict):
            continue
        fp = normalize_weight_path(str(it.get("file") or it.get("file_path") or it.get("path") or ""))
        if not fp:
            continue
        method = str(it.get("method") or it.get("method_name") or "").strip() or "*"
        note = str(it.get("note") or "") or None
        parsed.append((fp, method, note))
    if not parsed:
        return {"ok": False, "error": "需要 sources 数组或 file+method"}
    marked = []
    unmatched: list[str] = []
    with SessionLocal() as db:
        by_path = _load_weight_rows(db, ctx.project_id, [fp for fp, _, _ in parsed])
        seen: set[int] = set()
        for fp, method, note in parsed:
            fw = _match_weight_row(fp, by_path)
            store_path = fw.path if fw is not None else fp
            db.add(
                Source(
                    project_id=ctx.project_id,
                    file_path=store_path,
                    method_name=method,
                    note=note,
                )
            )
            if fw is None:
                unmatched.append(fp)
                continue
            if fw.id not in seen:
                fw.has_source = True
                fw.weight = 100
                fw.skipped = False
                seen.add(fw.id)
            marked.append({"file": store_path, "method": method})
        db.commit()
    result: dict[str, Any] = {"ok": True, "marked": marked, "count": len(marked)}
    if unmatched:
        result["ok"] = False
        result["unmatched"] = unmatched
        result["error"] = _unmatched_error(unmatched)
    return result


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
    unmatched: list[str] = []
    with SessionLocal() as db:
        by_path = _load_weight_rows(db, ctx.project_id, paths)
        seen: set[int] = set()
        for p in paths:
            fw = _match_weight_row(p, by_path)
            if fw is None:
                unmatched.append(p)
                continue
            if fw.id in seen:
                continue
            seen.add(fw.id)
            if fw.has_source:
                fw.weight = 100
            else:
                fw.weight = weight
            fw.skipped = False
            updated.append({"path": fw.path, "weight": fw.weight})
        db.commit()
    result: dict[str, Any] = {"ok": True, "updated": updated, "count": len(updated)}
    if unmatched:
        result["ok"] = False
        result["unmatched"] = unmatched
        result["error"] = _unmatched_error(unmatched)
    return result


def _mark_skip(ctx, args: dict[str, Any]) -> dict[str, Any]:
    paths = _normalize_paths(args)
    if not paths:
        return {"ok": False, "error": "缺少 path/paths"}
    updated = []
    unmatched: list[str] = []
    with SessionLocal() as db:
        by_path = _load_weight_rows(db, ctx.project_id, paths)
        seen: set[int] = set()
        for p in paths:
            fw = _match_weight_row(p, by_path)
            if fw is None:
                unmatched.append(p)
                continue
            if fw.id in seen:
                continue
            seen.add(fw.id)
            fw.skipped = True
            fw.weight = 0
            updated.append(fw.path)
        db.commit()
    result: dict[str, Any] = {"ok": True, "skipped": updated, "count": len(updated)}
    if unmatched:
        result["ok"] = False
        result["unmatched"] = unmatched
        result["error"] = _unmatched_error(unmatched)
    return result


_ADDED_SAMPLE = 30
_SOURCE_EXT_DONE_HINT = "扩展名检查已声明结束，系统将结束本会话，随后进入历史漏洞与盖章。"
_SOURCE_EXT_WRITE_HINT = (
    "已入库。请继续检查其他模板/映射扩展名；全部确认后再 AddSourceExt(done=true)。"
    "无需追加时用 AddSourceExt(none=true)。落盘不会结束本会话。"
)


def _meta_exts(meta: dict[str, Any]) -> list[str]:
    raw = meta.get("exts")
    if isinstance(raw, str):
        parts = [p.strip() for p in raw.replace(",", " ").split() if p.strip()]
    elif isinstance(raw, list):
        parts = [str(p).strip() for p in raw if str(p).strip()]
    else:
        parts = []
    out: list[str] = []
    seen: set[str] = set()
    for p in parts:
        ext = p if p.startswith(".") else f".{p}"
        ext = ext.lower()
        if ext in seen:
            continue
        seen.add(ext)
        out.append(ext)
    return out


def _load_source_exts_state(project_id: int) -> tuple[list[str], int, bool]:
    path = _source_exts_path(project_id)
    if not path.exists():
        return [], 0, False
    text = path.read_text(encoding="utf-8", errors="ignore")
    meta, _ = _parse_frontmatter(text)
    added = meta.get("added_count")
    try:
        added_n = int(added or 0)
    except (TypeError, ValueError):
        added_n = 0
    return _meta_exts(meta), added_n, _truthy_meta(meta.get("complete"))


def _write_source_exts_doc(
    project_id: int,
    *,
    exts: list[str],
    added_count: int,
    complete: bool,
    note: str = "",
) -> Path:
    path = _source_exts_path(project_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    ext_yaml = ", ".join(f'"{e}"' for e in exts)
    listed = "、".join(f"`{e}`" for e in exts) if exts else "无（沿用默认编程语言白名单）"
    extra = f"\n\n说明：{note}\n" if note else ""
    body = (
        "---\n"
        "title: 额外源码扩展名\n"
        "summary: 侦察确认后追加的模板/映射等执行面文件类型\n"
        f"complete: {'true' if complete else 'false'}\n"
        f"exts: [{ext_yaml}]\n"
        f"added_count: {added_count}\n"
        "---\n\n"
        "# 额外源码扩展名\n\n"
        f"已确认扩展名：{listed}。累计新增 {added_count} 个文件（测试路径自动跳过）。"
        f"{extra}"
    )
    path.write_text(body, encoding="utf-8")
    return path


def _add_source_ext(ctx, args: dict[str, Any]) -> dict[str, Any]:
    raw = args.get("exts") if args.get("exts") is not None else args.get("ext")
    if isinstance(raw, str):
        extra = [raw]
    elif isinstance(raw, list):
        extra = [str(x) for x in raw if str(x).strip()]
    else:
        extra = []

    # Support removing extensions
    raw_remove = args.get("remove_exts") or args.get("remove_ext") or args.get("remove")
    if isinstance(raw_remove, str):
        to_remove = [raw_remove]
    elif isinstance(raw_remove, list):
        to_remove = [str(x) for x in raw_remove if str(x).strip()]
    else:
        to_remove = []

    none = bool(args.get("none") or args.get("no_extra") or args.get("no_findings"))
    conclude = bool(args.get("done") or args.get("complete") or none)
    if not extra and not to_remove and not conclude:
        return {
            "ok": False,
            "error": "缺少 ext/exts 或 remove_exts；无需追加时用 AddSourceExt(none=true)，全部确认后 AddSourceExt(done=true)",
        }

    prev_exts, prev_added, _ = _load_source_exts_state(ctx.project_id)
    added: list[str] = []
    skipped_test = 0
    accepted: list[str] = []
    rejected: list[str] = []
    if extra:
        result = expand_file_index(ctx.project_id, extra, assign_weight=None)
        accepted = list(result["exts"])
        rejected = list(result["rejected"])
        added = list(result["added"])
        skipped_test = int(result["skipped_test"] or 0)
        if not accepted and not conclude:
            return {
                "ok": False,
                "error": f"扩展名无效或属于忽略类型（图片/压缩包/二进制等）: {rejected}",
                "rejected": rejected,
            }

    # Normalize remove list
    removed: list[str] = []
    for raw_ext in to_remove:
        ext = normalize_source_ext(raw_ext)
        if ext and ext in prev_exts:
            removed.append(ext)

    # Merge: add new extensions, remove specified ones
    merged: list[str] = []
    seen: set[str] = set()
    for ext in prev_exts + accepted:
        if ext in seen:
            continue
        if ext in removed:
            continue
        seen.add(ext)
        merged.append(ext)
    added_count = prev_added + len(added)
    path = _write_source_exts_doc(
        ctx.project_id,
        exts=merged,
        added_count=added_count,
        complete=conclude,
        note=str(args.get("note") or "").strip(),
    )

    # If concluding, trigger final file scan
    scanned = 0
    if conclude:
        from ..services.ingest import build_file_index_with_exts

        final_exts = list(SOURCE_EXTS) + merged
        scanned = build_file_index_with_exts(ctx.project_id, final_exts)

    if conclude:
        hint = _SOURCE_EXT_DONE_HINT
        if none and not merged:
            hint = "无需追加扩展名，系统将结束本会话。"
        if scanned > 0:
            hint += f" 已入库 {scanned} 个文件。"
    elif added or removed:
        hint = _SOURCE_EXT_WRITE_HINT
    else:
        hint = "未发现新文件（可能已入库或位于忽略目录）。" + _SOURCE_EXT_WRITE_HINT
    if skipped_test:
        hint += f" 其中 {skipped_test} 个测试路径已自动跳过。"
    if rejected:
        hint += f" 已忽略无效或应跳过的扩展名: {rejected}。"
    if removed:
        hint += f" 已移除扩展名: {', '.join(removed)}。"
    return {
        "ok": True,
        "exts": merged,
        "added_count": len(added),
        "added_total": added_count,
        "removed_exts": removed,
        "skipped_test": skipped_test,
        "rejected": rejected,
        "added_sample": added[:_ADDED_SAMPLE],
        "scanned": scanned,
        "done": conclude,
        "none": none,
        "path": "docs/source-exts.md",
        "hint": hint,
        "doc": str(path.name),
    }


_SLUG_RE = re.compile(r"[^\w.\-\u4e00-\u9fff]+", re.UNICODE)
_WRITE_NOW_HINT = (
    "已落盘。请立即继续下一条/下一批，不要等全部调查完再调用工具。"
    "本阶段只收集、不读源码：GHSA/WebSearch 标 patched；未关闭 GitHub Issues 标 unpatched。"
    "框架 CVE 清单、依赖历史漏洞、安全政策帖、错误产品不要建档。"
    "落盘不会结束本会话；本轮结束后再 WriteOldVuln(done=true, note=跳过说明)。"
)
_CRAWL_PASS_DONE_HINT = "爬虫核验已声明结束，系统将结束本会话并启动 WebSearch 补漏。"
_SEARCH_DONE_HINT = "检索已声明结束，系统将结束本会话。"
_INDEX_NOTE_MARKERS = ("\n\n检索说明", "\n\n经 WebSearch", "\n\n经 LLM", "\n\n经 GHSA")


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


def _index_trailing_notes(text: str) -> str:
    positions = [text.find(marker) for marker in _INDEX_NOTE_MARKERS]
    hits = [p for p in positions if p >= 0]
    if not hits:
        return ""
    return text[min(hits):]


def _read_index_state(old_dir: Path) -> tuple[dict[str, Any], str]:
    index = old_dir / "index.md"
    if not index.exists():
        return {}, ""
    text = index.read_text(encoding="utf-8", errors="ignore")
    meta, _ = _parse_frontmatter(text)
    if not isinstance(meta, dict):
        meta = {}
    return meta, _index_trailing_notes(text)


def _rebuild_old_vuln_index(
    old_dir: Path,
    *,
    complete: bool | None = None,
    llm_complete: bool | None = None,
) -> int:
    prev_meta, notes = _read_index_state(old_dir)
    prev_complete = _truthy_meta(prev_meta.get("complete"))
    prev_llm = _truthy_meta(prev_meta.get("llm_complete")) or prev_complete
    if complete is None:
        complete = prev_complete
    if llm_complete is None:
        llm_complete = prev_llm or bool(complete)
    rows: list[str] = []
    for fp in _iter_old_vuln_files(old_dir):
        text = fp.read_text(encoding="utf-8", errors="ignore")
        meta, _ = _parse_frontmatter(text)
        title = str(meta.get("title") or fp.stem).replace("|", "\\|").replace("\n", " ")
        summary = str(meta.get("summary") or "").replace("|", "\\|").replace("\n", " ")
        status = _normalize_fix_status(meta.get("fix_status"))
        status_label = _fix_status_label(status)
        rows.append(f"| {title} | {summary} | {status_label} | {fp.name} |")
    count = len(rows)
    if not rows:
        rows = ["| （暂无） | 经检索未写入历史漏洞 |  |  |"]
    body = (
        "---\n"
        "title: 历史漏洞索引\n"
        "summary: 本项目已知历史漏洞列表\n"
        f"complete: {'true' if complete else 'false'}\n"
        f"llm_complete: {'true' if llm_complete else 'false'}\n"
        "---\n\n"
        "# 历史漏洞索引\n\n"
        "| 标题 | 摘要 | 修复状态 | 文件 |\n"
        "|------|------|----------|------|\n"
        + "\n".join(rows)
        + "\n"
    )
    if notes:
        body = body.rstrip() + notes
        if not body.endswith("\n"):
            body += "\n"
    (old_dir / "index.md").write_text(body, encoding="utf-8")
    return count


def _append_search_note(old_dir: Path, *, note: str, no_findings: bool, count: int) -> None:
    extra = ""
    if note:
        extra = f"\n\n检索说明：{note}\n"
    elif no_findings and count == 0:
        extra = "\n\n经 GHSA / GitHub Issues 爬虫与 WebSearch 补漏，未发现需单独建档的公开历史漏洞。\n"
    if not extra:
        return
    index = old_dir / "index.md"
    current = index.read_text(encoding="utf-8") if index.exists() else ""
    snippet = extra.strip()
    if snippet and snippet in current:
        return
    index.write_text(current + extra, encoding="utf-8")


def _is_old_vuln_ghsa_pass(ctx) -> bool:
    phase = str(getattr(ctx, "phase", "") or "").replace("_", "-").strip().lower()
    role = str(getattr(ctx, "role", "") or "").replace("_", "-").strip().lower()
    return phase.endswith("old-vuln-ghsa") or role.endswith("old-vuln-ghsa")


def _list_str_args(raw: Any) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, str):
        parts = [p.strip() for p in raw.replace(",", " ").split() if p.strip()]
        return parts
    if isinstance(raw, list):
        return [str(p).strip() for p in raw if str(p).strip()]
    return []


def _persist_pass1_crawl_spec(ctx, args: dict[str, Any]) -> None:
    keyword = str(args.get("keyword") or args.get("crawl_keyword") or "").strip()
    affects = _list_str_args(args.get("affects") or args.get("packages"))
    ecosystems = _list_str_args(args.get("ecosystems") or args.get("ecosystem"))
    if not keyword and not affects and not ecosystems:
        return
    save_crawl_spec(
        ctx.project_id,
        keyword=keyword or None,
        affects=affects or None,
        ecosystems=ecosystems or None,
    )


def _conclude_old_vuln_search(
    old_dir: Path,
    *,
    no_findings: bool,
    note: str,
    complete: bool,
    llm_complete: bool,
    hint: str,
) -> dict[str, Any]:
    count = _rebuild_old_vuln_index(old_dir, complete=complete, llm_complete=llm_complete)
    _append_search_note(old_dir, note=note, no_findings=no_findings, count=count)
    return {
        "ok": True,
        "no_findings": no_findings,
        "done": True,
        "indexed": count,
        "llm_complete": llm_complete,
        "complete": complete,
        "path": "docs/old-vulns/index.md",
        "hint": hint,
    }


def mark_old_vuln_search_complete(project_id: int, *, note: str = "") -> dict[str, Any]:
    """Pipeline helper: close the historical-vuln phase (e.g. tests or empty-queue short-circuit)."""
    old_dir = old_vulns_dir(project_id)
    old_dir.mkdir(parents=True, exist_ok=True)
    return _conclude_old_vuln_search(
        old_dir,
        no_findings=False,
        note=note,
        complete=True,
        llm_complete=True,
        hint=_SEARCH_DONE_HINT,
    )


def _write_old_vuln(ctx, args: dict[str, Any]) -> dict[str, Any]:
    no_findings = bool(args.get("no_findings"))
    done = bool(args.get("done") or args.get("complete") or args.get("search_done"))
    conclude = no_findings or done
    title = str(args.get("title") or "").strip()
    old_dir = old_vulns_dir(ctx.project_id)
    old_dir.mkdir(parents=True, exist_ok=True)
    ghsa_pass = _is_old_vuln_ghsa_pass(ctx)
    llm_complete = True if conclude else None
    complete = True if (conclude and ghsa_pass) else (False if conclude else None)
    hint = _SEARCH_DONE_HINT if ghsa_pass else _CRAWL_PASS_DONE_HINT

    if conclude and not ghsa_pass:
        _persist_pass1_crawl_spec(ctx, args)

    if conclude and (no_findings or not title):
        return _conclude_old_vuln_search(
            old_dir,
            no_findings=no_findings,
            note=str(args.get("note") or "").strip(),
            complete=bool(complete),
            llm_complete=True,
            hint=hint,
        )

    summary = str(args.get("summary") or "").strip()
    content = args.get("content")
    if content is None:
        content = args.get("body") or args.get("markdown") or ""
    content = str(content)
    if not title:
        return {
            "ok": False,
            "error": "缺少 title。每确认一条符合口径的历史漏洞立刻调用，不要攒着。本轮结束后再 WriteOldVuln(done=true)。",
        }
    if not summary:
        return {"ok": False, "error": "缺少 summary"}
    if not content.strip():
        return {"ok": False, "error": "缺少 content（请写入公告/Issue 摘要、影响版本、参考链接等正文）"}

    extra_meta, body = _parse_frontmatter(content) if content.lstrip().startswith("---") else ({}, content)
    if not isinstance(extra_meta, dict):
        extra_meta = {}
    cve = str(args.get("cve") or extra_meta.get("cve") or "").strip()
    cwe = str(args.get("cwe") or extra_meta.get("cwe") or "").strip()
    filename = str(args.get("filename") or args.get("file") or args.get("path") or "").strip()
    source = _normalize_old_vuln_source(args.get("source") or extra_meta.get("source"))
    fix_status = _normalize_fix_status(args.get("fix_status") or extra_meta.get("fix_status"))
    if not fix_status:
        fix_status = _default_fix_status(source)
    meta: dict[str, Any] = {
        "title": title,
        "summary": summary,
        "cve": cve,
        "cwe": cwe,
        "fix_status": fix_status,
    }
    if source:
        meta["source"] = source
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
    indexed = _rebuild_old_vuln_index(old_dir, complete=complete, llm_complete=llm_complete)
    if conclude:
        _append_search_note(
            old_dir,
            note=str(args.get("note") or "").strip(),
            no_findings=no_findings,
            count=indexed,
        )
    rel = f"docs/old-vulns/{target.name}"
    return {
        "ok": True,
        "path": rel,
        "title": title,
        "created": created,
        "indexed": indexed,
        "fix_status": fix_status,
        "source": source,
        "done": conclude,
        "llm_complete": True if conclude else recon_old_vuln_llm_ready(ctx.project_id),
        "complete": bool(complete) if conclude else recon_old_vulns_ready(ctx.project_id),
        "hint": hint if conclude else _WRITE_NOW_HINT,
    }


def _finish_recon_map(ctx, args: dict[str, Any]) -> dict[str, Any]:
    if not map_refresh_pending(ctx.project_id):
        return {"ok": False, "error": "当前不是地图/鉴权重跑会话，无需调用 FinishReconMap"}
    if not recon_map_ready(ctx.project_id):
        return {
            "ok": False,
            "error": (
                "请先用 Write 更新并保留非空的 docs/code-map.md 与 docs/auth.md；"
                "若存在字节码还须 MarkBusinessJar(done=true) 或 none=true"
            ),
        }
    clear_map_refresh(ctx.project_id)
    return {
        "ok": True,
        "hint": "地图/鉴权已确认更新，系统将结束本会话",
        "path": ["docs/code-map.md", "docs/auth.md"],
    }


def register_recon_tools() -> None:
    registry.register(
        ToolSpec(
            name="FinishReconMap",
            description=(
                "仅地图/鉴权重跑会话使用：在更新并写回 docs/code-map.md 与 docs/auth.md 后调用，"
                "声明本会话结束。首次侦察两份文档写齐后由系统自动结束，不要调用本工具"
            ),
            parameters={"type": "object", "properties": {}},
            handler=_finish_recon_map,
        )
    )
    registry.register(
        ToolSpec(
            name="MarkSource",
            description="标记一个或多个用户可控入口（HTTP / WebSocket / RPC / MQ / 回调，以及组件公开 API / 解析器参数入口，自动权重 100）。每确认一个入口就立即调用，不要等全部侦察完再批量标记，不要只标 HTTP",
            parameters={
                "type": "object",
                "properties": {
                    "sources": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "file": {
                                    "type": "string",
                                    "description": "入口文件路径，相对 src/，如 src/metabase/session/api.clj",
                                },
                                "method": {
                                    "type": "string",
                                    "description": "HTTP 方法与路由，或非 HTTP 入口说明",
                                },
                                "note": {"type": "string", "description": "入口说明，可省略"},
                            },
                            "required": ["file"],
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
            description=(
                "为文件标记审计权重（0-100）。用户可控入口（HTTP / WebSocket / RPC / MQ / 回调，以及组件公开 API / 解析入口）请用 MarkSource（自动 100）；"
                "Service/过滤器 70–90；Mapper/模板/危险工具 40–60；DTO/常量/启动类 10–30。"
                "同一类文件用 paths 一次标记，不要逐个调用"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "单个文件路径，相对 src/。多个文件改用 paths。",
                    },
                    "paths": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "多个文件路径。与 path 二选一。",
                    },
                    "weight": {"type": "integer", "description": "审计权重 0-100"},
                },
                "required": ["path", "weight"],
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
                    "path": {
                        "type": "string",
                        "description": "单个文件路径，相对 src/。多个文件改用 paths。",
                    },
                    "paths": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "多个文件路径。与 path 二选一。",
                    },
                },
                "required": ["path"],
            },
            handler=_mark_skip,
        )
    )
    registry.register(
        ToolSpec(
            name="AddSourceExt",
            description=(
                "根据代码地图与仓库实际文件追加或移除源码扩展名。"
                "用于模板/映射/脚本等默认未索引类型，也用于移除噪音扩展名。"
                "以仓库为准，不要按固定名单照抄。"
                "逐次追加/移除不会结束本会话；全部确认后设 done=true。"
                "无需追加时设 none=true。不要为图片、压缩包、第三方静态资源加扩展名。"
                "结束时会入库扩展名对应文件（跳过无效文件），防止落盘无效文件。"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "ext": {"type": "string", "description": "单个扩展名，如 .ftl"},
                    "exts": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "多个扩展名，如 [\".ftl\", \".xml\"]",
                    },
                    "remove_ext": {
                        "type": "string",
                        "description": "单个要移除的扩展名，如 .json",
                    },
                    "remove_exts": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "多个要移除的扩展名，如 [\".json\", \".xml\"]",
                    },
                    "done": {
                        "type": "boolean",
                        "description": "扩展名已全部确认时为 true，结束本会话并入库文件；逐次追加时不要设",
                    },
                    "none": {
                        "type": "boolean",
                        "description": "无需追加任何扩展名时为 true，写空记录并结束本会话",
                    },
                    "note": {"type": "string", "description": "可选说明，写入 docs/source-exts.md"},
                },
            },
            handler=_add_source_ext,
        )
    )
    registry.register(
        ToolSpec(
            name="WriteOldVuln",
            description=(
                "立即写入一条历史漏洞到 docs/old-vulns/ 并自动更新 index.md。"
                "本阶段只收集、不读源码。GHSA/WebSearch 公开洞标 patched；未关闭 GitHub Issues 标 unpatched（可省略，按 source 默认）。"
                "不要扫框架 CVE 清单，不要收录依赖/框架自身的历史漏洞。每确认一条就调用；禁止调查完再一次性写入。"
                "逐条落盘不会结束本会话。本轮结束后设 done=true；无符合口径的条目时设 no_findings=true。"
                "爬虫落盘轮不要调用 WebSearch；搜索补漏轮再用 WebSearch 按产品短名补缺。"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "title": {"type": "string", "description": "漏洞标题"},
                    "summary": {"type": "string", "description": "一句话摘要"},
                    "content": {
                        "type": "string",
                        "description": "Markdown 正文（公告/Issue 摘要、影响版本、参考链接；不要写源码调用点分析）",
                    },
                    "cve": {"type": "string"},
                    "cwe": {"type": "string"},
                    "severity": {"type": "string"},
                    "vuln_type": {"type": "string"},
                    "component": {"type": "string"},
                    "affected_version": {"type": "string"},
                    "fix_status": {
                        "type": "string",
                        "description": (
                            "patched=已修复历史洞（GHSA/WebSearch 默认）；"
                            "unpatched=未关闭 GitHub Issue（source=github_issue 时默认）。可省略"
                        ),
                    },
                    "source": {
                        "type": "string",
                        "description": "来源：websearch / ghsa / github_issue。github_issue 默认 unpatched，其余默认 patched",
                    },
                    "filename": {"type": "string", "description": "可选文件名，默认由 CVE/标题生成"},
                    "keyword": {
                        "type": "string",
                        "description": "可选产品短名（如 halo）；爬虫已用项目身份，此处仅作记录",
                    },
                    "affects": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "可选本项目包名，仅作记录；不要填 Spring 等依赖坐标",
                    },
                    "ecosystems": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "可选生态，如 maven/npm/pip/composer；省略则按仓库推断",
                    },
                    "done": {
                        "type": "boolean",
                        "description": "本轮检索已完成时为 true，声明本会话结束；逐条落盘时不要设",
                    },
                    "no_findings": {
                        "type": "boolean",
                        "description": "本轮已检索且无符合口径的历史漏洞时为 true，写空索引并结束本会话",
                    },
                    "note": {
                        "type": "string",
                        "description": "结束说明：跳过的依赖/框架 CVE 清单、错误产品或安全政策帖",
                    },
                },
            },
            handler=_write_old_vuln,
        )
    )


register_recon_tools()

"""Catalog FinishRound reports, recon docs, and visible phase summaries."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .paths import project_root, summaries_dir, workspace_dir

_SUMMARY_NAME = re.compile(
    r"^(?P<phase>recon(?:-old-vuln-ghsa|-old-vuln|-source-ext|-mark)?|worker|fast-worker|bypass-worker|sink-triage|fix|reviewer(?:-lab)?|verifier|attack_chain)"
    r"(?:-(?P<kind>round|rescue))?"
    r"-(?P<n>\d+)\.md$"
)
_ROUND_NAME = re.compile(r"^round-(?P<n>\d+)\.md$")
_FAST_ROUND_NAME = re.compile(r"^fast-round-(?P<n>\d+)\.md$")
_BYPASS_ROUND_NAME = re.compile(r"^bypass-round-(?P<n>\d+)\.md$")
_ROUND_TITLE = "单轮挖掘方向"
_FAST_ROUND_TITLE = "快速 Sink 回推"
_BYPASS_ROUND_TITLE = "历史漏洞绕过"

# filename phase -> (control phase, control label, subphase id)
_PHASE_META: dict[str, tuple[str, str, str]] = {
    "recon": ("recon", "侦察", "map"),
    "recon-source-ext": ("recon", "侦察", "source_ext"),
    "recon-old-vuln": ("recon", "侦察", "old_vulns"),
    "recon-old-vuln-ghsa": ("recon", "侦察", "old_vulns"),
    "recon-mark": ("recon", "侦察", "mark"),
    "fast-worker": ("worker", "挖掘", "fast"),
    "bypass-worker": ("worker", "挖掘", "bypass"),
    "sink-triage": ("worker", "挖掘", "fast"),
    "worker": ("worker", "挖掘", "mine"),
    "fix": ("worker", "挖掘", "fix"),
    "reviewer": ("reviewer", "审核", "reviewer"),
    "reviewer-lab": ("reviewer", "审核", "lab"),
    "reviewer-lab-bringup": ("reviewer", "审核", "lab"),
    "verifier": ("verifier", "验证", "verify"),
    "attack_chain": ("attack_chain", "攻击链", "chain"),
}

_CONTROL_LABEL = {
    "recon": "侦察",
    "worker": "挖掘",
    "reviewer": "审核",
    "verifier": "验证",
    "attack_chain": "攻击链",
}
_SUB_LABEL = {
    "map": "地图/鉴权",
    "source_ext": "扩展名",
    "old_vulns": "历史漏洞",
    "mark": "盖章",
    "mine": "启发式",
    "fast": "快速扫描",
    "bypass": "历史漏洞绕过",
    "fix": "修复",
    "lab": "环境搭建",
    "reviewer": "审核",
    "verify": "互联网验证",
    "chain": "攻击链串联",
}
_KIND_LABEL = {"doc": "文档", "round": "审计", "summary": "摘要", "rescue": "抢救"}

_DOC_SPECS: tuple[tuple[str, str, str, str], ...] = (
    ("docs/code-map.md", "recon", "map", "代码地图"),
    ("docs/auth.md", "recon", "map", "鉴权说明"),
    ("docs/source-exts.md", "recon", "source_ext", "额外源码扩展名"),
    ("docs/old-vulns/index.md", "recon", "old_vulns", "历史漏洞索引"),
    ("docs/lab.md", "reviewer", "lab", "动态环境搭建"),
    ("docs/attack-chains/index.md", "attack_chain", "chain", "攻击链索引"),
)
_DOC_BY_REL = {rel: (control, subphase, title) for rel, control, subphase, title in _DOC_SPECS}
_PREVIEW_CHARS = 8192
_CONTROL_PHASES = ("recon", "worker", "reviewer", "verifier", "attack_chain")


@dataclass(frozen=True)
class _ReportCandidate:
    rel: str
    path: Path
    control: str
    subphase: str
    kind: str
    round_no: int | None
    title: str
    sort_mtime: float


def _shows_summary_in_phase_reports(control: str) -> bool:
    # Worker summaries are context-compression checkpoints; the user-facing
    # mining report is the FinishRound report under workspace/rounds.
    return control != "worker"


def _iso_mtime(path: Path) -> str:
    return datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).isoformat()


def _heading_or_preview(text: str) -> tuple[str | None, str]:
    heading = None
    preview_parts: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#"):
            title = line.lstrip("#").strip()
            if title and heading is None:
                heading = title
            continue
        preview_parts.append(line)
        if sum(len(p) for p in preview_parts) >= 160:
            break
    preview = " ".join(preview_parts)
    if len(preview) > 160:
        preview = preview[:157] + "…"
    return heading, preview


def _split_frontmatter(text: str) -> tuple[dict[str, Any], str]:
    if not text.startswith("---"):
        return {}, text
    parts = text.split("---", 2)
    if len(parts) < 3:
        return {}, text
    try:
        import yaml

        meta = yaml.safe_load(parts[1]) or {}
    except Exception:  # noqa: BLE001
        meta = {}
    if not isinstance(meta, dict):
        meta = {}
    return meta, parts[2].lstrip("\n")


def _read_preview_text(path: Path) -> str:
    with path.open("r", encoding="utf-8", errors="replace") as f:
        return f.read(_PREVIEW_CHARS)


def _item(
    *,
    rel: str,
    path: Path,
    control: str,
    subphase: str,
    kind: str,
    round_no: int | None,
    title: str,
    content: str | None = None,
) -> dict[str, Any]:
    text = content if content is not None else _read_preview_text(path)
    meta, body = _split_frontmatter(text)
    heading, preview = _heading_or_preview(body)
    fm_title = str(meta.get("title") or "").strip()
    if kind == "round":
        display_title = title
    else:
        display_title = fm_title or heading or title
    out: dict[str, Any] = {
        "id": rel.replace("\\", "/"),
        "phase": control,
        "phase_label": _CONTROL_LABEL[control],
        "subphase": subphase,
        "subphase_label": _SUB_LABEL[subphase],
        "kind": kind,
        "kind_label": _KIND_LABEL[kind],
        "round": round_no,
        "title": display_title,
        "preview": preview,
        "mtime": _iso_mtime(path),
        "size": path.stat().st_size,
    }
    if content is not None:
        out["content"] = text
    return out


def _candidate(
    *,
    rel: str,
    path: Path,
    control: str,
    subphase: str,
    kind: str,
    round_no: int | None,
    title: str,
) -> _ReportCandidate | None:
    if not path.is_file():
        return None
    try:
        stat = path.stat()
    except OSError:
        return None
    if stat.st_size <= 0:
        return None
    return _ReportCandidate(
        rel=rel,
        path=path,
        control=control,
        subphase=subphase,
        kind=kind,
        round_no=round_no,
        title=title,
        sort_mtime=stat.st_mtime,
    )


def _candidate_item(c: _ReportCandidate) -> dict[str, Any]:
    return _item(
        rel=c.rel,
        path=c.path,
        control=c.control,
        subphase=c.subphase,
        kind=c.kind,
        round_no=c.round_no,
        title=c.title,
    )


def _safe_rel(rel: str) -> str:
    cleaned = (rel or "").replace("\\", "/").lstrip("/")
    if not cleaned or ".." in Path(cleaned).parts:
        raise ValueError("非法路径")
    if not (
        cleaned.startswith("docs/")
        or cleaned.startswith("workspace/rounds/")
    ):
        raise ValueError("非法路径")
    if not cleaned.endswith(".md"):
        raise ValueError("仅支持 markdown 报告")
    return cleaned


def _resolve(project_id: int, rel: str) -> Path:
    rel = _safe_rel(rel)
    root = project_root(project_id).resolve()
    target = (root / rel).resolve()
    try:
        target.relative_to(root)
    except ValueError as e:
        raise ValueError("路径越界") from e
    return target


def _item_for_rel(project_id: int, rel: str, *, content: str | None = None) -> dict[str, Any]:
    rel = _safe_rel(rel)
    path = _resolve(project_id, rel)
    if not path.is_file() or path.stat().st_size <= 0:
        raise FileNotFoundError(rel)
    if rel in _DOC_BY_REL:
        control, subphase, title = _DOC_BY_REL[rel]
        return _item(
            rel=rel,
            path=path,
            control=control,
            subphase=subphase,
            kind="doc",
            round_no=None,
            title=title,
            content=content,
        )
    if rel.startswith("workspace/rounds/"):
        m = _ROUND_NAME.match(path.name)
        if m:
            n = int(m.group("n"))
            return _item(
                rel=rel,
                path=path,
                control="worker",
                subphase="mine",
                kind="round",
                round_no=n,
                title=_ROUND_TITLE,
                content=content,
            )
        fm = _FAST_ROUND_NAME.match(path.name)
        bm = _BYPASS_ROUND_NAME.match(path.name)
        if fm:
            n = int(fm.group("n"))
            return _item(
                rel=rel,
                path=path,
                control="worker",
                subphase="fast",
                kind="round",
                round_no=n,
                title=_FAST_ROUND_TITLE,
                content=content,
            )
        if bm:
            n = int(bm.group("n"))
            return _item(
                rel=rel,
                path=path,
                control="worker",
                subphase="bypass",
                kind="round",
                round_no=n,
                title=_BYPASS_ROUND_TITLE,
                content=content,
            )
        raise FileNotFoundError(rel)
    if rel.startswith("docs/attack-chains/"):
        return _item(
            rel=rel,
            path=path,
            control="attack_chain",
            subphase="chain",
            kind="doc",
            round_no=None,
            title="攻击链索引" if path.name == "index.md" else f"攻击链 · {path.stem}",
            content=content,
        )
    if rel.startswith("docs/verifier/"):
        stem = path.stem
        if not stem.isdigit():
            raise FileNotFoundError(rel)
        return _item(
            rel=rel,
            path=path,
            control="verifier",
            subphase="verify",
            kind="doc",
            round_no=None,
            title=f"互联网验证 · 漏洞 #{int(stem)}",
            content=content,
        )
    if rel.startswith("docs/summaries/"):
        m = _SUMMARY_NAME.match(path.name)
        if not m:
            raise FileNotFoundError(rel)
        phase = m.group("phase")
        kind_raw = m.group("kind")
        n = int(m.group("n"))
        kind = "rescue" if kind_raw == "rescue" else "summary"
        control, _, subphase = _PHASE_META[phase]
        return _item(
            rel=rel,
            path=path,
            control=control,
            subphase=subphase,
            kind=kind,
            round_no=n,
            title=_summary_title(phase, kind_raw, n),
            content=content,
        )
    raise FileNotFoundError(rel)


def _summary_title(phase: str, kind: str | None, n: int) -> str:
    sub = _SUB_LABEL[_PHASE_META[phase][2]]
    if kind == "round":
        return f"{sub}第 {n} 轮压缩摘要"
    if kind == "rescue":
        return f"{sub}抢救 · 第 {n} 次"
    return f"{sub}压缩摘要 · 第 {n} 次"


def _collect_phase_report_candidates(project_id: int) -> list[_ReportCandidate]:
    items: list[_ReportCandidate] = []
    root = project_root(project_id)

    for rel, control, subphase, title in _DOC_SPECS:
        path = root / rel
        item = _candidate(
            rel=rel,
            path=path,
            control=control,
            subphase=subphase,
            kind="doc",
            round_no=None,
            title=title,
        )
        if item is not None:
            items.append(item)

    rounds = workspace_dir(project_id) / "rounds"
    if rounds.is_dir():
        for path in rounds.glob("round-*.md"):
            m = _ROUND_NAME.match(path.name)
            if not m:
                continue
            n = int(m.group("n"))
            item = _candidate(
                rel=f"workspace/rounds/{path.name}",
                path=path,
                control="worker",
                subphase="mine",
                kind="round",
                round_no=n,
                title=_ROUND_TITLE,
            )
            if item is not None:
                items.append(item)
        for path in rounds.glob("fast-round-*.md"):
            m = _FAST_ROUND_NAME.match(path.name)
            if not m:
                continue
            n = int(m.group("n"))
            item = _candidate(
                rel=f"workspace/rounds/{path.name}",
                path=path,
                control="worker",
                subphase="fast",
                kind="round",
                round_no=n,
                title=_FAST_ROUND_TITLE,
            )
            if item is not None:
                items.append(item)
        for path in rounds.glob("bypass-round-*.md"):
            m = _BYPASS_ROUND_NAME.match(path.name)
            if not m:
                continue
            n = int(m.group("n"))
            item = _candidate(
                rel=f"workspace/rounds/{path.name}",
                path=path,
                control="worker",
                subphase="bypass",
                kind="round",
                round_no=n,
                title=_BYPASS_ROUND_TITLE,
            )
            if item is not None:
                items.append(item)

    verifier_dir = root / "docs" / "verifier"
    if verifier_dir.is_dir():
        for path in verifier_dir.glob("*.md"):
            if not path.stem.isdigit():
                continue
            item = _candidate(
                rel=f"docs/verifier/{path.name}",
                path=path,
                control="verifier",
                subphase="verify",
                kind="doc",
                round_no=None,
                title=f"互联网验证 · 漏洞 #{int(path.stem)}",
            )
            if item is not None:
                items.append(item)

    chain_dir = root / "docs" / "attack-chains"
    if chain_dir.is_dir():
        for path in chain_dir.glob("*.md"):
            if path.name == "index.md":
                continue
            item = _candidate(
                rel=f"docs/attack-chains/{path.name}",
                path=path,
                control="attack_chain",
                subphase="chain",
                kind="doc",
                round_no=None,
                title=f"攻击链 · {path.stem}",
            )
            if item is not None:
                items.append(item)

    d = summaries_dir(project_id)
    if d.is_dir():
        for path in d.glob("*.md"):
            m = _SUMMARY_NAME.match(path.name)
            if not m:
                continue
            phase = m.group("phase")
            kind_raw = m.group("kind")
            n = int(m.group("n"))
            kind = "rescue" if kind_raw == "rescue" else "summary"
            control, _, subphase = _PHASE_META[phase]
            if not _shows_summary_in_phase_reports(control):
                continue
            item = _candidate(
                rel=f"docs/summaries/{path.name}",
                path=path,
                control=control,
                subphase=subphase,
                kind=kind,
                round_no=n,
                title=_summary_title(phase, kind_raw, n),
            )
            if item is not None:
                items.append(item)

    items.sort(key=lambda x: (x.sort_mtime, x.rel), reverse=True)
    return items


def list_phase_reports(project_id: int) -> list[dict[str, Any]]:
    return [_candidate_item(c) for c in _collect_phase_report_candidates(project_id)]


def reports_by_phase(
    project_id: int,
    *,
    phase: str | None = None,
    subphase: str | None = None,
    limit: int | None = None,
    offset: int = 0,
) -> dict[str, Any]:
    selected_phase = (phase or "").strip()
    if selected_phase == "all":
        selected_phase = ""
    if selected_phase and selected_phase not in _CONTROL_LABEL:
        raise ValueError("未知阶段")
    selected_subphase = (subphase or "").strip()
    if selected_subphase == "all":
        selected_subphase = ""
    if selected_subphase and selected_subphase not in _SUB_LABEL:
        raise ValueError("未知子阶段")

    candidates = _collect_phase_report_candidates(project_id)
    grouped: dict[str, list[_ReportCandidate]] = {key: [] for key in _CONTROL_PHASES}
    for item in candidates:
        grouped.setdefault(item.control, []).append(item)

    offset = max(0, offset)
    if limit is not None:
        limit = max(0, limit)

    reports_by_control: dict[str, list[dict[str, Any]]] = {key: [] for key in _CONTROL_PHASES}
    if selected_phase:
        selected = grouped[selected_phase]
        if selected_subphase:
            selected = [item for item in selected if item.subphase == selected_subphase]
        selected_count = len(selected)
        page = selected[offset : offset + limit] if limit is not None else selected[offset:]
        reports_by_control[selected_phase] = [_candidate_item(item) for item in page]
    else:
        selected = candidates
        if selected_subphase:
            selected = [item for item in selected if item.subphase == selected_subphase]
        selected_count = len(selected)
        for key in _CONTROL_PHASES:
            page_source = grouped[key]
            if selected_subphase:
                page_source = [item for item in page_source if item.subphase == selected_subphase]
            page = page_source[offset : offset + limit] if limit is not None else page_source[offset:]
            reports_by_control[key] = [_candidate_item(item) for item in page]

    phases = [
        {
            "phase": key,
            "label": _CONTROL_LABEL[key],
            "count": len(grouped[key]),
            "reports": reports_by_control[key],
        }
        for key in _CONTROL_PHASES
    ]
    return {
        "phases": phases,
        "count": len(candidates),
        "selected_count": selected_count,
        "limit": limit,
        "offset": offset,
        "phase": selected_phase,
        "subphase": selected_subphase,
    }


def read_phase_report(project_id: int, rel: str) -> dict[str, Any]:
    rel = _safe_rel(rel)
    path = _resolve(project_id, rel)
    if not path.is_file():
        raise FileNotFoundError(rel)
    meta = _item_for_rel(project_id, rel)
    text = path.read_text(encoding="utf-8", errors="replace")
    return {**meta, "content": text}

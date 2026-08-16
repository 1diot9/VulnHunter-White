"""Catalog FinishRound reports, recon docs, and visible phase summaries."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .paths import project_root, summaries_dir, workspace_dir

_SUMMARY_NAME = re.compile(
    r"^(?P<phase>recon(?:-old-vuln|-mark)?|worker|fix|reviewer)"
    r"(?:-(?P<kind>round|rescue))?"
    r"-(?P<n>\d+)\.md$"
)
_ROUND_NAME = re.compile(r"^round-(?P<n>\d+)\.md$")

# filename phase -> (control phase, control label, subphase id)
_PHASE_META: dict[str, tuple[str, str, str]] = {
    "recon": ("recon", "侦察", "map"),
    "recon-old-vuln": ("recon", "侦察", "old_vulns"),
    "recon-mark": ("recon", "侦察", "mark"),
    "worker": ("worker", "挖掘", "mine"),
    "fix": ("worker", "挖掘", "fix"),
    "reviewer": ("reviewer", "审核", "reviewer"),
}

_CONTROL_LABEL = {"recon": "侦察", "worker": "挖掘", "reviewer": "审核"}
_SUB_LABEL = {
    "map": "地图/鉴权",
    "old_vulns": "历史漏洞",
    "mark": "盖章",
    "mine": "挖掘",
    "fix": "修复",
    "reviewer": "审核",
}
_KIND_LABEL = {"doc": "文档", "round": "审计", "summary": "摘要", "rescue": "抢救"}

_DOC_SPECS: tuple[tuple[str, str, str, str], ...] = (
    ("docs/code-map.md", "recon", "map", "代码地图"),
    ("docs/auth.md", "recon", "map", "鉴权说明"),
    ("docs/old-vulns/index.md", "recon", "old_vulns", "历史漏洞索引"),
    ("docs/lab.md", "reviewer", "reviewer", "动态环境搭建"),
)
_DOC_BY_REL = {rel: (control, subphase, title) for rel, control, subphase, title in _DOC_SPECS}
_PREVIEW_CHARS = 8192


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
    heading, preview = _heading_or_preview(text)
    out: dict[str, Any] = {
        "id": rel.replace("\\", "/"),
        "phase": control,
        "phase_label": _CONTROL_LABEL[control],
        "subphase": subphase,
        "subphase_label": _SUB_LABEL[subphase],
        "kind": kind,
        "kind_label": _KIND_LABEL[kind],
        "round": round_no,
        "title": heading or title,
        "preview": preview,
        "mtime": _iso_mtime(path),
        "size": path.stat().st_size,
    }
    if content is not None:
        out["content"] = text
    return out


def _safe_rel(rel: str) -> str:
    cleaned = (rel or "").replace("\\", "/").lstrip("/")
    if not cleaned or ".." in Path(cleaned).parts:
        raise ValueError("非法路径")
    if not (cleaned.startswith("docs/") or cleaned.startswith("workspace/rounds/")):
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
        if not m:
            raise FileNotFoundError(rel)
        n = int(m.group("n"))
        return _item(
            rel=rel,
            path=path,
            control="worker",
            subphase="mine",
            kind="round",
            round_no=n,
            title=f"第 {n} 轮审计",
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


def list_phase_reports(project_id: int) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    root = project_root(project_id)

    for rel, control, subphase, title in _DOC_SPECS:
        path = root / rel
        if path.is_file() and path.stat().st_size > 0:
            items.append(
                _item(
                    rel=rel,
                    path=path,
                    control=control,
                    subphase=subphase,
                    kind="doc",
                    round_no=None,
                    title=title,
                )
            )

    rounds = workspace_dir(project_id) / "rounds"
    if rounds.is_dir():
        for path in rounds.glob("round-*.md"):
            m = _ROUND_NAME.match(path.name)
            if not m or not path.is_file() or path.stat().st_size <= 0:
                continue
            n = int(m.group("n"))
            items.append(
                _item(
                    rel=f"workspace/rounds/{path.name}",
                    path=path,
                    control="worker",
                    subphase="mine",
                    kind="round",
                    round_no=n,
                    title=f"第 {n} 轮审计",
                )
            )

    d = summaries_dir(project_id)
    if d.is_dir():
        for path in d.glob("*.md"):
            m = _SUMMARY_NAME.match(path.name)
            if not m or not path.is_file() or path.stat().st_size <= 0:
                continue
            phase = m.group("phase")
            kind_raw = m.group("kind")
            n = int(m.group("n"))
            kind = "rescue" if kind_raw == "rescue" else "summary"
            control, _, subphase = _PHASE_META[phase]
            if not _shows_summary_in_phase_reports(control):
                continue
            items.append(
                _item(
                    rel=f"docs/summaries/{path.name}",
                    path=path,
                    control=control,
                    subphase=subphase,
                    kind=kind,
                    round_no=n,
                    title=_summary_title(phase, kind_raw, n),
                )
            )

    items.sort(key=lambda x: (x["mtime"], x["id"]), reverse=True)
    return items


def reports_by_phase(project_id: int) -> dict[str, Any]:
    items = list_phase_reports(project_id)
    grouped: dict[str, list[dict[str, Any]]] = {"recon": [], "worker": [], "reviewer": []}
    for item in items:
        grouped.setdefault(item["phase"], []).append(item)
    phases = [
        {
            "phase": key,
            "label": _CONTROL_LABEL[key],
            "count": len(grouped[key]),
            "reports": grouped[key],
        }
        for key in ("recon", "worker", "reviewer")
    ]
    return {"phases": phases, "count": len(items)}


def read_phase_report(project_id: int, rel: str) -> dict[str, Any]:
    rel = _safe_rel(rel)
    path = _resolve(project_id, rel)
    if not path.is_file():
        raise FileNotFoundError(rel)
    meta = _item_for_rel(project_id, rel)
    text = path.read_text(encoding="utf-8", errors="replace")
    return {**meta, "content": text}

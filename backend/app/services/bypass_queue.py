"""Persist, freeze, claim, and pick historical-vuln bypass targets."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from ..models import BypassTarget, Project, SessionLocal, utcnow
from .paths import old_vulns_dir

ACTIVE_STATUSES = ("queued", "claimed")
OPEN_STATUSES = ("queued", "claimed")
_CVE_RE = re.compile(r"CVE[-_](\d{4})[-_](\d+)", re.I)


def _norm_rel(name: str) -> str:
    return f"docs/old-vulns/{Path(name).name}"


def _parse_frontmatter(text: str) -> tuple[dict[str, Any], str]:
    if not text.lstrip().startswith("---"):
        return {}, text
    parts = text.split("---", 2)
    if len(parts) < 3:
        return {}, text
    try:
        meta = yaml.safe_load(parts[1]) or {}
    except Exception:  # noqa: BLE001
        meta = {}
    if not isinstance(meta, dict):
        meta = {}
    return meta, parts[2].lstrip("\n")


def _cve_recency_tuple(*parts: str | None) -> tuple[int, int]:
    """Higher (year, sequence) is newer. Missing CVE sorts as oldest."""
    blob = " ".join(str(p or "") for p in parts)
    best = (0, 0)
    for m in _CVE_RE.finditer(blob):
        key = (int(m.group(1)), int(m.group(2)))
        if key > best:
            best = key
    return best


def _iter_old_vuln_files(project_id: int) -> list[Path]:
    old_dir = old_vulns_dir(project_id)
    if not old_dir.is_dir():
        return []
    files = [fp for fp in old_dir.glob("*.md") if fp.name != "index.md" and fp.is_file()]
    files.sort(key=lambda fp: (_cve_recency_tuple(fp.name), fp.name.lower()), reverse=True)
    return files


def ingest_old_vulns(project_id: int) -> int:
    """Create queued rows for each historical-vuln document. Existing paths are kept."""
    files = _iter_old_vuln_files(project_id)
    with SessionLocal() as db:
        existing = {
            str(row.file_path or "")
            for row in db.query(BypassTarget).filter(BypassTarget.project_id == project_id).all()
        }
        n = 0
        for fp in files:
            rel = _norm_rel(fp.name)
            if rel in existing:
                continue
            text = fp.read_text(encoding="utf-8", errors="ignore")
            meta, _body = _parse_frontmatter(text)
            db.add(
                BypassTarget(
                    project_id=project_id,
                    file_path=rel,
                    title=str(meta.get("title") or fp.stem)[:512],
                    summary=str(meta.get("summary") or "")[:2000] or None,
                    cve=str(meta.get("cve") or "").strip()[:64] or None,
                    cwe=str(meta.get("cwe") or "").strip()[:64] or None,
                    fix_status=str(meta.get("fix_status") or "").strip()[:32] or None,
                    source=str(meta.get("source") or "").strip()[:64] or None,
                    status="queued",
                    verdict="pending",
                )
            )
            n += 1
        db.commit()
        return n


def freeze_bypass_queue(project_id: int) -> int:
    ingest_old_vulns(project_id)
    with SessionLocal() as db:
        queued = (
            db.query(BypassTarget)
            .filter(BypassTarget.project_id == project_id, BypassTarget.status.in_(("queued", "claimed", "done")))
            .count()
        )
        proj = db.get(Project, project_id)
        if proj:
            proj.bypass_queue_frozen = True
        db.commit()
        return int(queued)


def freeze_empty_bypass_queue(project_id: int) -> None:
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        if proj:
            proj.bypass_queue_frozen = True
            db.commit()


def queue_frozen(project_id: int) -> bool:
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        return bool(proj and proj.bypass_queue_frozen)


def bypass_counts(project_id: int) -> dict[str, int]:
    with SessionLocal() as db:
        rows = db.query(BypassTarget).filter(BypassTarget.project_id == project_id).all()
    queued = sum(1 for row in rows if row.status in ("queued", "claimed", "done"))
    done = sum(1 for row in rows if row.status == "done")
    return {"queued": queued, "done": done, "open": sum(1 for row in rows if row.status in ACTIVE_STATUSES)}


def bypass_path_complete(project_id: int) -> bool:
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        if not proj or not bool(getattr(proj, "bypass_enabled", False)):
            return True
        if not bool(getattr(proj, "bypass_queue_frozen", False)):
            return False
        open_n = (
            db.query(BypassTarget)
            .filter(BypassTarget.project_id == project_id, BypassTarget.status.in_(ACTIVE_STATUSES))
            .count()
        )
        return open_n == 0


def pick_next_bypass(project_id: int, worker_id: str) -> BypassTarget | None:
    with SessionLocal() as db:
        rows = (
            db.query(BypassTarget)
            .filter(
                BypassTarget.project_id == project_id,
                BypassTarget.status == "queued",
                BypassTarget.claimed_by.is_(None),
            )
            .all()
        )
        if not rows:
            return None
        rows.sort(
            key=lambda row: (_cve_recency_tuple(row.cve, row.file_path), int(row.id or 0)),
            reverse=True,
        )
        chosen = rows[0]
        chosen.status = "claimed"
        chosen.claimed_by = worker_id
        chosen.claimed_at = utcnow()
        db.commit()
        db.refresh(chosen)
        db.expunge(chosen)
        return chosen


def reclaim_bypass(project_id: int, bypass_id: int, worker_id: str) -> BypassTarget | None:
    with SessionLocal() as db:
        row = db.get(BypassTarget, bypass_id)
        if not row or row.project_id != project_id:
            return None
        if row.status == "done":
            db.expunge(row)
            return row
        row.status = "claimed"
        row.claimed_by = worker_id
        row.claimed_at = utcnow()
        db.commit()
        db.refresh(row)
        db.expunge(row)
        return row


def release_bypass_claim(project_id: int, bypass_id: int, worker_id: str) -> None:
    with SessionLocal() as db:
        row = db.get(BypassTarget, bypass_id)
        if not row or row.project_id != project_id:
            return
        if row.status == "done":
            return
        if row.claimed_by == worker_id or row.status == "claimed":
            row.status = "queued"
            row.claimed_by = None
            row.claimed_at = None
            db.commit()


def release_stale_bypass_claims(project_id: int, *, stale_before, except_ids: set[int] | None = None) -> int:
    keep = except_ids or set()
    with SessionLocal() as db:
        rows = (
            db.query(BypassTarget)
            .filter(
                BypassTarget.project_id == project_id,
                BypassTarget.status == "claimed",
                BypassTarget.claimed_at.isnot(None),
                BypassTarget.claimed_at < stale_before,
            )
            .all()
        )
        n = 0
        for row in rows:
            if row.id in keep:
                continue
            row.status = "queued"
            row.claimed_by = None
            row.claimed_at = None
            n += 1
        if n:
            db.commit()
        return n


def reset_bypass_progress(project_id: int) -> int:
    """Unclaim finished/queued bypass targets; keep the frozen roster."""
    with SessionLocal() as db:
        rows = (
            db.query(BypassTarget)
            .filter(BypassTarget.project_id == project_id, BypassTarget.status.in_(("queued", "claimed", "done")))
            .all()
        )
        n = 0
        for row in rows:
            row.status = "queued"
            row.claimed_by = None
            row.claimed_at = None
            row.verdict = "pending"
            row.vuln_id = None
            n += 1
        db.commit()
        return n


def load_bypass_doc(project_id: int, file_path: str, *, max_chars: int) -> str:
    name = Path(str(file_path or "")).name
    if not name or name == "index.md":
        return ""
    path = old_vulns_dir(project_id) / name
    if not path.is_file():
        return ""
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        return ""
    if len(text) > max_chars:
        return text[:max_chars] + f"\n...[truncated {len(text) - max_chars} chars]"
    return text


def bypass_card(row: BypassTarget) -> dict[str, Any]:
    return {
        "id": row.id,
        "file_path": row.file_path,
        "title": row.title,
        "summary": row.summary or "",
        "cve": row.cve or "",
        "cwe": row.cwe or "",
        "fix_status": row.fix_status or "",
        "source": row.source or "",
        "status": row.status,
    }


def parse_bypass_ref(raw: str | None) -> int | None:
    text = str(raw or "").strip()
    if not text.startswith("bypass:"):
        return None
    try:
        return int(text.split(":", 1)[1])
    except (TypeError, ValueError):
        return None


def bypass_ref(bypass_id: int) -> str:
    return f"bypass:{int(bypass_id)}"

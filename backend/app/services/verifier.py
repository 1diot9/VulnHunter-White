"""Verifier queue: after Reviewer confirms a frontend vuln, hunt lookalikes via FOFA."""

from __future__ import annotations

import re
from typing import Any

from ..models import Project, SessionLocal, Vuln
from .paths import docs_dir, vuln_dir

VERIFIER_NONE = "none"
VERIFIER_PENDING = "pending"
VERIFIER_VERIFIED = "verified"
VERIFIER_FAILED = "failed"
VERIFIER_SKIPPED = "skipped"
VERIFIER_STATUSES = frozenset(
    {VERIFIER_NONE, VERIFIER_PENDING, VERIFIER_VERIFIED, VERIFIER_FAILED, VERIFIER_SKIPPED}
)
CONFIRMED_STATUSES = frozenset({"confirmed", "static_only"})
_FOFA_BLOCK = re.compile(
    r"####\s*FOFA\s*\n+```(?:text|fofa)?\n(.*?)```",
    re.IGNORECASE | re.DOTALL,
)


def normalize_verifier_status(raw: Any) -> str:
    s = str(raw or "").strip().lower()
    return s if s in VERIFIER_STATUSES else VERIFIER_NONE


def is_verifier_enabled(project_id: int) -> bool:
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        return bool(proj and proj.verifier_enabled)


def extract_fofa_query(report_md: str) -> str:
    m = _FOFA_BLOCK.search(report_md or "")
    if not m:
        return ""
    return " ".join(m.group(1).split()).strip()


def read_report_md(project_id: int, vuln_id: int) -> str:
    path = vuln_dir(project_id, vuln_id) / "report.md"
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def verifier_report_rel(vuln_id: int) -> str:
    return f"docs/verifier/{int(vuln_id)}.md"


def verifier_report_path(project_id: int, vuln_id: int):
    path = docs_dir(project_id) / "verifier" / f"{int(vuln_id)}.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def enqueue_frontend_vuln(project_id: int, vuln_id: int) -> bool:
    """Queue one confirmed frontend vuln if Verifier is enabled. Returns True if queued."""
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        if not proj or not proj.verifier_enabled:
            return False
        vuln = db.get(Vuln, int(vuln_id))
        if not vuln or vuln.project_id != project_id:
            return False
        if vuln.status not in CONFIRMED_STATUSES:
            return False
        if (vuln.attack_surface or "") != "frontend":
            return False
        current = normalize_verifier_status(vuln.verifier_status)
        if current not in (VERIFIER_NONE, ""):
            return False
        vuln.verifier_status = VERIFIER_PENDING
        db.commit()
        return True


def enqueue_confirmed_frontend(project_id: int) -> int:
    """When enabling Verifier, queue already-confirmed frontend vulns. Returns queued count."""
    n = 0
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        if not proj or not proj.verifier_enabled:
            return 0
        rows = (
            db.query(Vuln)
            .filter(
                Vuln.project_id == project_id,
                Vuln.status.in_(tuple(CONFIRMED_STATUSES)),
                Vuln.attack_surface == "frontend",
            )
            .all()
        )
        for vuln in rows:
            current = normalize_verifier_status(vuln.verifier_status)
            if current in (VERIFIER_NONE, ""):
                vuln.verifier_status = VERIFIER_PENDING
                n += 1
        if n:
            db.commit()
    return n


def pending_verifier_count(project_id: int) -> int:
    with SessionLocal() as db:
        return (
            db.query(Vuln)
            .filter(
                Vuln.project_id == project_id,
                Vuln.verifier_status == VERIFIER_PENDING,
                Vuln.status.in_(tuple(CONFIRMED_STATUSES)),
                Vuln.attack_surface == "frontend",
            )
            .count()
        )


def pick_pending_verifier_vuln(project_id: int, prefer_id: int | None = None) -> Vuln | None:
    with SessionLocal() as db:
        vuln = None
        if prefer_id is not None:
            vuln = db.get(Vuln, int(prefer_id))
            if vuln and (
                vuln.project_id != project_id
                or vuln.verifier_status != VERIFIER_PENDING
                or vuln.status not in CONFIRMED_STATUSES
            ):
                vuln = None
        if vuln is None:
            vuln = (
                db.query(Vuln)
                .filter(
                    Vuln.project_id == project_id,
                    Vuln.verifier_status == VERIFIER_PENDING,
                    Vuln.status.in_(tuple(CONFIRMED_STATUSES)),
                    Vuln.attack_surface == "frontend",
                )
                .order_by(Vuln.id.asc())
                .first()
            )
        if not vuln:
            return None
        db.expunge(vuln)
        return vuln

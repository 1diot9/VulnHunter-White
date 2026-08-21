"""Idempotent seed for the bundled MemoBoard showcase project (id=11).

Commits workspace files under data/projects/11/ and a JSON DB manifest;
runtime `data/app.db` is never committed. On first boot (or when the demo
rows are missing), `seed_bundled_demo_project()` inserts the showcase
project so the frontend can list it without scanning the filesystem.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from sqlalchemy import Boolean, DateTime, Integer, inspect as sa_inspect, text
from sqlalchemy.orm import Session

from ..config import settings
from ..models import (
    AttackChain,
    FileWeight,
    PhaseRun,
    Project,
    SessionLocal,
    Source,
    TokenUsage,
    Vuln,
)
from .paths import project_dir

log = logging.getLogger("vulnhunter.demo_seed")

DEMO_PROJECT_ID = 11
DEMO_PROJECT_NAME = "vulnhunter-python-lab"
SEED_RELATIVE = Path("showcase") / "db-seed.json"

# Insert order respects foreign keys (project first, then children).
SEED_TABLE_ORDER = (
    "projects",
    "file_weights",
    "sources",
    "vulns",
    "attack_chains",
    "phase_runs",
    "token_usages",
)

MODEL_BY_TABLE: dict[str, type] = {
    "projects": Project,
    "file_weights": FileWeight,
    "sources": Source,
    "vulns": Vuln,
    "attack_chains": AttackChain,
    "phase_runs": PhaseRun,
    "token_usages": TokenUsage,
}


def demo_seed_manifest_path(project_id: int = DEMO_PROJECT_ID) -> Path:
    return project_dir(project_id) / SEED_RELATIVE


def demo_workspace_present(project_id: int = DEMO_PROJECT_ID) -> bool:
    root = project_dir(project_id)
    return (root / "src").is_dir() or (root / "vulns").is_dir()


def load_demo_seed_manifest(path: Path | None = None) -> dict[str, Any] | None:
    manifest = Path(path) if path is not None else demo_seed_manifest_path()
    if not manifest.is_file():
        return None
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        log.warning("demo seed manifest unreadable path=%s err=%s", manifest, exc)
        return None
    if not isinstance(data, dict):
        return None
    tables = data.get("tables")
    if not isinstance(tables, dict):
        return None
    return data


def _parse_dt(value: Any) -> Any:
    if value is None or isinstance(value, datetime):
        return value
    if isinstance(value, str):
        text_v = value.strip()
        if not text_v:
            return None
        try:
            return datetime.fromisoformat(text_v)
        except ValueError:
            return value
    return value


def _row_kwargs(model: type, row: dict[str, Any]) -> dict[str, Any]:
    mapper = sa_inspect(model).mapper
    out: dict[str, Any] = {}
    for key, value in row.items():
        if key not in mapper.columns:
            continue
        col = mapper.columns[key]
        if value is None:
            out[key] = None
            continue
        if isinstance(col.type, Boolean):
            out[key] = bool(value)
        elif isinstance(col.type, DateTime):
            out[key] = _parse_dt(value)
        elif isinstance(col.type, Integer) and not isinstance(value, bool):
            try:
                out[key] = int(value)
            except (TypeError, ValueError):
                out[key] = value
        else:
            out[key] = value
    return out


def _bump_sqlite_sequence(db: Session, table: str, at_least: int) -> None:
    """Raise SQLite AUTOINCREMENT high-water mark past showcase ids when possible."""
    if at_least < 1:
        return
    has_seq = db.execute(
        text("SELECT 1 FROM sqlite_master WHERE type='table' AND name='sqlite_sequence'")
    ).scalar()
    if not has_seq:
        # Without AUTOINCREMENT, SQLite uses MAX(id)+1 — explicit showcase ids are enough.
        return
    cur = db.execute(
        text("SELECT seq FROM sqlite_sequence WHERE name = :n"),
        {"n": table},
    ).scalar()
    if cur is None:
        db.execute(
            text("INSERT INTO sqlite_sequence(name, seq) VALUES (:n, :s)"),
            {"n": table, "s": int(at_least)},
        )
    elif int(cur) < int(at_least):
        db.execute(
            text("UPDATE sqlite_sequence SET seq = :s WHERE name = :n"),
            {"n": table, "s": int(at_least)},
        )


def _insert_missing_rows(
    db: Session,
    table: str,
    rows: list[dict[str, Any]],
) -> int:
    model = MODEL_BY_TABLE.get(table)
    if model is None or not rows:
        return 0
    existing_ids = {
        int(r[0])
        for r in db.query(model.id).all()  # type: ignore[attr-defined]
        if r[0] is not None
    }
    added = 0
    max_id = 0
    for raw in rows:
        if not isinstance(raw, dict):
            continue
        kwargs = _row_kwargs(model, raw)
        row_id = kwargs.get("id")
        if row_id is None:
            continue
        rid = int(row_id)
        max_id = max(max_id, rid)
        if rid in existing_ids:
            continue
        db.add(model(**kwargs))
        existing_ids.add(rid)
        added += 1
    if max_id:
        db.flush()
        _bump_sqlite_sequence(db, table, max_id)
    return added


def seed_bundled_demo_project(
    *,
    db: Session | None = None,
    manifest_path: Path | None = None,
    force: bool = False,
) -> dict[str, Any]:
    """Import showcase DB rows when the bundled workspace + manifest exist.

    Returns a small status dict for tests / logging. Never overwrites a
    non-demo project that already occupies id=11.
    """
    result: dict[str, Any] = {
        "seeded": False,
        "skipped": False,
        "reason": "",
        "project_id": DEMO_PROJECT_ID,
        "added": {},
    }

    if not force and not bool(getattr(settings, "demo_seed", True)):
        result["skipped"] = True
        result["reason"] = "disabled"
        return result

    data = load_demo_seed_manifest(manifest_path)
    if data is None:
        result["skipped"] = True
        result["reason"] = "manifest_missing"
        return result

    # Default bundle requires on-disk workspace; explicit manifest_path is for tests.
    if manifest_path is None and not demo_workspace_present(DEMO_PROJECT_ID):
        result["skipped"] = True
        result["reason"] = "workspace_missing"
        return result

    tables = data.get("tables") or {}
    project_rows = tables.get("projects") or []
    if not project_rows:
        result["skipped"] = True
        result["reason"] = "empty_manifest"
        return result

    expected_name = str(data.get("project_name") or DEMO_PROJECT_NAME).strip() or DEMO_PROJECT_NAME
    owns_session = db is None
    session = db or SessionLocal()
    try:
        existing = session.get(Project, DEMO_PROJECT_ID)
        if existing is not None:
            name = (existing.name or "").strip()
            if name != expected_name and name != DEMO_PROJECT_NAME:
                log.warning(
                    "demo seed skipped: projects.id=%s already occupied by %r",
                    DEMO_PROJECT_ID,
                    name,
                )
                result["skipped"] = True
                result["reason"] = "id_conflict"
                return result
        else:
            # Insert project row first.
            proj_kwargs = _row_kwargs(Project, project_rows[0])
            proj_kwargs["id"] = DEMO_PROJECT_ID
            proj_kwargs["name"] = expected_name
            proj_kwargs["status"] = "completed"
            proj_kwargs["phase"] = "done"
            proj_kwargs["recon_done"] = True
            proj_kwargs["attack_chain_done"] = True
            if not (proj_kwargs.get("dynamic_verify_mode") or "").strip():
                proj_kwargs["dynamic_verify_mode"] = "harness"
            session.add(Project(**proj_kwargs))
            session.flush()
            _bump_sqlite_sequence(session, "projects", DEMO_PROJECT_ID)
            result["added"]["projects"] = 1

        for table in SEED_TABLE_ORDER:
            if table == "projects":
                continue
            rows = tables.get(table) or []
            if not isinstance(rows, list):
                continue
            n = _insert_missing_rows(session, table, rows)
            if n:
                result["added"][table] = n

        session.commit()
        result["seeded"] = bool(result["added"])
        result["reason"] = "ok" if result["seeded"] else "already_present"
        if result["seeded"]:
            log.info(
                "demo seed imported project_id=%s added=%s",
                DEMO_PROJECT_ID,
                result["added"],
            )
        return result
    except Exception:
        session.rollback()
        raise
    finally:
        if owns_session:
            session.close()

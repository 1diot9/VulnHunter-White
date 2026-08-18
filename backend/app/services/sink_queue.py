"""Persist, freeze, claim, and pick Semgrep sinks for the fast path."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..models import FileWeight, Project, SessionLocal, Sink, Source, utcnow
from .paths import src_dir
from .sink_filter import (
    AUDIT_QUEUE_LIMIT,
    CANDIDATE_LIMIT,
    FilterContext,
    merge_findings,
    protected_from_drop,
    select_candidates,
)

ACTIVE_STATUSES = ("queued", "claimed")
OPEN_STATUSES = ("candidate", "queued", "claimed")


def _norm(path: str) -> str:
    return str(path or "").replace("\\", "/").lstrip("./")


def filter_context(project_id: int, *, bounty: bool) -> FilterContext:
    with SessionLocal() as db:
        files = db.query(FileWeight).filter(FileWeight.project_id == project_id).all()
        sources = db.query(Source).filter(Source.project_id == project_id).all()
        skipped = {_norm(row.path) for row in files if row.skipped}
        weights = {_norm(row.path): int(row.weight or 0) for row in files if row.weight is not None}
        has_source = {_norm(row.path) for row in files if row.has_source}
        source_files = {_norm(row.file_path) for row in sources}
    return FilterContext(
        skipped_paths=skipped,
        file_weights=weights,
        has_source=has_source,
        source_files=source_files,
        bounty=bounty,
    )


def persist_candidates(project_id: int, findings: list[dict[str, Any]]) -> int:
    with SessionLocal() as db:
        db.query(Sink).filter(Sink.project_id == project_id).delete(synchronize_session=False)
        n = 0
        for item in findings:
            db.add(
                Sink(
                    project_id=project_id,
                    file_path=str(item.get("file_path") or ""),
                    line_start=int(item.get("line_start") or 0),
                    line_end=int(item.get("line_end") or 0),
                    check_ids=json.dumps(item.get("check_ids") or [], ensure_ascii=False),
                    snippet=str(item.get("snippet") or "")[:4000],
                    severity=str(item.get("severity") or "WARNING"),
                    confidence=str(item.get("confidence") or "MEDIUM"),
                    mapped_vuln_type=str(item.get("mapped_vuln_type") or "other"),
                    code_score=int(item.get("code_score") or 0),
                    status="candidate",
                    verdict="pending",
                )
            )
            n += 1
        proj = db.get(Project, project_id)
        if proj:
            proj.fast_queue_frozen = False
        db.commit()
        return n


def ingest_semgrep_results(
    project_id: int,
    payload: dict[str, Any],
    *,
    bounty: bool,
    limit: int = CANDIDATE_LIMIT,
) -> int:
    ctx = filter_context(project_id, bounty=bounty)
    raw = payload.get("results") if isinstance(payload, dict) else []
    merged = merge_findings(
        raw if isinstance(raw, list) else [],
        ctx,
        src_root=src_dir(project_id),
    )
    return persist_candidates(project_id, select_candidates(merged, limit=limit))


def load_undecided_candidates(project_id: int, *, limit: int = 30) -> list[Sink]:
    with SessionLocal() as db:
        rows = (
            db.query(Sink)
            .filter(
                Sink.project_id == project_id,
                Sink.status == "candidate",
                Sink.agent_decision.is_(None),
            )
            .order_by(Sink.code_score.desc(), Sink.id.asc())
            .limit(max(1, int(limit)))
            .all()
        )
        for row in rows:
            db.expunge(row)
        return rows


def apply_triage_decisions(project_id: int, decisions: list[dict[str, Any]]) -> dict[str, int]:
    applied = 0
    ignored = 0
    with SessionLocal() as db:
        ctx = filter_context(project_id, bounty=False)
        by_id = {
            int(item.get("id") or item.get("sink_id") or 0): item
            for item in decisions
            if isinstance(item, dict)
        }
        rows = (
            db.query(Sink)
            .filter(Sink.project_id == project_id, Sink.id.in_(list(by_id) or [-1]))
            .all()
        )
        for row in rows:
            item = by_id.get(row.id) or {}
            decision = str(item.get("decision") or "").strip().lower()
            if decision not in {"keep", "drop", "defer"}:
                ignored += 1
                continue
            if decision == "drop" and protected_from_drop(
                severity=row.severity,
                confidence=row.confidence,
                path=row.file_path,
                ctx=ctx,
            ):
                decision = "defer"
            row.agent_decision = decision
            row.agent_reason = str(item.get("reason") or "")[:1000] or None
            applied += 1
        db.commit()
    return {"applied": applied, "ignored": ignored}


def freeze_audit_queue(project_id: int, *, limit: int = AUDIT_QUEUE_LIMIT) -> int:
    with SessionLocal() as db:
        rows = (
            db.query(Sink)
            .filter(Sink.project_id == project_id, Sink.status.in_(("candidate", "queued", "dropped_agent")))
            .all()
        )
        ranked: list[tuple[int, Sink]] = []
        for row in rows:
            bonus = 0
            if row.agent_decision == "keep":
                bonus = 15
            elif row.agent_decision == "drop":
                bonus = -40
            ranked.append((int(row.code_score or 0) + bonus, row))
        ranked.sort(key=lambda item: (-item[0], item[1].file_path, item[1].id))
        keep_ids = {row.id for _score, row in ranked[: max(0, int(limit))]}
        queued = 0
        for _score, row in ranked:
            if row.id in keep_ids:
                row.status = "queued"
                row.claimed_by = None
                row.claimed_at = None
                row.verdict = "pending"
                queued += 1
            else:
                row.status = "dropped_agent"
                row.claimed_by = None
                row.claimed_at = None
        proj = db.get(Project, project_id)
        if proj:
            proj.fast_queue_frozen = True
        db.commit()
        return queued


def freeze_empty_queue(project_id: int) -> None:
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        if proj:
            proj.fast_queue_frozen = True
            db.commit()


def queue_frozen(project_id: int) -> bool:
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        return bool(proj and proj.fast_queue_frozen)


def sink_counts(project_id: int) -> dict[str, int]:
    with SessionLocal() as db:
        rows = db.query(Sink).filter(Sink.project_id == project_id).all()
    queued = sum(1 for row in rows if row.status in ("queued", "claimed", "done"))
    done = sum(1 for row in rows if row.status == "done")
    return {"queued": queued, "done": done, "open": sum(1 for row in rows if row.status in ACTIVE_STATUSES)}


def fast_path_complete(project_id: int) -> bool:
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        if not proj or not proj.fast_enabled:
            return True
        if not proj.fast_queue_frozen:
            return False
        open_n = (
            db.query(Sink)
            .filter(Sink.project_id == project_id, Sink.status.in_(ACTIVE_STATUSES))
            .count()
        )
        return open_n == 0


def pick_next_sink(project_id: int, worker_id: str, *, prefer_dir: str | None = None) -> Sink | None:
    with SessionLocal() as db:
        q = (
            db.query(Sink)
            .filter(
                Sink.project_id == project_id,
                Sink.status == "queued",
                Sink.claimed_by.is_(None),
            )
            .order_by(Sink.code_score.desc(), Sink.id.asc())
        )
        rows = q.all()
        chosen: Sink | None = None
        if prefer_dir:
            prefix = prefer_dir.replace("\\", "/").rstrip("/")
            for row in rows:
                parent = str(Path(row.file_path).parent).replace("\\", "/")
                if parent == prefix or row.file_path.replace("\\", "/").startswith(f"{prefix}/"):
                    chosen = row
                    break
        if chosen is None and rows:
            chosen = rows[0]
        if chosen is None:
            return None
        chosen.status = "claimed"
        chosen.claimed_by = worker_id
        chosen.claimed_at = utcnow()
        db.commit()
        db.refresh(chosen)
        db.expunge(chosen)
        return chosen


def reclaim_sink(project_id: int, sink_id: int, worker_id: str) -> Sink | None:
    with SessionLocal() as db:
        row = db.get(Sink, sink_id)
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


def release_sink_claim(project_id: int, sink_id: int, worker_id: str) -> None:
    with SessionLocal() as db:
        row = db.get(Sink, sink_id)
        if not row or row.project_id != project_id:
            return
        if row.status == "done":
            return
        if row.claimed_by == worker_id or row.status == "claimed":
            row.status = "queued"
            row.claimed_by = None
            row.claimed_at = None
            db.commit()


def release_stale_sink_claims(project_id: int, *, stale_before, except_ids: set[int] | None = None) -> int:
    keep = except_ids or set()
    with SessionLocal() as db:
        rows = (
            db.query(Sink)
            .filter(
                Sink.project_id == project_id,
                Sink.status == "claimed",
                Sink.claimed_at.isnot(None),
                Sink.claimed_at < stale_before,
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


def reset_sink_progress(project_id: int) -> int:
    """Unclaim finished/queued sinks; keep the frozen audit roster."""
    with SessionLocal() as db:
        rows = (
            db.query(Sink)
            .filter(Sink.project_id == project_id, Sink.status.in_(("queued", "claimed", "done")))
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


def sink_card(row: Sink) -> dict[str, Any]:
    try:
        check_ids = json.loads(row.check_ids or "[]")
    except json.JSONDecodeError:
        check_ids = []
    if not isinstance(check_ids, list):
        check_ids = []
    return {
        "id": row.id,
        "file_path": row.file_path,
        "line_start": row.line_start,
        "line_end": row.line_end,
        "check_ids": check_ids,
        "snippet": row.snippet or "",
        "severity": row.severity,
        "confidence": row.confidence,
        "mapped_vuln_type": row.mapped_vuln_type,
        "code_score": row.code_score,
        "status": row.status,
    }


def parse_sink_ref(raw: str | None) -> int | None:
    text = str(raw or "").strip()
    if not text.startswith("sink:"):
        return None
    try:
        return int(text.split(":", 1)[1])
    except (TypeError, ValueError):
        return None


def sink_ref(sink_id: int) -> str:
    return f"sink:{int(sink_id)}"

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from fastapi.responses import StreamingResponse
from sqlalchemy import case, func

from ..models import AppSettings, FileWeight, PhaseRun, Project, SessionLocal, TokenUsage, ToolLog, Vuln
from ..schemas import (
    EventsChunk,
    FileWeightOut,
    PhaseReportDetail,
    PhaseReportList,
    PhaseRunOut,
    ProjectCreate,
    ProjectOut,
)
from ..services.live_log import live_log
from ..services.paths import ensure_project_dirs, force_rmtree, project_root
from ..services.phase_reports import read_phase_report, reports_by_phase
from ..services.pipeline import (
    control_phase,
    get_phase_states,
    request_cancel,
    request_pause,
    request_phase_pause,
    request_phase_restart,
    request_phase_resume,
    request_resume,
    start_ingest_and_audit,
)
from ..services.shutdown import is_shutting_down, wait_or_shutdown
from ..tools.phase_recon import recon_subphases

router = APIRouter(prefix="/api/projects", tags=["projects"])


def _empty_project_summary() -> dict[str, int]:
    return {
        "vuln_confirmed": 0,
        "vuln_false_positive": 0,
        "vuln_pending": 0,
        "files_total": 0,
        "files_weighted": 0,
        "files_skipped": 0,
        "files_audited": 0,
        "files_unmarked": 0,
        "worker_rounds": 0,
        "tokens_input": 0,
        "tokens_output": 0,
        "tokens_cached": 0,
        "tokens_total": 0,
    }


def _project_summaries(db, project_ids: list[int]) -> dict[int, dict[str, int]]:
    ids = list(dict.fromkeys(project_ids))
    summaries = {pid: _empty_project_summary() for pid in ids}
    if not ids:
        return summaries

    for row in (
        db.query(
            Vuln.project_id,
            func.sum(case((Vuln.status.in_(("confirmed", "static_only")), 1), else_=0)),
            func.sum(case((Vuln.status == "false_positive", 1), else_=0)),
            func.sum(case((Vuln.status.in_(("pending_review", "returned", "fixing")), 1), else_=0)),
        )
        .filter(Vuln.project_id.in_(ids))
        .group_by(Vuln.project_id)
    ):
        s = summaries[int(row[0])]
        s["vuln_confirmed"] = int(row[1] or 0)
        s["vuln_false_positive"] = int(row[2] or 0)
        s["vuln_pending"] = int(row[3] or 0)

    for row in (
        db.query(
            FileWeight.project_id,
            func.count(FileWeight.id),
            func.sum(case((FileWeight.weight.isnot(None) & FileWeight.skipped.is_(False), 1), else_=0)),
            func.sum(case((FileWeight.skipped.is_(True), 1), else_=0)),
            func.sum(case((FileWeight.audited.is_(True), 1), else_=0)),
            func.sum(case((FileWeight.skipped.is_(False) & FileWeight.weight.is_(None), 1), else_=0)),
        )
        .filter(FileWeight.project_id.in_(ids))
        .group_by(FileWeight.project_id)
    ):
        s = summaries[int(row[0])]
        s["files_total"] = int(row[1] or 0)
        s["files_weighted"] = int(row[2] or 0)
        s["files_skipped"] = int(row[3] or 0)
        s["files_audited"] = int(row[4] or 0)
        s["files_unmarked"] = int(row[5] or 0)

    for row in (
        db.query(PhaseRun.project_id, func.count(PhaseRun.id))
        .filter(PhaseRun.project_id.in_(ids), PhaseRun.phase == "worker")
        .group_by(PhaseRun.project_id)
    ):
        summaries[int(row[0])]["worker_rounds"] = int(row[1] or 0)

    for row in (
        db.query(
            TokenUsage.project_id,
            func.coalesce(func.sum(TokenUsage.tokens_input), 0),
            func.coalesce(func.sum(TokenUsage.tokens_output), 0),
            func.coalesce(func.sum(TokenUsage.tokens_cached), 0),
            func.coalesce(func.sum(TokenUsage.tokens_total), 0),
        )
        .filter(TokenUsage.project_id.in_(ids))
        .group_by(TokenUsage.project_id)
    ):
        s = summaries[int(row[0])]
        s["tokens_input"] = int(row[1] or 0)
        s["tokens_output"] = int(row[2] or 0)
        s["tokens_cached"] = int(row[3] or 0)
        s["tokens_total"] = int(row[4] or 0)

    return summaries


def _project_out(db, p: Project, summary: dict[str, int] | None = None) -> ProjectOut:
    summary = summary or _project_summaries(db, [p.id]).get(p.id, _empty_project_summary())
    return ProjectOut(
        id=p.id,
        name=p.name,
        source_type=p.source_type,
        source_url=p.source_url,
        identity=p.identity,
        status=p.status,
        phase=p.phase,
        recon_done=p.recon_done,
        error=p.error,
        worker_concurrency=p.worker_concurrency,
        created_at=p.created_at,
        updated_at=p.updated_at,
        vuln_confirmed=summary["vuln_confirmed"],
        vuln_false_positive=summary["vuln_false_positive"],
        vuln_pending=summary["vuln_pending"],
        files_total=summary["files_total"],
        files_weighted=summary["files_weighted"],
        files_skipped=summary["files_skipped"],
        files_audited=summary["files_audited"],
        worker_rounds=summary["worker_rounds"],
        tokens_input=summary["tokens_input"],
        tokens_output=summary["tokens_output"],
        tokens_cached=summary["tokens_cached"],
        tokens_total=summary["tokens_total"],
        recon_subphases=recon_subphases(p.id, summary["files_unmarked"]),
        **_phase_state_fields(p.id),
    )


@router.get("", response_model=list[ProjectOut])
def list_projects() -> list[ProjectOut]:
    with SessionLocal() as db:
        rows = db.query(Project).order_by(Project.id.desc()).all()
        summaries = _project_summaries(db, [p.id for p in rows])
        return [_project_out(db, p, summaries.get(p.id)) for p in rows]


@router.get("/{project_id}", response_model=ProjectOut)
def get_project(project_id: int) -> ProjectOut:
    with SessionLocal() as db:
        p = db.get(Project, project_id)
        if not p:
            raise HTTPException(404, "项目不存在")
        return _project_out(db, p)


@router.post("", response_model=ProjectOut)
def create_project_github(body: ProjectCreate) -> ProjectOut:
    if body.source_type != "github":
        raise HTTPException(400, "请使用 /api/projects/upload 上传 zip")
    if not (body.source_url or "").strip():
        raise HTTPException(400, "缺少 source_url")
    name = (body.name or "").strip() or body.source_url.strip().rstrip("/").split("/")[-1]
    with SessionLocal() as db:
        p = Project(
            name=name,
            source_type="github",
            source_url=body.source_url.strip(),
            status="pending",
            phase="pending",
        )
        db.add(p)
        db.commit()
        db.refresh(p)
        pid = p.id
        settings_row = db.query(AppSettings).first()
        pat = (settings_row.github_pat if settings_row else None) or None
        out = _project_out(db, p)
    ensure_project_dirs(pid)
    start_ingest_and_audit(pid, source_type="github", source_url=body.source_url.strip(), github_pat=pat)
    return out


@router.post("/upload", response_model=ProjectOut)
async def create_project_zip(
    file: UploadFile = File(...),
    name: str = Form(""),
) -> ProjectOut:
    raw_name = name.strip() or (file.filename or "upload").rsplit(".", 1)[0]
    with SessionLocal() as db:
        p = Project(name=raw_name, source_type="zip", status="pending", phase="pending")
        db.add(p)
        db.commit()
        db.refresh(p)
        pid = p.id
        out = _project_out(db, p)
    ensure_project_dirs(pid)
    tmp = Path(tempfile.mkdtemp(prefix="vh-zip-"))
    zip_path = tmp / (file.filename or "src.zip")
    content = await file.read()
    zip_path.write_bytes(content)
    start_ingest_and_audit(pid, source_type="zip", zip_path=zip_path)
    return out


def _phase_state_fields(project_id: int) -> dict:
    try:
        states = get_phase_states(project_id)
    except Exception:  # noqa: BLE001
        return {"phase_states": {}, "project_paused": False}
    return {"phase_states": states.get("phases") or {}, "project_paused": bool(states.get("project_paused"))}


@router.post("/{project_id}/pause")
def pause_project(project_id: int) -> dict:
    request_pause(project_id)
    return {"ok": True, **get_phase_states(project_id)}


@router.post("/{project_id}/resume")
def resume_project(project_id: int) -> dict:
    request_resume(project_id)
    return {"ok": True, **get_phase_states(project_id)}


@router.get("/{project_id}/phases/state")
def project_phase_state(project_id: int) -> dict:
    with SessionLocal() as db:
        if not db.get(Project, project_id):
            raise HTTPException(404, "项目不存在")
    return get_phase_states(project_id)


@router.post("/{project_id}/phases/{phase}/pause")
def pause_project_phase(project_id: int, phase: str) -> dict:
    try:
        control_phase(phase)
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    with SessionLocal() as db:
        if not db.get(Project, project_id):
            raise HTTPException(404, "项目不存在")
    return {"ok": True, **request_phase_pause(project_id, phase)}


@router.post("/{project_id}/phases/{phase}/resume")
def resume_project_phase(project_id: int, phase: str) -> dict:
    try:
        control_phase(phase)
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    with SessionLocal() as db:
        if not db.get(Project, project_id):
            raise HTTPException(404, "项目不存在")
    return {"ok": True, **request_phase_resume(project_id, phase)}


@router.post("/{project_id}/phases/{phase}/restart")
def restart_project_phase(project_id: int, phase: str) -> dict:
    try:
        control_phase(phase)
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    with SessionLocal() as db:
        if not db.get(Project, project_id):
            raise HTTPException(404, "项目不存在")
    return {"ok": True, **request_phase_restart(project_id, phase)}


@router.post("/{project_id}/cancel")
def cancel_project(project_id: int) -> dict:
    request_cancel(project_id)
    return {"ok": True}


@router.get("/{project_id}/events", response_model=EventsChunk)
def project_events(
    project_id: int,
    offset: int = 0,
    limit: int = 100,
    tail: bool = False,
    before: int | None = None,
    phase: str | None = None,
    session: int | None = None,
) -> EventsChunk:
    page = live_log.read_events(
        project_id,
        offset=offset,
        limit=limit,
        tail=tail,
        before=before,
        phase=phase,
        session=session,
    )
    return EventsChunk(
        events=page.events,
        offset=page.offset,
        done=page.done,
        oldest=page.oldest,
        has_older=page.has_older,
        total=page.total,
        file_end=page.file_end,
        session=page.session,
        session_count=page.session_count,
    )


@router.get("/{project_id}/stream")
async def project_stream(project_id: int, from_offset: int = 0, phase: str | None = None, session: int | None = None):
    import json

    async def gen():
        offset = max(0, int(from_offset or 0))
        last_status: tuple[str, str] | None = None
        try:
            # Browser EventSource reconnects this quickly after reload.
            yield "retry: 800\n\n"
            while not is_shutting_down():
                page = live_log.read_events(project_id, offset=offset, limit=200, phase=phase, session=session)
                if page.events:
                    offset = page.offset
                else:
                    offset = max(offset, page.file_end)
                for ev in page.events:
                    payload = {"type": "event", **ev}
                    yield f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"
                with SessionLocal() as db:
                    p = db.get(Project, project_id)
                    if p:
                        key = (p.status or "", p.phase or "")
                        if key != last_status:
                            last_status = key
                            yield (
                                "data: "
                                + json.dumps(
                                    {"type": "status", "status": p.status, "phase": p.phase},
                                    ensure_ascii=False,
                                )
                                + "\n\n"
                            )
                if await wait_or_shutdown(0.5):
                    return
        except (asyncio.CancelledError, ConnectionError, BrokenPipeError, OSError):
            return

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/{project_id}/files", response_model=list[FileWeightOut])
def list_files(project_id: int) -> list[FileWeightOut]:
    with SessionLocal() as db:
        rows = (
            db.query(FileWeight)
            .filter(FileWeight.project_id == project_id)
            .order_by(FileWeight.path)
            .limit(2000)
            .all()
        )
        # sort weights in python for sqlite compatibility
        rows.sort(key=lambda r: (-(r.weight if r.weight is not None else -1), r.path))
        return [FileWeightOut.model_validate(r) for r in rows]


@router.get("/{project_id}/phases", response_model=list[PhaseRunOut])
def list_phases(project_id: int) -> list[PhaseRunOut]:
    with SessionLocal() as db:
        rows = (
            db.query(PhaseRun)
            .filter(PhaseRun.project_id == project_id)
            .order_by(PhaseRun.id.desc())
            .limit(200)
            .all()
        )
        return [PhaseRunOut.model_validate(r) for r in rows]


@router.get("/{project_id}/reports", response_model=PhaseReportList)
def list_project_reports(project_id: int) -> PhaseReportList:
    with SessionLocal() as db:
        if not db.get(Project, project_id):
            raise HTTPException(404, "项目不存在")
    return PhaseReportList.model_validate(reports_by_phase(project_id))


@router.get("/{project_id}/reports/file", response_model=PhaseReportDetail)
def get_project_report(project_id: int, path: str) -> PhaseReportDetail:
    with SessionLocal() as db:
        if not db.get(Project, project_id):
            raise HTTPException(404, "项目不存在")
    try:
        return PhaseReportDetail.model_validate(read_phase_report(project_id, path))
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    except FileNotFoundError as e:
        raise HTTPException(404, "报告不存在") from e


@router.delete("/{project_id}")
def delete_project(project_id: int) -> dict:
    request_cancel(project_id)
    with SessionLocal() as db:
        p = db.get(Project, project_id)
        if not p:
            raise HTTPException(404, "项目不存在")
        db.query(TokenUsage).filter(TokenUsage.project_id == project_id).delete()
        db.query(ToolLog).filter(ToolLog.project_id == project_id).delete()
        db.delete(p)
        db.commit()
    force_rmtree(project_root(project_id))
    return {"ok": True}

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

from fastapi import APIRouter, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import StreamingResponse
from sqlalchemy import case, cast, func, or_
from sqlalchemy.types import String

from ..audit_mode import (
    AUDIT_MODE_CUSTOM,
    AUDIT_MODE_EDITABLE_STATUSES,
    normalize_audit_mode,
    parse_audit_mode,
)
from ..dynamic_verify import (
    VERIFY_MODE_HARNESS,
    VERIFY_MODE_LAB,
    VERIFY_MODE_OFF,
    apply_verify_mode,
    project_verify_mode,
    resolve_verify_mode,
    verify_mode_enabled,
)
from ..mining_paths import (
    HEURISTIC_LITE_WEIGHT,
    MINING_PATH_EDITABLE_STATUSES,
    MiningPathError,
    parse_heuristic_lite,
    parse_mining_paths,
)
from ..target_kind import (
    TARGET_KIND_EDITABLE_STATUSES,
    create_verify_defaults,
    is_component_target,
    normalize_target_kind,
    parse_target_kind,
    target_kind_label,
)
from ..models import (
    AppSettings,
    BypassTarget,
    FileWeight,
    PhaseRun,
    Project,
    SessionLocal,
    Sink,
    TokenUsage,
    ToolLog,
    Vuln,
)
from ..schemas import (
    EventsChunk,
    FileWeightOut,
    PhaseReportDetail,
    PhaseReportList,
    PhaseRunOut,
    ProjectCreate,
    ProjectListOut,
    ProjectOut,
    ProjectRunStatusCounts,
    ProjectUpdate,
    normalize_manual_lab_prompt,
    normalize_worker_hint,
    normalize_lab_retry_message,
    LabSetupRetryBody,
    ConversationBody,
    ConversationStateOut,
    normalize_conversation_message,
)
from ..services.ingest import indexed_weight_exts
from ..dynamic_verify import is_lab_mode, project_verify_mode
from ..services.lab import lab_setup_failed, lab_setup_finished, sync_manual_lab_notes
from ..services.live_log import live_log
from ..services.llm_settings import normalize_project_llm_model
from ..services import custom_audit_modes as cam
from ..services.paths import ensure_project_dirs, force_rmtree, project_dir, project_root
from ..services.phase_reports import read_phase_report, reports_by_phase
from ..services.conversation import get_conversation_state, request_conversation
from ..services.pipeline import (
    get_phase_states,
    note_audit_mode_changed,
    note_dynamic_verify_changed,
    note_mining_paths_changed,
    note_verifier_enabled,
    note_attack_chain_enabled,
    request_cancel,
    request_pause,
    request_recon_subphase_rerun,
    request_lab_setup_retry,
    request_resume,
    request_worker_progress_reset,
    start_audit,
    start_ingest_and_audit,
)
from ..services.verifier import enqueue_confirmed_frontend
from ..services.shutdown import is_shutting_down, wait_or_shutdown
from ..tools.phase_recon import recon_subphases
from ..tools.phase_worker import project_complete_gates

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
        "files_weight100": 0,
        "files_weight100_audited": 0,
        "sinks_queued": 0,
        "sinks_done": 0,
        "bypass_queued": 0,
        "bypass_done": 0,
        "files_unmarked": 0,
        "worker_rounds": 0,
        "tokens_input": 0,
        "tokens_output": 0,
        "tokens_cached": 0,
        "tokens_total": 0,
        "verifier_pending": 0,
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
            func.sum(
                case(
                    (
                        (Vuln.verifier_status == "pending")
                        & Vuln.status.in_(("confirmed", "static_only"))
                        & (Vuln.attack_surface == "frontend"),
                        1,
                    ),
                    else_=0,
                )
            ),
        )
        .filter(Vuln.project_id.in_(ids))
        .group_by(Vuln.project_id)
    ):
        s = summaries[int(row[0])]
        s["vuln_confirmed"] = int(row[1] or 0)
        s["vuln_false_positive"] = int(row[2] or 0)
        s["vuln_pending"] = int(row[3] or 0)
        s["verifier_pending"] = int(row[4] or 0)

    for row in (
        db.query(
            FileWeight.project_id,
            func.count(FileWeight.id),
            func.sum(case((FileWeight.weight.isnot(None) & FileWeight.skipped.is_(False), 1), else_=0)),
            func.sum(case((FileWeight.skipped.is_(True), 1), else_=0)),
            func.sum(case((FileWeight.audited.is_(True) & FileWeight.skipped.is_(False), 1), else_=0)),
            func.sum(case((FileWeight.skipped.is_(False) & FileWeight.weight.is_(None), 1), else_=0)),
            func.sum(
                case(
                    ((FileWeight.weight == HEURISTIC_LITE_WEIGHT) & FileWeight.skipped.is_(False), 1),
                    else_=0,
                )
            ),
            func.sum(
                case(
                    (
                        (FileWeight.weight == HEURISTIC_LITE_WEIGHT)
                        & FileWeight.skipped.is_(False)
                        & FileWeight.audited.is_(True),
                        1,
                    ),
                    else_=0,
                )
            ),
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
        s["files_weight100"] = int(row[6] or 0)
        s["files_weight100_audited"] = int(row[7] or 0)

    for row in (
        db.query(
            Sink.project_id,
            func.sum(case((Sink.status.in_(("queued", "claimed", "done")), 1), else_=0)),
            func.sum(case((Sink.status == "done", 1), else_=0)),
        )
        .filter(Sink.project_id.in_(ids))
        .group_by(Sink.project_id)
    ):
        s = summaries[int(row[0])]
        s["sinks_queued"] = int(row[1] or 0)
        s["sinks_done"] = int(row[2] or 0)

    for row in (
        db.query(
            BypassTarget.project_id,
            func.sum(case((BypassTarget.status.in_(("queued", "claimed", "done")), 1), else_=0)),
            func.sum(case((BypassTarget.status == "done", 1), else_=0)),
        )
        .filter(BypassTarget.project_id.in_(ids))
        .group_by(BypassTarget.project_id)
    ):
        s = summaries[int(row[0])]
        s["bypass_queued"] = int(row[1] or 0)
        s["bypass_done"] = int(row[2] or 0)

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


def _project_out(
    db,
    p: Project,
    summary: dict[str, int] | None = None,
    weight_exts: list | None = None,
) -> ProjectOut:
    summary = summary or _project_summaries(db, [p.id]).get(p.id, _empty_project_summary())
    if weight_exts is None:
        weight_exts = indexed_weight_exts(db, [p.id]).get(p.id, [])
    return ProjectOut(
        id=p.id,
        name=p.name,
        source_type=p.source_type,
        source_url=p.source_url,
        identity=p.identity,
        status=p.status,
        phase=p.phase,
        recon_done=p.recon_done,
        audit_mode=normalize_audit_mode(p.audit_mode),
        target_kind=normalize_target_kind(getattr(p, "target_kind", None)),
        custom_audit_mode_id=getattr(p, "custom_audit_mode_id", None),
        custom_audit_mode_name=(getattr(p, "custom_audit_mode_name", None) or "").strip(),
        custom_audit_prompt=(getattr(p, "custom_audit_prompt", None) or "").strip(),
        manual_lab=bool(p.manual_lab),
        manual_lab_prompt=(p.manual_lab_prompt or "").strip(),
        verifier_enabled=bool(p.verifier_enabled),
        attack_chain_enabled=bool(getattr(p, "attack_chain_enabled", False)),
        attack_chain_done=bool(getattr(p, "attack_chain_done", False)),
        dynamic_verify_enabled=verify_mode_enabled(project_verify_mode(p)),
        dynamic_verify_mode=project_verify_mode(p),
        heuristic_enabled=bool(getattr(p, "heuristic_enabled", True)),
        heuristic_lite=bool(getattr(p, "heuristic_lite", False)),
        fast_enabled=bool(getattr(p, "fast_enabled", False)),
        fast_queue_frozen=bool(getattr(p, "fast_queue_frozen", False)),
        bypass_enabled=bool(getattr(p, "bypass_enabled", False)),
        bypass_queue_frozen=bool(getattr(p, "bypass_queue_frozen", False)),
        llm_model=normalize_project_llm_model(getattr(p, "llm_model", None)) or "",
        worker_hint=(getattr(p, "worker_hint", None) or "").strip(),
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
        files_weight100=int(summary.get("files_weight100") or 0),
        files_weight100_audited=int(summary.get("files_weight100_audited") or 0),
        sinks_queued=int(summary.get("sinks_queued") or 0),
        sinks_done=int(summary.get("sinks_done") or 0),
        bypass_queued=int(summary.get("bypass_queued") or 0),
        bypass_done=int(summary.get("bypass_done") or 0),
        weight_exts=weight_exts,
        worker_rounds=summary["worker_rounds"],
        tokens_input=summary["tokens_input"],
        tokens_output=summary["tokens_output"],
        tokens_cached=summary["tokens_cached"],
        tokens_total=summary["tokens_total"],
        recon_subphases=recon_subphases(p.id, summary["files_unmarked"]),
        lab_setup_done=lab_setup_finished(p.id),
        lab_setup_retryable=is_lab_mode(project_verify_mode(p)) and lab_setup_failed(p.id),
        verifier_pending=int(summary.get("verifier_pending") or 0),
        **_phase_state_fields(p.id),
    )


def _apply_project_search(query, q: str):
    tokens = [t for t in (q or "").strip().lower().split() if t]
    if not tokens:
        return query
    for token in tokens:
        pattern = f"%{token}%"
        query = query.filter(
            or_(
                Project.name.ilike(pattern),
                Project.identity.ilike(pattern),
                Project.source_url.ilike(pattern),
                Project.source_type.ilike(pattern),
                Project.llm_model.ilike(pattern),
                Project.custom_audit_mode_name.ilike(pattern),
                Project.audit_mode.ilike(pattern),
                Project.status.ilike(pattern),
                cast(Project.id, String).ilike(pattern),
            )
        )
    return query


def _project_run_bucket(status: str, project_paused: bool) -> str:
    if status == "completed":
        return "completed"
    if status == "paused" or project_paused:
        return "paused"
    if status in {"cancelled", "error"}:
        return "stopped"
    return "running"


def _filter_project_rows(
    rows: list[Project],
    run_status: str,
) -> tuple[list[Project], ProjectRunStatusCounts]:
    counts = ProjectRunStatusCounts()
    filtered: list[Project] = []
    for p in rows:
        paused = bool(get_phase_states(p.id).get("project_paused"))
        bucket = _project_run_bucket(p.status, paused)
        counts.all += 1
        if bucket == "running":
            counts.running += 1
        elif bucket == "paused":
            counts.paused += 1
        elif bucket == "completed":
            counts.completed += 1
        if run_status == "all" or run_status == bucket:
            filtered.append(p)
    return filtered, counts


def _upload_zip_stem(filename: str | None) -> str:
    """Project name from the upload filename: basename only, never a path."""
    name = Path(str(filename or "").replace("\\", "/")).name
    if not name or name in {".", ".."}:
        return "upload"
    stem = name.rsplit(".", 1)[0].strip()
    return stem or "upload"


@router.get("", response_model=ProjectListOut)
def list_projects(
    limit: int = Query(5, ge=1, le=100),
    offset: int = Query(0, ge=0),
    q: str = Query(""),
    run_status: str = Query("all", pattern="^(all|running|paused|completed)$"),
) -> ProjectListOut:
    with SessionLocal() as db:
        query = _apply_project_search(db.query(Project), q)
        rows = query.order_by(Project.id.desc()).all()
        filtered, status_counts = _filter_project_rows(rows, run_status)
        total = len(filtered)
        page_rows = filtered[offset : offset + limit]
        ids = [p.id for p in page_rows]
        summaries = _project_summaries(db, ids)
        exts = indexed_weight_exts(db, ids)
        items = [
            _project_out(db, p, summaries.get(p.id), exts.get(p.id, [])) for p in page_rows
        ]
        return ProjectListOut(
            items=items,
            total=total,
            limit=limit,
            offset=offset,
            status_counts=status_counts,
        )


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
    try:
        audit_mode = parse_audit_mode(body.audit_mode)
        target_kind = parse_target_kind(body.target_kind)
        manual_lab_prompt = normalize_manual_lab_prompt(body.manual_lab_prompt)
        worker_hint = normalize_worker_hint(body.worker_hint)
        heuristic_enabled, fast_enabled, bypass_enabled = parse_mining_paths(
            heuristic_enabled=body.heuristic_enabled,
            fast_enabled=body.fast_enabled,
            bypass_enabled=body.bypass_enabled,
        )
        heuristic_lite = parse_heuristic_lite(body.heuristic_lite)
        verify_mode_arg = body.dynamic_verify_mode
        if verify_mode_arg is None and is_component_target(target_kind):
            verify_mode_arg = create_verify_defaults(target_kind)["dynamic_verify_mode"]
        verify_mode = resolve_verify_mode(
            mode=verify_mode_arg,
            enabled=body.dynamic_verify_enabled,
            manual_lab=body.manual_lab,
            manual_lab_prompt=manual_lab_prompt,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    with SessionLocal() as db:
        try:
            custom_preset = None
            if audit_mode == AUDIT_MODE_CUSTOM:
                custom_preset = cam.resolve_custom_for_project(
                    db, custom_audit_mode_id=body.custom_audit_mode_id
                )
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        p = Project(
            name=name,
            source_type="github",
            source_url=body.source_url.strip(),
            status="pending",
            phase="pending",
            audit_mode=audit_mode,
            target_kind=target_kind,
            manual_lab=bool(body.manual_lab) if verify_mode == VERIFY_MODE_LAB else False,
            manual_lab_prompt=manual_lab_prompt or None if verify_mode == VERIFY_MODE_LAB else None,
            verifier_enabled=bool(body.verifier_enabled),
            attack_chain_enabled=bool(body.attack_chain_enabled),
            heuristic_enabled=heuristic_enabled,
            heuristic_lite=heuristic_lite,
            fast_enabled=fast_enabled,
            bypass_enabled=bypass_enabled,
            llm_model=normalize_project_llm_model(body.llm_model),
            worker_hint=worker_hint or None,
        )
        if custom_preset is not None:
            cam.apply_project_custom_snapshot(p, custom_preset)
        else:
            cam.clear_project_custom_snapshot(p)
        apply_verify_mode(p, verify_mode)
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
    audit_mode: str = Form("bounty"),
    target_kind: str = Form("web"),
    custom_audit_mode_id: str = Form(""),
    manual_lab: bool = Form(False),
    manual_lab_prompt: str = Form(""),
    verifier_enabled: bool = Form(False),
    attack_chain_enabled: bool = Form(False),
    dynamic_verify_enabled: bool = Form(False),
    dynamic_verify_mode: str = Form(""),
    heuristic_enabled: str = Form("true"),
    heuristic_lite: str = Form("false"),
    fast_enabled: str = Form("false"),
    bypass_enabled: str = Form("false"),
    llm_model: str = Form(""),
    worker_hint: str = Form(""),
) -> ProjectOut:
    raw_name = name.strip() or _upload_zip_stem(file.filename)
    try:
        mode = parse_audit_mode(audit_mode)
        kind = parse_target_kind(target_kind)
        prompt = normalize_manual_lab_prompt(manual_lab_prompt)
        hint = normalize_worker_hint(worker_hint)
        heuristic_on, fast_on, bypass_on = parse_mining_paths(
            heuristic_enabled=heuristic_enabled,
            fast_enabled=fast_enabled,
            bypass_enabled=bypass_enabled,
        )
        lite_on = parse_heuristic_lite(heuristic_lite)
        verify_mode_arg = dynamic_verify_mode or None
        if verify_mode_arg is None and is_component_target(kind):
            verify_mode_arg = create_verify_defaults(kind)["dynamic_verify_mode"]
        verify_mode = resolve_verify_mode(
            mode=verify_mode_arg,
            enabled=dynamic_verify_enabled,
            manual_lab=manual_lab,
            manual_lab_prompt=prompt,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    custom_id = None
    raw_custom = (custom_audit_mode_id or "").strip()
    if raw_custom:
        try:
            custom_id = int(raw_custom)
        except ValueError as exc:
            raise HTTPException(400, "custom_audit_mode_id 必须是整数") from exc
    with SessionLocal() as db:
        try:
            custom_preset = None
            if mode == AUDIT_MODE_CUSTOM:
                custom_preset = cam.resolve_custom_for_project(db, custom_audit_mode_id=custom_id)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        p = Project(
            name=raw_name,
            source_type="zip",
            status="pending",
            phase="pending",
            audit_mode=mode,
            target_kind=kind,
            manual_lab=bool(manual_lab) if verify_mode == VERIFY_MODE_LAB else False,
            manual_lab_prompt=prompt or None if verify_mode == VERIFY_MODE_LAB else None,
            verifier_enabled=bool(verifier_enabled),
            attack_chain_enabled=bool(attack_chain_enabled),
            heuristic_enabled=heuristic_on,
            heuristic_lite=lite_on,
            fast_enabled=fast_on,
            bypass_enabled=bypass_on,
            llm_model=normalize_project_llm_model(llm_model),
            worker_hint=hint or None,
        )
        if custom_preset is not None:
            cam.apply_project_custom_snapshot(p, custom_preset)
        else:
            cam.clear_project_custom_snapshot(p)
        apply_verify_mode(p, verify_mode)
        db.add(p)
        db.commit()
        db.refresh(p)
        pid = p.id
        out = _project_out(db, p)
    ensure_project_dirs(pid)
    tmp = Path(tempfile.mkdtemp(prefix="vh-zip-"))
    zip_path = tmp / "src.zip"
    content = await file.read()
    zip_path.write_bytes(content)
    start_ingest_and_audit(pid, source_type="zip", zip_path=zip_path)
    return out


@router.patch("/{project_id}", response_model=ProjectOut)
def update_project(project_id: int, body: ProjectUpdate) -> ProjectOut:
    if (
        body.audit_mode is None
        and body.target_kind is None
        and body.custom_audit_mode_id is None
        and body.manual_lab is None
        and body.manual_lab_prompt is None
        and body.verifier_enabled is None
        and body.attack_chain_enabled is None
        and body.dynamic_verify_enabled is None
        and body.dynamic_verify_mode is None
        and body.heuristic_enabled is None
        and body.heuristic_lite is None
        and body.fast_enabled is None
        and body.bypass_enabled is None
        and body.llm_model is None
        and body.worker_hint is None
    ):
        raise HTTPException(400, "没有需要更新的字段")
    mode = None
    kind = None
    prompt = None
    hint = None
    try:
        if body.audit_mode is not None:
            mode = parse_audit_mode(body.audit_mode)
        if body.target_kind is not None:
            kind = parse_target_kind(body.target_kind)
        if body.manual_lab_prompt is not None:
            prompt = normalize_manual_lab_prompt(body.manual_lab_prompt)
        if body.worker_hint is not None:
            hint = normalize_worker_hint(body.worker_hint)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    paths_changed = False
    audit_mode_changed = False
    new_mode_for_note = "bounty"
    custom_name_for_note = None
    with SessionLocal() as db:
        p = db.get(Project, project_id)
        if not p:
            raise HTTPException(404, "项目不存在")
        old_mode = normalize_audit_mode(p.audit_mode)
        old_kind = normalize_target_kind(getattr(p, "target_kind", None))
        old_custom_id = getattr(p, "custom_audit_mode_id", None)
        old_verifier = bool(p.verifier_enabled)
        old_attack_chain = bool(getattr(p, "attack_chain_enabled", False))
        old_verify_mode = project_verify_mode(p)
        old_dynamic = old_verify_mode != VERIFY_MODE_OFF
        old_heuristic = bool(getattr(p, "heuristic_enabled", True))
        old_lite = bool(getattr(p, "heuristic_lite", False))
        old_fast = bool(getattr(p, "fast_enabled", False))
        old_bypass = bool(getattr(p, "bypass_enabled", False))
        old_llm_model = normalize_project_llm_model(getattr(p, "llm_model", None))
        old_worker_hint = (getattr(p, "worker_hint", None) or "").strip()
        if kind is not None:
            if p.status not in TARGET_KIND_EDITABLE_STATUSES:
                raise HTTPException(400, "审计对象仅在项目暂停或完成后可更改")
            p.target_kind = kind
        if (
            body.heuristic_enabled is not None
            or body.fast_enabled is not None
            or body.bypass_enabled is not None
            or body.heuristic_lite is not None
        ):
            if p.status not in MINING_PATH_EDITABLE_STATUSES:
                raise HTTPException(400, "挖掘路径仅在项目暂停或完成后可更改")
            try:
                heuristic_on, fast_on, bypass_on = parse_mining_paths(
                    heuristic_enabled=old_heuristic if body.heuristic_enabled is None else body.heuristic_enabled,
                    fast_enabled=old_fast if body.fast_enabled is None else body.fast_enabled,
                    bypass_enabled=old_bypass if body.bypass_enabled is None else body.bypass_enabled,
                    default_heuristic=old_heuristic,
                    default_fast=old_fast,
                    default_bypass=old_bypass,
                )
            except MiningPathError as exc:
                raise HTTPException(400, str(exc)) from exc
            lite_on = parse_heuristic_lite(
                old_lite if body.heuristic_lite is None else body.heuristic_lite,
                default=old_lite,
            )
            p.heuristic_enabled = heuristic_on
            p.heuristic_lite = lite_on
            p.fast_enabled = fast_on
            p.bypass_enabled = bypass_on
            paths_changed = (
                heuristic_on != old_heuristic
                or fast_on != old_fast
                or bypass_on != old_bypass
                or lite_on != old_lite
            )
        next_mode = mode if mode is not None else old_mode
        wants_custom_change = (
            mode == AUDIT_MODE_CUSTOM
            or (mode is None and old_mode == AUDIT_MODE_CUSTOM and body.custom_audit_mode_id is not None)
        )
        if mode is not None or wants_custom_change:
            if p.status not in AUDIT_MODE_EDITABLE_STATUSES:
                raise HTTPException(400, "挖掘模式仅在项目暂停或完成后可更改")
        if next_mode == AUDIT_MODE_CUSTOM and (mode is not None or body.custom_audit_mode_id is not None):
            preset_id = (
                body.custom_audit_mode_id
                if body.custom_audit_mode_id is not None
                else old_custom_id
            )
            try:
                preset = cam.resolve_custom_for_project(db, custom_audit_mode_id=preset_id)
            except ValueError as exc:
                raise HTTPException(400, str(exc)) from exc
            cam.apply_project_custom_snapshot(p, preset)
        elif mode is not None and next_mode != AUDIT_MODE_CUSTOM:
            p.audit_mode = next_mode
            cam.clear_project_custom_snapshot(p)
        if prompt is not None:
            p.manual_lab_prompt = prompt or None
            if body.manual_lab is None:
                p.manual_lab = bool(prompt)
        if body.manual_lab is not None:
            p.manual_lab = bool(body.manual_lab)
        if body.verifier_enabled is not None:
            p.verifier_enabled = bool(body.verifier_enabled)
        if body.attack_chain_enabled is not None:
            p.attack_chain_enabled = bool(body.attack_chain_enabled)
        if body.dynamic_verify_mode is not None or body.dynamic_verify_enabled is not None:
            try:
                next_verify = resolve_verify_mode(
                    mode=body.dynamic_verify_mode,
                    enabled=body.dynamic_verify_enabled,
                    current_mode=old_verify_mode,
                    current_enabled=old_dynamic,
                )
            except ValueError as exc:
                raise HTTPException(400, str(exc)) from exc
            apply_verify_mode(p, next_verify)
            if next_verify != VERIFY_MODE_LAB:
                if body.manual_lab is None and prompt is None:
                    p.manual_lab = False
        if body.llm_model is not None:
            p.llm_model = normalize_project_llm_model(body.llm_model)
        if hint is not None:
            p.worker_hint = hint or None
        db.commit()
        db.refresh(p)
        out = _project_out(db, p)
        new_mode_for_note = normalize_audit_mode(out.audit_mode)
        custom_name_for_note = out.custom_audit_mode_name or None
        audit_mode_changed = new_mode_for_note != old_mode or (
            new_mode_for_note == AUDIT_MODE_CUSTOM and out.custom_audit_mode_id != old_custom_id
        )
        sync_notes = prompt is not None
        notes_text = out.manual_lab_prompt
        restarted = False
        if body.verifier_enabled is True and not old_verifier:
            queued = enqueue_confirmed_frontend(project_id)
            live_log.system(project_id, f"已开启 Verifier，排队 {queued} 条前台漏洞")
            note_verifier_enabled(project_id)
            if p.status == "completed" and queued > 0:
                p.status = "auditing"
                p.phase = "verifier"
                db.commit()
                db.refresh(p)
                out = _project_out(db, p)
                restarted = True
            elif p.status not in ("completed", "cancelled", "error", "pending", "ingesting"):
                restarted = True
        elif body.verifier_enabled is False and old_verifier:
            live_log.system(project_id, "已关闭 Verifier，不再对新的前台漏洞做互联网复测")
        if body.attack_chain_enabled is True and not old_attack_chain:
            live_log.system(project_id, "已开启攻击链串联，挖掘与审核结束后将尝试多漏洞串联")
            note_attack_chain_enabled(project_id)
            if p.status == "completed":
                p.status = "auditing"
                p.phase = "attack_chain"
                db.commit()
                db.refresh(p)
                out = _project_out(db, p)
                restarted = True
            elif p.status not in ("completed", "cancelled", "error", "pending", "ingesting"):
                restarted = True
        elif body.attack_chain_enabled is False and old_attack_chain:
            live_log.system(project_id, "已关闭攻击链串联")
        new_verify_mode = out.dynamic_verify_mode
        if new_verify_mode != old_verify_mode:
            if new_verify_mode == VERIFY_MODE_LAB:
                live_log.system(project_id, "已开启靶场动态验证，后续审核将搭建靶场并做动态复现")
            elif new_verify_mode == VERIFY_MODE_HARNESS:
                live_log.system(project_id, "已开启局部验证，后续审核用沙箱 harness 复现，不搭建 Docker 靶场")
            else:
                live_log.system(project_id, "已关闭动态验证，后续审核仅静态复核")
            note_dynamic_verify_changed(project_id, enabled=new_verify_mode != VERIFY_MODE_OFF)
            if new_verify_mode != VERIFY_MODE_OFF and p.status not in (
                "completed",
                "cancelled",
                "error",
                "pending",
                "ingesting",
            ):
                restarted = True
        if body.llm_model is not None:
            new_llm_model = normalize_project_llm_model(out.llm_model)
            if new_llm_model != old_llm_model:
                if new_llm_model:
                    live_log.system(
                        project_id,
                        f"项目模型已改为 {new_llm_model}，下一轮 Agent 生效",
                    )
                else:
                    live_log.system(project_id, "项目模型已改回全局默认，下一轮 Agent 生效")
        if kind is not None and normalize_target_kind(out.target_kind) != old_kind:
            live_log.system(
                project_id,
                f"审计对象已改为{target_kind_label(out.target_kind)}，下一轮 Agent 生效",
            )
        if hint is not None and (hint or "") != old_worker_hint:
            if hint:
                live_log.system(project_id, "挖掘 Worker 提示已更新，下一轮挖掘生效")
            else:
                live_log.system(project_id, "挖掘 Worker 提示已清空，下一轮挖掘不再注入")
    if audit_mode_changed:
        note_audit_mode_changed(project_id, new_mode_for_note, custom_name=custom_name_for_note)
    if paths_changed:
        note_mining_paths_changed(
            project_id,
            heuristic_enabled=bool(out.heuristic_enabled),
            fast_enabled=bool(out.fast_enabled),
            bypass_enabled=bool(out.bypass_enabled),
            heuristic_lite=bool(out.heuristic_lite),
        )
        if out.status == "completed" and not project_complete_gates(project_id):
            with SessionLocal() as db:
                p = db.get(Project, project_id)
                if p and p.status == "completed":
                    p.status = "paused"
                    p.phase = "worker"
                    db.commit()
                    db.refresh(p)
                    out = _project_out(db, p)
            live_log.system(
                project_id,
                "挖掘范围已扩大，项目改回暂停，续跑后按新范围继续",
                phase="worker",
            )
    if sync_notes:
        sync_manual_lab_notes(project_id, notes_text)
    if restarted:
        start_audit(project_id)
    return out


def _phase_state_fields(project_id: int) -> dict:
    try:
        states = get_phase_states(project_id)
    except Exception:  # noqa: BLE001
        return {"phase_states": {}, "project_paused": False}
    return {"phase_states": states.get("phases") or {}, "project_paused": bool(states.get("project_paused"))}


def _ensure_can_pause(project_id: int) -> None:
    with SessionLocal() as db:
        p = db.get(Project, project_id)
        if not p:
            raise HTTPException(404, "项目不存在")
        if p.status == "completed":
            raise HTTPException(400, "已完成项目不可暂停")


@router.post("/{project_id}/pause")
def pause_project(project_id: int) -> dict:
    _ensure_can_pause(project_id)
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


@router.get("/{project_id}/conversation", response_model=ConversationStateOut)
def get_project_conversation(
    project_id: int,
    log_phase: str = Query(..., min_length=1),
) -> ConversationStateOut:
    with SessionLocal() as db:
        if not db.get(Project, project_id):
            raise HTTPException(404, "项目不存在")
    return ConversationStateOut(**get_conversation_state(project_id, log_phase))


@router.post("/{project_id}/conversation")
def post_project_conversation(project_id: int, body: ConversationBody) -> dict:
    with SessionLocal() as db:
        if not db.get(Project, project_id):
            raise HTTPException(404, "项目不存在")
    try:
        return request_conversation(project_id, body.log_phase, body.action, body.message)
    except ValueError as e:
        raise HTTPException(400, str(e)) from e


@router.post("/{project_id}/recon-subphases/{subphase}/rerun")
def rerun_recon_subphase(project_id: int, subphase: str) -> dict:
    with SessionLocal() as db:
        if not db.get(Project, project_id):
            raise HTTPException(404, "项目不存在")
    try:
        return request_recon_subphase_rerun(project_id, subphase)
    except ValueError as e:
        raise HTTPException(400, str(e)) from e


@router.post("/{project_id}/lab-setup/retry")
def retry_lab_setup(project_id: int, body: LabSetupRetryBody | None = None) -> dict:
    with SessionLocal() as db:
        if not db.get(Project, project_id):
            raise HTTPException(404, "项目不存在")
    try:
        msg = normalize_lab_retry_message((body.user_message if body else "") or "")
        return request_lab_setup_retry(project_id, msg)
    except ValueError as e:
        raise HTTPException(400, str(e)) from e


@router.post("/{project_id}/reset-progress", response_model=ProjectOut)
def reset_project_progress(project_id: int) -> ProjectOut:
    with SessionLocal() as db:
        if not db.get(Project, project_id):
            raise HTTPException(404, "项目不存在")
    try:
        request_worker_progress_reset(project_id)
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    with SessionLocal() as db:
        p = db.get(Project, project_id)
        if not p:
            raise HTTPException(404, "项目不存在")
        return _project_out(db, p)


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
def list_project_reports(
    project_id: int,
    phase: str | None = None,
    subphase: str | None = None,
    limit: int = Query(10, ge=1, le=100),
    offset: int = Query(0, ge=0),
) -> PhaseReportList:
    with SessionLocal() as db:
        if not db.get(Project, project_id):
            raise HTTPException(404, "项目不存在")
    try:
        return PhaseReportList.model_validate(
            reports_by_phase(project_id, phase=phase, subphase=subphase, limit=limit, offset=offset)
        )
    except ValueError as e:
        raise HTTPException(400, str(e)) from e


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
    with SessionLocal() as db:
        p = db.get(Project, project_id)
        if not p:
            raise HTTPException(404, "项目不存在")
    request_cancel(project_id)
    with SessionLocal() as db:
        p = db.get(Project, project_id)
        if p:
            db.query(TokenUsage).filter(TokenUsage.project_id == project_id).delete()
            db.query(ToolLog).filter(ToolLog.project_id == project_id).delete()
            db.delete(p)
            db.commit()
    force_rmtree(project_dir(project_id))
    return {"ok": True}

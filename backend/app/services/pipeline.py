"""Project audit orchestrator: recon, then heuristic after old vulns; review queue; isolated fix pool."""

from __future__ import annotations

import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from typing import Any

from sqlalchemy.exc import OperationalError

from ..agent.checkpoint import (
    LoopCheckpoint,
    clear_checkpoint,
    list_resumable_runs,
    load_checkpoint,
    resumable_file_paths,
    resumable_vuln_ids,
    save_checkpoint,
    set_phase_run_status,
    set_phase_run_worker,
)
from ..agent.compression import (
    inject_summary_block,
    inject_fast_prior_block,
    inject_bypass_prior_block,
    inject_worker_prior_block,
    latest_summary,
    max_fast_round_report_no,
    max_bypass_round_report_no,
    max_round_report_no,
)
from ..agent.loop import AgentLoop
from ..audit_mode import (
    AUDIT_MODE_CUSTOM,
    audit_mode_label,
    initial_hint,
    is_bounty_mode,
    normalize_audit_mode,
)
from ..config import settings
from ..dynamic_verify import (
    VERIFY_MODE_HARNESS,
    VERIFY_MODE_OFF,
    is_harness_mode,
    is_lab_mode,
    project_verify_mode,
    verify_mode_enabled,
)
from ..mining_paths import HEURISTIC_LITE_WEIGHT, heuristic_lite_active, mining_path_label
from ..models import FileWeight, PhaseRun, Project, SessionLocal, Sink, Source, Vuln, utcnow
from ..prompts import load_prompt, render_prompt
from ..services.custom_audit_modes import project_custom_overlay
from ..services.ingest import build_file_index, clone_github, extract_zip
from ..services.lab import (
    debug_ports_for_runtime,
    lab_naming,
    lab_ready,
    lab_round_complete,
    lab_setup_finished,
    load_env,
    mark_lab_setup_finished,
    recreate_lab,
)
from ..services.live_log import live_log
from ..services.llm_settings import get_settings_row, resolve_llm
from ..services.mcp_router import reviewer_debug_plan
from ..services.sandbox_exec import harness_debug_plan
from ..services.paths import ensure_project_dirs, src_dir, summaries_dir, workspace_dir
from ..services.poc_script import read_poc_code
from ..services.vuln_followup import archive_reviewer_checkpoint, latest_reviewer_context
from ..tools import register_all_tools
from ..tools.phase_recon import (
    apply_recon_done,
    begin_map_refresh,
    clear_map_refresh,
    clear_old_vuln_completion,
    paths_fully_marked,
    pick_unmarked_batch,
    recon_gates_met,
    recon_gates_status,
    recon_map_ready,
    recon_map_refresh_ready,
    recon_old_vuln_llm_ready,
    recon_old_vulns_ready,
    recon_source_ext_ready,
)
from ..tools.phase_worker import heuristic_complete, mining_complete, project_complete_gates

register_all_tools()

_lock = threading.Lock()
_cancel_events: dict[int, threading.Event] = {}
_pause_flags: dict[int, threading.Event] = {}
_phase_pause_flags: dict[tuple[int, str], threading.Event] = {}
_phase_generation: dict[tuple[int, str], int] = {}
_force_new_run: set[tuple[int, str]] = set()
_pending_inject: dict[tuple[int, str], list[dict[str, Any]]] = {}
_threads: dict[int, list[threading.Thread]] = {}
_recon_threads: dict[int, threading.Thread] = {}
_recon_rerun_threads: dict[int, threading.Thread] = {}
_reviewer_threads: dict[int, threading.Thread] = {}
_verifier_threads: dict[int, threading.Thread] = {}
_reviewer_inflight: dict[int, bool] = {}
_verifier_inflight: dict[int, bool] = {}
_fix_inflight: dict[int, set[int]] = {}
_adopted_phase_runs: set[tuple[int, int]] = set()
_fast_prepare_threads: dict[int, threading.Thread] = {}
_fast_last_dir: dict[int, str] = {}
_DB_LOCK_RETRY_SECONDS = 1.0

# Role pools: Recon 1 / Worker 2 (mine 1 + fix 1) / Reviewer 1
RECON_POOL = 1
WORKER_MINE_POOL = 1
WORKER_FIX_POOL = 1
REVIEWER_POOL = 1

CONTROL_PHASES = ("recon", "worker", "reviewer", "verifier")
CONTROL_DB_PHASES: dict[str, tuple[str, ...]] = {
    "recon": ("recon", "recon-source-ext", "recon-old-vuln", "recon-old-vuln-ghsa", "recon-mark"),
    "worker": ("worker", "fix", "fast-worker", "sink-triage", "bypass-worker"),
    "reviewer": ("reviewer", "reviewer-lab"),
    "verifier": ("verifier",),
}
CONTROL_LABELS = {"recon": "侦察", "worker": "挖掘", "reviewer": "审核", "verifier": "验证"}
RECON_RERUN_SUBPHASES = ("map", "old_vulns")
RECON_RERUN_LABELS = {"map": "地图/鉴权", "old_vulns": "历史漏洞"}
WORKER_PROGRESS_RESET_STATUSES = ("paused", "completed", "cancelled", "error")


def _is_sqlite_locked(exc: BaseException) -> bool:
    return "database is locked" in str(exc).lower()


class CombinedEvent:
    """Event-like: set if any child is set. wait() polls so pause loops do not spin."""

    def __init__(self, *events: threading.Event) -> None:
        self._events = events

    def is_set(self) -> bool:
        return any(e.is_set() for e in self._events)

    def wait(self, timeout: float | None = None) -> bool:
        deadline = None if timeout is None else time.time() + max(0.0, timeout)
        while not self.is_set():
            remaining = None if deadline is None else deadline - time.time()
            if remaining is not None and remaining <= 0:
                return False
            time.sleep(min(0.2, remaining if remaining is not None else 0.2))
        return True


class GenerationCancel:
    """Project cancel, or this phase was 新跑'd (generation bumped)."""

    def __init__(self, project_cancel: threading.Event, project_id: int, phase: str, generation: int) -> None:
        self._project = project_cancel
        self._project_id = project_id
        self._phase = phase
        self._generation = generation

    def is_set(self) -> bool:
        if self._project.is_set():
            return True
        return _phase_generation_of(self._project_id, self._phase) != self._generation

    def wait(self, timeout: float | None = None) -> bool:
        deadline = None if timeout is None else time.time() + max(0.0, timeout)
        while not self.is_set():
            remaining = None if deadline is None else deadline - time.time()
            if remaining is not None and remaining <= 0:
                return False
            time.sleep(min(0.2, remaining if remaining is not None else 0.2))
        return True


def control_phase(phase: str) -> str:
    p = (phase or "").strip()
    if p in (
        "recon",
        "recon-mark",
        "recon_mark",
        "recon-old-vuln",
        "recon_old_vuln",
        "recon-old-vuln-ghsa",
        "recon_old_vuln_ghsa",
        "recon-map",
        "recon-source-ext",
        "recon_source_ext",
    ):
        return "recon"
    if p in (
        "worker",
        "fix",
        "mine",
        "fast",
        "fast-worker",
        "fast_worker",
        "sink-triage",
        "sink_triage",
        "bypass-worker",
        "bypass_worker",
        "bypass",
    ):
        return "worker"
    if p in ("reviewer", "reviewer-lab", "reviewer_lab"):
        return "reviewer"
    if p == "verifier":
        return "verifier"
    raise ValueError(f"未知阶段: {phase}")


def _phase_generation_of(project_id: int, phase: str) -> int:
    return _phase_generation.get((project_id, control_phase(phase)), 0)


def _bump_phase_generation(project_id: int, phase: str) -> int:
    key = (project_id, control_phase(phase))
    with _lock:
        nxt = _phase_generation.get(key, 0) + 1
        _phase_generation[key] = nxt
        return nxt


def _phase_pause_event(project_id: int, phase: str) -> threading.Event:
    key = (project_id, control_phase(phase))
    with _lock:
        if key not in _phase_pause_flags:
            _phase_pause_flags[key] = threading.Event()
        return _phase_pause_flags[key]


def _combined_pause(project_id: int, phase: str) -> CombinedEvent:
    return CombinedEvent(_pause_event(project_id), _phase_pause_event(project_id, phase))


def _loop_cancel(project_id: int, phase: str) -> GenerationCancel:
    return GenerationCancel(_cancel_event(project_id), project_id, control_phase(phase), _phase_generation_of(project_id, phase))


def _phase_is_paused(project_id: int, phase: str) -> bool:
    return _pause_event(project_id).is_set() or _phase_pause_event(project_id, phase).is_set()


def reset_runtime_state() -> None:
    """Test helper: drop in-memory orchestrator flags."""
    from ..tools.phase_recon import _map_refresh_pending

    with _lock:
        _cancel_events.clear()
        _pause_flags.clear()
        _phase_pause_flags.clear()
        _phase_generation.clear()
        _force_new_run.clear()
        _pending_inject.clear()
        _threads.clear()
        _recon_threads.clear()
        _recon_rerun_threads.clear()
        _reviewer_threads.clear()
        _verifier_threads.clear()
        _reviewer_inflight.clear()
        _verifier_inflight.clear()
        _fix_inflight.clear()
        _adopted_phase_runs.clear()
        _fast_prepare_threads.clear()
        _fast_last_dir.clear()
        _map_refresh_pending.clear()
    from .llm_thread import llm_thread_limiter

    llm_thread_limiter.reset()


def _cancel_event(project_id: int) -> threading.Event:
    with _lock:
        if project_id not in _cancel_events:
            _cancel_events[project_id] = threading.Event()
        return _cancel_events[project_id]


def _pause_event(project_id: int) -> threading.Event:
    with _lock:
        if project_id not in _pause_flags:
            _pause_flags[project_id] = threading.Event()
        return _pause_flags[project_id]


def request_cancel(project_id: int) -> None:
    _cancel_event(project_id).set()
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        if proj and proj.status not in ("completed",):
            proj.status = "cancelled"
            db.commit()
    live_log.system(project_id, "用户取消审计")


def request_pause(project_id: int) -> None:
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        if proj and proj.status == "completed":
            return
    _pause_event(project_id).set()
    for phase in CONTROL_PHASES:
        _phase_pause_event(project_id, phase).set()
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        if proj and proj.status != "completed":
            proj.status = "paused"
            db.commit()
    live_log.system(project_id, "用户暂停全部阶段")


def note_mining_paths_changed(
    project_id: int,
    *,
    heuristic_enabled: bool,
    fast_enabled: bool,
    bypass_enabled: bool = False,
    heuristic_lite: bool = False,
) -> None:
    """Keep paused; next resume uses the new mining paths."""
    _force_new_run.add((project_id, "worker"))
    _abandon_phase_checkpoints(project_id, "worker")
    _bump_phase_generation(project_id, "worker")
    live_log.system(
        project_id,
        f"挖掘路径已改为{mining_path_label(heuristic_enabled=heuristic_enabled, fast_enabled=fast_enabled, bypass_enabled=bypass_enabled, heuristic_lite=heuristic_lite)}，续跑后按新路径调度",
        phase="worker",
    )


def note_audit_mode_changed(
    project_id: int,
    mode: str,
    *,
    custom_name: str | None = None,
) -> None:
    """Keep the project paused; next resume must use the new Worker/Reviewer rules."""
    for control in ("worker", "reviewer"):
        _force_new_run.add((project_id, control))
        _abandon_phase_checkpoints(project_id, control)
        _bump_phase_generation(project_id, control)
    live_log.system(
        project_id,
        f"挖掘模式已改为{audit_mode_label(mode, custom_name=custom_name)}，续跑后 Worker/Reviewer 将按新规则新开",
    )


def note_verifier_enabled(project_id: int) -> None:
    """Enabling Verifier mid-run should not inherit a leftover phase-pause bit."""
    if not _pause_event(project_id).is_set():
        _phase_pause_event(project_id, "verifier").clear()


def note_dynamic_verify_changed(project_id: int, *, enabled: bool) -> None:
    """Next Reviewer round should pick up the new static/dynamic gate."""
    _force_new_run.add((project_id, "reviewer"))
    _abandon_phase_checkpoints(project_id, "reviewer")
    _bump_phase_generation(project_id, "reviewer")
    if enabled and not _pause_event(project_id).is_set():
        _phase_pause_event(project_id, "reviewer").clear()


class DynamicVerifyRequestError(RuntimeError):
    def __init__(self, message: str, *, status_code: int = 400) -> None:
        super().__init__(message)
        self.status_code = status_code


def is_static_only_vuln(vuln: Vuln) -> bool:
    if vuln.status == "static_only":
        return True
    return vuln.status == "confirmed" and (vuln.evidence_level or "") == "static_only"


def reviewer_run_active_for_vuln(project_id: int, vuln_id: int) -> bool:
    with SessionLocal() as db:
        row = (
            db.query(PhaseRun)
            .filter(
                PhaseRun.project_id == project_id,
                PhaseRun.phase == "reviewer",
                PhaseRun.vuln_id == vuln_id,
                PhaseRun.status.in_(("running", "paused")),
            )
            .first()
        )
        return row is not None


def dynamic_verify_flags(vuln: Vuln, *, project: Project | None = None) -> tuple[bool, bool]:
    queued = reviewer_run_active_for_vuln(vuln.project_id, vuln.id)
    proj = project
    if proj is None:
        with SessionLocal() as db:
            proj = db.get(Project, vuln.project_id)
    can = bool(
        is_static_only_vuln(vuln)
        and proj is not None
        and verify_mode_enabled(project_verify_mode(proj))
        and proj.status not in ("cancelled", "error", "pending", "ingesting")
        and vuln.status != "merged"
    )
    return can, queued


def request_dynamic_verify(vuln_id: int) -> dict[str, Any]:
    """Queue a Reviewer follow-up that continues the static round with dynamic verification."""
    with SessionLocal() as db:
        vuln = db.get(Vuln, vuln_id)
        if not vuln:
            raise DynamicVerifyRequestError("漏洞不存在", status_code=404)
        proj = db.get(Project, vuln.project_id)
        if not proj:
            raise DynamicVerifyRequestError("项目不存在", status_code=404)
        db.expunge(vuln)
        db.expunge(proj)
    if proj.status in ("cancelled", "error", "pending", "ingesting"):
        raise DynamicVerifyRequestError("当前项目状态不可追加动态验证")
    verify_mode = project_verify_mode(proj)
    if not verify_mode_enabled(verify_mode):
        raise DynamicVerifyRequestError("请先在项目设置中开启靶场动态或局部验证")
    if vuln.status == "merged":
        raise DynamicVerifyRequestError("该漏洞已并入其他报告")
    if not is_static_only_vuln(vuln):
        raise DynamicVerifyRequestError("仅 static_only 的漏洞可追加验证")
    if reviewer_run_active_for_vuln(proj.id, vuln.id):
        raise DynamicVerifyRequestError("该漏洞已在追加验证中", status_code=409)

    ctx = latest_reviewer_context(proj.id, vuln.id)
    system = _phase_system_prompt(proj.id, "reviewer.md")
    if ctx and ctx.get("messages"):
        messages = list(ctx.get("messages") or [])
        if messages and messages[0].get("role") == "system":
            messages[0] = {**messages[0], "content": system}
        else:
            messages.insert(0, {"role": "system", "content": system})
        user_prompt = str(ctx.get("user_prompt") or "")
        last_prompt_tokens = int(ctx.get("last_prompt_tokens") or 0)
        source_run = ctx.get("phase_run_id")
    else:
        messages = [{"role": "system", "content": system}]
        user_prompt = ""
        last_prompt_tokens = 0
        source_run = None

    run_id = _new_phase_run(proj.id, "reviewer", "reviewer", vuln_id=vuln.id)
    save_checkpoint(
        LoopCheckpoint(
            project_id=proj.id,
            phase_run_id=run_id,
            role="reviewer",
            phase="reviewer",
            system_prompt=system,
            user_prompt=user_prompt,
            messages=messages,
            state={
                "dynamic_followup": True,
                "dynamic_followup_prompted": False,
                "review_done": False,
                "source_phase_run_id": source_run,
            },
            vuln_id=vuln.id,
            last_prompt_tokens=last_prompt_tokens,
            timeout_sec=settings.timeout_reviewer_static,
        )
    )
    _force_new_run.discard((proj.id, "reviewer"))
    if _pause_event(proj.id).is_set():
        for phase in CONTROL_PHASES:
            if phase != "reviewer":
                _phase_pause_event(proj.id, phase).set()
        _pause_event(proj.id).clear()
    _phase_pause_event(proj.id, "reviewer").clear()
    cancel = _cancel_event(proj.id)
    if cancel.is_set():
        cancel.clear()
    with SessionLocal() as db:
        row = db.get(Project, proj.id)
        if row and row.status in ("completed", "paused"):
            row.status = "reviewing"
            row.phase = "reviewer"
            row.error = None
            db.commit()
    followup_kind = "局部验证" if is_harness_mode(verify_mode) else "动态验证"
    live_log.system(
        proj.id,
        f"漏洞 #{vuln.id} 接续原审核轮次追加{followup_kind}",
        phase="reviewer",
    )
    start_audit(proj.id)
    _ensure_reviewer(proj.id, _cancel_event(proj.id))
    return {"ok": True, "vuln_id": vuln.id, "project_id": proj.id, "phase_run_id": run_id}


def request_resume(project_id: int) -> None:
    _pause_event(project_id).clear()
    for phase in CONTROL_PHASES:
        _phase_pause_event(project_id, phase).clear()
    cancel = _cancel_event(project_id)
    if cancel.is_set():
        cancel.clear()
    _prepare_project_resume(project_id)
    _set_project_running(project_id)
    live_log.system(project_id, "全部阶段续跑（接续原上下文）")
    start_audit(project_id)


def _enabled_control_phases(project_id: int) -> tuple[str, ...]:
    if _read_verifier_enabled(project_id):
        return CONTROL_PHASES
    return ("recon", "worker", "reviewer")


def request_recon_subphase_rerun(project_id: int, subphase: str) -> dict[str, Any]:
    """Re-run recon map/auth or old-vulns while keeping existing docs for update."""
    key = (subphase or "").strip().replace("-", "_")
    if key in ("map", "recon_map", "reconmap"):
        sub = "map"
    elif key in ("old_vulns", "old_vuln", "recon_old_vuln", "recon_old_vulns"):
        sub = "old_vulns"
    else:
        raise ValueError("仅支持重跑 map（地图/鉴权）或 old_vulns（历史漏洞）")

    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        if not proj:
            raise ValueError("项目不存在")
        if proj.status in ("cancelled", "ingesting", "error"):
            raise ValueError("当前项目状态不可重跑侦察子阶段")

    label = RECON_RERUN_LABELS[sub]
    if sub == "map":
        if not recon_map_ready(project_id):
            raise ValueError("地图/鉴权尚未完成，完成后才能重跑更新")
        db_phases = ("recon",)
    else:
        if not recon_old_vulns_ready(project_id):
            raise ValueError("历史漏洞尚未完成，完成后才能重跑更新")
        clear_old_vuln_completion(project_id)
        db_phases = ("recon-old-vuln", "recon-old-vuln-ghsa")

    with _lock:
        t = _recon_rerun_threads.get(project_id)
        if t is not None and t.is_alive():
            raise ValueError("已有侦察子阶段正在重跑")

    _abandon_db_phase_runs(project_id, db_phases, reason=f"用户重跑{label}")
    _bump_phase_generation(project_id, "recon")
    _force_new_run.discard((project_id, "recon"))

    was_paused = _pause_event(project_id).is_set()
    _pause_event(project_id).clear()
    _phase_pause_event(project_id, "recon").clear()
    cancel = _cancel_event(project_id)
    if cancel.is_set():
        cancel.clear()
    if not was_paused:
        _set_project_running(project_id)
    else:
        # Keep other phases paused; only let this recon refresh session run.
        for p in CONTROL_PHASES:
            if p != "recon":
                _phase_pause_event(project_id, p).set()
        with SessionLocal() as db:
            proj = db.get(Project, project_id)
            if proj and proj.status == "paused":
                proj.status = "recon" if not proj.recon_done else "auditing"
                proj.error = None
                db.commit()

    # 日志并入地图/鉴权或历史漏洞小阶段；由后续 AgentLoop 的 _start_log_session 新开一轮。
    rt = threading.Thread(
        target=_run_recon_subphase_rerun,
        args=(project_id, sub, was_paused),
        daemon=True,
        name=f"vh-recon-rerun-{project_id}-{sub}",
    )
    with _lock:
        _recon_rerun_threads[project_id] = rt
        _threads.setdefault(project_id, []).append(rt)
    rt.start()
    return {"ok": True, "subphase": sub, "label": label, **get_phase_states(project_id)}


def _run_recon_subphase_rerun(project_id: int, subphase: str, restore_pause: bool) -> None:
    cancel = _cancel_event(project_id)
    label = RECON_RERUN_LABELS.get(subphase, subphase)
    log_phase = "recon" if subphase == "map" else "recon-old-vuln"
    try:
        if subphase == "map":
            ok = _run_recon_map_refresh(project_id, cancel)
        else:
            ok = _run_recon_old_vulns(project_id, cancel)
        if not ok and not cancel.is_set():
            live_log.system(project_id, f"{label}未完成", phase=log_phase)
    except Exception as e:  # noqa: BLE001
        live_log.error(project_id, f"{label}异常: {e}", phase=log_phase)
    finally:
        clear_map_refresh(project_id)
        if restore_pause and not cancel.is_set():
            _pause_event(project_id).set()
            for phase in CONTROL_PHASES:
                _phase_pause_event(project_id, phase).set()
            with SessionLocal() as db:
                proj = db.get(Project, project_id)
                if proj and proj.status not in ("completed", "cancelled"):
                    proj.status = "paused"
                    db.commit()
            live_log.system(project_id, "项目恢复暂停")


def request_worker_progress_reset(project_id: int) -> dict[str, Any]:
    """Reset heuristic Worker file progress so a new model can re-mine that path.

    Keeps vulns, recon docs, file weights/skips, lab, reviewer/verifier state,
    fast-scan Sink queue, and historical-vuln bypass queue.
    Clears audited/claim flags, heuristic Worker checkpoints, round reports, and
    summaries that would tell the next heuristic Worker to skip already-tried paths.
    Project stays paused so the user can switch mode or model, then resume.
    """
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        if not proj:
            raise ValueError("项目不存在")
        if proj.status not in WORKER_PROGRESS_RESET_STATUSES:
            raise ValueError("请先全部暂停项目，再重置挖掘进度")
        recon_done = bool(proj.recon_done)
        audited = (
            db.query(FileWeight)
            .filter(FileWeight.project_id == project_id, FileWeight.audited.is_(True))
            .count()
        )
        db.query(FileWeight).filter(FileWeight.project_id == project_id).update(
            {
                FileWeight.audited: False,
                FileWeight.claimed_by: None,
                FileWeight.claimed_at: None,
                FileWeight.audit_attempts: 0,
            },
            synchronize_session=False,
        )
        proj.status = "paused"
        proj.phase = "worker" if recon_done else "recon"
        proj.error = None
        db.commit()

    n_fix = _reset_fixing_to_returned(project_id, except_ids=set())
    n_rounds = _clear_heuristic_progress_files(project_id)
    _abandon_db_phase_runs(project_id, ("worker", "fix"), reason="用户重置启发式挖掘进度")
    with _lock:
        _pending_inject.pop((project_id, "worker"), None)
    _pause_event(project_id).set()
    for phase in CONTROL_PHASES:
        _phase_pause_event(project_id, phase).set()
    live_log.system(
        project_id,
        "已重置启发式挖掘进度：文件恢复未审计，启发式轮次摘要已清；快速扫描与历史漏洞绕过进度保留。漏洞产出与侦察文档保留。"
        + (f" fixing→returned {n_fix}。" if n_fix else "")
        + f" 已审计文件 {audited}，轮次文件 {n_rounds}。"
        " 项目保持暂停，可更换模型或切换挖掘模式后全部续跑。",
        phase="worker",
    )
    return get_phase_states(project_id)


def _clear_heuristic_progress_files(project_id: int) -> int:
    """Delete heuristic Worker round reports, compression summaries, and worker/fix todos."""
    n = 0
    rounds = workspace_dir(project_id) / "rounds"
    if rounds.is_dir():
        n += _unlink_glob(rounds, "round-*.md")
    summaries = summaries_dir(project_id)
    if summaries.is_dir():
        n += _unlink_glob(summaries, "worker-*.md")
        n += _unlink_glob(summaries, "fix-*.md")
    ws = workspace_dir(project_id)
    n += _unlink_glob(ws, "todos-worker-*.json")
    n += _unlink_glob(ws, "todos-fix-*.json")
    return n


def _unlink_glob(directory: Path, pattern: str) -> int:
    n = 0
    for path in directory.glob(pattern):
        if not path.is_file():
            continue
        try:
            path.unlink()
            n += 1
        except OSError:
            pass
    return n


def _start_log_session(
    project_id: int,
    phase: str,
    extra: str = "",
    *,
    role: str | None = None,
) -> int:
    """调度器新开 AgentLoop 时翻日志页；当前页还没有事件则留在第 1 页。"""
    control = control_phase(phase)
    prev = live_log.current_session(project_id, phase)
    nxt = live_log.begin_session(project_id, phase, if_used=True)
    started = nxt > prev
    label = CONTROL_LABELS[control]
    suffix = f"（{extra}）" if extra else ""
    live_log.system(
        project_id,
        f"{label}{'新开对话' if started else '开始'}{suffix}",
        phase=phase,
        role=role,
        session_start=started,
    )
    return nxt


def _set_project_running(project_id: int) -> None:
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        if proj and proj.status != "completed":
            if proj.recon_done:
                proj.status = "auditing"
                if proj.phase in ("pending", "recon"):
                    proj.phase = "worker"
            else:
                proj.status = "recon"
                proj.phase = "recon"
            proj.error = None
            db.commit()


def _wait_if_paused(project_id: int, cancel: threading.Event, phase: str | None = None) -> bool:
    while True:
        if cancel.is_set():
            return False
        if phase:
            paused = _phase_is_paused(project_id, phase)
        else:
            paused = _pause_event(project_id).is_set()
        if not paused:
            return not cancel.is_set()
        time.sleep(0.2)


def _resumable_for_control(project_id: int, phase: str) -> list:
    rows: list = []
    for db_phase in CONTROL_DB_PHASES[control_phase(phase)]:
        rows.extend(list_resumable_runs(project_id, db_phase))
    return rows


def _collect_inject_targets(project_id: int, phase: str) -> list[dict[str, Any]]:
    seen_files: set[str] = set()
    seen_vulns: set[int] = set()
    out: list[dict[str, Any]] = []
    for pr in _resumable_for_control(project_id, phase):
        cp = load_checkpoint(project_id, pr.id)
        path = (cp.file_path if cp else None) or pr.file_path
        vuln_id = (cp.vuln_id if cp else None) or pr.vuln_id
        item: dict[str, Any] = {}
        if path and path not in seen_files:
            seen_files.add(path)
            item["file_path"] = path
        if vuln_id is not None and int(vuln_id) not in seen_vulns:
            seen_vulns.add(int(vuln_id))
            item["vuln_id"] = int(vuln_id)
        if item:
            out.append(item)
    return out


def _abandon_db_phase_runs(project_id: int, db_phases: tuple[str, ...], *, reason: str) -> None:
    for db_phase in db_phases:
        for pr in list_resumable_runs(project_id, db_phase):
            _release_adopted(project_id, pr.id)
            _finish_phase_run(pr.id, "cancelled", reason)


def _abandon_phase_checkpoints(project_id: int, phase: str, *, reason: str = "用户新跑") -> None:
    _abandon_db_phase_runs(project_id, CONTROL_DB_PHASES[control_phase(phase)], reason=reason)


def _prepare_phase_resume(project_id: int, phase: str) -> None:
    control = control_phase(phase)
    if control == "worker":
        keep_paths = resumable_file_paths(project_id)
        keep_vulns = resumable_vuln_ids(project_id, "fix")
        n_claims = _release_claims(project_id, except_paths=keep_paths)
        n_fix = _reset_fixing_to_returned(project_id, except_ids=keep_vulns)
        from .sink_queue import parse_sink_ref
        from .bypass_queue import parse_bypass_ref
        from ..models import BypassTarget, Sink

        keep_sinks = {parse_sink_ref(p) for p in keep_paths if parse_sink_ref(p)}
        keep_bypass = {parse_bypass_ref(p) for p in keep_paths if parse_bypass_ref(p)}
        n_sinks = 0
        n_bypass = 0
        with SessionLocal() as db:
            rows = (
                db.query(Sink)
                .filter(Sink.project_id == project_id, Sink.status == "claimed")
                .all()
            )
            for row in rows:
                if row.id in keep_sinks:
                    continue
                row.status = "queued"
                row.claimed_by = None
                row.claimed_at = None
                n_sinks += 1
            bypass_rows = (
                db.query(BypassTarget)
                .filter(BypassTarget.project_id == project_id, BypassTarget.status == "claimed")
                .all()
            )
            for row in bypass_rows:
                if row.id in keep_bypass:
                    continue
                row.status = "queued"
                row.claimed_by = None
                row.claimed_at = None
                n_bypass += 1
            if n_sinks or n_bypass:
                db.commit()
        if n_claims or n_fix or n_sinks or n_bypass:
            live_log.system(
                project_id,
                f"挖掘续跑准备：清认领 {n_claims}，Sink {n_sinks}，绕过 {n_bypass}，fixing→returned {n_fix}",
                phase="worker",
            )
    n_cp = len(_resumable_for_control(project_id, control))
    if n_cp:
        live_log.system(project_id, f"发现 {n_cp} 个可接续检查点，将接着原上下文继续", phase=control)


def _take_pending_inject(project_id: int, phase: str) -> list[dict[str, Any]]:
    key = (project_id, control_phase(phase))
    with _lock:
        return list(_pending_inject.pop(key, []))


def _take_inject_file(project_id: int, worker_id: str) -> FileWeight | None:
    items = _take_pending_inject(project_id, "worker")
    rest: list[dict[str, Any]] = []
    chosen: str | None = None
    for item in items:
        path = item.get("file_path")
        if chosen is None and path:
            chosen = str(path)
        elif path or item.get("vuln_id") is not None:
            rest.append(item)
    if rest:
        with _lock:
            _pending_inject[(project_id, "worker")] = rest + list(_pending_inject.get((project_id, "worker"), []))
    if not chosen:
        return None
    _reclaim_file(project_id, chosen, worker_id)
    with SessionLocal() as db:
        row = (
            db.query(FileWeight)
            .filter(FileWeight.project_id == project_id, FileWeight.path == chosen)
            .first()
        )
        if not row or row.audited:
            return None
        db.expunge(row)
        return row


def _take_inject_vuln(project_id: int, phase: str) -> int | None:
    items = _take_pending_inject(project_id, phase)
    rest: list[dict[str, Any]] = []
    chosen: int | None = None
    for item in items:
        vid = item.get("vuln_id")
        if chosen is None and vid is not None:
            chosen = int(vid)
        else:
            rest.append(item)
    if rest:
        key = (project_id, control_phase(phase))
        with _lock:
            _pending_inject[key] = rest + list(_pending_inject.get(key, []))
    return chosen


def _consume_force_new(project_id: int, phase: str) -> bool:
    key = (project_id, control_phase(phase))
    with _lock:
        if key in _force_new_run:
            _force_new_run.discard(key)
            return True
        return False


def _should_skip_checkpoint(project_id: int, phase: str) -> bool:
    return (project_id, control_phase(phase)) in _force_new_run


def get_phase_states(project_id: int) -> dict[str, Any]:
    project_paused = _pause_event(project_id).is_set()
    states: dict[str, Any] = {}
    for phase in CONTROL_PHASES:
        paused = project_paused or _phase_pause_event(project_id, phase).is_set()
        resumable = bool(_resumable_for_control(project_id, phase))
        states[phase] = {
            "paused": paused,
            "running": _phase_thread_alive(project_id, phase),
            "resumable": resumable,
            "force_new": (project_id, phase) in _force_new_run,
        }
    return {"phases": states, "project_paused": project_paused}


def _phase_thread_alive(project_id: int, phase: str) -> bool:
    control = control_phase(phase)
    if control == "recon":
        t = _recon_threads.get(project_id)
        return t is not None and t.is_alive()
    if control == "reviewer":
        t = _reviewer_threads.get(project_id)
        return t is not None and t.is_alive()
    if control == "verifier":
        t = _verifier_threads.get(project_id)
        return t is not None and t.is_alive()
    for t in _threads.get(project_id, []):
        name = t.name or ""
        if t.is_alive() and ("worker" in name or "fast" in name):
            return True
    if _fix_inflight.get(project_id):
        return True
    return False


def _new_phase_run(
    project_id: int,
    phase: str,
    role: str,
    worker_id: str | None = None,
    vuln_id: int | None = None,
    file_path: str | None = None,
) -> int:
    from sqlalchemy.exc import OperationalError

    from ..models import ensure_schema

    ensure_schema()
    for attempt in range(2):
        try:
            with SessionLocal() as db:
                pr = PhaseRun(
                    project_id=project_id,
                    phase=phase,
                    role=role,
                    status="running",
                    worker_id=worker_id,
                    vuln_id=vuln_id,
                    file_path=file_path,
                )
                db.add(pr)
                db.commit()
                db.refresh(pr)
                return pr.id
        except OperationalError as e:
            if attempt == 0 and "no such table" in str(e).lower():
                ensure_schema()
                continue
            raise
    raise RuntimeError("无法创建 phase_run")


def _finish_phase_run(run_id: int, status: str, error: str | None = None) -> None:
    project_id: int | None = None
    phase: str | None = None
    with SessionLocal() as db:
        pr = db.get(PhaseRun, run_id)
        if pr:
            project_id = pr.project_id
            phase = pr.phase
            pr.status = status
            pr.error = error
            pr.finished_at = utcnow()
            db.commit()
    if project_id is not None:
        if phase == "reviewer" and status == "completed":
            archive_reviewer_checkpoint(project_id, run_id)
        clear_checkpoint(project_id, run_id)


def _context_window() -> int:
    row = get_settings_row()
    return int(row.context_window or settings.default_context_window)


def _worker_concurrency(project_id: int) -> int:
    return WORKER_MINE_POOL


def _fix_concurrency() -> int:
    """打回报告修改用独立池，不占用挖掘 Worker 名额。"""
    return WORKER_FIX_POOL


def _read_file_snippet(project_id: int, rel: str) -> str:
    path = src_dir(project_id) / rel
    if not path.exists():
        return f"（文件不存在: {rel}）"
    data = path.read_bytes()[: settings.file_inject_max_bytes]
    return data.decode("utf-8", errors="replace")


def _release_claims(
    project_id: int,
    worker_id: str | None = None,
    except_paths: set[str] | None = None,
) -> int:
    keep = except_paths or set()
    with SessionLocal() as db:
        q = db.query(FileWeight).filter(
            FileWeight.project_id == project_id,
            FileWeight.claimed_by.isnot(None),
            FileWeight.audited.is_(False),
        )
        if worker_id:
            q = q.filter(FileWeight.claimed_by == worker_id)
        rows = q.all()
        n = 0
        for row in rows:
            if row.path in keep:
                continue
            row.claimed_by = None
            row.claimed_at = None
            n += 1
        if n:
            db.commit()
        return n


def _release_claim_if_unfinished(project_id: int, path: str, worker_id: str, *, failed: bool) -> None:
    with SessionLocal() as db:
        row = (
            db.query(FileWeight)
            .filter(FileWeight.project_id == project_id, FileWeight.path == path)
            .first()
        )
        if not row:
            return
        if row.claimed_by == worker_id and not row.audited:
            row.claimed_by = None
            row.claimed_at = None
            if failed:
                row.audit_attempts = int(row.audit_attempts or 0) + 1
            db.commit()


def _release_stale_claims(project_id: int) -> int:
    cutoff = utcnow() - timedelta(seconds=max(60, int(settings.claim_stale_sec)))
    with SessionLocal() as db:
        rows = (
            db.query(FileWeight)
            .filter(
                FileWeight.project_id == project_id,
                FileWeight.claimed_by.isnot(None),
                FileWeight.audited.is_(False),
                FileWeight.claimed_at.isnot(None),
                FileWeight.claimed_at < cutoff,
            )
            .all()
        )
        protected = resumable_file_paths(project_id)
        n = 0
        for row in rows:
            if row.path in protected:
                continue
            live_log.system(
                project_id,
                f"回收陈旧认领: {row.path} (by={row.claimed_by})",
                phase="worker",
            )
            row.claimed_by = None
            row.claimed_at = None
            n += 1
        if n:
            db.commit()
    n += _release_stale_sink_claims(project_id, cutoff)
    n += _release_stale_bypass_claims(project_id, cutoff)
    return n


def _release_stale_sink_claims(project_id: int, cutoff) -> int:
    from .sink_queue import parse_sink_ref, release_stale_sink_claims

    keep = {
        sid
        for sid in (parse_sink_ref(p) for p in resumable_file_paths(project_id))
        if sid
    }
    n = release_stale_sink_claims(project_id, stale_before=cutoff, except_ids=keep)
    if n:
        live_log.system(project_id, f"回收陈旧 Sink 认领 {n}", phase="fast-worker")
    return n


def _release_stale_bypass_claims(project_id: int, cutoff) -> int:
    from .bypass_queue import parse_bypass_ref, release_stale_bypass_claims

    keep = {
        bid
        for bid in (parse_bypass_ref(p) for p in resumable_file_paths(project_id))
        if bid
    }
    n = release_stale_bypass_claims(project_id, stale_before=cutoff, except_ids=keep)
    if n:
        live_log.system(project_id, f"回收陈旧绕过认领 {n}", phase="bypass-worker")
    return n


def _reset_fixing_to_returned(project_id: int, except_ids: set[int] | None = None) -> int:
    keep = except_ids or set()
    with SessionLocal() as db:
        rows = (
            db.query(Vuln)
            .filter(Vuln.project_id == project_id, Vuln.status == "fixing")
            .all()
        )
        n = 0
        for v in rows:
            if v.id in keep:
                continue
            v.status = "returned"
            n += 1
        if n:
            db.commit()
        return n


def _prepare_project_resume(project_id: int) -> None:
    keep_paths = resumable_file_paths(project_id)
    keep_vulns = resumable_vuln_ids(project_id, "fix")
    n_claims = _release_claims(project_id, except_paths=keep_paths)
    n_fix = _reset_fixing_to_returned(project_id, except_ids=keep_vulns)
    if n_claims or n_fix:
        live_log.system(
            project_id,
            f"恢复准备：清认领 {n_claims}，fixing→returned {n_fix}",
        )
    n_cp = len(list_resumable_runs(project_id))
    if n_cp:
        live_log.system(project_id, f"发现 {n_cp} 个可接续检查点，将接着原上下文继续")


def _pick_next_file(project_id: int, worker_id: str) -> FileWeight | None:
    protected = resumable_file_paths(project_id)
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        lite = heuristic_lite_active(
            heuristic_enabled=bool(getattr(proj, "heuristic_enabled", True)) if proj else True,
            heuristic_lite=bool(getattr(proj, "heuristic_lite", False)) if proj else False,
        )
        q = db.query(FileWeight).filter(
            FileWeight.project_id == project_id,
            FileWeight.skipped.is_(False),
            FileWeight.audited.is_(False),
            FileWeight.weight.isnot(None),
            FileWeight.claimed_by.is_(None),
        )
        if lite:
            q = q.filter(FileWeight.weight == HEURISTIC_LITE_WEIGHT)
        q = q.order_by(
            FileWeight.audit_attempts.asc(),
            FileWeight.has_source.desc(),
            FileWeight.weight.desc(),
            FileWeight.path.asc(),
        )
        row = None
        for cand in q.all():
            if cand.path in protected:
                continue
            row = cand
            break
        if not row:
            return None
        row.claimed_by = worker_id
        row.claimed_at = utcnow()
        db.commit()
        db.refresh(row)
        db.expunge(row)
        return row


def _sources_for_file(project_id: int, path: str) -> list[str]:
    with SessionLocal() as db:
        rows = (
            db.query(Source)
            .filter(Source.project_id == project_id, Source.file_path == path)
            .all()
        )
        return [f"{r.method_name}" for r in rows]


def _read_audit_mode(project_id: int) -> str:
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        return normalize_audit_mode(None if not proj else proj.audit_mode)


def _read_manual_lab(project_id: int) -> tuple[bool, str]:
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        if not proj:
            return False, ""
        prompt = str(proj.manual_lab_prompt or "").strip()
        return bool(proj.manual_lab) or bool(prompt), prompt


def _read_verifier_enabled(project_id: int) -> bool:
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        return bool(proj and proj.verifier_enabled)


def _read_dynamic_verify_mode(project_id: int) -> str:
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        return project_verify_mode(proj)


def _read_dynamic_verify_enabled(project_id: int) -> bool:
    return verify_mode_enabled(_read_dynamic_verify_mode(project_id))


def _reviewer_has_lab_work(project_id: int) -> bool:
    if not is_lab_mode(_read_dynamic_verify_mode(project_id)):
        return False
    return not lab_setup_finished(project_id) or bool(list_resumable_runs(project_id, "reviewer-lab"))


def _reviewer_has_review_work(project_id: int, pending: int | None = None) -> bool:
    if pending is None:
        with SessionLocal() as db:
            pending = (
                db.query(Vuln)
                .filter(Vuln.project_id == project_id, Vuln.status == "pending_review")
                .count()
            )
    return pending > 0 or bool(list_resumable_runs(project_id, "reviewer"))


_ASSET_PROOF_LAB_HINT = (
    "应用指纹是项目级的（docs/app-fingerprints.json），全项目只识别一次。"
    "有可访问的漏洞环境时，用 CollectLabFingerprints 升级项目指纹（标题/body/header/favicon），"
    "再写入本条报告（apply=true 或 ConfirmVuln 传 fofa_fingerprint/x_fingerprint）。"
    "不要把「待运行环境确认」留到确认后，也不要为此 ReturnToWorker。"
)


_STATIC_REVIEW_NOTE = (
    "本项目仅静态验证：不要搭建 Docker、不要对靶场发请求或运行 poc.py、"
    "不要 docker exec / debug MCP。"
    "ConfirmVuln 必须 evidence_level=static_only。"
    "应用指纹是项目级的（docs/app-fingerprints.json），系统已在侦察结束后采集一次；"
    "不要每条漏洞重新识别，Confirm 会写入报告。不要编造 hash。"
)

_HARNESS_REVIEW_NOTE = (
    "本项目为局部验证：不要搭建 Docker 靶场，不要对 target_url 发请求或运行 poc.py，不要 debug MCP。"
    "用 RunCode 按目标语言写 mock/harness；打通且成立性满足时 evidence_level=harness。"
    "沙箱不可用或 mock 失败不要误报，静态已能证明默认可利用则 static_only。"
    "不要把 harness 写进 poc.py。应用指纹复用 docs/app-fingerprints.json，不要 CollectLabFingerprints。"
)


def _docker_lab_note(project_id: int) -> str | None:
    env = load_env(project_id)
    if not (lab_ready(env) or env.get("accepted")):
        return None
    rec = recreate_lab(project_id)
    dbg = debug_ports_for_runtime(load_env(project_id) or env)
    return f"环境: {json_dumps(rec)}\n调试: {json_dumps(dbg)}"


def _reviewer_lab_note(project_id: int) -> str:
    mode = _read_dynamic_verify_mode(project_id)
    if mode == VERIFY_MODE_OFF:
        return _STATIC_REVIEW_NOTE
    if mode == VERIFY_MODE_HARNESS:
        return _HARNESS_REVIEW_NOTE
    _enabled, prompt = _read_manual_lab(project_id)
    docker_note = _docker_lab_note(project_id)
    if prompt:
        parts = [
            "优先使用用户提供的人工靶场（地址、账号、路径以用户说明为准）：",
            prompt,
        ]
        if docker_note:
            parts.append("若人工环境不可达，回退到已有 Docker 靶场：")
            parts.append(docker_note)
        else:
            parts.append(
                "Docker 靶场尚未就绪。若人工环境不可达，无法动态验证时用 evidence_level=static_only 或误报。"
            )
        parts.append(_ASSET_PROOF_LAB_HINT)
        return "\n".join(parts)
    if docker_note:
        return f"{docker_note}\n{_ASSET_PROOF_LAB_HINT}"
    return (
        "动态环境搭建轮已结束；靶场未就绪，见 docs/lab.md。"
        "本轮只审核漏洞，不要再搭建 Docker 靶场。"
        "环境起不来时用 evidence_level=static_only 或误报。"
    )


def _next_reviewer_step(project_id: int, pending: int) -> str:
    """Prefer reviewing with a manual lab note; otherwise finish Docker lab first."""
    lab_pending = _reviewer_has_lab_work(project_id)
    review_work = _reviewer_has_review_work(project_id, pending)
    if not lab_pending:
        return "review"
    if review_work and (_read_manual_lab(project_id)[1] or not lab_pending):
        return "review"
    if lab_pending:
        return "lab"
    return "review"


def _audit_mode_vars(project_id: int) -> dict[str, str]:
    mode = _read_audit_mode(project_id)
    custom_name = ""
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        if proj:
            custom_name = (getattr(proj, "custom_audit_mode_name", None) or "").strip()
    return {
        "audit_mode": mode,
        "audit_mode_label": audit_mode_label(mode, custom_name=custom_name or None),
        "audit_mode_hint": initial_hint(mode, custom_name=custom_name or None),
    }


_POC_PROMPT_PHASES = frozenset(
    {"worker.md", "fast_worker.md", "bypass_worker.md", "reviewer.md", "verifier.md"}
)


def _phase_system_prompt(project_id: int, name: str) -> str:
    base = load_prompt(name).rstrip()
    mode = _read_audit_mode(project_id)
    if mode == AUDIT_MODE_CUSTOM:
        with SessionLocal() as db:
            proj = db.get(Project, project_id)
            overlay = project_custom_overlay(proj).strip()
        if not overlay:
            overlay = (
                "## 当前挖掘模式：自定义模式\n\n"
                "自定义提示词快照为空；请勿提交或确认任何漏洞，并提示用户在设置中配置后再续跑。"
            )
    else:
        overlay = load_prompt(f"modes/{mode}.md").strip()
    parts = [base, overlay]
    if name in _POC_PROMPT_PHASES:
        parts.append(load_prompt("poc.md").strip())
    if name == "reviewer.md":
        verify_mode = _read_dynamic_verify_mode(project_id)
        if verify_mode == VERIFY_MODE_OFF:
            parts.append(load_prompt("verify/static.md").strip())
        elif verify_mode == VERIFY_MODE_HARNESS:
            parts.append(load_prompt("verify/harness.md").strip())
    return "\n\n".join(parts) + "\n"


def _initial_prompt(name: str, **kwargs: object) -> str:
    """Render a user-message document from prompts/initial/ and inject it as-is."""
    kwargs.setdefault("audit_mode", "bounty")
    kwargs.setdefault("audit_mode_label", audit_mode_label("bounty"))
    kwargs.setdefault("audit_mode_hint", initial_hint("bounty"))
    return render_prompt(f"initial/{name}", **kwargs)


def _prompt_with_summary(phase: str, project_id: int, body: str, *, for_file: bool = False) -> str:
    summary = latest_summary(project_id, phase)
    # Also try rescue / round variants for worker
    if not summary and phase == "worker":
        summary = latest_summary(project_id, "worker-rescue") or latest_summary(project_id, "worker-round")
    block = inject_summary_block(summary, for_file=for_file)
    text = f"{block}{body}" if block else body
    if phase == "worker" and for_file:
        prior = inject_worker_prior_block(project_id)
        if prior:
            text = f"{prior}{text}"
    return text


def _adopt_resumable(
    project_id: int,
    phase: str,
    *,
    worker_id: str | None = None,
    vuln_id: int | None = None,
) -> LoopCheckpoint | None:
    if _should_skip_checkpoint(project_id, phase):
        return None
    with _lock:
        for pr in list_resumable_runs(project_id, phase):
            key = (project_id, pr.id)
            if key in _adopted_phase_runs:
                continue
            if vuln_id is not None and pr.vuln_id != vuln_id:
                continue
            cp = load_checkpoint(project_id, pr.id)
            if not cp:
                continue
            _adopted_phase_runs.add(key)
            if worker_id:
                set_phase_run_worker(pr.id, worker_id, file_path=cp.file_path)
                cp.worker_id = worker_id
            set_phase_run_status(pr.id, "running")
            live_log.system(
                project_id,
                f"从检查点接续上下文 phase={phase} run={pr.id}",
                phase=phase,
            )
            return cp
    return None


def _release_adopted(project_id: int, run_id: int | None) -> None:
    if run_id is None:
        return
    with _lock:
        _adopted_phase_runs.discard((project_id, run_id))


def _reclaim_file(project_id: int, path: str, worker_id: str) -> None:
    with SessionLocal() as db:
        row = (
            db.query(FileWeight)
            .filter(FileWeight.project_id == project_id, FileWeight.path == path)
            .first()
        )
        if row and not row.audited:
            row.claimed_by = worker_id
            row.claimed_at = utcnow()
            db.commit()


def _loop_from_checkpoint(
    cp: LoopCheckpoint,
    *,
    cancel: threading.Event,
    stop_when,
    timeout_sec: int | None = None,
    llm=None,
    resumed: bool = True,
) -> AgentLoop:
    return AgentLoop.from_checkpoint(
        cp,
        cancel_event=_loop_cancel(cp.project_id, cp.phase),
        pause_event=_combined_pause(cp.project_id, cp.phase),
        stop_when=stop_when,
        context_window=_context_window(),
        timeout_sec=timeout_sec,
        llm=llm,
        resumed=resumed,
    )


def _pause_for_auth(project_id: int, error: str) -> None:
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        if proj:
            proj.error = error
            db.commit()
    request_pause(project_id)
    live_log.error(project_id, f"鉴权失败，已暂停: {error}")


def start_ingest_and_audit(
    project_id: int,
    *,
    source_type: str,
    source_url: str | None = None,
    zip_path=None,
    github_pat: str | None = None,
) -> None:
    from pathlib import Path

    t = threading.Thread(
        target=_ingest_then_audit,
        args=(project_id, source_type, source_url, zip_path, github_pat),
        daemon=True,
        name=f"vh-ingest-{project_id}",
    )
    with _lock:
        _threads.setdefault(project_id, []).append(t)
    t.start()


def _ingest_then_audit(
    project_id: int,
    source_type: str,
    source_url: str | None,
    zip_path,
    github_pat: str | None,
) -> None:
    cancel = _cancel_event(project_id)
    cancel.clear()
    ensure_project_dirs(project_id)
    try:
        with SessionLocal() as db:
            proj = db.get(Project, project_id)
            if proj:
                proj.status = "ingesting"
                proj.phase = "pending"
                db.commit()
        live_log.system(project_id, "开始导入源码")
        if source_type == "github":
            if not source_url:
                raise RuntimeError("缺少 GitHub URL")
            clone_github(project_id, source_url, pat=github_pat)
        elif source_type == "zip":
            if not zip_path:
                raise RuntimeError("缺少 zip 路径")
            extract_zip(project_id, zip_path)
        else:
            raise RuntimeError(f"未知 source_type: {source_type}")
        n = build_file_index(project_id)
        live_log.system(project_id, f"权重建库完成，共 {n} 个源码文件")
        with SessionLocal() as db:
            proj = db.get(Project, project_id)
            if proj:
                proj.status = "recon"
                proj.phase = "recon"
                db.commit()
        start_audit(project_id)
    except Exception as e:  # noqa: BLE001
        live_log.error(project_id, f"导入失败: {e}")
        with SessionLocal() as db:
            proj = db.get(Project, project_id)
            if proj:
                proj.status = "error"
                proj.error = str(e)
                db.commit()


def start_audit(project_id: int) -> None:
    cancel = _cancel_event(project_id)
    if cancel.is_set():
        cancel.clear()
    name = f"vh-orch-{project_id}"
    with _lock:
        alive = [t for t in _threads.get(project_id, []) if t.is_alive() and t.name == name]
        if alive:
            live_log.system(project_id, "调度器已在运行，跳过重复启动")
            return
        t = threading.Thread(
            target=_orchestrate,
            args=(project_id,),
            daemon=True,
            name=name,
        )
        _threads.setdefault(project_id, []).append(t)
    t.start()


def recover_inflight_projects() -> None:
    """Called on process startup to resume interrupted audits."""
    from ..models import ensure_schema

    ensure_schema()
    with SessionLocal() as db:
        projects = (
            db.query(Project)
            .filter(Project.status.in_(("recon", "auditing", "reviewing", "ingesting")))
            .all()
        )
        ids = [(p.id, p.status) for p in projects]
    for pid, status in ids:
        try:
            if status == "ingesting":
                with SessionLocal() as db:
                    n = db.query(FileWeight).filter(FileWeight.project_id == pid).count()
                    proj = db.get(Project, pid)
                    if n == 0:
                        if proj:
                            proj.status = "error"
                            proj.error = "导入中断，请重新导入"
                            db.commit()
                        live_log.error(pid, "导入中断且无文件索引，请重新导入")
                        continue
                    if proj:
                        proj.status = "recon" if not proj.recon_done else "auditing"
                        proj.phase = "recon" if not proj.recon_done else "worker"
                        db.commit()
            _prepare_project_resume(pid)
            live_log.system(pid, f"进程启动恢复审计（原 status={status}）")
            start_audit(pid)
        except Exception as e:  # noqa: BLE001
            live_log.error(pid, f"启动恢复失败: {e}")


def _maybe_mark_recon_done(project_id: int) -> bool:
    """Idempotent: already-done projects return True without logging again."""
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        if proj and proj.recon_done:
            return True
    if apply_recon_done(project_id):
        live_log.system(project_id, "侦察门闩已满足，系统标记 recon_done")
        _ensure_project_fingerprints_once(project_id)
        return True
    return False


def _ensure_project_fingerprints_once(project_id: int) -> None:
    """Identify application FOFA/X fingerprints once after recon; later phases reuse them."""
    try:
        from .asset_proof import ensure_project_fingerprints, fingerprints_usable

        cache = ensure_project_fingerprints(project_id)
        if fingerprints_usable(cache):
            origin = cache.get("origin") or "source"
            live_log.system(project_id, f"已写入项目应用指纹（{origin}），后续漏洞复用")
        else:
            live_log.system(project_id, "项目应用指纹暂缺稳定语句，后续确认/验证时再补")
    except Exception as e:  # noqa: BLE001
        live_log.error(project_id, f"采集项目应用指纹失败: {e}")


def _maybe_complete_project(project_id: int, *, reviewer_busy: bool, fix_busy: bool, verifier_busy: bool = False) -> bool:
    if reviewer_busy or fix_busy or verifier_busy:
        return False
    if list_resumable_runs(project_id, "reviewer") or list_resumable_runs(project_id, "reviewer-lab"):
        return False
    if not project_complete_gates(project_id):
        return False
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        if not proj or proj.status == "completed":
            return False
        proj.status = "completed"
        proj.phase = "done"
        proj.error = None
        db.commit()
    live_log.system(project_id, "项目审计完成（状态门闩满足）")
    return True


def _refresh_project_after_reviewer(project_id: int) -> None:
    """Clear leftover reviewing when the review queue is empty."""
    if _reviewer_has_lab_work(project_id) or _reviewer_has_review_work(project_id):
        return
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        if not proj or proj.status in ("completed", "cancelled", "error", "paused"):
            return
    with _lock:
        fix_busy = bool(_fix_inflight.get(project_id))
        verifier_busy = bool(_verifier_inflight.get(project_id))
    if _maybe_complete_project(
        project_id,
        reviewer_busy=False,
        fix_busy=fix_busy,
        verifier_busy=verifier_busy,
    ):
        return
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        if not proj or proj.status != "reviewing":
            return
        verifier_work = False
        if bool(proj.verifier_enabled):
            verifier_work = (
                db.query(Vuln)
                .filter(
                    Vuln.project_id == project_id,
                    Vuln.verifier_status == "pending",
                    Vuln.status.in_(("confirmed", "static_only")),
                    Vuln.attack_surface == "frontend",
                )
                .count()
                > 0
            )
        proj.status = "auditing"
        proj.phase = "verifier" if verifier_work or verifier_busy else "worker"
        db.commit()


def _ensure_recon(project_id: int, cancel: threading.Event) -> None:
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        if not proj or proj.recon_done or proj.status in ("completed", "cancelled", "error"):
            return
    if _phase_is_paused(project_id, "recon"):
        return
    with _lock:
        t = _recon_threads.get(project_id)
        if t is not None and t.is_alive():
            return
        rt = threading.Thread(
            target=_run_recon,
            args=(project_id,),
            daemon=True,
            name=f"vh-recon-{project_id}",
        )
        _recon_threads[project_id] = rt
        _threads.setdefault(project_id, []).append(rt)
    live_log.system(project_id, "拉起 Recon 线程")
    rt.start()


def _ensure_reviewer(project_id: int, cancel: threading.Event) -> None:
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        if not proj or proj.status in ("completed", "cancelled", "error"):
            return
        pending = (
            db.query(Vuln)
            .filter(Vuln.project_id == project_id, Vuln.status == "pending_review")
            .count()
        )
    if _phase_is_paused(project_id, "reviewer"):
        return
    has_lab_work = _reviewer_has_lab_work(project_id)
    has_review_work = _reviewer_has_review_work(project_id, pending)
    if not has_lab_work and not has_review_work:
        return
    with _lock:
        t = _reviewer_threads.get(project_id)
        if t is not None and t.is_alive():
            return
        rt = threading.Thread(
            target=_run_reviewer_loop,
            args=(project_id,),
            daemon=True,
            name=f"vh-reviewer-{project_id}",
        )
        _reviewer_threads[project_id] = rt
        _threads.setdefault(project_id, []).append(rt)
    live_log.system(project_id, "拉起 Reviewer 线程")
    rt.start()


def _run_reviewer_loop(project_id: int) -> None:
    cancel = _cancel_event(project_id)
    try:
        while not cancel.is_set():
            if not _wait_if_paused(project_id, _loop_cancel(project_id, "reviewer"), "reviewer"):
                break
            try:
                with SessionLocal() as db:
                    proj = db.get(Project, project_id)
                    if not proj or proj.status in ("completed", "cancelled", "error"):
                        return
                    pending = (
                        db.query(Vuln)
                        .filter(Vuln.project_id == project_id, Vuln.status == "pending_review")
                        .count()
                    )
            except OperationalError as e:
                if _is_sqlite_locked(e):
                    cancel.wait(timeout=_DB_LOCK_RETRY_SECONDS)
                    continue
                raise
            if not _reviewer_has_lab_work(project_id) and not _reviewer_has_review_work(project_id, pending):
                _refresh_project_after_reviewer(project_id)
                cancel.wait(timeout=5.0)
                continue
            with _lock:
                _reviewer_inflight[project_id] = True
            try:
                if _next_reviewer_step(project_id, pending) == "lab":
                    _run_reviewer_lab(project_id)
                else:
                    _run_reviewer_once(project_id)
            finally:
                with _lock:
                    _reviewer_inflight[project_id] = False
            _refresh_project_after_reviewer(project_id)
    except Exception as e:  # noqa: BLE001
        live_log.error(project_id, f"Reviewer 线程异常: {e}", phase="reviewer")
        with _lock:
            _reviewer_inflight[project_id] = False


def _ensure_verifier(project_id: int, cancel: threading.Event) -> None:
    from .verifier import is_verifier_enabled, pending_verifier_count

    if not is_verifier_enabled(project_id):
        return
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        if not proj or proj.status in ("completed", "cancelled", "error"):
            return
    if _phase_is_paused(project_id, "verifier"):
        return
    has_work = (
        pending_verifier_count(project_id) > 0
        or bool(list_resumable_runs(project_id, "verifier"))
        or _should_skip_checkpoint(project_id, "verifier")
    )
    if not has_work:
        return
    with _lock:
        t = _verifier_threads.get(project_id)
        if t is not None and t.is_alive():
            return
        vt = threading.Thread(
            target=_run_verifier_loop,
            args=(project_id,),
            daemon=True,
            name=f"vh-verifier-{project_id}",
        )
        _verifier_threads[project_id] = vt
        _threads.setdefault(project_id, []).append(vt)
    live_log.system(project_id, "拉起 Verifier 线程")
    vt.start()


def _run_verifier_loop(project_id: int) -> None:
    from .verifier import is_verifier_enabled, pending_verifier_count

    cancel = _cancel_event(project_id)
    try:
        while not cancel.is_set():
            if not _wait_if_paused(project_id, _loop_cancel(project_id, "verifier"), "verifier"):
                break
            if not is_verifier_enabled(project_id):
                break
            try:
                with SessionLocal() as db:
                    proj = db.get(Project, project_id)
                    if not proj or proj.status in ("completed", "cancelled", "error"):
                        return
                pending = pending_verifier_count(project_id)
            except OperationalError as e:
                if _is_sqlite_locked(e):
                    cancel.wait(timeout=_DB_LOCK_RETRY_SECONDS)
                    continue
                raise
            if (
                pending <= 0
                and not list_resumable_runs(project_id, "verifier")
                and not _should_skip_checkpoint(project_id, "verifier")
            ):
                cancel.wait(timeout=5.0)
                continue
            with _lock:
                _verifier_inflight[project_id] = True
            try:
                _run_verifier_once(project_id)
            finally:
                with _lock:
                    _verifier_inflight[project_id] = False
    except Exception as e:  # noqa: BLE001
        live_log.error(project_id, f"Verifier 线程异常: {e}", phase="verifier")
        with _lock:
            _verifier_inflight[project_id] = False


def _ensure_workers(
    project_id: int,
    active_workers: list[threading.Thread],
) -> list[threading.Thread]:
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        if not proj or proj.status in ("completed", "cancelled", "error"):
            return [t for t in active_workers if t.is_alive()]
        status = proj.status
        heuristic_on = bool(getattr(proj, "heuristic_enabled", True))
        lite = heuristic_lite_active(
            heuristic_enabled=heuristic_on,
            heuristic_lite=bool(getattr(proj, "heuristic_lite", False)),
        )
        q = db.query(FileWeight).filter(
            FileWeight.project_id == project_id,
            FileWeight.weight.isnot(None),
            FileWeight.skipped.is_(False),
            FileWeight.audited.is_(False),
        )
        if lite:
            q = q.filter(FileWeight.weight == HEURISTIC_LITE_WEIGHT)
        unaudited_weighted = q.count()
    if _phase_is_paused(project_id, "worker"):
        return [t for t in active_workers if t.is_alive()]

    alive = [t for t in active_workers if t.is_alive()]
    if not heuristic_on:
        return alive
    # 历史漏洞是启发式线索；LLM + GHSA/Issues 收齐前不拉 Worker。
    if not recon_old_vulns_ready(project_id):
        return alive
    if project_complete_gates(project_id):
        return alive
    if (
        unaudited_weighted <= 0
        and not list_resumable_runs(project_id, "worker")
        and not _pending_inject.get((project_id, "worker"))
        and not _should_skip_checkpoint(project_id, "worker")
    ):
        return alive

    conc = _worker_concurrency(project_id)
    while len(alive) < conc:
        wid = f"worker-{len(alive)+1}-{uuid.uuid4().hex[:6]}"
        wt = threading.Thread(
            target=_run_worker_loop,
            args=(project_id, wid),
            daemon=True,
            name=f"vh-{wid}",
        )
        alive.append(wt)
        with _lock:
            _threads.setdefault(project_id, []).append(wt)
        live_log.system(project_id, f"启动 Worker {wid}")
        wt.start()

    if status == "recon":
        with SessionLocal() as db:
            proj = db.get(Project, project_id)
            if proj and proj.status == "recon":
                proj.status = "auditing"
                db.commit()
    return alive


def _ensure_fast_prepare(project_id: int) -> None:
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        if not proj or not proj.recon_done or not bool(getattr(proj, "fast_enabled", False)):
            return
        if bool(getattr(proj, "fast_queue_frozen", False)):
            return
        if proj.status in ("completed", "cancelled", "error"):
            return
    if _phase_is_paused(project_id, "worker"):
        return
    with _lock:
        t = _fast_prepare_threads.get(project_id)
        if t is not None and t.is_alive():
            return
        rt = threading.Thread(
            target=_run_fast_prepare,
            args=(project_id,),
            daemon=True,
            name=f"vh-fast-prepare-{project_id}",
        )
        _fast_prepare_threads[project_id] = rt
        _threads.setdefault(project_id, []).append(rt)
    live_log.system(project_id, "拉起快速扫描准备（Semgrep + Sink 筛选）", phase="fast-worker")
    rt.start()


def _ensure_fast_workers(
    project_id: int,
    active_workers: list[threading.Thread],
) -> list[threading.Thread]:
    from .sink_queue import fast_path_complete, queue_frozen

    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        if not proj or proj.status in ("completed", "cancelled", "error"):
            return [t for t in active_workers if t.is_alive()]
        fast_on = bool(getattr(proj, "fast_enabled", False))
        heuristic_on = bool(getattr(proj, "heuristic_enabled", True))
        bypass_on = bool(getattr(proj, "bypass_enabled", False))
        status = proj.status
    if _phase_is_paused(project_id, "worker"):
        return [t for t in active_workers if t.is_alive()]
    alive = [t for t in active_workers if t.is_alive()]
    if not fast_on or not queue_frozen(project_id) or fast_path_complete(project_id):
        return alive
    if project_complete_gates(project_id):
        return alive
    conc = 1 if heuristic_on or bypass_on else _worker_concurrency(project_id)
    conc = max(1, conc)
    while len(alive) < conc:
        wid = f"fast-{len(alive)+1}-{uuid.uuid4().hex[:6]}"
        wt = threading.Thread(
            target=_run_fast_worker_loop,
            args=(project_id, wid),
            daemon=True,
            name=f"vh-{wid}",
        )
        alive.append(wt)
        with _lock:
            _threads.setdefault(project_id, []).append(wt)
        live_log.system(project_id, f"启动 Fast Worker {wid}", phase="fast-worker")
        wt.start()
    if status == "recon":
        with SessionLocal() as db:
            proj = db.get(Project, project_id)
            if proj and proj.status == "recon":
                proj.status = "auditing"
                db.commit()
    return alive


def _ensure_bypass_prepare(project_id: int) -> None:
    from .bypass_queue import freeze_bypass_queue

    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        if not proj or not bool(getattr(proj, "bypass_enabled", False)):
            return
        if bool(getattr(proj, "bypass_queue_frozen", False)):
            return
        if proj.status in ("completed", "cancelled", "error"):
            return
    if _phase_is_paused(project_id, "worker"):
        return
    if not recon_old_vulns_ready(project_id):
        return
    queued = freeze_bypass_queue(project_id)
    live_log.system(
        project_id,
        f"历史漏洞绕过队列已冻结，待尝试 {queued} 条",
        phase="bypass-worker",
    )


def _ensure_bypass_workers(
    project_id: int,
    active_workers: list[threading.Thread],
) -> list[threading.Thread]:
    from .bypass_queue import bypass_path_complete, queue_frozen

    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        if not proj or proj.status in ("completed", "cancelled", "error"):
            return [t for t in active_workers if t.is_alive()]
        bypass_on = bool(getattr(proj, "bypass_enabled", False))
        heuristic_on = bool(getattr(proj, "heuristic_enabled", True))
        fast_on = bool(getattr(proj, "fast_enabled", False))
        status = proj.status
    if _phase_is_paused(project_id, "worker"):
        return [t for t in active_workers if t.is_alive()]
    alive = [t for t in active_workers if t.is_alive()]
    if not bypass_on or not queue_frozen(project_id) or bypass_path_complete(project_id):
        return alive
    if project_complete_gates(project_id):
        return alive
    conc = 1 if heuristic_on or fast_on else _worker_concurrency(project_id)
    conc = max(1, conc)
    while len(alive) < conc:
        wid = f"bypass-{len(alive)+1}-{uuid.uuid4().hex[:6]}"
        wt = threading.Thread(
            target=_run_bypass_worker_loop,
            args=(project_id, wid),
            daemon=True,
            name=f"vh-{wid}",
        )
        alive.append(wt)
        with _lock:
            _threads.setdefault(project_id, []).append(wt)
        live_log.system(project_id, f"启动 Bypass Worker {wid}", phase="bypass-worker")
        wt.start()
    if status == "recon":
        with SessionLocal() as db:
            proj = db.get(Project, project_id)
            if proj and proj.status == "recon":
                proj.status = "auditing"
                db.commit()
    return alive


def _orchestrate(project_id: int) -> None:
    from ..models import ensure_schema

    cancel = _cancel_event(project_id)
    try:
        ensure_schema()
    except Exception as e:  # noqa: BLE001
        live_log.error(project_id, f"数据库 schema 初始化失败: {e}")
        return
    live_log.system(project_id, "调度器启动")
    active_workers: list[threading.Thread] = []
    active_fast_workers: list[threading.Thread] = []
    active_bypass_workers: list[threading.Thread] = []
    fix_pool = ThreadPoolExecutor(
        max_workers=_fix_concurrency(),
        thread_name_prefix=f"vh-fix-{project_id}-",
    )
    submitted_fix: set[int] = set()
    with _lock:
        _fix_inflight[project_id] = set()

    try:
        while not cancel.is_set():
            if not _wait_if_paused(project_id, cancel):
                break
            try:
                _release_stale_claims(project_id)
                _maybe_mark_recon_done(project_id)

                with SessionLocal() as db:
                    proj = db.get(Project, project_id)
                    if not proj or proj.status in ("completed", "cancelled", "error"):
                        break

                if not recon_gates_met(project_id):
                    with SessionLocal() as db:
                        proj = db.get(Project, project_id)
                        if proj and not proj.recon_done:
                            _ensure_recon(project_id, cancel)

                returned_ids: list[int] = []
                pending_vulns = 0
                with SessionLocal() as db:
                    pending_vulns = (
                        db.query(Vuln)
                        .filter(Vuln.project_id == project_id, Vuln.status == "pending_review")
                        .count()
                    )
                    returned = (
                        db.query(Vuln)
                        .filter(Vuln.project_id == project_id, Vuln.status == "returned")
                        .all()
                    )
                    returned_ids = [v.id for v in returned]
                    for v in returned:
                        v.status = "fixing"
                    if returned:
                        db.commit()
                for vid in resumable_vuln_ids(project_id, "fix"):
                    if vid not in returned_ids:
                        returned_ids.append(vid)

                active_workers = _ensure_workers(project_id, active_workers)
                _ensure_fast_prepare(project_id)
                active_fast_workers = _ensure_fast_workers(project_id, active_fast_workers)
                _ensure_bypass_prepare(project_id)
                active_bypass_workers = _ensure_bypass_workers(project_id, active_bypass_workers)

                for vid in returned_ids:
                    if _phase_is_paused(project_id, "worker"):
                        break
                    if vid in submitted_fix:
                        continue
                    submitted_fix.add(vid)
                    with _lock:
                        _fix_inflight.setdefault(project_id, set()).add(vid)

                    def _fix_done(fut, vid=vid):  # noqa: ANN001
                        with _lock:
                            _fix_inflight.get(project_id, set()).discard(vid)
                            submitted_fix.discard(vid)

                    fut = fix_pool.submit(_run_fix, project_id, vid)
                    fut.add_done_callback(_fix_done)

                _ensure_reviewer(project_id, cancel)
                _ensure_verifier(project_id, cancel)
                _refresh_project_after_reviewer(project_id)

                with _lock:
                    fix_busy = bool(_fix_inflight.get(project_id))
                    reviewer_busy = bool(_reviewer_inflight.get(project_id))
                    verifier_busy = bool(_verifier_inflight.get(project_id))

                if _maybe_complete_project(
                    project_id,
                    reviewer_busy=reviewer_busy,
                    fix_busy=fix_busy,
                    verifier_busy=verifier_busy,
                ):
                    break

                with SessionLocal() as db:
                    proj = db.get(Project, project_id)
                    if proj and proj.status == "completed":
                        break
            except Exception as e:  # noqa: BLE001
                live_log.error(project_id, f"调度器异常（将继续）: {e}")
            cancel.wait(timeout=2.0)
    finally:
        fix_pool.shutdown(wait=False, cancel_futures=True)
        live_log.system(project_id, "调度器退出")


def _run_recon(project_id: int) -> None:
    """Run recon sub-phases strictly in series: map/auth → source-ext → old vulns → mark."""
    cancel = _cancel_event(project_id)
    try:
        if _maybe_mark_recon_done(project_id):
            return
        if recon_map_ready(project_id):
            _finish_resumable_phase(project_id, "recon")
        elif not _run_recon_map(project_id, cancel):
            return
        if cancel.is_set():
            return
        if recon_source_ext_ready(project_id):
            _finish_resumable_phase(project_id, "recon-source-ext")
        elif not _run_recon_source_ext(project_id, cancel):
            return
        if cancel.is_set():
            return
        if recon_old_vulns_ready(project_id):
            _finish_resumable_phase(project_id, "recon-old-vuln")
            _finish_resumable_phase(project_id, "recon-old-vuln-ghsa")
        elif not _run_recon_old_vulns(project_id, cancel):
            return
        if cancel.is_set():
            return
        if _maybe_mark_recon_done(project_id):
            live_log.system(project_id, "Recon 完成")
            return
        _run_recon_marking(project_id, cancel)
        if _maybe_mark_recon_done(project_id):
            live_log.system(project_id, "Recon 完成")
    except Exception as e:  # noqa: BLE001
        live_log.error(project_id, f"Recon 线程异常: {e}", phase="recon")


def _finish_resumable_phase(project_id: int, phase: str) -> None:
    for pr in list_resumable_runs(project_id, phase):
        _finish_phase_run(pr.id, "completed")


def _run_recon_map(project_id: int, cancel: threading.Event) -> bool:
    return _run_recon_gated_session(
        project_id,
        cancel,
        phase="recon",
        role="recon",
        prompt_name="recon.md",
        ready=lambda: recon_map_ready(project_id),
        initial_doc="recon.md",
        retry_loop_doc="recon-retry-loop.md",
        retry_timeout_doc="recon-retry-timeout.md",
        retry_other_doc="recon-retry-other.md",
        done_log="代码地图与鉴权文档已就绪，进入扩展名检查",
        fail_error="recon 地图/鉴权会话未在重试上限内完成",
        fail_status="Recon 地图/鉴权未完成，将自动再拉起",
        fail_log="Recon 地图/鉴权会话重试用尽，等待调度器再拉起",
    )


def _run_recon_map_refresh(project_id: int, cancel: threading.Event) -> bool:
    """Re-run map/auth with existing docs kept; FinishReconMap ends the session."""
    begin_map_refresh(project_id)
    try:
        return _run_recon_gated_session(
            project_id,
            cancel,
            phase="recon",
            role="recon",
            prompt_name="recon.md",
            ready=lambda: recon_map_refresh_ready(project_id),
            initial_doc="recon-map-refresh.md",
            retry_loop_doc="recon-map-refresh-retry-loop.md",
            retry_timeout_doc="recon-map-refresh-retry-timeout.md",
            retry_other_doc="recon-map-refresh-retry-other.md",
            done_log="代码地图与鉴权文档已更新",
            fail_error="recon 地图/鉴权会话未在重试上限内完成",
            fail_status="Recon 地图/鉴权未完成，将自动再拉起",
            fail_log="Recon 地图/鉴权会话重试用尽，等待调度器再拉起",
            extra_label="代码地图/鉴权",
        )
    finally:
        clear_map_refresh(project_id)


def _old_vuln_crawl_prompt_vars(result) -> dict:
    ghsa_error = f"；爬虫警告：{result.error}" if result.error else ""
    return {
        "ghsa_count": result.ghsa_count,
        "issues_count": result.issue_count,
        "issues_repo": result.repo or "无",
        "keyword": result.keyword or "无",
        "ghsa_error": ghsa_error,
    }


def _run_recon_old_vulns(project_id: int, cancel: threading.Event) -> bool:
    if recon_old_vuln_llm_ready(project_id):
        _finish_resumable_phase(project_id, "recon-old-vuln")
    elif not _run_recon_old_vuln_crawl_pass(project_id, cancel):
        return False
    if cancel.is_set():
        return False
    if recon_old_vulns_ready(project_id):
        _finish_resumable_phase(project_id, "recon-old-vuln-ghsa")
        return True
    return _run_recon_old_vuln_ghsa(project_id, cancel)


def _run_recon_old_vuln_crawl_pass(project_id: int, cancel: threading.Event) -> bool:
    from .old_vuln_crawl import run_old_vuln_ghsa_crawl

    result = run_old_vuln_ghsa_crawl(project_id)
    if cancel.is_set():
        return False
    return _run_recon_gated_session(
        project_id,
        cancel,
        phase="recon-old-vuln",
        role="recon_old_vuln",
        prompt_name="recon-old-vuln.md",
        ready=lambda: recon_old_vuln_llm_ready(project_id),
        initial_doc="recon-old-vuln.md",
        retry_loop_doc="recon-old-vuln-retry-loop.md",
        retry_timeout_doc="recon-old-vuln-retry-timeout.md",
        retry_other_doc="recon-old-vuln-retry-other.md",
        done_log="历史漏洞爬虫核验已结束，进入 WebSearch 补漏",
        fail_error="recon 历史漏洞爬虫落盘未在重试上限内完成",
        fail_status="Recon 历史漏洞爬虫落盘未完成，将自动再拉起",
        fail_log="Recon 历史漏洞爬虫落盘重试用尽，等待调度器再拉起",
        extra_label="历史漏洞/爬虫落盘",
        prompt_vars=_old_vuln_crawl_prompt_vars(result),
    )


def _run_recon_old_vuln_ghsa(project_id: int, cancel: threading.Event) -> bool:
    return _run_recon_gated_session(
        project_id,
        cancel,
        phase="recon-old-vuln-ghsa",
        role="recon_old_vuln_ghsa",
        prompt_name="recon-old-vuln-ghsa.md",
        ready=lambda: recon_old_vulns_ready(project_id),
        initial_doc="recon-old-vuln-ghsa.md",
        retry_loop_doc="recon-old-vuln-ghsa-retry-loop.md",
        retry_timeout_doc="recon-old-vuln-ghsa-retry-timeout.md",
        retry_other_doc="recon-old-vuln-ghsa-retry-other.md",
        done_log="历史漏洞 WebSearch 补漏已结束，进入盖章轮",
        fail_error="recon 历史漏洞 WebSearch 补漏未在重试上限内完成",
        fail_status="Recon 历史漏洞 WebSearch 补漏未完成，将自动再拉起",
        fail_log="Recon 历史漏洞 WebSearch 补漏重试用尽，等待调度器再拉起",
        extra_label="历史漏洞/搜索补漏",
    )


def _run_recon_source_ext(project_id: int, cancel: threading.Event) -> bool:
    return _run_recon_gated_session(
        project_id,
        cancel,
        phase="recon-source-ext",
        role="recon_source_ext",
        prompt_name="recon-source-ext.md",
        ready=lambda: recon_source_ext_ready(project_id),
        initial_doc="recon-source-ext.md",
        retry_loop_doc="recon-source-ext-retry-loop.md",
        retry_timeout_doc="recon-source-ext-retry-timeout.md",
        retry_other_doc="recon-source-ext-retry-other.md",
        done_log="额外源码扩展名已确认，进入历史漏洞会话",
        fail_error="recon 扩展名会话未在重试上限内完成",
        fail_status="Recon 扩展名检查未完成，将自动再拉起",
        fail_log="Recon 扩展名会话重试用尽，等待调度器再拉起",
    )


def _run_recon_gated_session(
    project_id: int,
    cancel: threading.Event,
    *,
    phase: str,
    role: str,
    prompt_name: str,
    ready,
    initial_doc: str,
    retry_loop_doc: str,
    retry_timeout_doc: str,
    retry_other_doc: str,
    done_log: str,
    fail_error: str,
    fail_status: str,
    fail_log: str,
    extra_label: str | None = None,
    prompt_vars: dict[str, Any] | None = None,
) -> bool:
    system = load_prompt(prompt_name)
    vars_ = {"project_id": project_id, **(prompt_vars or {})}
    user = _prompt_with_summary(phase, project_id, _initial_prompt(initial_doc, **vars_))
    cp = _adopt_resumable(project_id, phase)
    run_id = cp.phase_run_id if cp else _new_phase_run(project_id, phase, role)
    resumes = 0
    used_checkpoint = False
    llm = resolve_llm("recon", project_id=project_id)
    try:
        while resumes <= settings.recon_max_resumes and not cancel.is_set():
            if not _wait_if_paused(project_id, _loop_cancel(project_id, "recon"), "recon"):
                _finish_phase_run(run_id, "cancelled")
                return False
            if ready():
                _finish_phase_run(run_id, "completed")
                live_log.system(project_id, done_log, phase=phase, role=role)
                return True
            if cp and not used_checkpoint:
                loop = _loop_from_checkpoint(
                    cp,
                    cancel=cancel,
                    stop_when=lambda st: ready(),
                    timeout_sec=settings.timeout_recon,
                    llm=llm,
                )
                used_checkpoint = True
            else:
                _consume_force_new(project_id, "recon")
                extra = extra_label or {
                    "recon-old-vuln": "历史漏洞/爬虫落盘",
                    "recon_old_vuln": "历史漏洞/爬虫落盘",
                    "recon-old-vuln-ghsa": "历史漏洞/搜索补漏",
                    "recon_old_vuln_ghsa": "历史漏洞/搜索补漏",
                    "recon-source-ext": "扩展名",
                    "recon_source_ext": "扩展名",
                }.get(phase, "代码地图/鉴权")
                if resumes:
                    extra = f"{extra} 重试 {resumes}/{settings.recon_max_resumes}"
                _start_log_session(project_id, phase, extra, role=role)
                loop = AgentLoop(
                    project_id=project_id,
                    role=role,
                    phase=phase,
                    system_prompt=system,
                    user_prompt=user,
                    phase_run_id=run_id,
                    cancel_event=_loop_cancel(project_id, "recon"),
                    pause_event=_combined_pause(project_id, "recon"),
                    timeout_sec=settings.timeout_recon,
                    context_window=_context_window(),
                    stop_when=lambda st: ready(),
                    llm=llm,
                )
            result = loop.run()
            if result.stop_reason == "auth_error":
                _pause_for_auth(project_id, result.error or "auth_error")
                return False
            if result.cancelled:
                _finish_phase_run(run_id, "cancelled")
                return False
            if _should_skip_checkpoint(project_id, "recon"):
                _finish_phase_run(run_id, "cancelled", "用户新跑")
                return False
            if ready():
                _finish_phase_run(run_id, "completed")
                live_log.system(project_id, done_log, phase=phase, role=role)
                return True
            resumes += 1
            if result.loop_aborted:
                user = _prompt_with_summary(phase, project_id, _initial_prompt(retry_loop_doc, **vars_))
                live_log.system(
                    project_id,
                    f"Recon {phase} 新开重试 {resumes}/{settings.recon_max_resumes}",
                    phase=phase,
                    role=role,
                )
            elif result.timed_out:
                user = _prompt_with_summary(
                    phase, project_id, _initial_prompt(retry_timeout_doc, **vars_)
                )
            else:
                user = _prompt_with_summary(
                    phase,
                    project_id,
                    _initial_prompt(
                        retry_other_doc,
                        stop_reason=result.stop_reason,
                        error=result.error,
                        **vars_,
                    ),
                )
            if resumes > settings.recon_max_resumes:
                break
        _finish_phase_run(run_id, "failed", error=fail_error)
        with SessionLocal() as db:
            proj = db.get(Project, project_id)
            if proj and not proj.recon_done:
                proj.error = fail_status
                db.commit()
        live_log.system(project_id, fail_log, phase=phase, role=role)
        return False
    finally:
        if cp:
            _release_adopted(project_id, cp.phase_run_id)


def _run_recon_marking(project_id: int, cancel: threading.Event) -> None:
    system = load_prompt("recon-mark.md")
    llm = resolve_llm("recon", project_id=project_id)
    batch_size = max(1, int(settings.recon_mark_batch_size))
    while not cancel.is_set():
        if not _wait_if_paused(project_id, _loop_cancel(project_id, "recon"), "recon"):
            return
        if recon_gates_met(project_id):
            return
        cp = _adopt_resumable(project_id, "recon-mark")
        if cp:
            try:
                paths = [str(p) for p in (cp.state.get("mark_paths") or []) if p]
                loop = _loop_from_checkpoint(
                    cp,
                    cancel=cancel,
                    stop_when=lambda st, batch=list(paths): (
                        paths_fully_marked(project_id, batch) if batch else recon_gates_met(project_id)
                    ),
                    timeout_sec=settings.timeout_recon_mark_round,
                    llm=llm,
                )
                result = loop.run()
                if result.stop_reason == "auth_error":
                    _pause_for_auth(project_id, result.error or "auth_error")
                    return
                if result.cancelled:
                    _finish_phase_run(cp.phase_run_id, "cancelled")
                    return
                done = bool(paths) and paths_fully_marked(project_id, paths)
                _finish_phase_run(
                    cp.phase_run_id,
                    "completed" if done else "failed",
                    None if done else (result.error or result.stop_reason),
                )
            finally:
                _release_adopted(project_id, cp.phase_run_id)
            continue
        batch = pick_unmarked_batch(project_id, batch_size)
        if not batch:
            return
        status = recon_gates_status(project_id)
        unmarked = int(status.get("unmarked") or 0)
        total = int(status.get("total") or 0)
        marked = max(0, total - unmarked)
        lines = "\n".join(f"- {p}" for p in batch)
        user = _initial_prompt(
            "recon-mark.md",
            project_id=project_id,
            marked=marked,
            total=total,
            batch_count=len(batch),
            paths=lines,
        )
        run_id = _new_phase_run(project_id, "recon-mark", "recon_mark")
        _consume_force_new(project_id, "recon")
        _start_log_session(
            project_id,
            "recon-mark",
            extra=f"盖章 {len(batch)} 个文件，剩余 {unmarked}",
            role="recon_mark",
        )
        loop = AgentLoop(
            project_id=project_id,
            role="recon_mark",
            phase="recon-mark",
            system_prompt=system,
            user_prompt=user,
            phase_run_id=run_id,
            cancel_event=_loop_cancel(project_id, "recon"),
            pause_event=_combined_pause(project_id, "recon"),
            timeout_sec=settings.timeout_recon_mark_round,
            context_window=_context_window(),
            stop_when=lambda st, paths=list(batch): paths_fully_marked(project_id, paths),
            llm=llm,
        )
        loop.state["mark_paths"] = list(batch)
        result = loop.run()
        if result.stop_reason == "auth_error":
            _pause_for_auth(project_id, result.error or "auth_error")
            return
        if result.cancelled:
            _finish_phase_run(run_id, "cancelled")
            return
        done = paths_fully_marked(project_id, batch)
        _finish_phase_run(
            run_id,
            "completed" if done else ("cancelled" if result.cancelled else "failed"),
            None if done else (result.error or result.stop_reason),
        )
        if done:
            live_log.system(
                project_id,
                f"侦察盖章轮完成：{len(batch)} 个文件",
                phase="recon-mark",
                role="recon_mark",
            )
        else:
            live_log.system(
                project_id,
                f"侦察盖章轮未完成（{result.stop_reason}），未标记文件将在下一轮再注入",
                phase="recon-mark",
                role="recon_mark",
            )


def _finish_worker_round(
    project_id: int,
    worker_id: str,
    path: str | None,
    run_id: int,
    result,
) -> str:
    """Return next | interrupt | cancel | restart after a worker AgentLoop ends."""
    if result.stop_reason == "auth_error":
        _pause_for_auth(project_id, result.error or "auth_error")
        return "interrupt"
    phase_restart = bool(result.cancelled) and not _cancel_event(project_id).is_set()
    failed = not (result.ok and result.state.get("round_finished"))
    if path and not phase_restart:
        _release_claim_if_unfinished(project_id, path, worker_id, failed=failed)
    _finish_phase_run(
        run_id,
        "completed" if result.ok else ("cancelled" if result.cancelled else "failed"),
        "用户新跑" if phase_restart else result.error,
    )
    if result.cancelled and _cancel_event(project_id).is_set():
        return "cancel"
    if phase_restart:
        return "restart"
    return "next"


def _round_report_exists(project_id: int, n: int) -> bool:
    path = workspace_dir(project_id) / "rounds" / f"round-{n}.md"
    return path.is_file() and path.stat().st_size > 0


def _next_worker_round_id(project_id: int) -> int:
    """Next FinishRound file index. Never reuse an existing round-N.md.

    Number from files on disk, not live-log session. After reset-progress the
    reports are deleted but worker/round-N.jsonl pages keep counting; tying the
    two wrote round-28.md as the first post-reset mining report.
    """
    return max_round_report_no(project_id) + 1


def _bind_worker_round_id(loop: AgentLoop, project_id: int, *, new_round: bool) -> int:
    if new_round:
        n = _next_worker_round_id(project_id)
    else:
        existing = int((loop.state or {}).get("round_id") or 0)
        if existing > 0 and not _round_report_exists(project_id, existing):
            n = existing
        else:
            n = _next_worker_round_id(project_id)
    loop.state["round_id"] = n
    return n


def _run_worker_loop(project_id: int, worker_id: str) -> None:
    cancel = _cancel_event(project_id)
    current_run_id: int | None = None
    try:
        while not cancel.is_set():
            if not _wait_if_paused(project_id, _loop_cancel(project_id, "worker"), "worker"):
                break
            with SessionLocal() as db:
                proj = db.get(Project, project_id)
                if not proj or proj.status in ("completed", "cancelled", "error"):
                    return
            if not recon_old_vulns_ready(project_id):
                cancel.wait(timeout=5.0)
                continue
            if heuristic_complete(project_id) and not _pending_inject.get((project_id, "worker")):
                cancel.wait(timeout=5.0)
                continue

            cp = _adopt_resumable(project_id, "worker", worker_id=worker_id)
            if cp:
                path = cp.file_path
                if path:
                    _reclaim_file(project_id, path, worker_id)
                current_run_id = cp.phase_run_id
                try:
                    loop = _loop_from_checkpoint(
                        cp,
                        cancel=cancel,
                        stop_when=lambda st: bool(st.get("round_finished")),
                        timeout_sec=settings.timeout_worker_round,
                    )
                    loop.worker_id = worker_id
                    _bind_worker_round_id(loop, project_id, new_round=False)
                    result = loop.run()
                    action = _finish_worker_round(
                        project_id, worker_id, path, cp.phase_run_id, result
                    )
                    if action in ("interrupt", "cancel"):
                        return
                    if action == "restart":
                        continue
                finally:
                    _release_adopted(project_id, cp.phase_run_id)
                    current_run_id = None
                continue

            fw = _take_inject_file(project_id, worker_id) or _pick_next_file(project_id, worker_id)
            if fw is None:
                cancel.wait(timeout=5.0)
                continue

            sources = _sources_for_file(project_id, fw.path)
            snippet = _read_file_snippet(project_id, fw.path)
            system = _phase_system_prompt(project_id, "worker.md")
            run_id = _new_phase_run(
                project_id, "worker", "worker", worker_id=worker_id, file_path=fw.path
            )
            current_run_id = run_id
            _consume_force_new(project_id, "worker")
            _start_log_session(project_id, "worker", extra=fw.path)
            round_id = _next_worker_round_id(project_id)
            body = _initial_prompt(
                "worker.md",
                worker_id=worker_id,
                round_id=round_id,
                file_path=fw.path,
                weight=fw.weight,
                has_source=fw.has_source,
                sources=", ".join(sources) if sources else "（无）",
                snippet=snippet,
                **_audit_mode_vars(project_id),
            )
            user = _prompt_with_summary("worker", project_id, body, for_file=True)
            loop = AgentLoop(
                project_id=project_id,
                role="worker",
                phase="worker",
                system_prompt=system,
                user_prompt=user,
                phase_run_id=run_id,
                worker_id=worker_id,
                cancel_event=_loop_cancel(project_id, "worker"),
                pause_event=_combined_pause(project_id, "worker"),
                timeout_sec=settings.timeout_worker_round,
                context_window=_context_window(),
                stop_when=lambda st: bool(st.get("round_finished")),
                file_path=fw.path,
            )
            loop.state["round_id"] = round_id
            result = loop.run()
            action = _finish_worker_round(project_id, worker_id, fw.path, run_id, result)
            current_run_id = None
            if action in ("interrupt", "cancel"):
                return
            if action == "restart":
                continue
    except Exception as e:  # noqa: BLE001
        live_log.error(project_id, f"Worker={worker_id} 异常: {e}", phase="worker")
        try:
            if current_run_id:
                _finish_phase_run(current_run_id, "failed", str(e))
            _release_claims(project_id, worker_id=worker_id)
        except Exception:  # noqa: BLE001
            pass


def _indexed_extensions(project_id: int) -> list[str]:
    with SessionLocal() as db:
        rows = db.query(FileWeight.path).filter(FileWeight.project_id == project_id).all()
    exts: set[str] = set()
    for (path,) in rows:
        suffix = Path(str(path or "")).suffix.lower()
        if suffix:
            exts.add(suffix)
    return sorted(exts)


def _nearby_sources(project_id: int, file_path: str) -> str:
    parent = str(Path(file_path).parent).replace("\\", "/")
    with SessionLocal() as db:
        rows = db.query(Source).filter(Source.project_id == project_id).all()
        same = [r for r in rows if r.file_path.replace("\\", "/") == file_path]
        nearby = [
            r
            for r in rows
            if r not in same and str(Path(r.file_path).parent).replace("\\", "/") == parent
        ]
    lines = [f"- {r.file_path} :: {r.method_name}" for r in (same + nearby)[:20]]
    return "\n".join(lines) if lines else "（附近无 Recon Source）"


def _format_sink_cards(rows) -> str:
    from .sink_queue import sink_card

    parts = []
    for row in rows:
        card = sink_card(row)
        parts.append(
            f"id={card['id']} {card['file_path']}:{card['line_start']} "
            f"sev={card['severity']} conf={card['confidence']} type={card['mapped_vuln_type']} "
            f"score={card['code_score']} rules={','.join(card['check_ids'])}\n"
            f"{(card['snippet'] or '')[:400]}"
        )
    return "\n\n".join(parts)


def _run_fast_prepare(project_id: int) -> None:
    from .semgrep_scan import SemgrepUnavailable, language_configs, run_semgrep_scan
    from .sink_queue import (
        freeze_audit_queue,
        freeze_empty_queue,
        ingest_semgrep_results,
        load_undecided_candidates,
        queue_frozen,
    )

    cancel = _cancel_event(project_id)
    try:
        if queue_frozen(project_id) or cancel.is_set():
            return
        with SessionLocal() as db:
            proj = db.get(Project, project_id)
            if not proj or not proj.fast_enabled:
                return
            heuristic_on = bool(proj.heuristic_enabled)
            bypass_on = bool(getattr(proj, "bypass_enabled", False))
            bounty = is_bounty_mode(proj.audit_mode)
        try:
            configs = language_configs(_indexed_extensions(project_id))
            live_log.system(
                project_id,
                f"开始 Semgrep 扫描（{' '.join('--config ' + c for c in configs)}）",
                phase="fast-worker",
            )
            payload = run_semgrep_scan(project_id, configs=configs)
        except SemgrepUnavailable as exc:
            live_log.error(project_id, str(exc), phase="fast-worker")
            if heuristic_on or bypass_on:
                freeze_empty_queue(project_id)
                live_log.system(project_id, "快速扫描跳过：无 Semgrep，其他挖掘路径继续", phase="fast-worker")
                return
            with SessionLocal() as db:
                proj = db.get(Project, project_id)
                if proj:
                    proj.status = "error"
                    proj.error = str(exc)
                    db.commit()
            return
        except Exception as exc:  # noqa: BLE001
            live_log.error(project_id, f"Semgrep 失败: {exc}", phase="fast-worker")
            if heuristic_on or bypass_on:
                freeze_empty_queue(project_id)
                return
            with SessionLocal() as db:
                proj = db.get(Project, project_id)
                if proj:
                    proj.status = "error"
                    proj.error = f"Semgrep 失败: {exc}"
                    db.commit()
            return

        n = ingest_semgrep_results(project_id, payload, bounty=bounty)
        live_log.system(project_id, f"代码筛后候选 Sink {n} 条", phase="fast-worker")
        if n <= 0:
            freeze_empty_queue(project_id)
            return

        while not cancel.is_set() and not _phase_is_paused(project_id, "worker"):
            batch = load_undecided_candidates(project_id, limit=30)
            if not batch:
                break
            if not _wait_if_paused(project_id, _loop_cancel(project_id, "worker"), "worker"):
                return
            cards = _format_sink_cards(batch)
            system = _phase_system_prompt(project_id, "sink_triage.md")
            run_id = _new_phase_run(project_id, "sink-triage", "sink_triage")
            _start_log_session(project_id, "sink-triage", extra=f"{len(batch)} sinks")
            body = _initial_prompt(
                "sink_triage.md",
                batch_count=len(batch),
                cards=cards,
                **_audit_mode_vars(project_id),
            )
            user = _prompt_with_summary("sink-triage", project_id, body)
            loop = AgentLoop(
                project_id=project_id,
                role="sink_triage",
                phase="sink-triage",
                system_prompt=system,
                user_prompt=user,
                phase_run_id=run_id,
                cancel_event=_loop_cancel(project_id, "worker"),
                pause_event=_combined_pause(project_id, "worker"),
                timeout_sec=settings.timeout_sink_triage,
                context_window=_context_window(),
                stop_when=lambda st: bool(st.get("triage_batch_finished")),
            )
            loop.state["triage_batch_ids"] = [row.id for row in batch]
            result = loop.run()
            _finish_phase_run(
                run_id,
                "completed" if result.state.get("triage_batch_finished") else ("cancelled" if result.cancelled else "failed"),
                result.error,
            )
            if result.stop_reason == "auth_error":
                _pause_for_auth(project_id, result.error or "auth_error")
                return
            if not result.state.get("triage_batch_finished"):
                live_log.system(project_id, "Sink 筛选本批未完成，按代码分冻结队列", phase="sink-triage")
                break

        queued = freeze_audit_queue(project_id)
        live_log.system(project_id, f"快速扫描队列已冻结，待审计 Sink {queued} 条", phase="fast-worker")
    except Exception as e:  # noqa: BLE001
        live_log.error(project_id, f"快速扫描准备异常: {e}", phase="fast-worker")
        with SessionLocal() as db:
            proj = db.get(Project, project_id)
            if proj and proj.fast_enabled and not proj.heuristic_enabled and not getattr(proj, "bypass_enabled", False):
                proj.status = "error"
                proj.error = f"快速扫描准备失败: {e}"
                db.commit()
            elif proj and proj.fast_enabled:
                freeze_empty_queue(project_id)


def _next_fast_round_id(project_id: int) -> int:
    return max_fast_round_report_no(project_id) + 1


def _finish_fast_round(project_id: int, worker_id: str, sink_id: int | None, run_id: int, result) -> str:
    from .sink_queue import release_sink_claim

    if result.stop_reason == "auth_error":
        _pause_for_auth(project_id, result.error or "auth_error")
        return "interrupt"
    phase_restart = bool(result.cancelled) and not _cancel_event(project_id).is_set()
    finished = bool(result.state.get("sink_finished"))
    if sink_id and not finished and not phase_restart:
        release_sink_claim(project_id, sink_id, worker_id)
    if finished and sink_id:
        with SessionLocal() as db:
            row = db.get(Sink, sink_id)
            if row:
                _fast_last_dir[project_id] = str(Path(row.file_path).parent).replace("\\", "/")
    _finish_phase_run(
        run_id,
        "completed" if result.ok else ("cancelled" if result.cancelled else "failed"),
        "用户新跑" if phase_restart else result.error,
    )
    if result.cancelled and _cancel_event(project_id).is_set():
        return "cancel"
    if phase_restart:
        return "restart"
    return "next"


def _run_fast_worker_loop(project_id: int, worker_id: str) -> None:
    from .sink_queue import (
        fast_path_complete,
        parse_sink_ref,
        pick_next_sink,
        reclaim_sink,
        sink_card,
        sink_ref,
    )

    cancel = _cancel_event(project_id)
    current_run_id: int | None = None
    try:
        while not cancel.is_set():
            if not _wait_if_paused(project_id, _loop_cancel(project_id, "worker"), "worker"):
                break
            with SessionLocal() as db:
                proj = db.get(Project, project_id)
                if not proj or proj.status in ("completed", "cancelled", "error"):
                    return
            if fast_path_complete(project_id):
                cancel.wait(timeout=5.0)
                continue

            cp = _adopt_resumable(project_id, "fast-worker", worker_id=worker_id)
            if cp:
                sink_id = parse_sink_ref(cp.file_path)
                if sink_id:
                    reclaim_sink(project_id, sink_id, worker_id)
                current_run_id = cp.phase_run_id
                try:
                    loop = _loop_from_checkpoint(
                        cp,
                        cancel=cancel,
                        stop_when=lambda st: bool(st.get("sink_finished")),
                        timeout_sec=settings.timeout_worker_round,
                    )
                    loop.worker_id = worker_id
                    if not int((loop.state or {}).get("round_id") or 0):
                        loop.state["round_id"] = _next_fast_round_id(project_id)
                    result = loop.run()
                    action = _finish_fast_round(project_id, worker_id, sink_id, cp.phase_run_id, result)
                    if action in ("interrupt", "cancel"):
                        return
                    if action == "restart":
                        continue
                finally:
                    _release_adopted(project_id, cp.phase_run_id)
                    current_run_id = None
                continue

            row = pick_next_sink(project_id, worker_id, prefer_dir=_fast_last_dir.get(project_id))
            if row is None:
                cancel.wait(timeout=5.0)
                continue
            card = sink_card(row)
            system = _phase_system_prompt(project_id, "fast_worker.md")
            run_id = _new_phase_run(
                project_id, "fast-worker", "fast_worker", worker_id=worker_id, file_path=sink_ref(row.id)
            )
            current_run_id = run_id
            _consume_force_new(project_id, "worker")
            _start_log_session(project_id, "fast-worker", extra=f"{row.file_path}:{row.line_start}")
            round_id = _next_fast_round_id(project_id)
            body = _initial_prompt(
                "fast_worker.md",
                worker_id=worker_id,
                round_id=round_id,
                sink_id=row.id,
                file_path=row.file_path,
                line_start=row.line_start,
                line_end=row.line_end,
                severity=row.severity,
                confidence=row.confidence,
                mapped_vuln_type=row.mapped_vuln_type,
                code_score=row.code_score,
                check_ids=", ".join(card.get("check_ids") or []),
                snippet=row.snippet or "",
                nearby_sources=_nearby_sources(project_id, row.file_path),
                **_audit_mode_vars(project_id),
            )
            user = _prompt_with_summary("fast-worker", project_id, body, for_file=True)
            prior = inject_fast_prior_block(project_id)
            if prior:
                user = f"{prior}{user}"
            loop = AgentLoop(
                project_id=project_id,
                role="fast_worker",
                phase="fast-worker",
                system_prompt=system,
                user_prompt=user,
                phase_run_id=run_id,
                worker_id=worker_id,
                cancel_event=_loop_cancel(project_id, "worker"),
                pause_event=_combined_pause(project_id, "worker"),
                timeout_sec=settings.timeout_worker_round,
                context_window=_context_window(),
                stop_when=lambda st: bool(st.get("sink_finished")),
                file_path=sink_ref(row.id),
            )
            loop.state["round_id"] = round_id
            loop.state["sink_id"] = row.id
            loop.state["injected_sink"] = sink_ref(row.id)
            result = loop.run()
            action = _finish_fast_round(project_id, worker_id, row.id, run_id, result)
            current_run_id = None
            if action in ("interrupt", "cancel"):
                return
            if action == "restart":
                continue
    except Exception as e:  # noqa: BLE001
        live_log.error(project_id, f"Fast Worker={worker_id} 异常: {e}", phase="fast-worker")
        try:
            if current_run_id:
                _finish_phase_run(current_run_id, "failed", str(e))
        except Exception:  # noqa: BLE001
            pass


def _next_bypass_round_id(project_id: int) -> int:
    return max_bypass_round_report_no(project_id) + 1


def _finish_bypass_round(project_id: int, worker_id: str, bypass_id: int | None, run_id: int, result) -> str:
    from .bypass_queue import release_bypass_claim

    if result.stop_reason == "auth_error":
        _pause_for_auth(project_id, result.error or "auth_error")
        return "interrupt"
    phase_restart = bool(result.cancelled) and not _cancel_event(project_id).is_set()
    finished = bool(result.state.get("bypass_finished"))
    if bypass_id and not finished and not phase_restart:
        release_bypass_claim(project_id, bypass_id, worker_id)
    _finish_phase_run(
        run_id,
        "completed" if result.ok else ("cancelled" if result.cancelled else "failed"),
        "用户新跑" if phase_restart else result.error,
    )
    if result.cancelled and _cancel_event(project_id).is_set():
        return "cancel"
    if phase_restart:
        return "restart"
    return "next"


def _run_bypass_worker_loop(project_id: int, worker_id: str) -> None:
    from .bypass_queue import (
        bypass_path_complete,
        bypass_ref,
        load_bypass_doc,
        parse_bypass_ref,
        pick_next_bypass,
        reclaim_bypass,
    )

    cancel = _cancel_event(project_id)
    current_run_id: int | None = None
    try:
        while not cancel.is_set():
            if not _wait_if_paused(project_id, _loop_cancel(project_id, "worker"), "worker"):
                break
            with SessionLocal() as db:
                proj = db.get(Project, project_id)
                if not proj or proj.status in ("completed", "cancelled", "error"):
                    return
            if bypass_path_complete(project_id):
                cancel.wait(timeout=5.0)
                continue

            cp = _adopt_resumable(project_id, "bypass-worker", worker_id=worker_id)
            if cp:
                bypass_id = parse_bypass_ref(cp.file_path)
                if bypass_id:
                    reclaim_bypass(project_id, bypass_id, worker_id)
                current_run_id = cp.phase_run_id
                try:
                    loop = _loop_from_checkpoint(
                        cp,
                        cancel=cancel,
                        stop_when=lambda st: bool(st.get("bypass_finished")),
                        timeout_sec=settings.timeout_worker_round,
                    )
                    loop.worker_id = worker_id
                    if not int((loop.state or {}).get("round_id") or 0):
                        loop.state["round_id"] = _next_bypass_round_id(project_id)
                    result = loop.run()
                    action = _finish_bypass_round(project_id, worker_id, bypass_id, cp.phase_run_id, result)
                    if action in ("interrupt", "cancel"):
                        return
                    if action == "restart":
                        continue
                finally:
                    _release_adopted(project_id, cp.phase_run_id)
                    current_run_id = None
                continue

            row = pick_next_bypass(project_id, worker_id)
            if row is None:
                cancel.wait(timeout=5.0)
                continue
            doc = load_bypass_doc(project_id, row.file_path, max_chars=settings.recon_doc_inject_max_chars)
            if not doc.strip():
                doc = "（文档缺失或为空，可 FinishBypass(verdict=incomplete)）"
            system = _phase_system_prompt(project_id, "bypass_worker.md")
            run_id = _new_phase_run(
                project_id, "bypass-worker", "bypass_worker", worker_id=worker_id, file_path=bypass_ref(row.id)
            )
            current_run_id = run_id
            _consume_force_new(project_id, "worker")
            _start_log_session(project_id, "bypass-worker", extra=row.file_path)
            round_id = _next_bypass_round_id(project_id)
            body = _initial_prompt(
                "bypass_worker.md",
                worker_id=worker_id,
                round_id=round_id,
                bypass_id=row.id,
                file_path=row.file_path,
                title=row.title,
                cve=row.cve or "",
                cwe=row.cwe or "",
                fix_status=row.fix_status or "",
                source=row.source or "",
                old_vuln_doc=doc,
                **_audit_mode_vars(project_id),
            )
            user = _prompt_with_summary("bypass-worker", project_id, body, for_file=True)
            prior = inject_bypass_prior_block(project_id)
            if prior:
                user = f"{prior}{user}"
            loop = AgentLoop(
                project_id=project_id,
                role="bypass_worker",
                phase="bypass-worker",
                system_prompt=system,
                user_prompt=user,
                phase_run_id=run_id,
                worker_id=worker_id,
                cancel_event=_loop_cancel(project_id, "worker"),
                pause_event=_combined_pause(project_id, "worker"),
                timeout_sec=settings.timeout_worker_round,
                context_window=_context_window(),
                stop_when=lambda st: bool(st.get("bypass_finished")),
                file_path=bypass_ref(row.id),
            )
            loop.state["round_id"] = round_id
            loop.state["bypass_id"] = row.id
            loop.state["injected_bypass"] = bypass_ref(row.id)
            result = loop.run()
            action = _finish_bypass_round(project_id, worker_id, row.id, run_id, result)
            current_run_id = None
            if action in ("interrupt", "cancel"):
                return
            if action == "restart":
                continue
    except Exception as e:  # noqa: BLE001
        live_log.error(project_id, f"Bypass Worker={worker_id} 异常: {e}", phase="bypass-worker")
        try:
            if current_run_id:
                _finish_phase_run(current_run_id, "failed", str(e))
        except Exception:  # noqa: BLE001
            pass


def _run_fix(project_id: int, vuln_id: int) -> None:
    cancel = _cancel_event(project_id)
    try:
        with SessionLocal() as db:
            vuln = db.get(Vuln, vuln_id)
            if not vuln or vuln.status not in ("returned", "fixing"):
                return
            reason = vuln.return_reason or ""
            title = vuln.title
            report_path = vuln.report_path
        cp = _adopt_resumable(project_id, "fix", vuln_id=vuln_id)
        system = _phase_system_prompt(project_id, "worker.md")
        body = _initial_prompt(
            "fix.md",
            vuln_id=vuln_id,
            title=title,
            reason=reason,
            report_path=report_path,
            **_audit_mode_vars(project_id),
        )
        user = _prompt_with_summary("fix", project_id, body)
        try:
            if cp:
                run_id = cp.phase_run_id
                loop = _loop_from_checkpoint(
                    cp,
                    cancel=cancel,
                    stop_when=lambda st: bool(st.get("fix_finished")),
                    timeout_sec=settings.timeout_worker_round,
                )
            else:
                run_id = _new_phase_run(project_id, "fix", "fix", vuln_id=vuln_id)
                _consume_force_new(project_id, "worker")
                _start_log_session(project_id, "fix", extra=f"漏洞 #{vuln_id}")
                loop = AgentLoop(
                    project_id=project_id,
                    role="fix",
                    phase="fix",
                    system_prompt=system,
                    user_prompt=user,
                    phase_run_id=run_id,
                    vuln_id=vuln_id,
                    cancel_event=_loop_cancel(project_id, "worker"),
                    pause_event=_combined_pause(project_id, "worker"),
                    timeout_sec=settings.timeout_worker_round,
                    context_window=_context_window(),
                    stop_when=lambda st: bool(st.get("fix_finished")),
                )
            result = loop.run()
        finally:
            if cp:
                _release_adopted(project_id, cp.phase_run_id)
        if result.stop_reason == "auth_error":
            _pause_for_auth(project_id, result.error or "auth_error")
            return
        if not result.state.get("fix_finished"):
            with SessionLocal() as db:
                vuln = db.get(Vuln, vuln_id)
                if vuln and vuln.status == "fixing":
                    vuln.status = "returned"
                    db.commit()
            live_log.system(project_id, f"Fix 未完成，vuln={vuln_id} 回 returned", phase="fix")
        _finish_phase_run(run_id, "completed" if result.ok else "failed", result.error)
    except Exception as e:  # noqa: BLE001
        live_log.error(project_id, f"Fix 异常 vuln={vuln_id}: {e}", phase="fix")
        try:
            with SessionLocal() as db:
                vuln = db.get(Vuln, vuln_id)
                if vuln and vuln.status == "fixing":
                    vuln.status = "returned"
                    db.commit()
        except Exception:  # noqa: BLE001
            pass


def _lab_system_prompt(project_id: int) -> str:
    names = lab_naming(project_id)
    return f"{render_prompt('reviewer-lab.md', **names)}\n\n{render_prompt('docker.md', **names)}\n"


def _run_reviewer_lab(project_id: int) -> None:
    cancel = _cancel_event(project_id)
    try:
        if not is_lab_mode(_read_dynamic_verify_mode(project_id)):
            _finish_resumable_phase(project_id, "reviewer-lab")
            return
        if lab_setup_finished(project_id):
            _finish_resumable_phase(project_id, "reviewer-lab")
            return
        env = load_env(project_id)
        if env.get("accepted"):
            rec = recreate_lab(project_id)
            if lab_ready(load_env(project_id) or env):
                mark_lab_setup_finished(project_id, via=str(rec.get("via") or "reuse"))
                _finish_resumable_phase(project_id, "reviewer-lab")
                live_log.system(project_id, "已复用现有 Docker 靶场，环境搭建轮结束", phase="reviewer-lab", role="reviewer_lab")
                return

        system = _lab_system_prompt(project_id)
        user = _prompt_with_summary(
            "reviewer-lab",
            project_id,
            _initial_prompt(
                "reviewer-lab.md",
                **_audit_mode_vars(project_id),
                **lab_naming(project_id),
            ),
        )
        cp = _adopt_resumable(project_id, "reviewer-lab")
        run_id = cp.phase_run_id if cp else _new_phase_run(project_id, "reviewer-lab", "reviewer_lab")
        resumes = 0
        used_checkpoint = False
        llm = resolve_llm("reviewer", project_id=project_id)
        timeout_sec = settings.timeout_docker + settings.timeout_reviewer_static
        max_resumes = max(0, int(settings.phase_max_resumes))
        try:
            while resumes <= max_resumes and not cancel.is_set():
                if not _wait_if_paused(project_id, _loop_cancel(project_id, "reviewer"), "reviewer"):
                    _finish_phase_run(run_id, "cancelled")
                    return
                if lab_round_complete(project_id):
                    mark_lab_setup_finished(project_id, via="lab-round")
                    _finish_phase_run(run_id, "completed")
                    live_log.system(project_id, "动态环境搭建轮已完成", phase="reviewer-lab", role="reviewer_lab")
                    return
                if cp and not used_checkpoint:
                    loop = _loop_from_checkpoint(
                        cp,
                        cancel=cancel,
                        stop_when=lambda st: lab_round_complete(project_id, st),
                        timeout_sec=timeout_sec,
                        llm=llm,
                    )
                    used_checkpoint = True
                else:
                    _consume_force_new(project_id, "reviewer")
                    extra = "动态环境搭建"
                    if resumes:
                        extra = f"{extra} 重试 {resumes}/{max_resumes}"
                    _start_log_session(project_id, "reviewer-lab", extra, role="reviewer_lab")
                    loop = AgentLoop(
                        project_id=project_id,
                        role="reviewer_lab",
                        phase="reviewer-lab",
                        system_prompt=system,
                        user_prompt=user,
                        phase_run_id=run_id,
                        cancel_event=_loop_cancel(project_id, "reviewer"),
                        pause_event=_combined_pause(project_id, "reviewer"),
                        timeout_sec=timeout_sec,
                        context_window=_context_window(),
                        stop_when=lambda st: lab_round_complete(project_id, st),
                        llm=llm,
                    )
                result = loop.run()
                if result.stop_reason == "auth_error":
                    _pause_for_auth(project_id, result.error or "auth_error")
                    return
                if result.cancelled:
                    _finish_phase_run(run_id, "cancelled")
                    return
                if _should_skip_checkpoint(project_id, "reviewer"):
                    _finish_phase_run(run_id, "cancelled", "用户新跑")
                    return
                if lab_round_complete(project_id, result.state):
                    mark_lab_setup_finished(project_id, via="lab-round")
                    _finish_phase_run(run_id, "completed")
                    live_log.system(project_id, "动态环境搭建轮已完成", phase="reviewer-lab", role="reviewer_lab")
                    return
                resumes += 1
                if result.loop_aborted:
                    user = _prompt_with_summary(
                        "reviewer-lab",
                        project_id,
                        _initial_prompt("reviewer-lab-retry-loop.md", project_id=project_id),
                    )
                    live_log.system(
                        project_id,
                        f"环境搭建新开重试 {resumes}/{max_resumes}",
                        phase="reviewer-lab",
                        role="reviewer_lab",
                    )
                elif result.timed_out:
                    user = _prompt_with_summary(
                        "reviewer-lab",
                        project_id,
                        _initial_prompt("reviewer-lab-retry-timeout.md", project_id=project_id),
                    )
                else:
                    user = _prompt_with_summary(
                        "reviewer-lab",
                        project_id,
                        _initial_prompt(
                            "reviewer-lab-retry-other.md",
                            project_id=project_id,
                            stop_reason=result.stop_reason,
                            error=result.error,
                        ),
                    )
                if resumes > max_resumes:
                    break
            mark_lab_setup_finished(
                project_id,
                skipped=True,
                notes="环境搭建轮次重试用尽",
                via="lab-round",
            )
            _finish_phase_run(run_id, "failed", error="reviewer 环境搭建未在重试上限内完成")
            live_log.system(
                project_id,
                "环境搭建轮重试用尽，已结束本轮（后续审核可 static_only）",
                phase="reviewer-lab",
                role="reviewer_lab",
            )
        finally:
            if cp:
                _release_adopted(project_id, cp.phase_run_id)
    except Exception as e:  # noqa: BLE001
        live_log.error(project_id, f"环境搭建轮异常: {e}", phase="reviewer-lab")
        if not lab_setup_finished(project_id):
            mark_lab_setup_finished(project_id, skipped=True, notes=f"环境搭建轮异常: {e}", via="lab-round")


def _append_dynamic_followup_turn(cp: LoopCheckpoint) -> None:
    system = _phase_system_prompt(cp.project_id, "reviewer.md")
    cp.system_prompt = system
    messages = list(cp.messages or [])
    if messages and messages[0].get("role") == "system":
        messages[0] = {**messages[0], "content": system}
    else:
        messages.insert(0, {"role": "system", "content": system})
    lab_note = _reviewer_lab_note(cp.project_id)
    mode = _read_dynamic_verify_mode(cp.project_id)
    if mode == VERIFY_MODE_HARNESS:
        debug_plan = harness_debug_plan()
        followup = "reviewer-harness-followup.md"
        extra_label = "追加局部验证"
    else:
        debug_plan = {**reviewer_debug_plan(cp.project_id), "enabled": True}
        followup = "reviewer-dynamic-followup.md"
        extra_label = "追加动态验证"
    body = _initial_prompt(
        followup,
        vuln_id=cp.vuln_id,
        lab_note=lab_note,
        debug_plan=json_dumps(debug_plan),
        **_audit_mode_vars(cp.project_id),
    )
    messages.append({"role": "user", "content": body})
    cp.messages = messages
    cp.state["review_done"] = False
    cp.state.pop("review_verdict", None)
    cp.state["dynamic_followup"] = True
    cp.state["dynamic_followup_prompted"] = True
    cp.state["followup_label"] = extra_label


def _run_reviewer_once(project_id: int) -> None:
    cancel = _cancel_event(project_id)
    try:
        cp = _adopt_resumable(project_id, "reviewer")
        if cp and cp.vuln_id is not None:
            first_followup = bool(cp.state.get("dynamic_followup")) and not bool(
                cp.state.get("dynamic_followup_prompted")
            )
            if first_followup:
                _append_dynamic_followup_turn(cp)
                save_checkpoint(cp)
                _start_log_session(
                    project_id,
                    "reviewer",
                    extra=f"漏洞 #{cp.vuln_id} {cp.state.get('followup_label') or '追加动态验证'}",
                )
            with SessionLocal() as db:
                proj = db.get(Project, project_id)
                if proj and proj.status not in ("completed", "cancelled", "paused"):
                    proj.phase = "reviewer"
                    proj.status = "reviewing"
                    db.commit()
            try:
                loop = _loop_from_checkpoint(
                    cp,
                    cancel=cancel,
                    stop_when=lambda st: bool(st.get("review_done")),
                    timeout_sec=settings.timeout_reviewer_static,
                    resumed=not first_followup,
                )
                result = loop.run()
            finally:
                _release_adopted(project_id, cp.phase_run_id)
            if result.stop_reason == "auth_error":
                _pause_for_auth(project_id, result.error or "auth_error")
                return
            _finish_phase_run(cp.phase_run_id, "completed" if result.ok else "failed", result.error)
            live_log.system(
                project_id,
                f"Reviewer 结束 vuln={cp.vuln_id} verdict={result.state.get('review_verdict')} reason={result.stop_reason}",
                phase="reviewer",
            )
            return

        prefer = _take_inject_vuln(project_id, "reviewer")
        with SessionLocal() as db:
            vuln = None
            if prefer is not None:
                vuln = db.get(Vuln, prefer)
                if vuln and vuln.status not in ("pending_review", "returned"):
                    vuln = None
            if vuln is None:
                vuln = (
                    db.query(Vuln)
                    .filter(Vuln.project_id == project_id, Vuln.status == "pending_review")
                    .order_by(Vuln.id.asc())
                    .first()
                )
            if not vuln:
                return
            vuln_id = vuln.id
            payload = {
                "title": vuln.title,
                "type": vuln.vuln_type,
                "severity": vuln.severity,
                "cwe": vuln.cwe,
                "file": vuln.file_path,
                "line": vuln.line_no,
                "intended_behavior": vuln.intended_behavior,
                "report_path": vuln.report_path,
                "auth_premise": vuln.auth_premise,
                "source_sink": vuln.source_sink,
            }

        lab_note = _reviewer_lab_note(project_id)
        mode = _read_dynamic_verify_mode(project_id)
        if mode == VERIFY_MODE_OFF:
            debug_plan = {"enabled": False, "preferred": "static_only"}
        elif mode == VERIFY_MODE_HARNESS:
            debug_plan = harness_debug_plan()
        else:
            debug_plan = {**reviewer_debug_plan(project_id), "enabled": True}

        with SessionLocal() as db:
            proj = db.get(Project, project_id)
            if proj and proj.status not in ("completed", "cancelled", "paused"):
                proj.phase = "reviewer"
                proj.status = "reviewing"
                db.commit()

        system = _phase_system_prompt(project_id, "reviewer.md")
        body = _initial_prompt(
            "reviewer.md",
            vuln_id=vuln_id,
            payload=json_dumps(payload),
            lab_note=lab_note,
            debug_plan=json_dumps(debug_plan),
            **_audit_mode_vars(project_id),
        )
        user = _prompt_with_summary("reviewer", project_id, body)
        run_id = _new_phase_run(project_id, "reviewer", "reviewer", vuln_id=vuln_id)
        _consume_force_new(project_id, "reviewer")
        _start_log_session(project_id, "reviewer", extra=f"漏洞 #{vuln_id}")
        loop = AgentLoop(
            project_id=project_id,
            role="reviewer",
            phase="reviewer",
            system_prompt=system,
            user_prompt=user,
            phase_run_id=run_id,
            vuln_id=vuln_id,
            cancel_event=_loop_cancel(project_id, "reviewer"),
            pause_event=_combined_pause(project_id, "reviewer"),
            timeout_sec=settings.timeout_reviewer_static,
            context_window=_context_window(),
            stop_when=lambda st: bool(st.get("review_done")),
        )
        result = loop.run()
        if result.stop_reason == "auth_error":
            _pause_for_auth(project_id, result.error or "auth_error")
            return
        _finish_phase_run(run_id, "completed" if result.ok else "failed", result.error)
        live_log.system(
            project_id,
            f"Reviewer 结束 vuln={vuln_id} verdict={result.state.get('review_verdict')} reason={result.stop_reason}",
            phase="reviewer",
        )
    except Exception as e:  # noqa: BLE001
        live_log.error(project_id, f"Reviewer 异常: {e}", phase="reviewer")


def _run_verifier_once(project_id: int) -> None:
    from .verifier import (
        extract_fofa_query,
        format_shared_fofa_hint,
        internet_test_block_reason_for_vuln,
        load_project_fofa_cache,
        mark_internet_unsafe_skipped,
        pick_pending_verifier_vuln,
        read_report_md,
        seed_fofa_state,
    )

    cancel = _cancel_event(project_id)
    try:
        cp = _adopt_resumable(project_id, "verifier")
        if cp and cp.vuln_id is not None:
            with SessionLocal() as db:
                proj = db.get(Project, project_id)
                if proj and proj.status not in ("completed", "cancelled", "paused"):
                    proj.phase = "verifier"
                    proj.status = "auditing"
                    db.commit()
            try:
                loop = _loop_from_checkpoint(
                    cp,
                    cancel=cancel,
                    stop_when=lambda st: bool(st.get("verifier_done")),
                    timeout_sec=settings.timeout_verifier,
                )
                seed_fofa_state(loop.state, project_id)
                result = loop.run()
            finally:
                _release_adopted(project_id, cp.phase_run_id)
            if result.stop_reason == "auth_error":
                _pause_for_auth(project_id, result.error or "auth_error")
                return
            _finish_phase_run(cp.phase_run_id, "completed" if result.ok else "failed", result.error)
            live_log.system(
                project_id,
                f"Verifier 结束 vuln={cp.vuln_id} verdict={result.state.get('verifier_verdict')} reason={result.stop_reason}",
                phase="verifier",
            )
            return

        prefer = _take_inject_vuln(project_id, "verifier")
        vuln = pick_pending_verifier_vuln(project_id, prefer)
        if not vuln:
            return
        vuln_id = vuln.id
        report_md = read_report_md(project_id, vuln_id)
        unsafe = internet_test_block_reason_for_vuln(vuln, report_md)
        if unsafe:
            mark_internet_unsafe_skipped(project_id, vuln_id, unsafe)
            live_log.system(
                project_id,
                f"漏洞 #{vuln_id} 跳过互联网复测：{unsafe}",
                phase="verifier",
            )
            return
        from .asset_proof import ensure_project_fingerprints, load_project_fingerprints
        from .report import is_placeholder_query

        ensure_project_fingerprints(project_id)
        app_fp = load_project_fingerprints(project_id) or {}
        fofa_cache = load_project_fofa_cache(project_id)
        report_query = extract_fofa_query(report_md)
        cached_query = str((fofa_cache or {}).get("query") or "").strip()
        if fofa_cache and fofa_cache.get("sample") and cached_query:
            fofa_query = cached_query
        elif not is_placeholder_query(app_fp.get("fofa")):
            fofa_query = str(app_fp.get("fofa") or "").strip()
        elif not is_placeholder_query(report_query):
            fofa_query = report_query
        else:
            fofa_query = "（项目指纹与报告均无可用 FOFA 语句：Read docs/app-fingerprints.json 与报告后改写再搜）"
        payload = {
            "title": vuln.title,
            "type": vuln.vuln_type,
            "severity": vuln.severity,
            "cwe": vuln.cwe,
            "file": vuln.file_path,
            "line": vuln.line_no,
            "report_path": vuln.report_path or f"vulns/{vuln_id}/report.md",
            "http_request": vuln.http_request,
            "poc_code": read_poc_code(project_id, vuln_id, fallback=vuln.poc_code),
            "expected_evidence": vuln.expected_evidence,
        }
        with SessionLocal() as db:
            proj = db.get(Project, project_id)
            if proj and proj.status not in ("completed", "cancelled", "paused"):
                proj.phase = "verifier"
                proj.status = "auditing"
                db.commit()

        system = _phase_system_prompt(project_id, "verifier.md")
        body = _initial_prompt(
            "verifier.md",
            vuln_id=vuln_id,
            payload=json_dumps(payload),
            fofa_query=fofa_query,
            fofa_shared=format_shared_fofa_hint(fofa_cache),
            **_audit_mode_vars(project_id),
        )
        user = _prompt_with_summary("verifier", project_id, body)
        run_id = _new_phase_run(project_id, "verifier", "verifier", vuln_id=vuln_id)
        _consume_force_new(project_id, "verifier")
        _start_log_session(project_id, "verifier", extra=f"漏洞 #{vuln_id}")
        loop = AgentLoop(
            project_id=project_id,
            role="verifier",
            phase="verifier",
            system_prompt=system,
            user_prompt=user,
            phase_run_id=run_id,
            vuln_id=vuln_id,
            cancel_event=_loop_cancel(project_id, "verifier"),
            pause_event=_combined_pause(project_id, "verifier"),
            timeout_sec=settings.timeout_verifier,
            context_window=_context_window(),
            stop_when=lambda st: bool(st.get("verifier_done")),
        )
        seed_fofa_state(loop.state, project_id)
        result = loop.run()
        if result.stop_reason == "auth_error":
            _pause_for_auth(project_id, result.error or "auth_error")
            return
        _finish_phase_run(run_id, "completed" if result.ok else "failed", result.error)
        live_log.system(
            project_id,
            f"Verifier 结束 vuln={vuln_id} verdict={result.state.get('verifier_verdict')} reason={result.stop_reason}",
            phase="verifier",
        )
    except Exception as e:  # noqa: BLE001
        live_log.error(project_id, f"Verifier 异常: {e}", phase="verifier")


def json_dumps(obj: Any) -> str:
    import json

    return json.dumps(obj, ensure_ascii=False, default=str)

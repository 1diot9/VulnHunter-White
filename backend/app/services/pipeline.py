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
    inject_unconstrained_prior_block,
    inject_security_policy_block,
    inject_worker_prior_block,
    latest_summary,
    max_fast_round_report_no,
    max_bypass_round_report_no,
    max_unconstrained_round_report_no,
    max_round_report_no,
)
from ..agent.loop import AgentLoop
from ..audit_mode import (
    AUDIT_MODE_CUSTOM,
    audit_mode_label,
    initial_hint as audit_mode_initial_hint,
    is_bounty_mode,
    normalize_audit_mode,
)
from ..config import settings
from ..harness_depth import (
    HARNESS_DEPTH_INTEGRATION,
    normalize_harness_depth,
)
from ..dynamic_verify import (
    EVIDENCE_HARNESS,
    VERIFY_MODE_HARNESS,
    VERIFY_MODE_LAB,
    VERIFY_MODE_OFF,
    is_harness_mode,
    is_lab_mode,
    project_verify_mode,
    review_timeouts_before_static,
    review_timeouts_exhausted,
    static_after_review_timeouts,
    verify_mode_enabled,
)
from ..mining_paths import HEURISTIC_LITE_WEIGHT, heuristic_lite_active, mining_path_label
from ..models import FileWeight, PhaseRun, Project, SessionLocal, Sink, Source, Vuln, utcnow
from ..prompts import load_prompt, render_prompt
from ..target_kind import (
    initial_hint as target_kind_initial_hint,
    normalize_target_kind,
    target_kind_label,
)
from ..services.custom_audit_modes import project_custom_overlay
from ..services.ingest import (
    backfill_missing_source_exts,
    build_file_index,
    build_file_index_with_exts,
    clone_github,
    extract_zip,
    prefilter_extensions,
)
from ..services.lab import (
    clear_lab_bring_up_failed,
    clear_lab_retry_flags,
    debug_ports_for_runtime,
    docker_available,
    format_lab_repairs_for_prompt,
    handoff_lab_for_repair,
    increment_lab_setup_timeout_streak,
    lab_bring_up_failed,
    lab_had_docker_lab,
    lab_naming,
    lab_ready,
    lab_rebuild_requested,
    lab_round_complete,
    lab_setup_failed,
    lab_setup_finished,
    lab_setup_timeouts_exhausted,
    load_env,
    mark_lab_bring_up_failed,
    mark_lab_setup_finished,
    recreate_lab,
    reset_lab_setup_for_retry,
    stop_lab,
)
from ..services.live_log import live_log
from ..services.llm_settings import get_settings_row, resolve_llm
from ..services.mcp_router import reviewer_debug_plan
from ..services.sandbox_exec import harness_debug_plan
from ..services.paths import ensure_project_dirs, project_root, src_dir, summaries_dir, workspace_dir
from ..services.poc_script import read_poc_code
from ..services.vuln_followup import archive_reviewer_checkpoint, latest_reviewer_context
from ..tools import register_all_tools
from ..tools.phase_recon import (
    apply_recon_done,
    begin_map_refresh,
    clear_map_refresh,
    clear_old_vuln_completion,
    paths_fully_marked,
    has_unmarked_files,
    pick_unmarked_batch,
    skip_non_source_weight_rows,
    recon_gates_met,
    recon_gates_status,
    recon_map_ready,
    recon_map_refresh_ready,
    recon_old_vuln_llm_ready,
    recon_old_vulns_ready,
    recon_source_ext_ready,
)
from ..tools.phase_worker import heuristic_complete, mining_complete, project_complete_gates, unconstrained_complete

register_all_tools()

# RLock: _ensure_recon_marking (and similar) call _cancel_event while already holding
# this lock. A plain Lock deadlocks every list_projects poll via is_project_paused.
_lock = threading.RLock()
_cancel_events: dict[int, threading.Event] = {}
_pause_flags: dict[int, threading.Event] = {}
_phase_pause_flags: dict[tuple[int, str], threading.Event] = {}
_phase_generation: dict[tuple[int, str], int] = {}
_force_new_run: set[tuple[int, str]] = set()
_pending_inject: dict[tuple[int, str], list[dict[str, Any]]] = {}
_threads: dict[int, list[threading.Thread]] = {}
_recon_threads: dict[int, threading.Thread] = {}
_recon_mark_threads: dict[int, threading.Thread] = {}
_recon_rerun_threads: dict[int, threading.Thread] = {}
_reviewer_threads: dict[int, threading.Thread] = {}
_verifier_threads: dict[int, threading.Thread] = {}
_attack_chain_threads: dict[int, threading.Thread] = {}
_reviewer_inflight: dict[int, bool] = {}
_verifier_inflight: dict[int, bool] = {}
_attack_chain_inflight: dict[int, bool] = {}
_fix_inflight: dict[int, set[int]] = {}
_adopted_phase_runs: set[tuple[int, int]] = set()
_pending_conversation_message: dict[tuple[int, str], str] = {}
_fast_prepare_threads: dict[int, threading.Thread] = {}
_fast_last_dir: dict[int, str] = {}
_DB_LOCK_RETRY_SECONDS = 1.0

# Role pools: Recon 1 / Worker 2 (mine 1 + fix 1) / Reviewer 1
RECON_POOL = 1
WORKER_MINE_POOL = 1
WORKER_FIX_POOL = 1
REVIEWER_POOL = 1

CONTROL_PHASES = ("recon", "worker", "reviewer", "verifier", "attack_chain")
CONTROL_DB_PHASES: dict[str, tuple[str, ...]] = {
    "recon": ("recon", "recon-source-ext", "recon-old-vuln", "recon-old-vuln-ghsa", "recon-mark"),
    "worker": ("worker", "fix", "fast-worker", "sink-triage", "bypass-worker", "unconstrained-worker"),
    "reviewer": ("reviewer", "reviewer-lab"),
    "verifier": ("verifier",),
    "attack_chain": ("attack_chain",),
}
CONTROL_LABELS = {
    "recon": "侦察",
    "worker": "挖掘",
    "reviewer": "审核",
    "verifier": "验证",
    "attack_chain": "攻击链",
}
RECON_RERUN_SUBPHASES = ("map", "old_vulns")
RECON_RERUN_LABELS = {"map": "地图/鉴权", "old_vulns": "历史漏洞"}
WORKER_PROGRESS_RESET_STATUSES = ("paused", "completed", "cancelled", "error")


def _is_sqlite_locked(exc: BaseException) -> bool:
    text = str(exc).lower()
    return "database is locked" in text or "database is busy" in text


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
        "unconstrained-worker",
        "unconstrained_worker",
        "unconstrained",
    ):
        return "worker"
    if p in ("reviewer", "reviewer-lab", "reviewer_lab"):
        return "reviewer"
    if p == "verifier":
        return "verifier"
    if p in ("attack_chain", "attack-chain"):
        return "attack_chain"
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
        _recon_mark_threads.clear()
        _recon_rerun_threads.clear()
        _reviewer_threads.clear()
        _verifier_threads.clear()
        _attack_chain_threads.clear()
        _reviewer_inflight.clear()
        _verifier_inflight.clear()
        _attack_chain_inflight.clear()
        _fix_inflight.clear()
        _adopted_phase_runs.clear()
        _fast_prepare_threads.clear()
        _fast_last_dir.clear()
        _map_refresh_pending.clear()
    from .cli_tool_index import stop_cli_tool_scanner
    from .llm_thread import llm_thread_limiter

    stop_cli_tool_scanner()
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


def is_project_paused(project_id: int) -> bool:
    """In-memory project pause flag without allocating an Event for unseen ids."""
    with _lock:
        ev = _pause_flags.get(int(project_id))
        return bool(ev is not None and ev.is_set())


def request_cancel(project_id: int) -> None:
    _cancel_event(project_id).set()
    try:
        from .decompile_java import cancel_project_jobs

        cancel_project_jobs(project_id)
    except Exception:  # noqa: BLE001
        pass
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        if proj and proj.status not in ("completed",):
            proj.status = "cancelled"
            db.commit()
    live_log.system(project_id, "用户取消审计")


def request_pause(project_id: int, *, reason: str | None = None) -> None:
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
    live_log.system(project_id, reason or "用户暂停全部阶段")


def note_mining_paths_changed(
    project_id: int,
    *,
    heuristic_enabled: bool,
    fast_enabled: bool,
    bypass_enabled: bool = False,
    unconstrained_enabled: bool = False,
    heuristic_lite: bool = False,
) -> None:
    """Keep paused; next resume uses the new mining paths."""
    _force_new_run.add((project_id, "worker"))
    _abandon_phase_checkpoints(project_id, "worker")
    _bump_phase_generation(project_id, "worker")
    live_log.system(
        project_id,
        f"挖掘路径已改为{mining_path_label(heuristic_enabled=heuristic_enabled, fast_enabled=fast_enabled, bypass_enabled=bypass_enabled, unconstrained_enabled=unconstrained_enabled, heuristic_lite=heuristic_lite)}，续跑后按新路径调度",
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


def kick_verifier(project_id: int) -> None:
    """Wake Verifier for pending work or a post-consent checkpoint (even if project completed)."""
    cancel = _cancel_event(project_id)
    _ensure_verifier(project_id, cancel, allow_completed=True)


def note_attack_chain_enabled(project_id: int) -> None:
    """Enabling Attack Chain mid-run clears leftover pause and allows a fresh run."""
    from ..tools.phase_attack_chain import clear_attack_chain_done

    clear_attack_chain_done(project_id)
    if not _pause_event(project_id).is_set():
        _phase_pause_event(project_id, "attack_chain").clear()
    _force_new_run.add((project_id, "attack_chain"))
    _abandon_phase_checkpoints(project_id, "attack_chain")


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


def is_harness_confirmed_vuln(vuln: Vuln) -> bool:
    """True when Reviewer already confirmed with local harness evidence."""
    if vuln.status == "merged":
        return False
    return (vuln.evidence_level or "").strip().lower() == EVIDENCE_HARNESS and vuln.status == "confirmed"


def is_harness_integration_upgradeable(vuln: Vuln) -> bool:
    """Harness-confirmed vuln with poc that can queue L3 integration follow-up."""
    if vuln.status == "merged" or vuln.status != "confirmed":
        return False
    if (vuln.evidence_level or "").strip().lower() != EVIDENCE_HARNESS:
        return False
    depth = normalize_harness_depth(vuln.harness_depth)
    if depth == HARNESS_DEPTH_INTEGRATION:
        return False
    from .poc_script import poc_path, read_poc_code

    landed = read_poc_code(vuln.project_id, int(vuln.id), fallback=vuln.poc_code)
    if landed:
        return True
    return poc_path(vuln.project_id, int(vuln.id)).is_file()


def can_append_dynamic_verify(vuln: Vuln, verify_mode: str) -> bool:
    """Whether this vuln can queue a follow-up under the project's current verify mode.

    - ``static_only`` → append lab or harness (whichever mode is on)
    - harness-confirmed (sink/module) + poc → append L3 integration (harness project)
    - harness-confirmed → append Docker lab only (upgrade evidence to dynamic/mcp)
    """
    if vuln.status == "merged":
        return False
    if not verify_mode_enabled(verify_mode):
        return False
    if is_static_only_vuln(vuln):
        return True
    if is_harness_mode(verify_mode) and is_harness_integration_upgradeable(vuln):
        return True
    if is_harness_confirmed_vuln(vuln) and is_lab_mode(verify_mode):
        return True
    return False


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
        proj is not None
        and can_append_dynamic_verify(vuln, project_verify_mode(proj))
        and proj.status not in ("cancelled", "error", "pending", "ingesting")
    )
    return can, queued


def request_dynamic_verify(vuln_id: int, *, followup_kind: str = "") -> dict[str, Any]:
    """Queue a Reviewer follow-up that continues the prior round with lab/harness/integration verification."""
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
    if not can_append_dynamic_verify(vuln, verify_mode):
        if is_harness_confirmed_vuln(vuln) and is_harness_mode(verify_mode):
            if normalize_harness_depth(vuln.harness_depth) == HARNESS_DEPTH_INTEGRATION:
                raise DynamicVerifyRequestError("该漏洞已完成集成验证")
            raise DynamicVerifyRequestError(
                "该漏洞已局部验证；若有 poc.py 可追加集成验证，或切换靶场动态后再追加"
            )
        if is_lab_mode(verify_mode):
            raise DynamicVerifyRequestError("仅 static_only 或局部验证确认的漏洞可追加靶场动态验证")
        raise DynamicVerifyRequestError("仅 static_only 的漏洞可追加局部验证")
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
    kind = str(followup_kind or "").strip().lower()
    if not kind and is_harness_mode(verify_mode) and is_harness_integration_upgradeable(vuln):
        kind = "integration"
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
                "followup_kind": kind or "default",
                "review_done": False,
                "source_phase_run_id": source_run,
                "prior_evidence_level": (vuln.evidence_level or "").strip().lower() or "static_only",
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
    from .token_budget import token_budget_block_reason

    blocked = token_budget_block_reason(project_id)
    if blocked:
        raise ValueError(blocked)
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
    phases = ["recon", "worker", "reviewer"]
    if _read_verifier_enabled(project_id):
        phases.append("verifier")
    if _read_attack_chain_enabled(project_id):
        phases.append("attack_chain")
    return tuple(phases)


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


def request_lab_setup_retry(project_id: int, user_message: str = "") -> dict[str, Any]:
    """Force another reviewer-lab round after setup retries were exhausted."""
    if not is_lab_mode(_read_dynamic_verify_mode(project_id)):
        raise ValueError("仅靶场动态验证模式可续跑环境搭建")

    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        if not proj:
            raise ValueError("项目不存在")
        if proj.status in ("cancelled", "ingesting", "error"):
            raise ValueError("当前项目状态不可续跑环境搭建")

    if not lab_setup_failed(project_id):
        raise ValueError("环境搭建尚未结束或靶场已就绪，无需续跑")
    if not lab_setup_finished(project_id):
        raise ValueError("环境搭建正在进行中")

    _abandon_db_phase_runs(project_id, ("reviewer-lab",), reason="用户续跑环境搭建")
    _force_new_run.add((project_id, "reviewer"))
    reset_lab_setup_for_retry(project_id, user_message)

    was_paused = _pause_event(project_id).is_set()
    _phase_pause_event(project_id, "reviewer").clear()
    cancel = _cancel_event(project_id)
    if cancel.is_set():
        cancel.clear()
    if not was_paused:
        _set_project_running(project_id)
    else:
        with SessionLocal() as db:
            proj = db.get(Project, project_id)
            if proj and proj.status == "paused":
                proj.status = "auditing"
                proj.error = None
                db.commit()

    live_log.system(
        project_id,
        "用户请求续跑环境搭建",
        phase="reviewer-lab",
        role="reviewer_lab",
    )
    _ensure_reviewer(project_id, cancel)
    return {"ok": True, **get_phase_states(project_id)}


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
        # Re-mining may add vulns; allow attack-chain to re-run after the next review drain.
        if bool(getattr(proj, "attack_chain_enabled", False)):
            proj.attack_chain_done = False
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
        if t is not None and t.is_alive():
            return True
        mt = _recon_mark_threads.get(project_id)
        return mt is not None and mt.is_alive()
    if control == "reviewer":
        t = _reviewer_threads.get(project_id)
        return t is not None and t.is_alive()
    if control == "verifier":
        t = _verifier_threads.get(project_id)
        return t is not None and t.is_alive()
    if control == "attack_chain":
        t = _attack_chain_threads.get(project_id)
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
    if project_id is not None and phase:
        cp = load_checkpoint(project_id, run_id)
        if cp and cp.messages and status in ("completed", "failed", "cancelled"):
            from .conversation_archive import archive_checkpoint

            archive_checkpoint(project_id, phase, cp)
        if phase == "reviewer" and status == "completed":
            archive_reviewer_checkpoint(project_id, run_id)
        clear_checkpoint(project_id, run_id)


def _context_window() -> int:
    row = get_settings_row()
    return int(row.context_window or settings.default_context_window)


def _worker_concurrency(project_id: int) -> int:
    return WORKER_MINE_POOL


def _fix_concurrency() -> int:
    """打回分析债务用独立池，不占用挖掘 Worker 名额。"""
    return WORKER_FIX_POOL


def _read_file_snippet(project_id: int, rel: str) -> str:
    norm = str(rel or "").replace("\\", "/").lstrip("/")
    if norm.startswith("workspace/"):
        path = project_root(project_id) / norm
    else:
        path = src_dir(project_id) / norm
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
    # resumable_file_paths opens its own SessionLocal; do not nest inside the write session.
    protected = resumable_file_paths(project_id)
    released: list[tuple[str, str]] = []
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
        n = 0
        for row in rows:
            if row.path in protected:
                continue
            released.append((row.path, str(row.claimed_by or "")))
            row.claimed_by = None
            row.claimed_at = None
            n += 1
        if n:
            db.commit()
    for path, by in released:
        live_log.system(
            project_id,
            f"回收陈旧认领: {path} (by={by})",
            phase="worker",
        )
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


def _abandon_zombie_phase_runs(project_id: int) -> int:
    """Mark running/paused PhaseRuns with no checkpoint as failed (process-death leftovers)."""
    from ..agent.checkpoint import checkpoint_exists

    n = 0
    with SessionLocal() as db:
        rows = (
            db.query(PhaseRun)
            .filter(
                PhaseRun.project_id == project_id,
                PhaseRun.status.in_(("running", "paused")),
            )
            .all()
        )
        for pr in rows:
            if checkpoint_exists(project_id, pr.id):
                continue
            pr.status = "failed"
            pr.error = "进程中断且无检查点"
            n += 1
        if n:
            db.commit()
    return n


def _prepare_project_resume(project_id: int) -> None:
    n_zombies = _abandon_zombie_phase_runs(project_id)
    keep_paths = resumable_file_paths(project_id)
    keep_vulns = resumable_vuln_ids(project_id, "fix")
    n_claims = _release_claims(project_id, except_paths=keep_paths)
    n_fix = _reset_fixing_to_returned(project_id, except_ids=keep_vulns)
    if n_claims or n_fix or n_zombies:
        live_log.system(
            project_id,
            f"恢复准备：清认领 {n_claims}，fixing→returned {n_fix}，丢弃无检查点轮次 {n_zombies}",
        )
    n_cp = len(list_resumable_runs(project_id))
    if n_cp:
        live_log.system(project_id, f"发现 {n_cp} 个可接续检查点，将接着原上下文继续")


def _pick_next_file(project_id: int, worker_id: str) -> FileWeight | None:
    from .decompile_store import app_db_write

    protected = resumable_file_paths(project_id)
    with app_db_write():
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
            if protected:
                q = q.filter(~FileWeight.path.in_(list(protected)))
            q = q.order_by(
                FileWeight.audit_attempts.asc(),
                FileWeight.has_source.desc(),
                FileWeight.weight.desc(),
                FileWeight.path.asc(),
            )
            row = q.first()
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


def _read_target_kind(project_id: int) -> str:
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        return normalize_target_kind(getattr(proj, "target_kind", None) if proj else None)


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


def _read_attack_chain_enabled(project_id: int) -> bool:
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        return bool(proj and getattr(proj, "attack_chain_enabled", False))


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


def _prepare_lab_for_review(project_id: int) -> str:
    """Return ready | static for review-time Docker handling.

    Recoverable lab failures hand off to reviewer-lab (timeout streak resets per handoff).
    """
    if not is_lab_mode(_read_dynamic_verify_mode(project_id)):
        return "static"
    if lab_bring_up_failed(project_id):
        return "static"
    if not lab_setup_finished(project_id):
        return "static"
    env = load_env(project_id)
    if lab_ready(env):
        rec = recreate_lab(project_id, mode="start")
        if rec.get("ok") and lab_ready(load_env(project_id)):
            clear_lab_bring_up_failed(project_id)
            return "ready"
        env = load_env(project_id)
    if not lab_had_docker_lab(project_id):
        return "static"
    if not docker_available():
        handoff_lab_for_repair(project_id, "本机无 docker", source="review-open")
        return "static"
    rec = recreate_lab(project_id, mode="start")
    if rec.get("ok") and lab_ready(load_env(project_id)):
        clear_lab_bring_up_failed(project_id)
        return "ready"
    reason = str(rec.get("error") or "靶场无法启动")
    handoff_lab_for_repair(project_id, reason, source="review-open")
    return "static"


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
    "不要把「待运行环境确认」留到确认后，也不要为此 ReturnToWorker。报告包装与 PoC 由本轮 Reviewer 改完 Confirm。"
)


_STATIC_REVIEW_NOTE = (
    "本项目仅静态验证：不要搭建 Docker、不要对靶场发请求或运行 poc.py、"
    "不要 docker exec / debug MCP。"
    "ConfirmVuln 必须 evidence_level=static_only。"
    "应用指纹是项目级的（docs/app-fingerprints.json），系统已在侦察结束后采集一次；"
    "不要每条漏洞重新识别，Confirm 会写入报告。不要编造 hash。"
)

_LAB_VERIFY_GATE = (
    "动态验证先跑当前 poc.py；靶场可用时 ConfirmVuln 会系统再跑一遍落盘脚本，"
    "退出码非 0 则拒绝确认，不要用 static_only 跳过。"
    "缺失/跑不通且需改写时才用 debug MCP 动态调试，不要一上来就挂 MCP。"
)
_STATIC_VERIFY_GATE = (
    "本轮仅静态审核：不要对靶场发请求、不要运行 poc.py、不要 debug MCP。"
    "ConfirmVuln 必须 evidence_level=static_only。"
    "静态已能证明默认可利用则立即 Confirm 或误报收口，不要再排查认证、路由或环境，"
    "也不要重复通读报告。"
)
_HARNESS_VERIFY_GATE = (
    "本轮局部验证（L1/L2）：不要对 Docker target_url 发请求或手工跑 poc.py，不要 debug MCP。"
    "用 RunCode 写 harness；打通后 ConfirmVuln(harness_depth=sink|module, evidence_level=harness)。"
    "L3 integration：ConfirmVuln(harness_depth=integration, integration_start=...) 由系统于 integration 沙箱起服务并跑 poc，通过 → dynamic。"
    "组件公开入口本身吃 HTTP/请求对象时，对 src/ 公开 API 做同进程请求级加强验证，禁止只拷内部 sink；"
    "YAML/编解码等无请求面 API 不要包 HTTP。"
    "沙箱不可用或 mock 失败不要因此误报，静态已能证明则 static_only。"
)

_HARNESS_REVIEW_NOTE = (
    "本项目为局部验证：不要搭建 Docker 靶场。"
    "L1/L2：RunCode 写 mock/harness，ConfirmVuln(harness_depth=sink|module, evidence_level=harness)。"
    "L3 integration：须有 poc.py 与报告「### 局部验证」；ConfirmVuln(harness_depth=integration, integration_start=...) "
    "由系统在 integration 沙箱内临时装依赖、起 127.0.0.1 服务并跑 poc，通过 → evidence_level=dynamic。"
    "L1/L2 不要手工跑 poc.py -u；不要在本机长期起服务。"
    "组件公开入口本身吃 HTTP/请求对象时，harness 须调用 src/ 公开 API 并在同进程内发请求（httptest/loopback）。"
    "harness 最终输出必须打印运行时实际数据；输出默认英语，须提供 --zh 切中文。"
    "不要把 harness 的内联/mock 写进 poc.py。"
    "应用指纹复用 docs/app-fingerprints.json，不要 CollectLabFingerprints。"
)

_BRINGUP_FAILED_NOTE = (
    "Docker 靶场拉起失败（见 docs/lab.md），本轮强制仅静态审核。"
    "不要搭建或启动 Docker、不要对靶场发请求或运行 poc.py、不要 docker exec / debug MCP。"
    "ConfirmVuln 必须 evidence_level=static_only。"
    "若判定靶场假就绪、需要完整重建而不是仅 docker start，"
    "可调用 RequestLabRebuild(reason=...) 交回环境搭建 Agent。"
)

_ATTACK_CHAIN_STATIC_NOTE = (
    "## 动态验证\n\n"
    "当前无可用的本地 Docker 靶场：只做静态串联推理与文档，不要执行利用、不要 curl 目标。"
    "SubmitAttackChain 不必传 chain_script。"
)


def _attack_chain_lab_note(project_id: int) -> str:
    """Inject lab URL for non-interactive chain script verification when Docker lab is up."""
    from ..tools.phase_attack_chain import resolve_attack_chain_lab_url

    target = resolve_attack_chain_lab_url(project_id)
    if not target:
        return _ATTACK_CHAIN_STATIC_NOTE
    return (
        "## 动态验证（本地 Docker 靶场可用）\n\n"
        f"- 靶场 URL：`{target}`\n"
        "- 无用户交互的详文链：须编写 `chain_script`（Python，`-u/--url` + `--proxy`），"
        "SubmitAttackChain 时传入；系统会执行 `python chain.py -u <target_url> --proxy \"\"`，"
        "退出码非 0 则拒绝提交。\n"
        "- 含 XSS / 存储型 XSS / CSRF，或任何需受害者浏览器/人工点击的链："
        "传 `needs_interaction=true`，**跳过**动态验证，不要为这类链强行写必跑脚本。\n"
        "- 只打上述靶场 URL，禁止打互联网目标。可用 Write/Bash 调试脚本后再提交。"
    )


def _docker_lab_note(project_id: int) -> str | None:
    env = load_env(project_id)
    if lab_bring_up_failed(project_id):
        return None
    if not (lab_ready(env) or env.get("accepted")):
        return None
    rec = recreate_lab(project_id, mode="start")
    if not rec.get("ok"):
        return None
    dbg = debug_ports_for_runtime(load_env(project_id) or env)
    return f"环境: {json_dumps(rec)}\n调试: {json_dumps(dbg)}"


def _pending_lab_repair_review_note(project_id: int) -> str:
    env = load_env(project_id)
    if not _truthy(env.get("pending_lab_repair_write")):
        return ""
    failure = str(env.get("pending_lab_repair_failure") or "").strip() or "见上一轮交回搭建时的 reason"
    return (
        "## 靶场刚修复完成\n"
        f"本轮第一步：验证 docs/lab.md / target_url 健康（业务入口可访问、可登录）。\n"
        f"第二步：将本次失效原因与解决方案写入 `docs/lab-repairs.md`（失效原因可参考：{failure}）。\n"
        "第三步：再 Read 报告并做漏洞验证。未完成前两步不要 ConfirmVuln。\n"
    )


def _reviewer_lab_note(project_id: int) -> str:
    mode = _read_dynamic_verify_mode(project_id)
    repair_note = _pending_lab_repair_review_note(project_id)
    if mode == VERIFY_MODE_OFF:
        return repair_note + _STATIC_REVIEW_NOTE if repair_note else _STATIC_REVIEW_NOTE
    if mode == VERIFY_MODE_HARNESS:
        base = _HARNESS_REVIEW_NOTE
        return f"{repair_note}{base}" if repair_note else base
    if lab_bring_up_failed(project_id):
        reason = str(load_env(project_id).get("bring_up_fail_reason") or "").strip()
        extra = f"失败原因：{reason}\n" if reason else ""
        return f"{extra}{_BRINGUP_FAILED_NOTE}\n{_ASSET_PROOF_LAB_HINT}"
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
        return (
            f"{repair_note}{docker_note}\n"
            "第一步先验证靶场健康，再跑 PoC。"
            "ConfirmVuln 会系统执行即将落盘的 poc.py（python poc.py -u <target_url>，直连）；"
            "退出码非 0 则拒绝确认，不要用 static_only 跳过。\n"
            f"{_ASSET_PROOF_LAB_HINT}"
        )
    base = (
        "动态环境搭建轮已结束；靶场未就绪，见 docs/lab.md。"
        "本轮只审核漏洞，不要再搭建 Docker 靶场。"
        "环境起不来时用 evidence_level=static_only 或误报。"
    )
    return f"{repair_note}{base}" if repair_note else base


def _next_reviewer_step(project_id: int, pending: int) -> str:
    """Prefer reviewing with a manual lab note; otherwise finish Docker lab first."""
    lab_pending = _reviewer_has_lab_work(project_id)
    review_work = _reviewer_has_review_work(project_id, pending)
    manual = bool(_read_manual_lab(project_id)[1])
    if lab_pending and not (review_work and manual):
        return "lab"
    if review_work and is_lab_mode(_read_dynamic_verify_mode(project_id)):
        if not lab_bring_up_failed(project_id) and lab_setup_finished(project_id):
            _prepare_lab_for_review(project_id)
            if _reviewer_has_lab_work(project_id):
                return "lab"
    if review_work:
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
        "audit_mode_hint": audit_mode_initial_hint(mode, custom_name=custom_name or None),
    }


def _target_kind_vars(project_id: int) -> dict[str, str]:
    kind = _read_target_kind(project_id)
    return {
        "target_kind": kind,
        "target_kind_label": target_kind_label(kind),
        "target_kind_hint": target_kind_initial_hint(kind),
    }


def _agent_prompt_vars(project_id: int) -> dict[str, str]:
    return {**_audit_mode_vars(project_id), **_target_kind_vars(project_id)}


def _target_kind_overlay(project_id: int) -> str:
    kind = _read_target_kind(project_id)
    return load_prompt(f"target_kinds/{kind}.md").strip()


_POC_PROMPT_PHASES = frozenset(
    {"worker.md", "fast_worker.md", "bypass_worker.md", "worker-unconstrained.md", "reviewer.md", "verifier.md"}
)
_REPORT_FORMAT_PHASES = frozenset(
    {"worker.md", "fast_worker.md", "bypass_worker.md", "worker-unconstrained.md", "reviewer.md"}
)
_WORKER_HINT_PHASES = frozenset({"worker", "fast-worker", "bypass-worker", "unconstrained-worker"})
_RECON_HINT_PHASES = frozenset(
    {"recon", "recon-source-ext", "recon-old-vuln", "recon-old-vuln-ghsa", "recon-mark"}
)
_LAB_HINT_PHASES = frozenset({"reviewer-lab"})


def _phase_system_prompt(
    project_id: int,
    name: str,
    *,
    verify_mode: str | None = None,
) -> str:
    base = load_prompt(name).rstrip()
    if name == "worker-unconstrained.md":
        overlay = load_prompt("modes/bounty.md").strip()
        path_overlay = load_prompt("mining_paths/unconstrained.md").strip()
        parts = [base, overlay, path_overlay, _target_kind_overlay(project_id)]
        if name in _POC_PROMPT_PHASES:
            parts.append(load_prompt("poc.md").strip())
        if name in _REPORT_FORMAT_PHASES:
            parts.append(load_prompt("report-formats.md").strip())
        return "\n\n".join(p for p in parts if p) + "\n"
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
    parts = [base, overlay, _target_kind_overlay(project_id)]
    if name in _POC_PROMPT_PHASES:
        parts.append(load_prompt("poc.md").strip())
    if name in _REPORT_FORMAT_PHASES:
        parts.append(load_prompt("report-formats.md").strip())
    if name == "reviewer.md":
        parts.append(load_prompt("cvss.md").strip())
        chosen = verify_mode if verify_mode is not None else _read_dynamic_verify_mode(project_id)
        if chosen == VERIFY_MODE_OFF:
            parts.append(load_prompt("verify/static.md").strip())
        elif chosen == VERIFY_MODE_HARNESS:
            parts.append(load_prompt("verify/harness.md").strip())
        elif chosen == VERIFY_MODE_LAB:
            parts.append(load_prompt("verify/lab.md").strip())
    return "\n\n".join(p for p in parts if p) + "\n"


def _reviewer_verify_gate(*, force_static: bool, mode: str) -> str:
    if force_static or mode == VERIFY_MODE_OFF:
        return _STATIC_VERIFY_GATE
    if mode == VERIFY_MODE_HARNESS:
        return _HARNESS_VERIFY_GATE
    return _LAB_VERIFY_GATE


def _timeout_forced_static_note(streak: int) -> str:
    threshold = review_timeouts_before_static()
    return (
        f"本条漏洞已连续超时 {streak} 轮（阈值 {threshold}），系统已强制本轮仅静态审核；"
        "失败后仅此一轮重试，须本轮立刻 ConfirmVuln(evidence_level=static_only) 或 MarkFalsePositive 收口。"
        "忽略上一轮未完成的动态环境、认证或路由排查。"
        "不要重复读报告，也不要再查登录/路由/容器。"
        "若 Docker 靶场假就绪（容器在跑但业务入口 404/无法登录等），"
        "调用 RequestLabRebuild 交回搭建，不要空转修容器。"
        f"\n{_STATIC_REVIEW_NOTE}"
    )


def _give_up_exhausted_review(project_id: int, vuln_id: int | None) -> bool:
    """If this pending vuln already used its timeout retry, mark FP and return True."""
    if vuln_id is None:
        return False
    from ..tools.phase_reviewer import mark_timeout_give_up

    with SessionLocal() as db:
        vuln = db.get(Vuln, int(vuln_id))
        if not vuln or vuln.project_id != project_id:
            return False
        if vuln.status != "pending_review":
            return False
        streak = int(vuln.review_timeout_streak or 0)
        if not review_timeouts_exhausted(streak):
            return False
        mark_timeout_give_up(vuln, streak)
        db.commit()
    live_log.system(
        project_id,
        f"漏洞 #{vuln_id} 审核超时已重试一轮仍未收口，已标误报",
        phase="reviewer",
    )
    return True


def _reviewer_round_verify(
    project_id: int, *, timeout_streak: int
) -> tuple[str, dict[str, Any], str, bool]:
    """lab_note, debug_plan, system_prompt, force_static."""
    force_static = static_after_review_timeouts(timeout_streak) or lab_bring_up_failed(project_id)
    if force_static:
        if lab_bring_up_failed(project_id):
            reason = str(load_env(project_id).get("bring_up_fail_reason") or "").strip()
            extra = f"失败原因：{reason}\n" if reason else ""
            lab_note = f"{extra}{_BRINGUP_FAILED_NOTE}"
            debug_plan = {
                "enabled": False,
                "preferred": "static_only",
                "reason": "lab_bring_up_failed",
            }
        else:
            lab_note = _timeout_forced_static_note(timeout_streak)
            debug_plan = {
                "enabled": False,
                "preferred": "static_only",
                "reason": "consecutive_review_timeouts",
            }
        system = _phase_system_prompt(project_id, "reviewer.md", verify_mode=VERIFY_MODE_OFF)
        return lab_note, debug_plan, system, True
    lab_note = _reviewer_lab_note(project_id)
    mode = _read_dynamic_verify_mode(project_id)
    if mode == VERIFY_MODE_OFF:
        debug_plan = {"enabled": False, "preferred": "static_only"}
    elif mode == VERIFY_MODE_HARNESS:
        debug_plan = harness_debug_plan()
    else:
        debug_plan = {**reviewer_debug_plan(project_id), "enabled": True}
    return lab_note, debug_plan, _phase_system_prompt(project_id, "reviewer.md"), False


def _note_reviewer_round_end(project_id: int, vuln_id: int | None, result: Any) -> None:
    """Count consecutive timeouts on a pending vuln; reset after a verdict."""
    if vuln_id is None:
        return
    review_done = bool((getattr(result, "state", None) or {}).get("review_done"))
    timed_out = bool(getattr(result, "timed_out", False)) or getattr(result, "stop_reason", "") == "timeout"
    with SessionLocal() as db:
        vuln = db.get(Vuln, int(vuln_id))
        if not vuln or vuln.project_id != project_id:
            return
        if review_done:
            vuln.review_timeout_streak = 0
            db.commit()
            return
        if not timed_out:
            return
        streak = int(vuln.review_timeout_streak or 0) + 1
        vuln.review_timeout_streak = streak
        abandoned = False
        if review_timeouts_exhausted(streak) and vuln.status == "pending_review":
            from ..tools.phase_reviewer import mark_timeout_give_up

            mark_timeout_give_up(vuln, streak)
            abandoned = True
        db.commit()
    threshold = review_timeouts_before_static()
    if abandoned:
        live_log.system(
            project_id,
            f"漏洞 #{vuln_id} 审核超时已重试一轮仍未收口，已标误报",
            phase="reviewer",
        )
    elif streak >= threshold:
        live_log.system(
            project_id,
            f"漏洞 #{vuln_id} 已连续超时 {streak} 轮，下一轮强制仅静态审核（仅此一轮重试）",
            phase="reviewer",
        )
    else:
        live_log.system(
            project_id,
            f"漏洞 #{vuln_id} 审核超时（连续 {streak}/{threshold}）",
            phase="reviewer",
        )


def _conversation_hint_block(project_id: int, phase: str) -> str:
    from .conversation_archive import db_phase_to_log_phase

    lp = db_phase_to_log_phase(phase)
    text = _pending_conversation_message.pop((project_id, lp), "")
    if not text:
        return ""
    return (
        "## 用户对话指示\n"
        "以下为用户在本小阶段新开或接续对话时提供的额外说明。请在本轮分析中参考；"
        "不要因此偏离本轮焦点任务。\n\n"
        f"{text}\n\n"
    )


def _set_conversation_message(project_id: int, log_phase: str, message: str) -> None:
    from .conversation_archive import normalize_log_phase

    text = (message or "").strip()
    if text:
        _pending_conversation_message[(project_id, normalize_log_phase(log_phase))] = text


def _log_phase_control(log_phase: str) -> str:
    from .conversation_archive import normalize_log_phase

    lp = normalize_log_phase(log_phase)
    if lp.startswith("recon"):
        return "recon"
    if lp in ("mine", "fast", "bypass", "fix"):
        return "worker"
    if lp.startswith("reviewer"):
        return "reviewer"
    if lp == "verifier":
        return "verifier"
    if lp == "attack_chain":
        return "attack_chain"
    return control_phase(lp)


def _append_continue_user_message(cp: LoopCheckpoint, message: str) -> None:
    if message:
        content = f"## 用户接续指示\n{message}\n\n请从中断处继续。"
    else:
        content = "用户请求接续此对话，请从中断处继续。"
    cp.messages = list(cp.messages) + [{"role": "user", "content": content}]


def request_conversation_continue(project_id: int, log_phase: str, message: str = "") -> dict[str, Any]:
    """Resume the latest conversation for a log sub-phase from checkpoint or archive."""
    from .conversation_archive import load_archived, log_phase_to_db_phases, normalize_log_phase

    lp = normalize_log_phase(log_phase)
    cp: LoopCheckpoint | None = None
    run_id: int | None = None
    for db_phase in log_phase_to_db_phases(lp):
        for pr in list_resumable_runs(project_id, db_phase):
            loaded = load_checkpoint(project_id, pr.id)
            if loaded and loaded.messages:
                cp = loaded
                run_id = pr.id
                break
        if cp:
            break
    from_archive = False
    if not cp:
        cp = load_archived(project_id, lp)
        from_archive = cp is not None
    if not cp:
        raise ValueError("没有可接续的对话")

    _append_continue_user_message(cp, message)
    if from_archive:
        run_id = _new_phase_run(
            project_id,
            cp.phase,
            cp.role,
            worker_id=cp.worker_id,
            vuln_id=cp.vuln_id,
            file_path=cp.file_path,
        )
        cp.phase_run_id = run_id
    else:
        assert run_id is not None
        cp.phase_run_id = run_id
    save_checkpoint(cp, status="running")
    set_phase_run_status(run_id, "running")

    control = _log_phase_control(lp)
    was_paused = _pause_event(project_id).is_set()
    _pause_event(project_id).clear()
    _phase_pause_event(project_id, control).clear()
    cancel = _cancel_event(project_id)
    if cancel.is_set():
        cancel.clear()
    if not was_paused:
        _set_project_running(project_id)
    elif control != "recon":
        for p in CONTROL_PHASES:
            if p != control:
                _phase_pause_event(project_id, p).set()
        with SessionLocal() as db:
            proj = db.get(Project, project_id)
            if proj and proj.status == "paused":
                proj.status = "recon" if not proj.recon_done else "auditing"
                proj.error = None
                db.commit()

    live_log.system(project_id, f"用户接续对话（{lp}）", phase=cp.phase, role=cp.role)
    start_audit(project_id)
    return {"ok": True, "action": "continue", "log_phase": lp, **get_phase_states(project_id)}


def request_conversation_new(project_id: int, log_phase: str, message: str = "") -> dict[str, Any]:
    """Start a fresh conversation round for a log sub-phase."""
    from .conversation_archive import clear_archived, log_phase_to_db_phases, normalize_log_phase
    from .conversation_steer import is_loop_running

    lp = normalize_log_phase(log_phase)
    _set_conversation_message(project_id, lp, message)

    if lp == "recon-map":
        if not recon_map_ready(project_id):
            raise ValueError("地图/鉴权尚未完成，完成后才能新开更新")
        return request_recon_subphase_rerun(project_id, "map")
    if lp == "recon-old-vuln":
        if not recon_old_vulns_ready(project_id):
            raise ValueError("历史漏洞尚未完成，完成后才能新开更新")
        return request_recon_subphase_rerun(project_id, "old_vulns")
    if lp == "reviewer-lab":
        if not is_lab_mode(_read_dynamic_verify_mode(project_id)):
            raise ValueError("仅靶场动态验证模式可新开环境搭建")
        if is_loop_running(project_id, lp):
            _abandon_db_phase_runs(project_id, ("reviewer-lab",), reason="用户新开环境搭建")
            _bump_phase_generation(project_id, "reviewer")
            reset_lab_setup_for_retry(project_id, message)
            _force_new_run.add((project_id, "reviewer"))
        elif lab_setup_failed(project_id) and lab_setup_finished(project_id):
            return request_lab_setup_retry(project_id, message)
        elif not lab_setup_finished(project_id):
            raise ValueError("环境搭建正在进行中，请使用引导")
        else:
            _abandon_db_phase_runs(project_id, ("reviewer-lab",), reason="用户新开环境搭建")
            reset_lab_setup_for_retry(project_id, message)
            _force_new_run.add((project_id, "reviewer"))
        was_paused = _pause_event(project_id).is_set()
        _phase_pause_event(project_id, "reviewer").clear()
        cancel = _cancel_event(project_id)
        if cancel.is_set():
            cancel.clear()
        if not was_paused:
            _set_project_running(project_id)
        live_log.system(project_id, "用户新开环境搭建对话", phase="reviewer-lab", role="reviewer_lab")
        _ensure_reviewer(project_id, cancel)
        return {"ok": True, "action": "new", "log_phase": lp, **get_phase_states(project_id)}

    db_phases = log_phase_to_db_phases(lp)
    control = _log_phase_control(lp)

    if is_loop_running(project_id, lp):
        _abandon_db_phase_runs(project_id, db_phases, reason="用户新开对话")
        _bump_phase_generation(project_id, control)

    _force_new_run.add((project_id, control))
    clear_archived(project_id, lp)
    for db_phase in db_phases:
        _abandon_db_phase_runs(project_id, (db_phase,), reason="用户新开对话")

    was_paused = _pause_event(project_id).is_set()
    _pause_event(project_id).clear()
    _phase_pause_event(project_id, control).clear()
    cancel = _cancel_event(project_id)
    if cancel.is_set():
        cancel.clear()
    if not was_paused:
        _set_project_running(project_id)
    else:
        for p in CONTROL_PHASES:
            if p != control:
                _phase_pause_event(project_id, p).set()
        with SessionLocal() as db:
            proj = db.get(Project, project_id)
            if proj and proj.status == "paused":
                proj.status = "recon" if control == "recon" and not proj.recon_done else "auditing"
                if control == "recon" and not proj.recon_done:
                    proj.status = "recon"
                proj.error = None
                db.commit()

    live_log.system(project_id, f"用户新开对话（{lp}）", phase=db_phases[0] if db_phases else lp)
    start_audit(project_id)
    return {"ok": True, "action": "new", "log_phase": lp, **get_phase_states(project_id)}


def _worker_hint_block(project_id: int) -> str:
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        text = str(getattr(proj, "worker_hint", None) or "").strip() if proj else ""
    if not text:
        return ""
    return (
        "## 项目人工提示（每轮都会注入）\n"
        "以下为用户为本项目挖掘 Worker 配置的额外提示。请在本轮分析中参考；"
        "不要因此改去挖未注入的焦点，也不要偏离本轮文件 / Sink / 历史漏洞。\n\n"
        f"{text}\n\n"
    )


def _recon_hint_block(project_id: int) -> str:
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        text = str(getattr(proj, "recon_hint", None) or "").strip() if proj else ""
    if not text:
        return ""
    return (
        "## 项目 Recon 提示（每轮都会注入）\n"
        "以下为用户为本项目侦察阶段配置的额外提示。请在本轮侦察中参考；"
        "不要因此跳过本轮门闩任务（地图/鉴权、扩展名、历史漏洞、盖章）。\n\n"
        f"{text}\n\n"
    )


def _lab_retry_hint_block(project_id: int) -> str:
    env = load_env(project_id)
    text = str(env.get("retry_user_message") or "").strip()
    if lab_rebuild_requested(project_id):
        body = (
            "## Reviewer 交回搭建\n"
            "审核判定当前靶场假就绪（容器在跑但业务入口不可用）。"
            "不要只 docker start 应用容器后直接 FinishLab。"
            "先用 compose 拉起依赖 sidecar，再确认业务 URL（登录页/门户/健康检查等）真正可访问；"
            "无法修复则 FinishLab(skipped=true, reason=...)。\n\n"
        )
        if text:
            body += f"{text}\n\n"
        return body
    if not text:
        return ""
    return (
        "## 用户续跑指示\n"
        "用户因环境搭建超时/重试用尽而请求再次搭建靶场。请优先按以下方向继续：\n\n"
        f"{text}\n\n"
    )


def _lab_initial_prompt_doc(project_id: int) -> str:
    env = load_env(project_id)
    if lab_rebuild_requested(project_id):
        return "reviewer-lab-rebuild.md"
    if _truthy(env.get("user_retry_requested")):
        return "reviewer-lab-user-retry.md"
    return "reviewer-lab.md"


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


def _initial_prompt(name: str, **kwargs: object) -> str:
    """Render a user-message document from prompts/initial/ and inject it as-is."""
    kwargs.setdefault("audit_mode", "bounty")
    kwargs.setdefault("audit_mode_label", audit_mode_label("bounty"))
    kwargs.setdefault("audit_mode_hint", audit_mode_initial_hint("bounty"))
    kwargs.setdefault("target_kind", "web")
    kwargs.setdefault("target_kind_label", target_kind_label("web"))
    kwargs.setdefault("target_kind_hint", target_kind_initial_hint("web"))
    kwargs.setdefault("prior_basis", "static_only")
    kwargs.setdefault("prior_conclusion", "静态结论")
    kwargs.setdefault("unconstrained_note", "")
    return render_prompt(f"initial/{name}", **kwargs)


def _prompt_with_summary(phase: str, project_id: int, body: str, *, for_file: bool = False) -> str:
    summary = latest_summary(project_id, phase)
    # Also try rescue / round variants for worker
    if not summary and phase == "worker":
        summary = latest_summary(project_id, "worker-rescue") or latest_summary(project_id, "worker-round")
    if not summary and phase == "unconstrained-worker":
        summary = (
            latest_summary(project_id, "unconstrained-worker-rescue")
            or latest_summary(project_id, "unconstrained-round")
        )
    block = inject_summary_block(summary, for_file=for_file)
    text = f"{block}{body}" if block else body
    if phase == "worker" and for_file:
        prior = inject_worker_prior_block(project_id)
        if prior:
            text = f"{prior}{text}"
    if phase == "unconstrained-worker":
        prior = inject_unconstrained_prior_block(project_id)
        if prior:
            text = f"{prior}{text}"
    if phase == "reviewer":
        policy = inject_security_policy_block(project_id)
        if policy:
            text = f"{policy}{text}"
    conv = _conversation_hint_block(project_id, phase)
    if conv:
        text = f"{text.rstrip()}\n\n{conv}"
    if phase in _WORKER_HINT_PHASES:
        hint = _worker_hint_block(project_id)
        if hint:
            text = f"{text.rstrip()}\n\n{hint}"
    if phase in _RECON_HINT_PHASES:
        hint = _recon_hint_block(project_id)
        if hint:
            text = f"{text.rstrip()}\n\n{hint}"
    if phase in _LAB_HINT_PHASES:
        hint = _lab_retry_hint_block(project_id)
        if hint:
            text = f"{text.rstrip()}\n\n{hint}"
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
    for pr in list_resumable_runs(project_id, phase):
        key = (project_id, pr.id)
        if vuln_id is not None and pr.vuln_id != vuln_id:
            continue
        with _lock:
            if key in _adopted_phase_runs:
                continue
            _adopted_phase_runs.add(key)
        cp = load_checkpoint(project_id, pr.id)
        if not cp:
            with _lock:
                _adopted_phase_runs.discard(key)
            continue
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
    from .decompile_store import app_db_write

    with app_db_write():
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
            already = True
        else:
            already = False
            t = threading.Thread(
                target=_orchestrate,
                args=(project_id,),
                daemon=True,
                name=name,
            )
            _threads.setdefault(project_id, []).append(t)
    if already:
        _resume_orphaned_decompile(project_id)
        return
    t.start()
    _resume_orphaned_decompile(project_id)


def _resume_orphaned_decompile(project_id: int) -> None:
    """Ask the decompile sidecar to re-queue leftover jadx jobs."""
    from .decompile_java import schedule_decompile_resume

    schedule_decompile_resume(project_id)


def recover_inflight_projects() -> None:
    """Called on process startup to resume interrupted audits."""
    from ..models import ensure_schema

    ensure_schema()
    with SessionLocal() as db:
        paused_ids = [
            int(pid) for (pid,) in db.query(Project.id).filter(Project.status == "paused").all()
        ]
        projects = (
            db.query(Project)
            .filter(Project.status.in_(("recon", "auditing", "reviewing", "ingesting")))
            .all()
        )
        ids = [(p.id, p.status) for p in projects]
    for pid in paused_ids:
        _pause_event(pid).set()
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


def _stop_lab_on_project_complete(project_id: int) -> None:
    """Best-effort stop of lab web container and compose sidecars after audit finishes."""
    try:
        if not docker_available():
            return
        if not load_env(project_id):
            return
        result = stop_lab(project_id, via="project-complete")
        if result.get("ok"):
            live_log.system(project_id, "项目完成，已自动停止靶场容器")
        elif result.get("error"):
            live_log.system(project_id, f"自动停止靶场失败: {result['error']}")
    except Exception as e:  # noqa: BLE001
        live_log.error(project_id, f"自动停止靶场异常: {e}")


def _maybe_complete_project(
    project_id: int,
    *,
    reviewer_busy: bool,
    fix_busy: bool,
    verifier_busy: bool = False,
    attack_chain_busy: bool = False,
) -> bool:
    if reviewer_busy or fix_busy or verifier_busy or attack_chain_busy:
        return False
    if list_resumable_runs(project_id, "reviewer") or list_resumable_runs(
        project_id, "reviewer-lab"
    ):
        return False
    if list_resumable_runs(project_id, "attack_chain"):
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
    threading.Thread(
        target=_stop_lab_on_project_complete,
        args=(project_id,),
        name=f"lab-stop-{project_id}",
        daemon=True,
    ).start()
    return True


def _refresh_project_after_reviewer(project_id: int) -> None:
    """Clear leftover reviewing when the review queue is empty."""
    if (
        _reviewer_has_lab_work(project_id)
        or _reviewer_has_review_work(project_id)
    ):
        return
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        if not proj or proj.status in ("completed", "cancelled", "error", "paused"):
            return
    with _lock:
        fix_busy = bool(_fix_inflight.get(project_id))
        verifier_busy = bool(_verifier_inflight.get(project_id))
        attack_chain_busy = bool(_attack_chain_inflight.get(project_id))
    if _maybe_complete_project(
        project_id,
        reviewer_busy=False,
        fix_busy=fix_busy,
        verifier_busy=verifier_busy,
        attack_chain_busy=attack_chain_busy,
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
        from ..tools.phase_attack_chain import (
            attack_chain_ready,
            reclaim_premature_attack_chain_done,
        )

        reclaim_premature_attack_chain_done(project_id)
        chain_work = attack_chain_ready(project_id)
        proj.status = "auditing"
        if chain_work or attack_chain_busy:
            proj.phase = "attack_chain"
        elif verifier_work or verifier_busy:
            proj.phase = "verifier"
        else:
            proj.phase = "worker"
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


def _ensure_recon_marking(project_id: int) -> None:
    """Stamp newly ingested files (e.g. late decompiled classes) even after recon_done."""
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        if not proj or proj.status in ("completed", "cancelled", "error"):
            return
        recon_done = bool(proj.recon_done)
    if _phase_is_paused(project_id, "recon"):
        return
    if not recon_done and not recon_old_vulns_ready(project_id):
        return
    if not has_unmarked_files(project_id):
        return
    if recon_done:
        from .llm_thread import llm_thread_limiter

        used, limit, waiting = llm_thread_limiter.snapshot()
        if waiting > 0 or used >= max(1, int(limit) - 1):
            return
    cancel = _cancel_event(project_id)
    with _lock:
        rt = _recon_threads.get(project_id)
        if rt is not None and rt.is_alive():
            return
        mt = _recon_mark_threads.get(project_id)
        if mt is not None and mt.is_alive():
            return
        t = threading.Thread(
            target=_run_recon_marking,
            args=(project_id, cancel),
            daemon=True,
            name=f"vh-recon-mark-{project_id}",
        )
        _recon_mark_threads[project_id] = t
        _threads.setdefault(project_id, []).append(t)
    live_log.system(project_id, "拉起盖章（待标记文件，含新入库反编译类）", phase="recon-mark", role="recon_mark")
    t.start()


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
            if (
                not _reviewer_has_lab_work(project_id)
                and not _reviewer_has_review_work(project_id, pending)
            ):
                _refresh_project_after_reviewer(project_id)
                cancel.wait(timeout=5.0)
                continue
            with _lock:
                _reviewer_inflight[project_id] = True
            try:
                step = _next_reviewer_step(project_id, pending)
                if step == "lab":
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


def _ensure_verifier(
    project_id: int,
    cancel: threading.Event,
    *,
    allow_completed: bool = False,
) -> None:
    from .verifier import is_verifier_enabled, pending_verifier_count

    if not is_verifier_enabled(project_id):
        return
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        if not proj:
            return
        if proj.status in ("cancelled", "error"):
            return
        if proj.status == "completed" and not allow_completed:
            # Still allow if a consented checkpoint is waiting to resume.
            if not list_resumable_runs(project_id, "verifier"):
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
            args=(project_id, allow_completed),
            daemon=True,
            name=f"vh-verifier-{project_id}",
        )
        _verifier_threads[project_id] = vt
        _threads.setdefault(project_id, []).append(vt)
    live_log.system(project_id, "拉起 Verifier 线程")
    vt.start()


def _run_verifier_loop(project_id: int, allow_completed: bool = False) -> None:
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
                    if not proj or proj.status in ("cancelled", "error"):
                        return
                    if proj.status == "completed" and not (
                        allow_completed or list_resumable_runs(project_id, "verifier")
                    ):
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


def _ensure_attack_chain(project_id: int, cancel: threading.Event) -> None:
    from ..tools.phase_attack_chain import (
        attack_chain_ready,
        confirmed_vuln_count,
        is_attack_chain_done,
        is_attack_chain_enabled,
        mark_attack_chain_done,
        reclaim_premature_attack_chain_done,
    )

    if not is_attack_chain_enabled(project_id):
        return
    reclaim_premature_attack_chain_done(project_id)
    if is_attack_chain_done(project_id):
        return
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        if not proj or proj.status in ("completed", "cancelled", "error"):
            return
    if _phase_is_paused(project_id, "attack_chain"):
        return
    # force_new only skips an old checkpoint; it must not start before mining/review settle.
    if not attack_chain_ready(project_id):
        return
    # Ready but fewer than 2 confirmed → skip without LLM.
    if confirmed_vuln_count(project_id) < 2:
        if not list_resumable_runs(project_id, "attack_chain"):
            mark_attack_chain_done(project_id, reason="已确认漏洞少于 2 条，跳过串联")
            return
    with _lock:
        t = _attack_chain_threads.get(project_id)
        if t is not None and t.is_alive():
            return
        at = threading.Thread(
            target=_run_attack_chain_loop,
            args=(project_id,),
            daemon=True,
            name=f"vh-attack-chain-{project_id}",
        )
        _attack_chain_threads[project_id] = at
        _threads.setdefault(project_id, []).append(at)
    live_log.system(project_id, "拉起攻击链串联线程")
    at.start()


def _run_attack_chain_loop(project_id: int) -> None:
    from ..tools.phase_attack_chain import (
        attack_chain_ready,
        confirmed_vuln_count,
        is_attack_chain_done,
        is_attack_chain_enabled,
        mark_attack_chain_done,
        reclaim_premature_attack_chain_done,
    )

    cancel = _cancel_event(project_id)
    try:
        while not cancel.is_set():
            if not _wait_if_paused(project_id, _loop_cancel(project_id, "attack_chain"), "attack_chain"):
                break
            if not is_attack_chain_enabled(project_id):
                break
            reclaim_premature_attack_chain_done(project_id)
            if is_attack_chain_done(project_id):
                break
            try:
                with SessionLocal() as db:
                    proj = db.get(Project, project_id)
                    if not proj or proj.status in ("completed", "cancelled", "error"):
                        return
                ready = attack_chain_ready(project_id)
            except OperationalError as e:
                if _is_sqlite_locked(e):
                    cancel.wait(timeout=_DB_LOCK_RETRY_SECONDS)
                    continue
                raise
            if not ready:
                cancel.wait(timeout=5.0)
                continue
            if confirmed_vuln_count(project_id) < 2 and not list_resumable_runs(project_id, "attack_chain"):
                mark_attack_chain_done(project_id, reason="已确认漏洞少于 2 条，跳过串联")
                break
            with _lock:
                _attack_chain_inflight[project_id] = True
            try:
                _run_attack_chain_once(project_id)
            finally:
                with _lock:
                    _attack_chain_inflight[project_id] = False
            if is_attack_chain_done(project_id):
                break
    except Exception as e:  # noqa: BLE001
        live_log.error(project_id, f"攻击链线程异常: {e}", phase="attack_chain")
        with _lock:
            _attack_chain_inflight[project_id] = False


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
        unaudited_weighted = q.limit(1).first() is not None
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
        not unaudited_weighted
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


def _ensure_unconstrained_workers(
    project_id: int,
    active_workers: list[threading.Thread],
) -> list[threading.Thread]:
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        if not proj or proj.status in ("completed", "cancelled", "error"):
            return [t for t in active_workers if t.is_alive()]
        unconstrained_on = bool(getattr(proj, "unconstrained_enabled", False))
        status = proj.status
    if _phase_is_paused(project_id, "worker"):
        return [t for t in active_workers if t.is_alive()]
    alive = [t for t in active_workers if t.is_alive()]
    if not unconstrained_on:
        return alive
    if not recon_old_vulns_ready(project_id):
        return alive
    if unconstrained_complete(project_id) and not list_resumable_runs(project_id, "unconstrained-worker"):
        return alive
    if project_complete_gates(project_id):
        return alive
    while len(alive) < 1:
        wid = f"unconstrained-{uuid.uuid4().hex[:6]}"
        wt = threading.Thread(
            target=_run_unconstrained_worker_loop,
            args=(project_id, wid),
            daemon=True,
            name=f"vh-{wid}",
        )
        alive.append(wt)
        with _lock:
            _threads.setdefault(project_id, []).append(wt)
        live_log.system(project_id, f"启动无约束扫描 Worker {wid}", phase="unconstrained-worker")
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
    active_unconstrained_workers: list[threading.Thread] = []
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
                _ensure_recon_marking(project_id)

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
                active_unconstrained_workers = _ensure_unconstrained_workers(
                    project_id, active_unconstrained_workers
                )

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
                _ensure_attack_chain(project_id, cancel)
                _refresh_project_after_reviewer(project_id)

                with _lock:
                    fix_busy = bool(_fix_inflight.get(project_id))
                    reviewer_busy = bool(_reviewer_inflight.get(project_id))
                    verifier_busy = bool(_verifier_inflight.get(project_id))
                    attack_chain_busy = bool(_attack_chain_inflight.get(project_id))

                if _maybe_complete_project(
                    project_id,
                    reviewer_busy=reviewer_busy,
                    fix_busy=fix_busy,
                    verifier_busy=verifier_busy,
                    attack_chain_busy=attack_chain_busy,
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


def _wait_business_jar_ingest_gate(project_id: int, cancel: threading.Event) -> bool:
    """Nudge the decompile sidecar; marking proceeds on already-indexed files."""
    from .decompile_java import (
        business_jar_decompile_pending,
        business_jar_map_ready,
        load_business_jar_state,
        schedule_decompile_resume,
        schedule_jar_ingest,
    )

    if cancel.is_set():
        return False
    if not business_jar_map_ready(project_id):
        return True
    state = load_business_jar_state(project_id)
    paths = list(state.get("paths") or [])
    if not paths:
        return True
    schedule_decompile_resume(project_id)
    schedule_jar_ingest(project_id)
    pending = business_jar_decompile_pending(project_id)
    leftover = max(0, len(paths) - len(load_business_jar_state(project_id).get("ingested") or []))
    if leftover or pending:
        extra = f"，其余 {leftover} 个仍待入库，盖章先处理已有文件" if leftover else "，盖章先处理已有文件"
        live_log.system(
            project_id,
            f"已点名 {len(paths)} 个业务 jar，入库由反编译服务异步完成{extra}",
            phase="recon-mark",
            role="recon_mark",
        )
    return True


def _run_recon(project_id: int) -> None:
    """Run recon sub-phases strictly in series: map/auth → source-ext → old vulns → mark."""
    cancel = _cancel_event(project_id)
    try:
        # Step 1: Code-based pre-filtering with broader extension coverage
        prefilt = prefilter_extensions(project_id)
        active_exts = prefilt.get("active_exts", [])
        noisy_exts = prefilt.get("noisy_exts", [])
        skipped_count = prefilt.get("skipped_count", 0)

        if prefilt.get("counts"):
            counts_msg = ", ".join(
                f"{ext}: {cnt}" for ext, cnt in sorted(prefilt["counts"].items(), key=lambda x: -x[1])[:10]
            )
            if len(prefilt["counts"]) > 10:
                counts_msg += "..."
            live_log.system(
                project_id,
                f"扩展名预筛选：有效 {len(active_exts)} 种，噪音 {len(noisy_exts)} 种，跳过 {skipped_count} 个文件",
                phase="recon-source-ext",
            )
        if prefilt.get("noisy_exts"):
            live_log.system(
                project_id,
                f"噪音扩展名（Agent 可恢复）：{', '.join(noisy_exts)}",
                phase="recon-source-ext",
            )

        # Build initial file index with pre-filtered extensions
        if active_exts:
            from ..services.ingest import SOURCE_EXTS

            final_exts = list(SOURCE_EXTS) + active_exts
            initial_count = build_file_index_with_exts(project_id, final_exts)
            if initial_count > 0:
                live_log.system(
                    project_id,
                    f"预筛选入库 {initial_count} 个文件",
                    phase="recon-source-ext",
                )

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
        if not _wait_business_jar_ingest_gate(project_id, cancel):
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
    try:
        from .decompile_java import enqueue_heuristic_candidates

        queued = enqueue_heuristic_candidates(project_id)
        if queued:
            live_log.system(
                project_id,
                f"已启发式入队 {len(queued)} 个 Java 反编译任务",
                phase="recon",
                role="recon",
            )
    except Exception as e:  # noqa: BLE001
        live_log.system(project_id, f"反编译启发式入队跳过: {e}", phase="recon", role="recon")
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
    tk = _target_kind_overlay(project_id)
    if tk:
        system = f"{system.rstrip()}\n\n{tk}\n"
    vars_ = {
        "project_id": project_id,
        **_target_kind_vars(project_id),
        **(prompt_vars or {}),
    }
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


def _chunk_list(paths: list[str], chunk_size: int) -> list[list[str]]:
    """Split a list into chunks of at most chunk_size elements."""
    return [paths[i : i + chunk_size] for i in range(0, len(paths), chunk_size)]


def _run_recon_marking(project_id: int, cancel: threading.Event) -> None:
    system = load_prompt("recon-mark.md")
    tk = _target_kind_overlay(project_id)
    if tk:
        system = f"{system.rstrip()}\n\n{tk}\n"
    llm = resolve_llm("recon", project_id=project_id)
    batch_size = max(1, int(settings.recon_mark_batch_size))
    sub_batch_size = max(1, int(settings.recon_mark_sub_batch_size))
    while not cancel.is_set():
        if not _wait_if_paused(project_id, _loop_cancel(project_id, "recon"), "recon"):
            return
        skipped_hidden = skip_non_source_weight_rows(project_id)
        if skipped_hidden:
            live_log.system(
                project_id,
                f"侦察盖章：已自动跳过 {skipped_hidden} 个隐藏/生成文件",
                phase="recon-mark",
                role="recon_mark",
            )
        from .decompile_java import schedule_jar_ingest

        schedule_jar_ingest(project_id)
        if recon_gates_met(project_id):
            return
        cp = _adopt_resumable(project_id, "recon-mark")
        if cp:
            try:
                paths = [str(p) for p in (cp.state.get("mark_paths") or []) if p]
                if paths and paths_fully_marked(project_id, paths):
                    _finish_phase_run(cp.phase_run_id, "completed")
                    live_log.system(
                        project_id,
                        f"侦察盖章轮完成：{len(paths)} 个文件",
                        phase="recon-mark",
                        role="recon_mark",
                    )
                    continue
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
        # Split into sub-batches to avoid LLM input truncation.
        sub_batches = _chunk_list(batch, sub_batch_size)
        for sub_idx, sub_batch in enumerate(sub_batches):
            if cancel.is_set():
                return
            if not _wait_if_paused(project_id, _loop_cancel(project_id, "recon"), "recon"):
                return
            sub_lines = "\n".join(f"- {p}" for p in sub_batch)
            user = _prompt_with_summary(
                "recon-mark",
                project_id,
                _initial_prompt(
                    "recon-mark.md",
                    project_id=project_id,
                    marked=marked,
                    total=total,
                    batch_count=len(sub_batch),
                    paths=sub_lines,
                    **_target_kind_vars(project_id),
                ),
            )
            sub_extra = f"盖章 {len(sub_batch)} 个文件（{sub_idx + 1}/{len(sub_batches)}），剩余 {unmarked}"
            run_id = _new_phase_run(project_id, "recon-mark", "recon_mark")
            if sub_idx == 0:
                _consume_force_new(project_id, "recon")
            _start_log_session(
                project_id,
                "recon-mark",
                extra=sub_extra,
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
                stop_when=lambda st, paths=list(sub_batch): paths_fully_marked(project_id, paths),
                llm=llm,
            )
            loop.state["mark_paths"] = list(sub_batch)
            result = loop.run()
            if result.stop_reason == "auth_error":
                _pause_for_auth(project_id, result.error or "auth_error")
                return
            if result.cancelled:
                _finish_phase_run(run_id, "cancelled")
                return
            done = paths_fully_marked(project_id, sub_batch)
            _finish_phase_run(
                run_id,
                "completed" if done else ("cancelled" if result.cancelled else "failed"),
                None if done else (result.error or result.stop_reason),
            )
            if not done:
                live_log.system(
                    project_id,
                    f"侦察盖章子批次未完成（{result.stop_reason}），未标记文件将在下一轮再注入",
                    phase="recon-mark",
                    role="recon_mark",
                )
                return
            # Update marked count for next sub-batch prompt.
            status = recon_gates_status(project_id)
            unmarked = int(status.get("unmarked") or 0)
            marked = max(0, total - unmarked)
        live_log.system(
            project_id,
            f"侦察盖章轮完成：{len(batch)} 个文件（{len(sub_batches)} 个子批次）",
            phase="recon-mark",
            role="recon_mark",
        )


def _project_is_terminal(project_id: int) -> bool:
    try:
        with SessionLocal() as db:
            proj = db.get(Project, project_id)
            return not proj or proj.status in ("completed", "cancelled", "error")
    except Exception:  # noqa: BLE001
        return False


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
    # Keep the checkpoint: db lock / generation bump / LLM slot wait cancelled
    # the in-memory loop, not the round. Clearing it made resume pick a new file
    # and look like "only the startup round" after restart.
    if result.stop_reason == "db_locked" or phase_restart:
        return "restart"
    failed = not (result.ok and result.state.get("round_finished"))
    if path:
        _release_claim_if_unfinished(project_id, path, worker_id, failed=failed)
    _finish_phase_run(
        run_id,
        "completed" if result.ok else ("cancelled" if result.cancelled else "failed"),
        result.error,
    )
    if result.cancelled and _cancel_event(project_id).is_set():
        return "cancel"
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
    while not cancel.is_set():
        try:
            _run_worker_loop_inner(project_id, worker_id, cancel)
        except OperationalError as e:
            if not _is_sqlite_locked(e):
                live_log.error(project_id, f"Worker={worker_id} 异常: {e}", phase="worker")
                try:
                    _release_claims(project_id, worker_id=worker_id)
                except Exception:  # noqa: BLE001
                    pass
                cancel.wait(timeout=_DB_LOCK_RETRY_SECONDS)
                continue
            live_log.system(
                project_id,
                "挖掘轮数据库忙，保留检查点稍后继续",
                phase="worker",
            )
            cancel.wait(timeout=_DB_LOCK_RETRY_SECONDS)
            continue
        except Exception as e:  # noqa: BLE001
            if _is_sqlite_locked(e):
                live_log.system(
                    project_id,
                    "挖掘轮数据库忙，保留检查点稍后继续",
                    phase="worker",
                )
                cancel.wait(timeout=_DB_LOCK_RETRY_SECONDS)
                continue
            live_log.error(project_id, f"Worker={worker_id} 异常: {e}", phase="worker")
            try:
                _release_claims(project_id, worker_id=worker_id)
            except Exception:  # noqa: BLE001
                pass
            cancel.wait(timeout=_DB_LOCK_RETRY_SECONDS)
            continue
        if cancel.is_set():
            return
        if _project_is_terminal(project_id):
            return
        if _phase_is_paused(project_id, "worker"):
            if not _wait_if_paused(project_id, cancel, "worker"):
                return
            continue
        live_log.system(
            project_id,
            "挖掘循环还要继续，重新进入下一轮",
            phase="worker",
        )
        cancel.wait(timeout=_DB_LOCK_RETRY_SECONDS)


def _run_worker_loop_inner(
    project_id: int, worker_id: str, cancel: threading.Event
) -> None:
    current_run_id: int | None = None
    try:
        while not cancel.is_set():
            if not _wait_if_paused(project_id, _loop_cancel(project_id, "worker"), "worker"):
                break
            try:
                with SessionLocal() as db:
                    proj = db.get(Project, project_id)
                    if not proj or proj.status in ("completed", "cancelled", "error"):
                        return
                old_ready = recon_old_vulns_ready(project_id)
                heur_done = heuristic_complete(project_id)
            except OperationalError as e:
                if _is_sqlite_locked(e):
                    cancel.wait(timeout=_DB_LOCK_RETRY_SECONDS)
                    continue
                raise
            if not old_ready:
                cancel.wait(timeout=5.0)
                continue
            if heur_done and not _pending_inject.get((project_id, "worker")):
                cancel.wait(timeout=5.0)
                continue

            cp = _adopt_resumable(project_id, "worker", worker_id=worker_id)
            if cp:
                path = cp.file_path
                if path:
                    _reclaim_file(project_id, path, worker_id)
                current_run_id = cp.phase_run_id
                try:
                    _start_log_session(project_id, "worker", extra=path or "接续")
                    loop = _loop_from_checkpoint(
                        cp,
                        cancel=cancel,
                        stop_when=lambda st: bool(st.get("round_finished")),
                        timeout_sec=settings.timeout_worker_round,
                    )
                    loop.worker_id = worker_id
                    _bind_worker_round_id(loop, project_id, new_round=False)
                    try:
                        result = loop.run()
                    except OperationalError as e:
                        if not _is_sqlite_locked(e):
                            raise
                        live_log.system(
                            project_id,
                            "挖掘轮数据库忙，保留检查点稍后继续",
                            phase="worker",
                        )
                        cancel.wait(timeout=_DB_LOCK_RETRY_SECONDS)
                        continue
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

            try:
                fw = _take_inject_file(project_id, worker_id) or _pick_next_file(project_id, worker_id)
            except OperationalError as e:
                if _is_sqlite_locked(e):
                    cancel.wait(timeout=_DB_LOCK_RETRY_SECONDS)
                    continue
                raise
            if fw is None:
                cancel.wait(timeout=5.0)
                continue

            sources = _sources_for_file(project_id, fw.path)
            snippet = _read_file_snippet(project_id, fw.path)
            fp_norm = str(fw.path).replace("\\", "/")
            file_path_display = fp_norm if fp_norm.startswith("workspace/") else f"src/{fp_norm}"
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
                file_path_display=file_path_display,
                weight=fw.weight,
                has_source=fw.has_source,
                sources=", ".join(sources) if sources else "（无）",
                snippet=snippet,
                **_agent_prompt_vars(project_id),
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
            try:
                result = loop.run()
            except OperationalError as e:
                if not _is_sqlite_locked(e):
                    raise
                live_log.system(
                    project_id,
                    "挖掘轮数据库忙，保留检查点稍后继续",
                    phase="worker",
                )
                cancel.wait(timeout=_DB_LOCK_RETRY_SECONDS)
                continue
            action = _finish_worker_round(project_id, worker_id, fw.path, run_id, result)
            current_run_id = None
            if action in ("interrupt", "cancel"):
                return
            if action == "restart":
                continue
    except OperationalError as e:
        if _is_sqlite_locked(e):
            raise
        live_log.error(project_id, f"Worker={worker_id} 异常: {e}", phase="worker")
        try:
            if current_run_id:
                _finish_phase_run(current_run_id, "failed", str(e))
            _release_claims(project_id, worker_id=worker_id)
        except Exception:  # noqa: BLE001
            pass
    except Exception as e:  # noqa: BLE001
        if _is_sqlite_locked(e):
            raise
        live_log.error(project_id, f"Worker={worker_id} 异常: {e}", phase="worker")
        try:
            if current_run_id:
                _finish_phase_run(current_run_id, "failed", str(e))
            _release_claims(project_id, worker_id=worker_id)
        except Exception:  # noqa: BLE001
            pass


def _next_unconstrained_round_id(project_id: int) -> int:
    from ..agent.compression import list_recent_unconstrained_round_summaries

    n_rep = max_unconstrained_round_report_no(project_id)
    summaries = list_recent_unconstrained_round_summaries(project_id, limit=-1)
    n_sum = summaries[-1][0] if summaries else 0
    return max(n_rep, n_sum) + 1


def _finish_unconstrained_round(project_id: int, worker_id: str, run_id: int, result) -> str:
    if result.stop_reason == "auth_error":
        _pause_for_auth(project_id, result.error or "auth_error")
        return "interrupt"
    phase_restart = bool(result.cancelled) and not _cancel_event(project_id).is_set()
    if result.stop_reason == "db_locked" or phase_restart:
        return "restart"
    _finish_phase_run(
        run_id,
        "completed" if result.ok else ("cancelled" if result.cancelled else "failed"),
        result.error,
    )
    if result.cancelled and _cancel_event(project_id).is_set():
        return "cancel"
    return "next"


def _run_unconstrained_worker_loop(project_id: int, worker_id: str) -> None:
    cancel = _cancel_event(project_id)
    current_run_id: int | None = None
    try:
        while not cancel.is_set():
            if not _wait_if_paused(project_id, _loop_cancel(project_id, "worker"), "worker"):
                break
            try:
                with SessionLocal() as db:
                    proj = db.get(Project, project_id)
                    if not proj or proj.status in ("completed", "cancelled", "error"):
                        return
                    unconstrained_on = bool(getattr(proj, "unconstrained_enabled", False))
                old_ready = recon_old_vulns_ready(project_id)
                path_done = unconstrained_complete(project_id)
            except OperationalError as e:
                if _is_sqlite_locked(e):
                    cancel.wait(timeout=_DB_LOCK_RETRY_SECONDS)
                    continue
                raise
            if not unconstrained_on:
                return
            if not old_ready:
                cancel.wait(timeout=5.0)
                continue

            cp = _adopt_resumable(project_id, "unconstrained-worker", worker_id=worker_id)
            if cp:
                current_run_id = cp.phase_run_id
                try:
                    _start_log_session(project_id, "unconstrained-worker", extra="接续")
                    loop = _loop_from_checkpoint(
                        cp,
                        cancel=cancel,
                        stop_when=lambda st: bool(st.get("round_finished")),
                        timeout_sec=settings.timeout_worker_round,
                    )
                    loop.worker_id = worker_id
                    try:
                        result = loop.run()
                    except OperationalError as e:
                        if not _is_sqlite_locked(e):
                            raise
                        live_log.system(
                            project_id,
                            "无约束扫描轮数据库忙，保留检查点稍后继续",
                            phase="unconstrained-worker",
                        )
                        cancel.wait(timeout=_DB_LOCK_RETRY_SECONDS)
                        continue
                    action = _finish_unconstrained_round(
                        project_id, worker_id, cp.phase_run_id, result
                    )
                    if action in ("interrupt", "cancel"):
                        return
                    if action == "restart":
                        continue
                finally:
                    _release_adopted(project_id, cp.phase_run_id)
                    current_run_id = None
                continue

            if path_done:
                return

            system = _phase_system_prompt(project_id, "worker-unconstrained.md")
            run_id = _new_phase_run(
                project_id, "unconstrained-worker", "unconstrained_worker", worker_id=worker_id
            )
            current_run_id = run_id
            _consume_force_new(project_id, "worker")
            _start_log_session(project_id, "unconstrained-worker", extra="自主巡航")
            round_id = _next_unconstrained_round_id(project_id)
            body = _initial_prompt(
                "unconstrained-worker.md",
                worker_id=worker_id,
                round_id=round_id,
                **_agent_prompt_vars(project_id),
            )
            user = _prompt_with_summary("unconstrained-worker", project_id, body)
            loop = AgentLoop(
                project_id=project_id,
                role="unconstrained_worker",
                phase="unconstrained-worker",
                system_prompt=system,
                user_prompt=user,
                phase_run_id=run_id,
                worker_id=worker_id,
                cancel_event=_loop_cancel(project_id, "worker"),
                pause_event=_combined_pause(project_id, "worker"),
                timeout_sec=settings.timeout_worker_round,
                context_window=_context_window(),
                stop_when=lambda st: bool(st.get("round_finished")),
            )
            loop.state["round_id"] = round_id
            try:
                result = loop.run()
            except OperationalError as e:
                if not _is_sqlite_locked(e):
                    raise
                live_log.system(
                    project_id,
                    "无约束扫描轮数据库忙，保留检查点稍后继续",
                    phase="unconstrained-worker",
                )
                cancel.wait(timeout=_DB_LOCK_RETRY_SECONDS)
                continue
            action = _finish_unconstrained_round(project_id, worker_id, run_id, result)
            current_run_id = None
            if action in ("interrupt", "cancel"):
                return
            if action == "restart":
                continue
    except OperationalError as e:
        if _is_sqlite_locked(e):
            raise
        live_log.error(project_id, f"无约束 Worker={worker_id} 异常: {e}", phase="unconstrained-worker")
        try:
            if current_run_id:
                _finish_phase_run(current_run_id, "failed", str(e))
        except Exception:  # noqa: BLE001
            pass
    except Exception as e:  # noqa: BLE001
        if _is_sqlite_locked(e):
            raise
        live_log.error(project_id, f"无约束 Worker={worker_id} 异常: {e}", phase="unconstrained-worker")
        try:
            if current_run_id:
                _finish_phase_run(current_run_id, "failed", str(e))
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
                **_agent_prompt_vars(project_id),
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
    if result.stop_reason == "db_locked" or phase_restart:
        return "restart"
    finished = bool(result.state.get("sink_finished"))
    if sink_id and not finished:
        release_sink_claim(project_id, sink_id, worker_id)
    if finished and sink_id:
        with SessionLocal() as db:
            row = db.get(Sink, sink_id)
            if row:
                _fast_last_dir[project_id] = str(Path(row.file_path).parent).replace("\\", "/")
    _finish_phase_run(
        run_id,
        "completed" if result.ok else ("cancelled" if result.cancelled else "failed"),
        result.error,
    )
    if result.cancelled and _cancel_event(project_id).is_set():
        return "cancel"
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
                **_agent_prompt_vars(project_id),
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
    if result.stop_reason == "db_locked" or phase_restart:
        return "restart"
    finished = bool(result.state.get("bypass_finished"))
    if bypass_id and not finished:
        release_bypass_claim(project_id, bypass_id, worker_id)
    _finish_phase_run(
        run_id,
        "completed" if result.ok else ("cancelled" if result.cancelled else "failed"),
        result.error,
    )
    if result.cancelled and _cancel_event(project_id).is_set():
        return "cancel"
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
                **_agent_prompt_vars(project_id),
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
            **_agent_prompt_vars(project_id),
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
        if env.get("accepted") and not lab_rebuild_requested(project_id):
            rec = recreate_lab(project_id, mode="start")
            if lab_ready(load_env(project_id) or env):
                mark_lab_setup_finished(project_id, via=str(rec.get("via") or "reuse"))
                clear_lab_retry_flags(project_id)
                _finish_resumable_phase(project_id, "reviewer-lab")
                live_log.system(project_id, "已复用现有 Docker 靶场，环境搭建轮结束", phase="reviewer-lab", role="reviewer_lab")
                return

        system = _lab_system_prompt(project_id)
        repairs_block = format_lab_repairs_for_prompt(project_id)
        lab_body = _initial_prompt(
            _lab_initial_prompt_doc(project_id),
            **_agent_prompt_vars(project_id),
            **lab_naming(project_id),
        )
        if repairs_block:
            lab_body = f"{repairs_block}\n{lab_body}"
        user = _prompt_with_summary("reviewer-lab", project_id, lab_body)
        cp = _adopt_resumable(project_id, "reviewer-lab")
        run_id = cp.phase_run_id if cp else _new_phase_run(project_id, "reviewer-lab", "reviewer_lab")
        resumes = 0
        used_checkpoint = False
        llm = resolve_llm("reviewer", project_id=project_id)
        timeout_sec = int(settings.timeout_reviewer_static)
        max_resumes = max(0, int(settings.phase_max_resumes))
        timeout_threshold = max(1, int(getattr(settings, "lab_setup_timeouts_before_static", 2) or 2))
        try:
            while resumes <= max_resumes and not cancel.is_set():
                if not _wait_if_paused(project_id, _loop_cancel(project_id, "reviewer"), "reviewer"):
                    _finish_phase_run(run_id, "cancelled")
                    return
                if lab_round_complete(project_id):
                    mark_lab_setup_finished(project_id, via="lab-round")
                    clear_lab_retry_flags(project_id)
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
                    clear_lab_retry_flags(project_id)
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
                elif result.timed_out or result.stop_reason == "timeout":
                    streak = increment_lab_setup_timeout_streak(project_id)
                    live_log.system(
                        project_id,
                        f"环境搭建超时（连续 {streak}/{timeout_threshold}）",
                        phase="reviewer-lab",
                        role="reviewer_lab",
                    )
                    if lab_setup_timeouts_exhausted(project_id):
                        reason = f"搭建 Agent 连续超时 {streak} 次（每次 {timeout_sec}s）"
                        mark_lab_bring_up_failed(project_id, reason=reason, via="lab-timeout")
                        mark_lab_setup_finished(
                            project_id,
                            skipped=True,
                            notes=reason,
                            via="lab-timeout",
                        )
                        _finish_phase_run(run_id, "failed", error=reason)
                        live_log.system(
                            project_id,
                            "搭建连续超时，后续审核强制仅静态",
                            phase="reviewer-lab",
                            role="reviewer_lab",
                        )
                        return
                    user = _prompt_with_summary(
                        "reviewer-lab",
                        project_id,
                        _initial_prompt("reviewer-lab-retry-timeout.md", project_id=project_id),
                    )
                    if repairs_block:
                        user = f"{repairs_block}\n{user}"
                    continue
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
    prior_evidence = str(cp.state.get("prior_evidence_level") or "").strip().lower()
    if not prior_evidence and cp.vuln_id is not None:
        with SessionLocal() as db:
            vuln = db.get(Vuln, cp.vuln_id)
            if vuln:
                prior_evidence = (vuln.evidence_level or "").strip().lower()
    if prior_evidence == EVIDENCE_HARNESS:
        prior_basis = "harness（局部验证）"
        prior_conclusion = "局部验证结论"
    else:
        prior_basis = "static_only"
        prior_conclusion = "静态结论"
    followup_kind = str(cp.state.get("followup_kind") or "").strip().lower()
    if followup_kind == "integration" and mode == VERIFY_MODE_HARNESS:
        debug_plan = harness_debug_plan()
        followup = "reviewer-integration-followup.md"
        extra_label = "追加集成验证"
    elif mode == VERIFY_MODE_HARNESS:
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
        prior_basis=prior_basis,
        prior_conclusion=prior_conclusion,
        **_agent_prompt_vars(cp.project_id),
    )
    messages.append({"role": "user", "content": body})
    cp.messages = messages
    cp.state["review_done"] = False
    cp.state.pop("review_verdict", None)
    cp.state["dynamic_followup"] = True
    cp.state["dynamic_followup_prompted"] = True
    cp.state["followup_label"] = extra_label
    cp.state["prior_evidence_level"] = prior_evidence or "static_only"


def _run_reviewer_once(project_id: int) -> None:
    cancel = _cancel_event(project_id)
    try:
        cp = _adopt_resumable(project_id, "reviewer")
        if cp and cp.vuln_id is not None:
            if _give_up_exhausted_review(project_id, cp.vuln_id):
                try:
                    _finish_phase_run(
                        cp.phase_run_id, "failed", "review timeout retries exhausted"
                    )
                finally:
                    _release_adopted(project_id, cp.phase_run_id)
                return
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
            _note_reviewer_round_end(project_id, cp.vuln_id, result)
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
            timeout_streak = int(vuln.review_timeout_streak or 0)
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
                "config_premise": vuln.config_premise,
                "source_sink": vuln.source_sink,
                "mining_path": vuln.mining_path,
            }
            unconstrained_note = ""
            if (vuln.mining_path or "").strip().lower() == "unconstrained":
                unconstrained_note = (
                    "本条来自无约束扫描。ConfirmVuln 必须传 rce_effect=true|false："
                    "由你判定是否达成前台 RCE 效果，不要只看 vuln_type。"
                    "true 且前台确认后该路径结束（当前 Worker 轮仍会跑完）。"
                    "本条始终走赏金闸门，即使项目是全量/自定义模式。"
                )

        if _give_up_exhausted_review(project_id, vuln_id):
            return

        lab_note, debug_plan, system, force_static = _reviewer_round_verify(
            project_id, timeout_streak=timeout_streak
        )
        if force_static:
            if lab_bring_up_failed(project_id):
                reason = str(load_env(project_id).get("bring_up_fail_reason") or "").strip()
                msg = f"漏洞 #{vuln_id} 靶场搭建连续超时，本轮强制仅静态审核"
                if reason:
                    msg = f"{msg}（{reason}）"
            else:
                msg = f"漏洞 #{vuln_id} 已连续审核超时 {timeout_streak} 轮，本轮强制仅静态审核"
            live_log.system(project_id, msg, phase="reviewer")

        with SessionLocal() as db:
            proj = db.get(Project, project_id)
            if proj and proj.status not in ("completed", "cancelled", "paused"):
                proj.phase = "reviewer"
                proj.status = "reviewing"
                db.commit()

        body = _initial_prompt(
            "reviewer.md",
            vuln_id=vuln_id,
            payload=json_dumps(payload),
            lab_note=lab_note,
            debug_plan=json_dumps(debug_plan),
            verify_gate=_reviewer_verify_gate(
                force_static=force_static,
                mode=VERIFY_MODE_OFF if force_static else _read_dynamic_verify_mode(project_id),
            ),
            unconstrained_note=unconstrained_note,
            **_agent_prompt_vars(project_id),
        )
        user = body if force_static else _prompt_with_summary("reviewer", project_id, body)
        run_id = _new_phase_run(project_id, "reviewer", "reviewer", vuln_id=vuln_id)
        _consume_force_new(project_id, "reviewer")
        extra = f"漏洞 #{vuln_id}"
        if force_static:
            extra = f"{extra} 强制仅静态"
        _start_log_session(project_id, "reviewer", extra=extra)
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
        _note_reviewer_round_end(project_id, vuln_id, result)
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
        internet_capability_skip_reason,
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
                    stop_when=lambda st: bool(st.get("verifier_done") or st.get("awaiting_user")),
                    timeout_sec=settings.timeout_verifier,
                )
                seed_fofa_state(loop.state, project_id)
                result = loop.run()
            finally:
                _release_adopted(project_id, cp.phase_run_id)
            if result.stop_reason == "auth_error":
                _pause_for_auth(project_id, result.error or "auth_error")
                return
            if result.stop_reason == "awaiting_user" or (
                result.state and result.state.get("awaiting_user")
            ):
                live_log.system(
                    project_id,
                    f"Verifier 等待用户确认 vuln={cp.vuln_id}",
                    phase="verifier",
                )
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
        # Capability gaps still auto-skip; harm types go through AskUser in-agent.
        capability = internet_capability_skip_reason(vuln)
        if capability:
            mark_internet_unsafe_skipped(project_id, vuln_id, capability)
            live_log.system(
                project_id,
                f"漏洞 #{vuln_id} 跳过互联网复测：{capability}",
                phase="verifier",
            )
            return
        from .asset_proof import ensure_project_fingerprints, fofa_search_variants, load_project_fingerprints
        from .report import is_placeholder_query

        ensure_project_fingerprints(project_id)
        app_fp = load_project_fingerprints(project_id) or {}
        fofa_cache = load_project_fofa_cache(project_id)
        report_query = extract_fofa_query(report_md)
        cached_query = str((fofa_cache or {}).get("query") or "").strip()
        search_variants = fofa_search_variants(app_fp)
        if fofa_cache and fofa_cache.get("sample") and cached_query:
            fofa_query = cached_query
        elif search_variants:
            fofa_query = search_variants[0]
        elif not is_placeholder_query(app_fp.get("fofa")):
            fofa_query = str(app_fp.get("fofa") or "").strip()
        elif not is_placeholder_query(report_query):
            fofa_query = report_query
        else:
            fofa_query = "（项目指纹与报告均无可用 FOFA 语句：Read docs/app-fingerprints.json 与报告后改写再搜）"
        if search_variants:
            fofa_alts = "；".join(f"`{item}`" for item in search_variants)
        else:
            fofa_alts = "（无独立备选；0 条时换另一类语法，title/app 与 body 各试一条）"
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
            fofa_alts=fofa_alts,
            fofa_shared=format_shared_fofa_hint(fofa_cache),
            **_agent_prompt_vars(project_id),
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
            stop_when=lambda st: bool(st.get("verifier_done") or st.get("awaiting_user")),
        )
        seed_fofa_state(loop.state, project_id)
        result = loop.run()
        if result.stop_reason == "auth_error":
            _pause_for_auth(project_id, result.error or "auth_error")
            return
        if result.stop_reason == "awaiting_user" or (
            result.state and result.state.get("awaiting_user")
        ):
            live_log.system(
                project_id,
                f"Verifier 等待用户确认 vuln={vuln_id}",
                phase="verifier",
            )
            return
        _finish_phase_run(run_id, "completed" if result.ok else "failed", result.error)
        live_log.system(
            project_id,
            f"Verifier 结束 vuln={vuln_id} verdict={result.state.get('verifier_verdict')} reason={result.stop_reason}",
            phase="verifier",
        )
    except Exception as e:  # noqa: BLE001
        live_log.error(project_id, f"Verifier 异常: {e}", phase="verifier")


def _run_attack_chain_once(project_id: int) -> None:
    from ..tools.phase_attack_chain import (
        attack_chain_prereqs,
        confirmed_vuln_count,
        is_attack_chain_done,
        mark_attack_chain_done,
    )

    cancel = _cancel_event(project_id)
    try:
        if not attack_chain_prereqs(project_id):
            return
        cp = _adopt_resumable(project_id, "attack_chain")
        if cp:
            with SessionLocal() as db:
                proj = db.get(Project, project_id)
                if proj and proj.status not in ("completed", "cancelled", "paused"):
                    proj.phase = "attack_chain"
                    proj.status = "auditing"
                    db.commit()
            try:
                loop = _loop_from_checkpoint(
                    cp,
                    cancel=cancel,
                    stop_when=lambda st: bool(st.get("attack_chain_done")),
                    timeout_sec=settings.timeout_attack_chain,
                )
                result = loop.run()
            finally:
                _release_adopted(project_id, cp.phase_run_id)
            if result.stop_reason == "auth_error":
                _pause_for_auth(project_id, result.error or "auth_error")
                return
            _finish_phase_run(cp.phase_run_id, "completed" if result.ok else "failed", result.error)
            if result.state.get("attack_chain_done") or is_attack_chain_done(project_id):
                if not is_attack_chain_done(project_id):
                    mark_attack_chain_done(project_id, reason="检查点会话结束")
            live_log.system(
                project_id,
                f"攻击链结束 reason={result.stop_reason}",
                phase="attack_chain",
            )
            return

        if is_attack_chain_done(project_id):
            return
        n_confirmed = confirmed_vuln_count(project_id)
        if n_confirmed < 2:
            mark_attack_chain_done(project_id, reason="已确认漏洞少于 2 条，跳过串联")
            return

        with SessionLocal() as db:
            proj = db.get(Project, project_id)
            if proj and proj.status not in ("completed", "cancelled", "paused"):
                proj.phase = "attack_chain"
                proj.status = "auditing"
                db.commit()
            rows = (
                db.query(Vuln)
                .filter(
                    Vuln.project_id == project_id,
                    Vuln.status.in_(("confirmed", "static_only")),
                )
                .order_by(Vuln.id.asc())
                .all()
            )
            catalog = [
                {
                    "vuln_id": v.id,
                    "title": v.title,
                    "vuln_type": v.vuln_type,
                    "status": v.status,
                    "attack_surface": v.attack_surface,
                    "required_account": v.required_account,
                    "auth_premise": (v.auth_premise or "")[:200],
                    "config_premise": v.config_premise,
                    "file_path": v.file_path,
                    "cwe": v.cwe,
                    "severity": v.severity,
                }
                for v in rows
            ]

        system = _phase_system_prompt(project_id, "attack_chain.md")
        body = _initial_prompt(
            "attack_chain.md",
            confirmed_count=n_confirmed,
            catalog=json_dumps(catalog),
            **_agent_prompt_vars(project_id),
        )
        lab_note = _attack_chain_lab_note(project_id)
        if lab_note:
            body = f"{body.rstrip()}\n\n{lab_note}\n"
        user = _prompt_with_summary("attack_chain", project_id, body)
        run_id = _new_phase_run(project_id, "attack_chain", "attack_chain")
        _consume_force_new(project_id, "attack_chain")
        _start_log_session(project_id, "attack_chain", extra=f"已确认 {n_confirmed} 条")
        loop = AgentLoop(
            project_id=project_id,
            role="attack_chain",
            phase="attack_chain",
            system_prompt=system,
            user_prompt=user,
            phase_run_id=run_id,
            cancel_event=_loop_cancel(project_id, "attack_chain"),
            pause_event=_combined_pause(project_id, "attack_chain"),
            timeout_sec=settings.timeout_attack_chain,
            context_window=_context_window(),
            stop_when=lambda st: bool(st.get("attack_chain_done")),
        )
        result = loop.run()
        if result.stop_reason == "auth_error":
            _pause_for_auth(project_id, result.error or "auth_error")
            return
        _finish_phase_run(run_id, "completed" if result.ok else "failed", result.error)
        if not is_attack_chain_done(project_id):
            # Agent exited without FinishAttackChain — still close the gate.
            mark_attack_chain_done(
                project_id,
                reason=f"会话结束未显式收工（{result.stop_reason}）",
            )
        live_log.system(
            project_id,
            f"攻击链结束 reason={result.stop_reason} submitted={len(result.state.get('attack_chains_submitted') or [])}",
            phase="attack_chain",
        )
    except Exception as e:  # noqa: BLE001
        live_log.error(project_id, f"攻击链异常: {e}", phase="attack_chain")


def json_dumps(obj: Any) -> str:
    import json

    return json.dumps(obj, ensure_ascii=False, default=str)

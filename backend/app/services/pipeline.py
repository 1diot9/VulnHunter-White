"""Project audit orchestrator: recon || worker, review queue, isolated fix pool."""

from __future__ import annotations

import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from typing import Any

from sqlalchemy.exc import OperationalError

from ..agent.checkpoint import (
    LoopCheckpoint,
    clear_checkpoint,
    list_resumable_runs,
    load_checkpoint,
    resumable_file_paths,
    resumable_vuln_ids,
    set_phase_run_status,
    set_phase_run_worker,
)
from ..agent.compression import inject_summary_block, inject_worker_prior_block, latest_summary
from ..agent.loop import AgentLoop
from ..audit_mode import audit_mode_label, initial_hint, normalize_audit_mode
from ..config import settings
from ..models import FileWeight, PhaseRun, Project, SessionLocal, Source, Vuln, utcnow
from ..prompts import load_prompt, render_prompt
from ..services.ingest import build_file_index, clone_github, extract_zip
from ..services.lab import ENV_BUILDER_HINT, debug_ports_for_runtime, load_env, recreate_lab
from ..services.live_log import live_log
from ..services.llm_settings import get_settings_row, resolve_llm
from ..services.mcp_router import reviewer_debug_plan
from ..services.paths import ensure_project_dirs, src_dir
from ..services.vuln_followup import archive_reviewer_checkpoint
from ..tools import register_all_tools
from ..tools.phase_recon import (
    apply_recon_done,
    paths_fully_marked,
    pick_unmarked_batch,
    recon_gates_met,
    recon_gates_status,
    recon_map_ready,
    recon_old_vulns_ready,
)
from ..tools.phase_worker import mining_complete, project_complete_gates

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
_reviewer_threads: dict[int, threading.Thread] = {}
_reviewer_inflight: dict[int, bool] = {}
_fix_inflight: dict[int, set[int]] = {}
_adopted_phase_runs: set[tuple[int, int]] = set()
_DB_LOCK_RETRY_SECONDS = 1.0

# Role pools: Recon 1 / Worker 2 (mine 1 + fix 1) / Reviewer 1
RECON_POOL = 1
WORKER_MINE_POOL = 1
WORKER_FIX_POOL = 1
REVIEWER_POOL = 1

CONTROL_PHASES = ("recon", "worker", "reviewer")
CONTROL_DB_PHASES: dict[str, tuple[str, ...]] = {
    "recon": ("recon", "recon-old-vuln", "recon-mark"),
    "worker": ("worker", "fix"),
    "reviewer": ("reviewer",),
}
CONTROL_LABELS = {"recon": "侦察", "worker": "挖掘", "reviewer": "审核"}


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
    if p in ("recon", "recon-mark", "recon_mark", "recon-old-vuln", "recon_old_vuln", "recon-map"):
        return "recon"
    if p in ("worker", "fix", "mine"):
        return "worker"
    if p == "reviewer":
        return "reviewer"
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
    with _lock:
        _cancel_events.clear()
        _pause_flags.clear()
        _phase_pause_flags.clear()
        _phase_generation.clear()
        _force_new_run.clear()
        _pending_inject.clear()
        _threads.clear()
        _recon_threads.clear()
        _reviewer_threads.clear()
        _reviewer_inflight.clear()
        _fix_inflight.clear()
        _adopted_phase_runs.clear()


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
    _pause_event(project_id).set()
    for phase in CONTROL_PHASES:
        _phase_pause_event(project_id, phase).set()
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        if proj:
            proj.status = "paused"
            db.commit()
    live_log.system(project_id, "用户暂停全部阶段")


def note_audit_mode_changed(project_id: int, mode: str) -> None:
    """Keep the project paused; next resume must use the new Worker/Reviewer rules."""
    for control in ("worker", "reviewer"):
        _force_new_run.add((project_id, control))
        _abandon_phase_checkpoints(project_id, control)
        _bump_phase_generation(project_id, control)
    live_log.system(
        project_id,
        f"挖掘模式已改为{audit_mode_label(mode)}，续跑后 Worker/Reviewer 将按新规则新开",
    )


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


def request_phase_pause(project_id: int, phase: str) -> dict[str, Any]:
    control = control_phase(phase)
    _phase_pause_event(project_id, control).set()
    if all(_phase_pause_event(project_id, p).is_set() for p in CONTROL_PHASES):
        _pause_event(project_id).set()
        with SessionLocal() as db:
            proj = db.get(Project, project_id)
            if proj and proj.status not in ("completed", "cancelled"):
                proj.status = "paused"
                db.commit()
    live_log.system(project_id, f"用户暂停{CONTROL_LABELS[control]}阶段", phase=control)
    return get_phase_states(project_id)


def request_phase_resume(project_id: int, phase: str) -> dict[str, Any]:
    """续跑：接续检查点 / 同一段对话，对标 Codex CLI resume。"""
    control = control_phase(phase)
    if _pause_event(project_id).is_set():
        for p in CONTROL_PHASES:
            if p != control:
                _phase_pause_event(project_id, p).set()
        _pause_event(project_id).clear()
    _phase_pause_event(project_id, control).clear()
    cancel = _cancel_event(project_id)
    if cancel.is_set():
        cancel.clear()
    _force_new_run.discard((project_id, control))
    _prepare_phase_resume(project_id, control)
    _set_project_running(project_id)
    n_cp = len(_resumable_for_control(project_id, control))
    live_log.system(
        project_id,
        f"{CONTROL_LABELS[control]}阶段续跑"
        + (f"（{n_cp} 个检查点接续上下文）" if n_cp else "（无检查点，按当前进度继续）"),
        phase=control,
    )
    start_audit(project_id)
    return get_phase_states(project_id)


def request_phase_restart(project_id: int, phase: str) -> dict[str, Any]:
    """新跑：丢弃当前对话，新开一轮并把文件等注入为初始上下文。"""
    control = control_phase(phase)
    inject = _collect_inject_targets(project_id, control)
    _pending_inject[(project_id, control)] = inject
    _force_new_run.add((project_id, control))
    _abandon_phase_checkpoints(project_id, control)
    if control == "worker":
        _reset_fixing_to_returned(project_id, except_ids=set())
    _bump_phase_generation(project_id, control)
    if _pause_event(project_id).is_set():
        for p in CONTROL_PHASES:
            if p != control:
                _phase_pause_event(project_id, p).set()
        _pause_event(project_id).clear()
    _phase_pause_event(project_id, control).clear()
    cancel = _cancel_event(project_id)
    if cancel.is_set():
        cancel.clear()
    _set_project_running(project_id)
    bits: list[str] = []
    files = [x.get("file_path") for x in inject if x.get("file_path")]
    vulns = [x.get("vuln_id") for x in inject if x.get("vuln_id") is not None]
    if files:
        bits.append("文件 " + ", ".join(str(p) for p in files[:4]))
    if vulns:
        bits.append("漏洞 " + ", ".join(f"#{v}" for v in vulns[:4]))
    extra = f"（注入：{'；'.join(bits)}）" if bits else "（按当前进度注入初始上下文）"
    live_log.begin_session(project_id, control)
    live_log.system(
        project_id,
        f"{CONTROL_LABELS[control]}阶段新跑，新开对话{extra}",
        phase=control,
        session_start=True,
    )
    start_audit(project_id)
    return get_phase_states(project_id)


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


def _abandon_phase_checkpoints(project_id: int, phase: str) -> None:
    for pr in _resumable_for_control(project_id, phase):
        _release_adopted(project_id, pr.id)
        _finish_phase_run(pr.id, "cancelled", "用户新跑")


def _prepare_phase_resume(project_id: int, phase: str) -> None:
    control = control_phase(phase)
    if control == "worker":
        keep_paths = resumable_file_paths(project_id)
        keep_vulns = resumable_vuln_ids(project_id, "fix")
        n_claims = _release_claims(project_id, except_paths=keep_paths)
        n_fix = _reset_fixing_to_returned(project_id, except_ids=keep_vulns)
        if n_claims or n_fix:
            live_log.system(
                project_id,
                f"挖掘续跑准备：清认领 {n_claims}，fixing→returned {n_fix}",
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
    for t in _threads.get(project_id, []):
        if t.is_alive() and "worker" in (t.name or ""):
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
        q = (
            db.query(FileWeight)
            .filter(
                FileWeight.project_id == project_id,
                FileWeight.skipped.is_(False),
                FileWeight.audited.is_(False),
                FileWeight.weight.isnot(None),
                FileWeight.claimed_by.is_(None),
            )
            .order_by(
                FileWeight.audit_attempts.asc(),
                FileWeight.has_source.desc(),
                FileWeight.weight.desc(),
                FileWeight.path.asc(),
            )
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


def _audit_mode_vars(project_id: int) -> dict[str, str]:
    mode = _read_audit_mode(project_id)
    return {
        "audit_mode": mode,
        "audit_mode_label": audit_mode_label(mode),
        "audit_mode_hint": initial_hint(mode),
    }


def _phase_system_prompt(project_id: int, name: str) -> str:
    base = load_prompt(name).rstrip()
    overlay = load_prompt(f"modes/{_read_audit_mode(project_id)}.md").strip()
    return f"{base}\n\n{overlay}\n"


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
) -> AgentLoop:
    return AgentLoop.from_checkpoint(
        cp,
        cancel_event=_loop_cancel(cp.project_id, cp.phase),
        pause_event=_combined_pause(cp.project_id, cp.phase),
        stop_when=stop_when,
        context_window=_context_window(),
        timeout_sec=timeout_sec,
        llm=llm,
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
        return True
    return False


def _maybe_complete_project(project_id: int, *, reviewer_busy: bool, fix_busy: bool) -> bool:
    if reviewer_busy or fix_busy:
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
    if pending <= 0 and not list_resumable_runs(project_id, "reviewer") and not _should_skip_checkpoint(project_id, "reviewer"):
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
            if pending <= 0 and not list_resumable_runs(project_id, "reviewer") and not _should_skip_checkpoint(project_id, "reviewer"):
                cancel.wait(timeout=5.0)
                continue
            with _lock:
                _reviewer_inflight[project_id] = True
            try:
                _run_reviewer_once(project_id)
            finally:
                with _lock:
                    _reviewer_inflight[project_id] = False
    except Exception as e:  # noqa: BLE001
        live_log.error(project_id, f"Reviewer 线程异常: {e}", phase="reviewer")
        with _lock:
            _reviewer_inflight[project_id] = False


def _ensure_workers(
    project_id: int,
    active_workers: list[threading.Thread],
) -> list[threading.Thread]:
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        if not proj or proj.status in ("completed", "cancelled", "error"):
            return [t for t in active_workers if t.is_alive()]
        status = proj.status
        unaudited_weighted = (
            db.query(FileWeight)
            .filter(
                FileWeight.project_id == project_id,
                FileWeight.weight.isnot(None),
                FileWeight.skipped.is_(False),
                FileWeight.audited.is_(False),
            )
            .count()
        )
    if _phase_is_paused(project_id, "worker"):
        return [t for t in active_workers if t.is_alive()]

    alive = [t for t in active_workers if t.is_alive()]
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

                if pending_vulns > 0:
                    _ensure_reviewer(project_id, cancel)

                with _lock:
                    fix_busy = bool(_fix_inflight.get(project_id))
                    reviewer_busy = bool(_reviewer_inflight.get(project_id))

                if _maybe_complete_project(project_id, reviewer_busy=reviewer_busy, fix_busy=fix_busy):
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
    """Run recon sub-phases strictly in series: map/auth → old vulns → mark."""
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
        if recon_old_vulns_ready(project_id):
            _finish_resumable_phase(project_id, "recon-old-vuln")
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
        done_log="代码地图与鉴权文档已就绪，进入历史漏洞会话",
        fail_error="recon 地图/鉴权会话未在重试上限内完成",
        fail_status="Recon 地图/鉴权未完成，将自动再拉起",
        fail_log="Recon 地图/鉴权会话重试用尽，等待调度器再拉起",
    )


def _run_recon_old_vulns(project_id: int, cancel: threading.Event) -> bool:
    return _run_recon_gated_session(
        project_id,
        cancel,
        phase="recon-old-vuln",
        role="recon_old_vuln",
        prompt_name="recon-old-vuln.md",
        ready=lambda: recon_old_vulns_ready(project_id),
        initial_doc="recon-old-vuln.md",
        retry_loop_doc="recon-old-vuln-retry-loop.md",
        retry_timeout_doc="recon-old-vuln-retry-timeout.md",
        retry_other_doc="recon-old-vuln-retry-other.md",
        done_log="历史漏洞检索已结束，进入盖章轮",
        fail_error="recon 历史漏洞会话未在重试上限内完成",
        fail_status="Recon 历史漏洞未完成，将自动再拉起",
        fail_log="Recon 历史漏洞会话重试用尽，等待调度器再拉起",
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
) -> bool:
    system = load_prompt(prompt_name)
    user = _prompt_with_summary(phase, project_id, _initial_prompt(initial_doc, project_id=project_id))
    cp = _adopt_resumable(project_id, phase)
    run_id = cp.phase_run_id if cp else _new_phase_run(project_id, phase, role)
    resumes = 0
    used_checkpoint = False
    llm = resolve_llm("recon")
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
                extra = "历史漏洞" if phase in ("recon-old-vuln", "recon_old_vuln") else "代码地图/鉴权"
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
                user = _prompt_with_summary(phase, project_id, _initial_prompt(retry_loop_doc, project_id=project_id))
                live_log.system(
                    project_id,
                    f"Recon {phase} 新开重试 {resumes}/{settings.recon_max_resumes}",
                    phase=phase,
                    role=role,
                )
            elif result.timed_out:
                user = _prompt_with_summary(
                    phase, project_id, _initial_prompt(retry_timeout_doc, project_id=project_id)
                )
            else:
                user = _prompt_with_summary(
                    phase,
                    project_id,
                    _initial_prompt(
                        retry_other_doc,
                        project_id=project_id,
                        stop_reason=result.stop_reason,
                        error=result.error,
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
    llm = resolve_llm("recon")
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


def _run_worker_loop(project_id: int, worker_id: str) -> None:
    cancel = _cancel_event(project_id)
    round_id = 0
    current_run_id: int | None = None
    try:
        while not cancel.is_set():
            if not _wait_if_paused(project_id, _loop_cancel(project_id, "worker"), "worker"):
                break
            with SessionLocal() as db:
                proj = db.get(Project, project_id)
                if not proj or proj.status in ("completed", "cancelled", "error"):
                    return
            if mining_complete(project_id) and not _pending_inject.get((project_id, "worker")):
                # No more files / bounced work — idle until project completes via reviewer
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

            round_id += 1
            sources = _sources_for_file(project_id, fw.path)
            snippet = _read_file_snippet(project_id, fw.path)
            system = _phase_system_prompt(project_id, "worker.md")
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
            run_id = _new_phase_run(
                project_id, "worker", "worker", worker_id=worker_id, file_path=fw.path
            )
            current_run_id = run_id
            _consume_force_new(project_id, "worker")
            _start_log_session(project_id, "worker", extra=fw.path)
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


def _run_reviewer_once(project_id: int) -> None:
    cancel = _cancel_event(project_id)
    try:
        cp = _adopt_resumable(project_id, "reviewer")
        if cp and cp.vuln_id is not None:
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
                    timeout_sec=settings.timeout_reviewer_static + settings.timeout_docker,
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

        env = load_env(project_id)
        lab_note = ""
        if not env.get("accepted"):
            lab_note = ENV_BUILDER_HINT
        else:
            rec = recreate_lab(project_id)
            dbg = debug_ports_for_runtime(load_env(project_id) or env)
            lab_note = f"环境: {json_dumps(rec)}\n调试: {json_dumps(dbg)}"
        debug_plan = reviewer_debug_plan(project_id)

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
            timeout_sec=settings.timeout_reviewer_static + settings.timeout_docker,
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


def json_dumps(obj: Any) -> str:
    import json

    return json.dumps(obj, ensure_ascii=False, default=str)

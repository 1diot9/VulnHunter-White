"""Unified continue / new / steer conversation actions per log sub-phase."""

from __future__ import annotations

from typing import Any

from ..agent.checkpoint import (
    LoopCheckpoint,
    list_resumable_runs,
    load_checkpoint,
    save_checkpoint,
    set_phase_run_status,
)
from ..models import PhaseRun, Project, SessionLocal
from ..schemas import normalize_conversation_message
from .conversation_archive import (
    has_archived,
    load_archived,
    log_phase_to_db_phases,
    normalize_log_phase,
)
from .conversation_steer import enqueue_steer, is_loop_running
from .live_log import live_log
from ..mining_paths import (
    MINING_PATH_LABELS,
    mining_path_enabled,
    mining_path_from_log_phase,
    mining_path_user_stopped,
)


CONTINUE_EMPTY = "用户请求接续此对话，请从中断处继续。"
CONTINUE_WITH_MSG = "## 用户接续指示\n{message}\n\n请从中断处继续。"
_UNCONSTRAINED_LOG_PHASES = frozenset({"unconstrained", "unconstrained-worker"})
_ATTACK_CHAIN_LOG_PHASES = frozenset({"attack_chain", "attack-chain"})


def _is_unconstrained_phase(log_phase: str) -> bool:
    return normalize_log_phase(log_phase) in _UNCONSTRAINED_LOG_PHASES


def _is_attack_chain_phase(log_phase: str) -> bool:
    return normalize_log_phase(log_phase) in _ATTACK_CHAIN_LOG_PHASES


def _project_ok(proj: Project | None) -> None:
    if not proj:
        raise ValueError("项目不存在")
    if proj.status in ("cancelled", "ingesting", "error"):
        raise ValueError("当前项目状态不可操作对话")


def _find_resumable_checkpoint(project_id: int, log_phase: str) -> LoopCheckpoint | None:
    for db_phase in log_phase_to_db_phases(log_phase):
        for pr in list_resumable_runs(project_id, db_phase):
            cp = load_checkpoint(project_id, pr.id)
            if cp and cp.messages:
                return cp
    return None


def _find_running_phase_run(project_id: int, log_phase: str) -> PhaseRun | None:
    db_phases = log_phase_to_db_phases(log_phase)
    with SessionLocal() as db:
        for db_phase in db_phases:
            row = (
                db.query(PhaseRun)
                .filter(
                    PhaseRun.project_id == project_id,
                    PhaseRun.phase == db_phase,
                    PhaseRun.status.in_(("running", "paused", "awaiting_user")),
                )
                .order_by(PhaseRun.id.desc())
                .first()
            )
            if row:
                db.expunge(row)
                return row
    return None


def _latest_session(project_id: int, log_phase: str) -> int:
    db_phases = log_phase_to_db_phases(log_phase)
    n = 1
    for db_phase in db_phases:
        n = max(n, live_log.current_session(project_id, db_phase))
    return n


def get_conversation_state(project_id: int, log_phase: str) -> dict[str, Any]:
    lp = normalize_log_phase(log_phase)
    running_loop = is_loop_running(project_id, lp)
    running_pr = _find_running_phase_run(project_id, lp) is not None
    running = running_loop or running_pr
    resumable = _find_resumable_checkpoint(project_id, lp) is not None
    archived = has_archived(project_id, lp)
    unconstrained = _is_unconstrained_phase(lp)
    mining_path = mining_path_from_log_phase(lp)
    unconstrained_done = False
    unconstrained_on = False
    path_on = False
    path_stopped = False
    attack_chain = _is_attack_chain_phase(lp)
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        blocked = proj is None or proj.status in ("cancelled", "ingesting", "error")
        if proj:
            unconstrained_on = bool(getattr(proj, "unconstrained_enabled", False))
            unconstrained_done = bool(getattr(proj, "unconstrained_done", False))
            completed = proj.status == "completed"
            if mining_path:
                path_on = mining_path_enabled(proj, mining_path)
                path_stopped = mining_path_user_stopped(proj, mining_path)
                if mining_path == "unconstrained":
                    path_stopped = path_stopped or unconstrained_done
            elif attack_chain:
                path_on = bool(getattr(proj, "attack_chain_enabled", False))
                path_stopped = bool(getattr(proj, "attack_chain_stopped", False))
        else:
            completed = False
    can_continue = (resumable or archived) and not running and not path_stopped
    can_steer = running
    can_new = (not blocked) and not unconstrained and not path_stopped
    stoppable = bool(mining_path) or attack_chain
    can_stop = stoppable and path_on and (not path_stopped) and not blocked and not completed
    can_start = stoppable and path_on and path_stopped and not blocked
    return {
        "log_phase": lp,
        "running": running,
        "can_continue": can_continue,
        "can_new": can_new,
        "can_steer": can_steer,
        "has_archived": archived,
        "latest_session": _latest_session(project_id, lp),
        "can_stop": can_stop,
        "can_start": can_start,
        "unconstrained_done": unconstrained_done if unconstrained else False,
        "path_stopped": path_stopped if stoppable else False,
    }


def request_conversation(
    project_id: int,
    log_phase: str,
    action: str,
    message: str = "",
) -> dict[str, Any]:
    from . import pipeline

    lp = normalize_log_phase(log_phase)
    if lp in ("code-intel", "code_intel"):
        raise ValueError("代码库构建无 Agent 会话，请使用重建按钮")
    act = (action or "").strip().lower()
    if act not in ("steer", "continue", "new", "stop", "start"):
        raise ValueError("action 须为 steer、continue、new、stop 或 start")

    msg = normalize_conversation_message(message) if message else ""

    with SessionLocal() as db:
        proj = db.get(Project, project_id)
    _project_ok(proj)

    unconstrained = _is_unconstrained_phase(lp)
    mining_path = mining_path_from_log_phase(lp)
    attack_chain = _is_attack_chain_phase(lp)
    if act == "stop":
        if mining_path:
            return pipeline.request_mining_path_stop(project_id, mining_path)
        if attack_chain:
            return pipeline.request_attack_chain_stop(project_id)
        raise ValueError("仅挖掘路径或攻击链支持暂停")
    if act == "start":
        if mining_path:
            return pipeline.request_mining_path_start(project_id, mining_path)
        if attack_chain:
            return pipeline.request_attack_chain_start(project_id)
        raise ValueError("仅挖掘路径或攻击链支持恢复")
    if act == "new" and unconstrained:
        raise ValueError("无约束扫描请使用停止或启动，不再支持新开")

    state = get_conversation_state(project_id, lp)
    if act == "steer":
        if not state["can_steer"]:
            if state["can_continue"]:
                act = "continue"
            else:
                raise ValueError(
                    "当前小阶段未在运行，请使用接续或启动"
                    if unconstrained
                    else "当前小阶段未在运行，请使用接续、新开或恢复"
                    if mining_path or attack_chain
                    else "当前小阶段未在运行，请使用接续或新开"
                )
        else:
            enqueue_steer(project_id, lp, msg)
            db_phases = log_phase_to_db_phases(lp)
            live_log.system(
                project_id,
                "已收到用户引导，将在下一轮模型调用前注入",
                phase=db_phases[0] if db_phases else lp,
            )
            return {"ok": True, "action": "steer", "log_phase": lp, **pipeline.get_phase_states(project_id)}

    if act == "continue":
        if state.get("path_stopped"):
            label = "攻击链串联" if attack_chain else MINING_PATH_LABELS.get(mining_path or "", "该挖掘路径")
            raise ValueError(f"{label}已暂停，请先恢复")
        if state["running"]:
            if msg:
                enqueue_steer(project_id, lp, msg)
                return {"ok": True, "action": "steer", "log_phase": lp, **pipeline.get_phase_states(project_id)}
            raise ValueError("该小阶段正在运行中")
        return pipeline.request_conversation_continue(project_id, lp, msg)

    if state.get("path_stopped"):
        label = "攻击链串联" if attack_chain else MINING_PATH_LABELS.get(mining_path or "", "该挖掘路径")
        raise ValueError(f"{label}已暂停，请先恢复")
    return pipeline.request_conversation_new(project_id, lp, msg)

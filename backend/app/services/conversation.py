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


CONTINUE_EMPTY = "用户请求接续此对话，请从中断处继续。"
CONTINUE_WITH_MSG = "## 用户接续指示\n{message}\n\n请从中断处继续。"


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
    can_continue = (resumable or archived) and not running
    can_steer = running
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        blocked = proj is None or proj.status in ("cancelled", "ingesting", "error")
    can_new = not blocked
    return {
        "log_phase": lp,
        "running": running,
        "can_continue": can_continue,
        "can_new": can_new,
        "can_steer": can_steer,
        "has_archived": archived,
        "latest_session": _latest_session(project_id, lp),
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
    if act not in ("steer", "continue", "new"):
        raise ValueError("action 须为 steer、continue 或 new")

    msg = normalize_conversation_message(message) if message else ""

    with SessionLocal() as db:
        proj = db.get(Project, project_id)
    _project_ok(proj)

    state = get_conversation_state(project_id, lp)
    if act == "steer":
        if not state["can_steer"]:
            if state["can_continue"]:
                act = "continue"
            else:
                raise ValueError("当前小阶段未在运行，请使用接续或新开")
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
        if state["running"]:
            if msg:
                enqueue_steer(project_id, lp, msg)
                return {"ok": True, "action": "steer", "log_phase": lp, **pipeline.get_phase_states(project_id)}
            raise ValueError("该小阶段正在运行中")
        return pipeline.request_conversation_continue(project_id, lp, msg)

    # new
    return pipeline.request_conversation_new(project_id, lp, msg)

"""In-flight user guidance: queue steer messages and register active AgentLoops."""

from __future__ import annotations

import json
import threading
from typing import TYPE_CHECKING, Any

from .conversation_archive import db_phase_to_log_phase, normalize_log_phase
from .paths import steer_dir

if TYPE_CHECKING:
    from ..agent.loop import AgentLoop

_lock = threading.Lock()
_active_loops: dict[tuple[int, str], AgentLoop] = {}


def _steer_path(project_id: int, log_phase: str) -> Any:
    lp = normalize_log_phase(log_phase)
    d = steer_dir(project_id)
    return d / f"{lp.replace('/', '_')}.json"


def _load_queue(project_id: int, log_phase: str) -> list[str]:
    path = _steer_path(project_id, log_phase)
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(data, dict):
        return []
    msgs = data.get("messages")
    if not isinstance(msgs, list):
        return []
    return [str(m).strip() for m in msgs if str(m).strip()]


def _save_queue(project_id: int, log_phase: str, messages: list[str]) -> None:
    path = _steer_path(project_id, log_phase)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"messages": messages}
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)


def register_loop(loop: AgentLoop) -> None:
    log_phase = db_phase_to_log_phase(loop.phase)
    with _lock:
        _active_loops[(loop.project_id, log_phase)] = loop


def unregister_loop(loop: AgentLoop) -> None:
    log_phase = db_phase_to_log_phase(loop.phase)
    with _lock:
        _active_loops.pop((loop.project_id, log_phase), None)


def get_active_loop(project_id: int, log_phase: str) -> AgentLoop | None:
    lp = normalize_log_phase(log_phase)
    with _lock:
        return _active_loops.get((project_id, lp))


def is_loop_running(project_id: int, log_phase: str) -> bool:
    loop = get_active_loop(project_id, log_phase)
    return loop is not None


def enqueue_steer(project_id: int, log_phase: str, message: str) -> None:
    text = (message or "").strip()
    if not text:
        raise ValueError("引导内容不能为空")
    lp = normalize_log_phase(log_phase)
    with _lock:
        queue = _load_queue(project_id, lp)
        queue.append(text)
        _save_queue(project_id, lp, queue)


def consume_steer_messages(project_id: int, log_phase: str) -> list[str]:
    lp = normalize_log_phase(log_phase)
    with _lock:
        queue = _load_queue(project_id, lp)
        if queue:
            _save_queue(project_id, lp, [])
        return queue


def clear_steer_queue(project_id: int, log_phase: str) -> None:
    lp = normalize_log_phase(log_phase)
    with _lock:
        _save_queue(project_id, lp, [])


STEER_USER_PREFIX = "## 用户引导\n"

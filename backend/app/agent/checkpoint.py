"""Persist in-flight AgentLoop messages so pause/restart can continue the same context."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

from ..models import PhaseRun, SessionLocal
from ..services.paths import checkpoints_dir


RESUMABLE_STATUSES = ("running", "paused")


@dataclass
class LoopCheckpoint:
    project_id: int
    phase_run_id: int
    role: str
    phase: str
    system_prompt: str
    user_prompt: str
    messages: list[dict[str, Any]]
    state: dict[str, Any] = field(default_factory=dict)
    worker_id: str | None = None
    vuln_id: int | None = None
    file_path: str | None = None
    watchdog: dict[str, Any] = field(default_factory=dict)
    last_prompt_tokens: int = 0
    timeout_sec: int = 0
    rate_limit_retries: int = 0
    transient_retries: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_id": self.project_id,
            "phase_run_id": self.phase_run_id,
            "role": self.role,
            "phase": self.phase,
            "system_prompt": self.system_prompt,
            "user_prompt": self.user_prompt,
            "messages": self.messages,
            "state": self.state,
            "worker_id": self.worker_id,
            "vuln_id": self.vuln_id,
            "file_path": self.file_path,
            "watchdog": self.watchdog,
            "last_prompt_tokens": self.last_prompt_tokens,
            "timeout_sec": self.timeout_sec,
            "rate_limit_retries": self.rate_limit_retries,
            "transient_retries": self.transient_retries,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> LoopCheckpoint:
        return cls(
            project_id=int(data["project_id"]),
            phase_run_id=int(data["phase_run_id"]),
            role=str(data.get("role") or ""),
            phase=str(data.get("phase") or ""),
            system_prompt=str(data.get("system_prompt") or ""),
            user_prompt=str(data.get("user_prompt") or ""),
            messages=list(data.get("messages") or []),
            state=dict(data.get("state") or {}),
            worker_id=data.get("worker_id"),
            vuln_id=data.get("vuln_id"),
            file_path=data.get("file_path"),
            watchdog=dict(data.get("watchdog") or {}),
            last_prompt_tokens=int(data.get("last_prompt_tokens") or 0),
            timeout_sec=int(data.get("timeout_sec") or 0),
            rate_limit_retries=int(data.get("rate_limit_retries") or 0),
            transient_retries=int(data.get("transient_retries") or 0),
        )


def checkpoint_path(project_id: int, phase_run_id: int):
    return checkpoints_dir(project_id) / f"{phase_run_id}.json"


def checkpoint_exists(project_id: int, phase_run_id: int) -> bool:
    return checkpoint_path(project_id, phase_run_id).is_file()


def save_checkpoint(cp: LoopCheckpoint, *, status: str = "running") -> None:
    path = checkpoint_path(cp.project_id, cp.phase_run_id)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(cp.to_dict(), ensure_ascii=False), encoding="utf-8")
    last_err: OSError | None = None
    for attempt in range(4):
        try:
            tmp.replace(path)
            last_err = None
            break
        except OSError as e:
            last_err = e
            time.sleep(0.05 * (attempt + 1))
    if last_err is not None:
        try:
            path.write_text(tmp.read_text(encoding="utf-8"), encoding="utf-8")
            tmp.unlink(missing_ok=True)
        except OSError:
            raise last_err from None
    _touch_phase_run(cp, status=status)


def load_checkpoint(project_id: int, phase_run_id: int) -> LoopCheckpoint | None:
    path = checkpoint_path(project_id, phase_run_id)
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict) or not data.get("messages"):
        return None
    return LoopCheckpoint.from_dict(data)


def clear_checkpoint(project_id: int, phase_run_id: int) -> None:
    path = checkpoint_path(project_id, phase_run_id)
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass
    tmp = path.with_suffix(".json.tmp")
    try:
        tmp.unlink(missing_ok=True)
    except OSError:
        pass


def list_resumable_runs(project_id: int, phase: str | None = None) -> list[PhaseRun]:
    with SessionLocal() as db:
        q = db.query(PhaseRun).filter(
            PhaseRun.project_id == project_id,
            PhaseRun.status.in_(RESUMABLE_STATUSES),
        )
        if phase:
            q = q.filter(PhaseRun.phase == phase)
        rows = q.order_by(PhaseRun.id.asc()).all()
        for row in rows:
            db.expunge(row)
    return [r for r in rows if checkpoint_exists(project_id, r.id)]


def resumable_file_paths(project_id: int) -> set[str]:
    paths: set[str] = set()
    for phase in ("worker", "fast-worker", "bypass-worker"):
        for pr in list_resumable_runs(project_id, phase):
            path = pr.file_path
            if not path:
                cp = load_checkpoint(project_id, pr.id)
                path = cp.file_path if cp else None
            if path:
                paths.add(path)
    return paths


def resumable_vuln_ids(project_id: int, phase: str = "fix") -> set[int]:
    ids: set[int] = set()
    for pr in list_resumable_runs(project_id, phase):
        if pr.vuln_id is not None:
            ids.add(int(pr.vuln_id))
    return ids


def set_phase_run_status(run_id: int, status: str) -> None:
    with SessionLocal() as db:
        pr = db.get(PhaseRun, run_id)
        if not pr:
            return
        pr.status = status
        if status == "running":
            pr.finished_at = None
            pr.error = None
        db.commit()


def set_phase_run_worker(run_id: int, worker_id: str, file_path: str | None = None) -> None:
    with SessionLocal() as db:
        pr = db.get(PhaseRun, run_id)
        if not pr:
            return
        pr.worker_id = worker_id
        if file_path:
            pr.file_path = file_path
        db.commit()


def _touch_phase_run(cp: LoopCheckpoint, *, status: str) -> None:
    try:
        with SessionLocal() as db:
            pr = db.get(PhaseRun, cp.phase_run_id)
            if not pr:
                return
            if pr.status in ("cancelled", "completed", "failed") and status in RESUMABLE_STATUSES:
                return
            pr.status = status
            if cp.file_path and not pr.file_path:
                pr.file_path = cp.file_path
            if status in RESUMABLE_STATUSES:
                pr.finished_at = None
            db.commit()
    except Exception:  # noqa: BLE001
        pass

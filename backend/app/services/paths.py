from __future__ import annotations

import os
import shutil
import stat
import time
from pathlib import Path

from ..config import PROJECTS_DIR


def force_rmtree(path: Path, attempts: int = 8) -> None:
    """Remove a directory tree, including Windows read-only .git files."""

    def _handle(func, p, _exc) -> None:  # noqa: ANN001
        try:
            os.chmod(p, stat.S_IWRITE)
            func(p)
        except OSError:
            pass

    target = Path(path)
    if not target.exists():
        return
    for i in range(attempts):
        try:
            shutil.rmtree(target, onexc=_handle)
        except TypeError:
            shutil.rmtree(target, onerror=lambda fn, p, err: _handle(fn, p, err))
        except OSError:
            pass
        if not target.exists():
            return
        time.sleep(0.3 * (i + 1))
    shutil.rmtree(target, ignore_errors=True)
    if target.exists():
        raise RuntimeError(f"无法删除目录: {target}")


def project_root(project_id: int) -> Path:
    path = PROJECTS_DIR / str(project_id)
    path.mkdir(parents=True, exist_ok=True)
    return path


def ensure_project_dirs(project_id: int) -> Path:
    root = project_root(project_id)
    for sub in (
        "src",
        "workspace",
        "workspace/checkpoints",
        "workspace/rounds",
        "docs",
        "docs/old-vulns",
        "docs/summaries",
        "docs/verifier",
        "vulns",
        "env",
        "logs",
    ):
        (root / sub).mkdir(parents=True, exist_ok=True)
    return root


def src_dir(project_id: int) -> Path:
    return ensure_project_dirs(project_id) / "src"


def workspace_dir(project_id: int) -> Path:
    return ensure_project_dirs(project_id) / "workspace"


def checkpoints_dir(project_id: int) -> Path:
    path = workspace_dir(project_id) / "checkpoints"
    path.mkdir(parents=True, exist_ok=True)
    return path


def docs_dir(project_id: int) -> Path:
    return ensure_project_dirs(project_id) / "docs"


def fofa_cache_path(project_id: int) -> Path:
    """Project-wide FOFA search cache shared by every Verifier vuln."""
    return docs_dir(project_id) / "fofa-targets.json"


def old_vulns_dir(project_id: int) -> Path:
    return docs_dir(project_id) / "old-vulns"


def summaries_dir(project_id: int) -> Path:
    return docs_dir(project_id) / "summaries"


def vulns_dir(project_id: int) -> Path:
    return ensure_project_dirs(project_id) / "vulns"


def vuln_dir(project_id: int, vuln_id: int) -> Path:
    path = vulns_dir(project_id) / str(vuln_id)
    path.mkdir(parents=True, exist_ok=True)
    return path


def env_dir(project_id: int) -> Path:
    return ensure_project_dirs(project_id) / "env"


def logs_dir(project_id: int) -> Path:
    return ensure_project_dirs(project_id) / "logs"


def tool_exec_errors_path(project_id: int) -> Path:
    return logs_dir(project_id) / "tool-exec-errors.jsonl"


def live_events_path(project_id: int) -> Path:
    return logs_dir(project_id) / "live.events.jsonl"


def phase_log_path(project_id: int, phase: str, run_id: int) -> Path:
    return logs_dir(project_id) / f"{phase}-{run_id}.jsonl"

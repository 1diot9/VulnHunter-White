from __future__ import annotations

import os
import shutil
import stat
import time
from pathlib import Path

from ..config import PROJECTS_DIR


def windows_long_path(path: Path | str) -> Path:
    """Return a Path that bypasses Windows MAX_PATH via the ``\\\\?\\`` prefix.

    No-op on POSIX. Already-prefixed paths are returned unchanged. UNC paths
    become ``\\\\?\\UNC\\server\\share\\...``. Git for Windows can checkout
    trees longer than 260 characters when ``core.longpaths`` is on; Python I/O
    still needs this prefix unless the OS long-path policy is enabled.
    """
    if os.name != "nt":
        return Path(path)
    raw = os.path.normpath(os.path.abspath(os.fspath(path)))
    if raw.startswith("\\\\?\\"):
        return Path(raw)
    if raw.startswith("\\\\"):
        return Path("\\\\?\\UNC\\" + raw[2:])
    return Path("\\\\?\\" + raw)


def strip_windows_long_path(path: Path | str) -> Path:
    """Remove a ``\\\\?\\`` / ``\\\\?\\UNC\\`` prefix so relative_to() still works."""
    raw = os.fspath(path)
    if raw.startswith("\\\\?\\UNC\\"):
        return Path("\\\\" + raw[8:])
    if raw.startswith("\\\\?\\"):
        return Path(raw[4:])
    return Path(path)


def force_rmtree(path: Path, attempts: int = 8) -> None:
    """Remove a directory tree, including Windows read-only .git files."""

    def _handle(func, p, _exc) -> None:  # noqa: ANN001
        try:
            os.chmod(p, stat.S_IWRITE)
            func(p)
        except OSError:
            pass

    target = windows_long_path(path)
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


def project_dir(project_id: int) -> Path:
    """Project workspace path without creating it."""
    return PROJECTS_DIR / str(project_id)


def project_root(project_id: int) -> Path:
    path = project_dir(project_id)
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
        "docs/attack-chains",
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


def app_fingerprints_path(project_id: int) -> Path:
    """Project-wide application FOFA/X fingerprint, collected once and reused."""
    return docs_dir(project_id) / "app-fingerprints.json"


def old_vulns_dir(project_id: int) -> Path:
    return docs_dir(project_id) / "old-vulns"


def attack_chains_dir(project_id: int) -> Path:
    path = docs_dir(project_id) / "attack-chains"
    path.mkdir(parents=True, exist_ok=True)
    return path


def old_vuln_crawl_spec_path(project_id: int) -> Path:
    """LLM pass product slug / extra packages for the GHSA crawler."""
    return workspace_dir(project_id) / "old-vuln-crawl.json"


def ghsa_new_path(project_id: int) -> Path:
    """Crawler output for the historical-vuln GHSA + GitHub Issues supplement pass."""
    return workspace_dir(project_id) / "ghsa_new.json"


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


def iter_project_ids() -> list[int]:
    """Numeric workspace folders under PROJECTS_DIR. Does not create anything."""
    root = PROJECTS_DIR
    if not root.exists():
        return []
    return sorted(int(p.name) for p in root.iterdir() if p.is_dir() and p.name.isdigit())


def tool_exec_errors_path(project_id: int) -> Path:
    return logs_dir(project_id) / "tool-exec-errors.jsonl"


def live_events_path(project_id: int) -> Path:
    return logs_dir(project_id) / "live.events.jsonl"


def phase_log_path(project_id: int, phase: str, run_id: int) -> Path:
    return logs_dir(project_id) / f"{phase}-{run_id}.jsonl"

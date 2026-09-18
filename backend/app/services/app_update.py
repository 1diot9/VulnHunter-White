"""Check and apply VulnHunter self-updates from the git upstream remote."""

from __future__ import annotations

import logging
import os
import re
import subprocess
import threading
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..config import ROOT_DIR, settings
from .runtime import is_docker_runtime
from .shutdown import is_shutting_down

logger = logging.getLogger(__name__)

DEFAULT_UPSTREAM_URL = "https://github.com/1diot9/VulnHunter-White.git"
_VERSION_RE = re.compile(r"^##\s+(V\d+\.\d+\.\d+)\b", re.M)
_SHA_RE = re.compile(r"^[0-9a-f]{7,64}$", re.I)
_CHECK_LOCK = threading.Lock()
_APPLY_LOCK = threading.Lock()
_poll_stop = threading.Event()
_poll_thread: threading.Thread | None = None
_applying = False
_restarting = False
_cached: AppUpdateStatus | None = None

_BACKEND_DEP_FILES = ("backend/requirements.txt",)
_FRONTEND_DEP_FILES = ("frontend/package.json", "frontend/package-lock.json")


@dataclass
class AppUpdateStatus:
    git_available: bool = False
    docker_runtime: bool = False
    current_version: str = ""
    current_sha: str = ""
    remote_name: str = ""
    remote_url: str = ""
    remote_ref: str = ""
    remote_sha: str = ""
    remote_version: str = ""
    update_available: bool = False
    can_apply: bool = False
    apply_blocked_reason: str = ""
    dirty: bool = False
    applying: bool = False
    restarting: bool = False
    last_checked_at: str | None = None
    last_error: str = ""
    check_interval_sec: int = 3600


def parse_changelog_version(text: str) -> str:
    match = _VERSION_RE.search(text or "")
    return match.group(1) if match else ""


def short_sha(sha: str) -> str:
    raw = (sha or "").strip()
    return raw[:7] if raw else ""


def redact_remote_url(url: str) -> str:
    text = (url or "").strip()
    text = re.sub(r"https://[^/@\s]+@", "https://", text)
    return text


def local_version(root: Path | None = None) -> str:
    path = (root or ROOT_DIR) / "CHANGELOG.md"
    try:
        return parse_changelog_version(path.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return ""


def status_to_out(status: AppUpdateStatus) -> dict[str, Any]:
    payload = asdict(status)
    payload["current_sha_short"] = short_sha(status.current_sha)
    payload["remote_sha_short"] = short_sha(status.remote_sha)
    return payload


def current_status() -> AppUpdateStatus:
    with _CHECK_LOCK:
        if _cached is not None:
            return _with_runtime_flags(_cached)
    return check_for_update()


def check_for_update() -> AppUpdateStatus:
    with _CHECK_LOCK:
        status = _probe()
        global _cached
        _cached = status
        return _with_runtime_flags(status)


def apply_update() -> dict[str, Any]:
    global _applying, _restarting
    with _APPLY_LOCK:
        if _applying or _restarting:
            return {
                "ok": False,
                "restarting": _restarting,
                "reason": "applying",
                "error": "",
                "old_sha": "",
                "new_sha": "",
                "pulled": False,
            }
        _applying = True
    try:
        status = check_for_update()
        if status.docker_runtime:
            return _apply_fail("docker")
        if not status.git_available:
            return _apply_fail(status.apply_blocked_reason or "not_git", status.last_error)
        if status.dirty:
            return _apply_fail("dirty")
        if not status.update_available:
            return _apply_fail(status.apply_blocked_reason or "no_update")
        if not status.can_apply:
            return _apply_fail(status.apply_blocked_reason or "check_failed", status.last_error)

        old_sha = status.current_sha
        pulled = _fast_forward(status)
        if pulled.get("ok") is not True:
            return {
                "ok": False,
                "restarting": False,
                "reason": str(pulled.get("reason") or "check_failed"),
                "error": str(pulled.get("error") or ""),
                "old_sha": old_sha,
                "new_sha": str(pulled.get("new_sha") or old_sha),
                "pulled": False,
            }
        new_sha = str(pulled.get("new_sha") or "")
        dep_error = _install_changed_deps(old_sha, new_sha)
        _restarting = True
        spawned = _spawn_restarter()
        if not spawned:
            _restarting = False
            return {
                "ok": False,
                "restarting": False,
                "reason": "check_failed",
                "error": dep_error or "无法拉起重启脚本",
                "old_sha": old_sha,
                "new_sha": new_sha,
                "pulled": True,
            }
        check_for_update()
        return {
            "ok": True,
            "restarting": True,
            "reason": "",
            "error": dep_error,
            "old_sha": old_sha,
            "new_sha": new_sha,
            "pulled": True,
        }
    except Exception as exc:  # noqa: BLE001
        logger.exception("app update failed")
        return _apply_fail("check_failed", str(exc))
    finally:
        _applying = False


def start_app_update_checker() -> None:
    global _poll_thread
    if not bool(settings.app_update_check):
        return
    if _poll_thread is not None and _poll_thread.is_alive():
        return
    _poll_stop.clear()
    _poll_thread = threading.Thread(target=_poll_loop, name="vh-app-update", daemon=True)
    _poll_thread.start()


def stop_app_update_checker() -> None:
    global _poll_thread
    _poll_stop.set()
    thread = _poll_thread
    if thread is not None and thread.is_alive() and thread is not threading.current_thread():
        thread.join(timeout=2)
    _poll_thread = None


def reset_app_update_state() -> None:
    """Test helper."""
    global _cached, _applying, _restarting
    stop_app_update_checker()
    _poll_stop.clear()
    with _CHECK_LOCK:
        _cached = None
    _applying = False
    _restarting = False


def _poll_loop() -> None:
    interval = _check_interval_sec()
    while not _poll_stop.is_set() and not is_shutting_down():
        try:
            check_for_update()
        except Exception:  # noqa: BLE001
            logger.exception("app update check failed")
        if _poll_stop.wait(interval):
            break
        if is_shutting_down():
            break


def _check_interval_sec() -> int:
    try:
        return max(60, int(settings.app_update_interval_sec or 3600))
    except (TypeError, ValueError):
        return 3600


def _with_runtime_flags(status: AppUpdateStatus) -> AppUpdateStatus:
    status.applying = _applying
    status.restarting = _restarting
    status.check_interval_sec = _check_interval_sec()
    if _restarting:
        status.can_apply = False
        if not status.apply_blocked_reason:
            status.apply_blocked_reason = "applying"
    return status


def _apply_fail(reason: str, error: str = "") -> dict[str, Any]:
    return {
        "ok": False,
        "restarting": False,
        "reason": reason,
        "error": error or "",
        "old_sha": "",
        "new_sha": "",
        "pulled": False,
    }


def _probe() -> AppUpdateStatus:
    status = AppUpdateStatus(
        docker_runtime=is_docker_runtime(),
        current_version=local_version(),
        last_checked_at=_now_iso(),
        check_interval_sec=_check_interval_sec(),
    )
    repo = ROOT_DIR
    if not _is_git_work_tree(repo):
        status.apply_blocked_reason = "not_git"
        status.last_error = "当前安装不是 git 工作副本"
        return status
    status.git_available = True
    dirty = _is_dirty(repo)
    status.dirty = dirty
    head = _rev_parse(repo, "HEAD")
    status.current_sha = head
    remote = _resolve_remote(repo)
    status.remote_name = remote["name"]
    status.remote_url = redact_remote_url(remote["url"])
    status.remote_ref = remote["ref"]
    if not remote["fetch_url"]:
        status.apply_blocked_reason = "check_failed"
        status.last_error = remote.get("error") or "没有可用的上游仓库"
        return _block_apply(status)
    try:
        remote_sha = _ls_remote_sha(repo, remote["fetch_url"], remote["ref"])
    except Exception as exc:  # noqa: BLE001
        status.apply_blocked_reason = "check_failed"
        status.last_error = str(exc)
        return _block_apply(status)
    status.remote_sha = remote_sha
    if remote_sha and remote_sha != head:
        status.update_available = True
        status.remote_version = _remote_changelog_version(status.remote_url, remote_sha)
    if status.docker_runtime:
        status.apply_blocked_reason = "docker"
        return _block_apply(status)
    if dirty:
        status.apply_blocked_reason = "dirty"
        return _block_apply(status)
    if not status.update_available:
        status.apply_blocked_reason = "no_update"
        return status
    status.can_apply = True
    return status


def _block_apply(status: AppUpdateStatus) -> AppUpdateStatus:
    status.can_apply = False
    return status


def _is_git_work_tree(repo: Path) -> bool:
    proc = _git(["rev-parse", "--is-inside-work-tree"], cwd=repo, timeout=15)
    return proc.returncode == 0 and (proc.stdout or "").strip().lower() == "true"


def _is_dirty(repo: Path) -> bool:
    proc = _git(["status", "--porcelain=v1", "-uno"], cwd=repo, timeout=20)
    if proc.returncode != 0:
        return False
    return bool((proc.stdout or "").strip())


def _rev_parse(repo: Path, ref: str) -> str:
    proc = _git(["rev-parse", ref], cwd=repo, timeout=15)
    if proc.returncode != 0:
        return ""
    sha = (proc.stdout or "").strip().lower()
    return sha if _SHA_RE.fullmatch(sha) else ""


def _resolve_remote(repo: Path) -> dict[str, str]:
    names = _remote_names(repo)
    name = "upstream" if "upstream" in names else ("origin" if "origin" in names else "")
    url = _remote_url(repo, name) if name else DEFAULT_UPSTREAM_URL
    ref = _tracking_ref(repo, name) or "HEAD"
    error = ""
    fetch_url = ""
    try:
        from .ingest import _authenticated_github_url

        fetch_url = _authenticated_github_url(url) if url else ""
    except Exception as exc:  # noqa: BLE001
        fetch_url = url
        error = str(exc)
    if not fetch_url:
        fetch_url = url
    return {
        "name": name or "upstream",
        "url": url,
        "ref": ref,
        "fetch_url": fetch_url,
        "error": error,
    }


def _remote_names(repo: Path) -> list[str]:
    proc = _git(["remote"], cwd=repo, timeout=15)
    if proc.returncode != 0:
        return []
    return [line.strip() for line in (proc.stdout or "").splitlines() if line.strip()]


def _remote_url(repo: Path, name: str) -> str:
    proc = _git(["remote", "get-url", name], cwd=repo, timeout=15)
    if proc.returncode != 0:
        return ""
    return (proc.stdout or "").strip()


def _tracking_ref(repo: Path, remote_name: str) -> str:
    if not remote_name:
        return ""
    proc = _git(
        ["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"],
        cwd=repo,
        timeout=15,
    )
    if proc.returncode != 0:
        return ""
    tracking = (proc.stdout or "").strip()
    prefix = f"{remote_name}/"
    if not tracking.startswith(prefix):
        return ""
    branch = tracking[len(prefix) :].strip()
    if not branch or branch in {"HEAD", "@{u}"}:
        return ""
    if branch.startswith("refs/"):
        return branch
    return f"refs/heads/{branch}"


def _ls_remote_sha(repo: Path, fetch_url: str, ref: str) -> str:
    from .ingest import _GIT_LS_REMOTE_TIMEOUT, _parse_ls_remote_head

    spec = ref if ref and ref != "HEAD" else "HEAD"
    proc = _git(["ls-remote", fetch_url, spec], cwd=repo, timeout=_GIT_LS_REMOTE_TIMEOUT)
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "git ls-remote 失败").strip()
        raise RuntimeError(detail)
    return _parse_ls_remote_head(proc.stdout)


def _remote_changelog_version(remote_url: str, sha: str) -> str:
    owner_repo = _github_owner_repo(remote_url)
    if not owner_repo or not sha:
        return ""
    url = f"https://raw.githubusercontent.com/{owner_repo}/{sha}/CHANGELOG.md"
    try:
        from .http_client import http_client

        with http_client(timeout=12.0) as client:
            response = client.get(url)
        if response.status_code != 200:
            return ""
        return parse_changelog_version(response.text)
    except Exception:  # noqa: BLE001
        return ""


def _github_owner_repo(url: str) -> str:
    try:
        from .github_discover import parse_owner_repo

        return parse_owner_repo(url) or ""
    except Exception:  # noqa: BLE001
        return ""


def _fast_forward(status: AppUpdateStatus) -> dict[str, Any]:
    from .ingest import _GIT_FETCH_TIMEOUT

    repo = ROOT_DIR
    remote = _resolve_remote(repo)
    fetch_url = remote["fetch_url"]
    ref = status.remote_ref or remote["ref"] or "HEAD"
    fetch_ref = "HEAD" if ref == "HEAD" else ref
    fetched = _git(
        ["fetch", fetch_url, fetch_ref],
        cwd=repo,
        timeout=_GIT_FETCH_TIMEOUT,
    )
    if fetched.returncode != 0:
        return {
            "ok": False,
            "reason": "check_failed",
            "error": (fetched.stderr or fetched.stdout or "git fetch 失败").strip(),
        }
    fetch_head = _rev_parse(repo, "FETCH_HEAD")
    if not fetch_head:
        return {"ok": False, "reason": "check_failed", "error": "无法解析 FETCH_HEAD"}
    head = _rev_parse(repo, "HEAD")
    if fetch_head == head:
        return {"ok": True, "new_sha": head}
    if not _is_ancestor(repo, head, fetch_head):
        if _is_ancestor(repo, fetch_head, head):
            return {"ok": False, "reason": "ahead", "error": "本地提交比上游新，未执行快进"}
        return {"ok": False, "reason": "diverged", "error": "本地与上游已分叉，无法快进"}
    merged = _git(["merge", "--ff-only", "FETCH_HEAD"], cwd=repo, timeout=120)
    if merged.returncode != 0:
        return {
            "ok": False,
            "reason": "check_failed",
            "error": (merged.stderr or merged.stdout or "git merge 失败").strip(),
            "new_sha": head,
        }
    return {"ok": True, "new_sha": _rev_parse(repo, "HEAD") or fetch_head}


def _is_ancestor(repo: Path, maybe_ancestor: str, maybe_descendant: str) -> bool:
    if not maybe_ancestor or not maybe_descendant:
        return False
    proc = _git(
        ["merge-base", "--is-ancestor", maybe_ancestor, maybe_descendant],
        cwd=repo,
        timeout=20,
    )
    return proc.returncode == 0


def _install_changed_deps(old_sha: str, new_sha: str) -> str:
    changed = _changed_files(old_sha, new_sha)
    errors: list[str] = []
    if _paths_changed(changed, _BACKEND_DEP_FILES):
        err = _install_backend_deps()
        if err:
            errors.append(err)
    if _paths_changed(changed, _FRONTEND_DEP_FILES):
        err = _install_frontend_deps()
        if err:
            errors.append(err)
    return "\n".join(errors)


def _changed_files(old_sha: str, new_sha: str) -> set[str]:
    if not old_sha or not new_sha or old_sha == new_sha:
        return set()
    proc = _git(["diff", "--name-only", old_sha, new_sha], cwd=ROOT_DIR, timeout=30)
    if proc.returncode != 0:
        return set(_BACKEND_DEP_FILES + _FRONTEND_DEP_FILES)
    names = {(line or "").strip().replace("\\", "/") for line in (proc.stdout or "").splitlines()}
    names.discard("")
    return names


def _paths_changed(changed: set[str], paths: tuple[str, ...]) -> bool:
    wanted = {item.replace("\\", "/") for item in paths}
    return bool(changed & wanted)


def _install_backend_deps() -> str:
    pip = _venv_pip()
    if pip is None:
        return "未找到 backend/.venv，无法安装依赖"
    req = ROOT_DIR / "backend" / "requirements.txt"
    index = (os.environ.get("VULNHUNTER_PIP_INDEX_URL") or "https://pypi.tuna.tsinghua.edu.cn/simple").strip()
    proc = _run_cmd([str(pip), "install", "-r", str(req), "-i", index], timeout=300)
    if proc.returncode == 0:
        return ""
    retry = _run_cmd([str(pip), "install", "-r", str(req)], timeout=300)
    if retry.returncode == 0:
        return ""
    return (retry.stderr or retry.stdout or proc.stderr or "pip install 失败").strip()


def _install_frontend_deps() -> str:
    frontend = ROOT_DIR / "frontend"
    proc = _run_cmd(
        ["npm", "install", "--registry=https://registry.npmmirror.com"],
        cwd=frontend,
        timeout=300,
    )
    if proc.returncode == 0:
        return ""
    return (proc.stderr or proc.stdout or "npm install 失败").strip()


def _venv_pip() -> Path | None:
    if os.name == "nt":
        candidate = ROOT_DIR / "backend" / ".venv" / "Scripts" / "pip.exe"
    else:
        candidate = ROOT_DIR / "backend" / ".venv" / "bin" / "pip"
    return candidate if candidate.is_file() else None


def _spawn_restarter() -> bool:
    env = os.environ.copy()
    _fill_listen_env(env)
    if os.name == "nt":
        script = ROOT_DIR / "scripts" / "_hot-update-restart.cmd"
        if not script.is_file():
            return False
        creationflags = (
            getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            | getattr(subprocess, "DETACHED_PROCESS", 0)
            | getattr(subprocess, "CREATE_NO_WINDOW", 0)
        )
        subprocess.Popen(  # noqa: S603
            ["cmd.exe", "/c", str(script)],
            cwd=str(ROOT_DIR),
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            creationflags=creationflags,
        )
        return True
    script = ROOT_DIR / "scripts" / "_hot-update-restart.sh"
    if not script.is_file():
        return False
    subprocess.Popen(  # noqa: S603
        ["sh", str(script)],
        cwd=str(ROOT_DIR),
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        start_new_session=True,
    )
    return True


def _fill_listen_env(env: dict[str, str]) -> None:
    ports = _read_ports_env()
    for key in ("VULNHUNTER_PORT", "VULNHUNTER_FRONTEND_PORT", "VULNHUNTER_HOST", "VULNHUNTER_RELOAD"):
        current = (env.get(key) or "").strip()
        if current:
            continue
        fallback = (ports.get(key) or "").strip()
        if fallback:
            env[key] = fallback


def _read_ports_env() -> dict[str, str]:
    path = ROOT_DIR / "data" / "run" / "ports.env"
    out: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return out
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if key:
            out[key] = value.strip()
    return out


def _git(args: list[str], *, cwd: Path | None = None, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    from .ingest import _run_git

    return _run_git(args, cwd=cwd, timeout=timeout)


def _run_cmd(
    args: list[str],
    *,
    cwd: Path | None = None,
    timeout: int = 120,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=str(cwd) if cwd is not None else str(ROOT_DIR),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        env=os.environ.copy(),
        shell=False,
    )


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

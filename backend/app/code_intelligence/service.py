"""Project-level CodeGraph index lifecycle."""

from __future__ import annotations

import hashlib
import json
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..config import settings
from ..models import Project, SessionLocal, utcnow
from ..services.ingest import IGNORE_DIR_NAMES
from ..services.live_log import live_log
from ..services.paths import code_intel_dir, src_dir, strip_windows_long_path
from .cli import cli_version, ensure_codegraph, find_codegraph, popen_ui, stream_codegraph

CODE_INTEL_PHASE = "code_intel"
STATUSES = ("pending", "building", "ready", "degraded", "stale")
_STALE_CHECK_SEC = 30.0
_last_stale_check: dict[int, float] = {}
_ui_lock = threading.Lock()
_ui_procs: dict[int, Any] = {}
_ui_urls: dict[int, str] = {}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _meta_path(project_id: int) -> Path:
    return code_intel_dir(project_id) / "metadata.json"


def _index_dir(project_id: int) -> Path:
    return src_dir(project_id) / ".codegraph"


def read_metadata(project_id: int) -> dict[str, Any]:
    path = _meta_path(project_id)
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def write_metadata(project_id: int, payload: dict[str, Any]) -> None:
    path = _meta_path(project_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    current = read_metadata(project_id)
    current.update(payload)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(current, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)


def source_fingerprint(project_id: int) -> str:
    """Hash of source files under src/ (size + mtime). Skips .codegraph and ignore dirs."""
    root = src_dir(project_id)
    if not root.is_dir():
        return hashlib.sha256(b"").hexdigest()
    skip = set(IGNORE_DIR_NAMES) | {".codegraph"}
    lines: list[str] = []
    for dirpath, dirnames, filenames in os_walk_sorted(root):
        dirnames[:] = [d for d in sorted(dirnames) if d not in skip and d != "." and d != ".."]
        rel_dir = Path(dirpath).relative_to(root).as_posix()
        for name in sorted(filenames):
            if name.startswith("."):
                continue
            rel = name if rel_dir in (".", "") else f"{rel_dir}/{name}"
            path = Path(dirpath) / name
            try:
                st = path.stat()
            except OSError:
                continue
            lines.append(f"{rel}\0{st.st_size}\0{int(st.st_mtime_ns)}")
    blob = "\n".join(lines).encode("utf-8", errors="replace")
    return hashlib.sha256(blob).hexdigest()


def os_walk_sorted(root: Path):
    import os

    return os.walk(root)


def code_intel_settled(project_id: int) -> bool:
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        return bool(proj and getattr(proj, "code_intel_done", False))


def _set_project_fields(project_id: int, **fields: Any) -> None:
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        if not proj:
            return
        for key, value in fields.items():
            setattr(proj, key, value)
        proj.updated_at = utcnow()
        db.commit()


def status_payload(project_id: int) -> dict[str, Any]:
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        if not proj:
            return {
                "status": "pending",
                "done": False,
                "error": "",
                "source_hash": "",
                "version": "",
                "stale": False,
            }
        status = (getattr(proj, "code_intel_status", None) or "pending").strip() or "pending"
        return {
            "status": status,
            "done": bool(getattr(proj, "code_intel_done", False)),
            "error": (getattr(proj, "code_intel_error", None) or "").strip(),
            "source_hash": (getattr(proj, "code_intel_source_hash", None) or "").strip(),
            "version": (getattr(proj, "code_intel_version", None) or "").strip(),
            "stale": status == "stale",
        }


def metadata_payload(project_id: int) -> dict[str, Any]:
    meta = read_metadata(project_id)
    payload = status_payload(project_id)
    payload["backend"] = str(meta.get("backend") or "codegraph")
    payload["index_dir"] = str(meta.get("index_dir") or "src/.codegraph")
    payload["created_at"] = str(meta.get("created_at") or "")
    return payload


def _log(project_id: int, text: str) -> None:
    live_log.system(project_id, text, phase=CODE_INTEL_PHASE, role="code_intel")


def mark_stale_if_source_changed(project_id: int) -> bool:
    """If src/ changed after a ready index, mark stale. Does not rebuild."""
    now = time.time()
    last = _last_stale_check.get(project_id, 0.0)
    if now - last < _STALE_CHECK_SEC:
        return False
    _last_stale_check[project_id] = now
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        if not proj:
            return False
        status = (getattr(proj, "code_intel_status", None) or "").strip()
        if status not in ("ready", "stale"):
            return False
        stored = (getattr(proj, "code_intel_source_hash", None) or "").strip()
    if not stored:
        return False
    current = source_fingerprint(project_id)
    if current == stored:
        if status == "stale":
            _set_project_fields(project_id, code_intel_status="ready", code_intel_error=None)
            write_metadata(project_id, {"status": "ready"})
        return False
    if status != "stale":
        _set_project_fields(project_id, code_intel_status="stale")
        write_metadata(project_id, {"status": "stale", "source_hash": stored})
        _log(project_id, "检测到 src/ 文件变化，代码库已过期。不会自动重建，请点击重建。")
    return True


def run_build(
    project_id: int,
    *,
    force: bool = False,
    cancel: threading.Event | None = None,
) -> str:
    """Build or rebuild the CodeGraph index. Returns final status (ready|degraded)."""
    src = src_dir(project_id)
    src.mkdir(parents=True, exist_ok=True)
    _set_project_fields(
        project_id,
        code_intel_status="building",
        code_intel_error=None,
    )
    write_metadata(
        project_id,
        {
            "backend": "codegraph",
            "status": "building",
            "index_dir": "src/.codegraph",
            "created_at": read_metadata(project_id).get("created_at") or _now_iso(),
        },
    )
    try:
        live_log.begin_session(project_id, CODE_INTEL_PHASE, if_used=True)
    except Exception:  # noqa: BLE001
        pass
    _log(
        project_id,
        "开始重建代码数据库（CodeGraph，仅源码）" if force else "开始构建代码数据库（CodeGraph，仅源码）",
    )

    def log_line(text: str) -> None:
        if text.strip():
            _log(project_id, text[:2000])

    try:
        binary = ensure_codegraph(log=log_line)
    except Exception as exc:  # noqa: BLE001
        return _degrade(project_id, f"安装 CodeGraph 失败: {exc}")
    if binary is None:
        return _degrade(project_id, "未找到 CodeGraph，自动安装失败；已降级为 Read/Grep")

    version = cli_version(binary)
    timeout = int(getattr(settings, "timeout_codegraph_index", 1800) or 1800)
    # CodeGraph `index` requires a prior `init` (needs codegraph.db, not just
    # the .codegraph/ folder). Imported trees often ship an empty .codegraph/
    # gitignore placeholder; treating that as "already indexed" caused
    # "CodeGraph not initialized / run init first" and a silent degrade.
    if (_index_dir(project_id) / "codegraph.db").is_file():
        args = ["index", "--force"]
    else:
        args = ["init", "--yes"]
    try:
        code = stream_codegraph(
            args,
            cwd=src,
            timeout=timeout,
            log=log_line,
            binary=binary,
            cancel=cancel,
        )
    except FileNotFoundError as exc:
        return _degrade(project_id, str(exc))
    except Exception as exc:  # noqa: BLE001
        return _degrade(project_id, f"CodeGraph 执行失败: {exc}")
    if cancel is not None and cancel.is_set():
        _log(project_id, "构建已取消")
        return "cancelled"
    if code != 0:
        return _degrade(project_id, f"CodeGraph 退出码 {code}")
    db_path = _index_dir(project_id) / "codegraph.db"
    if not db_path.is_file():
        return _degrade(project_id, "构建结束但未生成 src/.codegraph/codegraph.db")

    fingerprint = source_fingerprint(project_id)
    _set_project_fields(
        project_id,
        code_intel_status="ready",
        code_intel_done=True,
        code_intel_error=None,
        code_intel_source_hash=fingerprint,
        code_intel_version=version or None,
    )
    write_metadata(
        project_id,
        {
            "backend": "codegraph",
            "version": version,
            "source_hash": fingerprint,
            "created_at": read_metadata(project_id).get("created_at") or _now_iso(),
            "status": "ready",
            "index_dir": "src/.codegraph",
        },
    )
    _log(project_id, f"代码数据库就绪（CodeGraph {version or 'unknown'}）")
    _log(
        project_id,
        "测试可用：在本阶段点击「打开图浏览器」，或于 src/ 下执行 codegraph ui --no-open",
    )
    return "ready"


def _degrade(project_id: int, error: str) -> str:
    msg = (error or "构建失败").strip()[:2000]
    _set_project_fields(
        project_id,
        code_intel_status="degraded",
        code_intel_done=True,
        code_intel_error=msg,
    )
    write_metadata(project_id, {"status": "degraded", "error": msg})
    live_log.error(project_id, f"代码库构建失败，已降级继续审计: {msg}", phase=CODE_INTEL_PHASE)
    return "degraded"


def request_rebuild(project_id: int) -> dict[str, Any]:
    from ..services.pipeline import request_code_intel_rebuild

    return request_code_intel_rebuild(project_id)


def request_ui(project_id: int) -> dict[str, Any]:
    """Start `codegraph ui --no-open` for testers. Returns local URL."""
    payload = status_payload(project_id)
    if payload["status"] not in ("ready", "stale"):
        return {"ok": False, "error": "代码库尚未就绪，无法打开图浏览器"}
    if find_codegraph() is None:
        return {"ok": False, "error": "未找到 codegraph CLI"}
    src = src_dir(project_id)
    with _ui_lock:
        proc = _ui_procs.get(project_id)
        if proc is not None and proc.poll() is None and _ui_urls.get(project_id):
            return {"ok": True, "url": _ui_urls[project_id], "reused": True}
        try:
            proc = popen_ui(src)
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error": str(exc)}
        url = "http://127.0.0.1:4747"
        deadline = time.time() + 8
        assert proc.stdout is not None
        buf = ""
        while time.time() < deadline:
            if proc.poll() is not None:
                rest = proc.stdout.read() or ""
                return {"ok": False, "error": (buf + rest).strip()[:800] or "图浏览器进程已退出"}
            line = proc.stdout.readline()
            if not line:
                time.sleep(0.05)
                continue
            buf += line
            for token in line.replace("'", " ").split():
                if token.startswith("http://127.0.0.1:") or token.startswith("http://localhost:"):
                    url = token.rstrip(".,)")
                    break
            if "127.0.0.1" in line or "localhost" in line:
                break
        _ui_procs[project_id] = proc
        _ui_urls[project_id] = url
    _log(project_id, f"图浏览器已在本机启动: {url}（仅 127.0.0.1，供测试查看）")
    return {"ok": True, "url": url, "reused": False}


def reset_runtime_state() -> None:
    _last_stale_check.clear()
    with _ui_lock:
        for proc in _ui_procs.values():
            try:
                if proc.poll() is None:
                    proc.terminate()
            except Exception:  # noqa: BLE001
                pass
        _ui_procs.clear()
        _ui_urls.clear()


def index_ready(project_id: int) -> bool:
    status = status_payload(project_id)["status"]
    return status in ("ready", "stale") and (_index_dir(project_id) / "codegraph.db").is_file()


def src_root(project_id: int) -> Path:
    return strip_windows_long_path(src_dir(project_id))

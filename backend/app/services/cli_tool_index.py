"""Poll a user CLI-tools directory, index each subdirectory with a silent Agent, and search the index."""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..config import ROOT_DIR, resolve_repo_path, settings
from ..prompts import load_prompt, render_prompt
from ..services.shutdown import is_shutting_down

INDEX_FILENAME = ".vulnhunter-index.json"
LOCK_FILENAME = ".vulnhunter-index.lock"
LOG_FILENAME = "agent.log.jsonl"
CONCLUDE_FILENAME = "conclude.md"
MAX_INDEX_TURNS = 30
_META_NAMES = frozenset(
    {INDEX_FILENAME, LOCK_FILENAME, LOG_FILENAME, CONCLUDE_FILENAME, "compress.md"}
)
_SKIP_DIR_NAMES = frozenset({".git", "__pycache__", "node_modules", ".venv", "venv"})

_STATUS_READY = "ready"
_STATUS_INDEXING = "indexing"
_STATUS_FAILED = "failed"
_STATUS_PENDING = "pending"

_poll_stop = threading.Event()
_poll_thread: threading.Thread | None = None
_index_lock = threading.Lock()
_indexing: set[str] = set()
_log_cache: dict[str, "FileEventLog"] = {}
_log_cache_lock = threading.Lock()


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _local_ts() -> str:
    return datetime.now().astimezone().strftime("%H:%M:%S")


def configured_cli_tools_dir() -> str:
    try:
        from .llm_settings import get_settings_row

        row = get_settings_row()
        stored = str(getattr(row, "cli_tools_dir", None) or "").strip()
        if stored:
            return stored
    except Exception:  # noqa: BLE001
        pass
    return (settings.cli_tools_dir or "tools/cli").strip() or "tools/cli"


def resolve_cli_tools_dir() -> Path:
    return resolve_repo_path(configured_cli_tools_dir(), fallback="tools/cli")


class FileEventLog:
    """JSONL event log written into a CLI tool directory (silent; not project live-events)."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()

    def _append(self, ev: dict[str, Any]) -> None:
        row = {"ts": _local_ts(), **ev}
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            line = json.dumps(row, ensure_ascii=False)
            with self._lock:
                with self.path.open("a", encoding="utf-8") as f:
                    f.write(line + "\n")
        except OSError:
            pass

    def agent(self, project_id: int, text: str, *, phase: str | None = None, role: str | None = None) -> None:
        body = (text or "").strip()
        if not body:
            return
        ev: dict[str, Any] = {"kind": "agent", "text": body, "phase": phase}
        if role:
            ev["role"] = role
        self._append(ev)

    def reasoning(self, project_id: int, text: str, *, phase: str | None = None, role: str | None = None) -> None:
        body = (text or "").strip()
        if not body:
            return
        ev: dict[str, Any] = {"kind": "reasoning", "text": body, "phase": phase}
        if role:
            ev["role"] = role
        self._append(ev)

    def system(
        self,
        project_id: int,
        text: str,
        *,
        source: str = "system",
        phase: str | None = None,
        role: str | None = None,
        session_start: bool = False,
    ) -> None:
        ev: dict[str, Any] = {"kind": "system", "text": text, "source": source, "phase": phase}
        if role:
            ev["role"] = role
        if session_start:
            ev["session_start"] = True
        self._append(ev)

    def error(self, project_id: int, text: str, *, phase: str | None = None, role: str | None = None) -> None:
        ev: dict[str, Any] = {"kind": "error", "text": text, "phase": phase}
        if role:
            ev["role"] = role
        self._append(ev)

    def cmd(
        self,
        project_id: int,
        command: str,
        output: str = "",
        exit_code: int | None = None,
        *,
        phase: str | None = None,
        tool: str | None = None,
        role: str | None = None,
    ) -> None:
        ev: dict[str, Any] = {
            "kind": "cmd",
            "command": command,
            "output": (output or "")[:4000],
            "exit_code": exit_code,
            "phase": phase,
        }
        if tool:
            ev["tool"] = tool
        if role:
            ev["role"] = role
        self._append(ev)

    def tokens(
        self,
        project_id: int,
        *,
        input_tokens: int = 0,
        output_tokens: int = 0,
        cached: int = 0,
        total: int = 0,
        phase: str | None = None,
        role: str | None = None,
    ) -> None:
        ev: dict[str, Any] = {
            "kind": "tokens",
            "input": input_tokens,
            "output": output_tokens,
            "cached": cached,
            "total": total or (input_tokens + output_tokens),
            "phase": phase,
        }
        if role:
            ev["role"] = role
        self._append(ev)

    def tool(
        self,
        project_id: int,
        name: str,
        arguments: dict[str, Any] | None = None,
        result: Any = None,
        *,
        phase: str | None = None,
        role: str | None = None,
        started: bool = False,
    ) -> None:
        from .live_log import format_tool_command, format_tool_output

        command = format_tool_command(name, arguments)
        if started:
            self.cmd(project_id, command, output="", phase=phase, tool=name, role=role)
            return
        ok = True
        if isinstance(result, dict) and "ok" in result:
            ok = bool(result.get("ok"))
        self.cmd(
            project_id,
            command,
            output=format_tool_output(result),
            exit_code=0 if ok else 1,
            phase=phase,
            tool=name,
            role=role,
        )

    def tool_exec_error(
        self,
        project_id: int,
        name: str,
        arguments: dict[str, Any] | None = None,
        result: Any = None,
        *,
        phase: str | None = None,
        role: str | None = None,
        duration_ms: float | None = None,
        phase_run_id: int | None = None,
    ) -> None:
        from .live_log import format_tool_command, format_tool_output

        err = ""
        if isinstance(result, dict):
            err = str(result.get("error") or "")
        ev: dict[str, Any] = {
            "kind": "tool_exec_error",
            "tool": name,
            "command": format_tool_command(name, arguments),
            "text": err or format_tool_output(result),
            "exit_code": 1,
            "phase": phase,
        }
        if role:
            ev["role"] = role
        if duration_ms is not None:
            ev["duration_ms"] = duration_ms
        if phase_run_id is not None:
            ev["phase_run_id"] = phase_run_id
        self._append(ev)


def file_event_log(path: Path) -> FileEventLog:
    key = str(Path(path).resolve())
    with _log_cache_lock:
        log = _log_cache.get(key)
        if log is None:
            log = FileEventLog(Path(path))
            _log_cache[key] = log
        return log


def index_path(tool_dir: Path) -> Path:
    return tool_dir / INDEX_FILENAME


def lock_path(tool_dir: Path) -> Path:
    return tool_dir / LOCK_FILENAME


def log_path_for(tool_dir: Path) -> Path:
    return tool_dir / LOG_FILENAME


def load_index(tool_dir: Path) -> dict[str, Any] | None:
    path = index_path(tool_dir)
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError):
        return None
    return data if isinstance(data, dict) else None


def write_index(tool_dir: Path, payload: dict[str, Any]) -> Path:
    path = index_path(tool_dir)
    body = dict(payload)
    body["name"] = str(body.get("name") or tool_dir.name)
    body["dir"] = str(tool_dir.resolve())
    body["indexed_at"] = body.get("indexed_at") or _ts()
    path.write_text(json.dumps(body, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path


def dir_fingerprint(tool_dir: Path) -> str:
    """Hash of non-meta files: relative path, size, mtime."""
    root = tool_dir.resolve()
    rows: list[str] = []
    if not root.is_dir():
        return hashlib.sha256(b"").hexdigest()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(
            d for d in dirnames if d not in _SKIP_DIR_NAMES and not d.startswith(".")
        )
        for name in sorted(filenames):
            if name in _META_NAMES or name.startswith("."):
                continue
            full = Path(dirpath) / name
            try:
                rel = full.relative_to(root).as_posix()
                st = full.stat()
            except (OSError, ValueError):
                continue
            rows.append(f"{rel}\0{st.st_size}\0{st.st_mtime_ns}")
    digest = hashlib.sha256("\n".join(rows).encode("utf-8", errors="replace"))
    return digest.hexdigest()


def discover_tool_dirs(root: Path | None = None) -> list[Path]:
    base = (root or resolve_cli_tools_dir()).resolve()
    if not base.is_dir():
        return []
    out: list[Path] = []
    try:
        entries = sorted(base.iterdir(), key=lambda p: p.name.lower())
    except OSError:
        return []
    for item in entries:
        if not item.is_dir():
            continue
        if item.name.startswith(".") or item.name in _SKIP_DIR_NAMES:
            continue
        out.append(item.resolve())
    return out


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _lock_stale(tool_dir: Path) -> bool:
    path = lock_path(tool_dir)
    if not path.is_file():
        return True
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError):
        return True
    if not isinstance(data, dict):
        return True
    pid = int(data.get("pid") or 0)
    started = str(data.get("started_at") or "")
    if pid and _pid_alive(pid):
        return False
    if started:
        try:
            dt = datetime.fromisoformat(started.replace("Z", "+00:00"))
            age = time.time() - dt.timestamp()
            if age < max(60, int(settings.timeout_cli_index)):
                return False
        except ValueError:
            return True
    return True


def _write_lock(tool_dir: Path) -> None:
    payload = {"pid": os.getpid(), "started_at": _ts()}
    lock_path(tool_dir).write_text(json.dumps(payload), encoding="utf-8")


def _clear_lock(tool_dir: Path) -> None:
    try:
        lock_path(tool_dir).unlink(missing_ok=True)
    except OSError:
        pass


def needs_index(tool_dir: Path) -> bool:
    fp = dir_fingerprint(tool_dir)
    rec = load_index(tool_dir)
    if rec is None:
        return True
    status = str(rec.get("status") or _STATUS_PENDING)
    stored_fp = str(rec.get("fingerprint") or "")
    if stored_fp and stored_fp != fp:
        return True
    if status == _STATUS_READY:
        return False
    if status == _STATUS_FAILED:
        return False
    if status == _STATUS_INDEXING:
        return _lock_stale(tool_dir)
    return True


def public_tool_record(rec: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": str(rec.get("name") or ""),
        "dir": str(rec.get("dir") or ""),
        "path": str(rec.get("path") or rec.get("dir") or ""),
        "entry": str(rec.get("entry") or ""),
        "description": str(rec.get("description") or ""),
    }


def search_cli_tools(query: str = "") -> list[dict[str, Any]]:
    q = (query or "").strip().lower()
    hits: list[dict[str, Any]] = []
    for tool_dir in discover_tool_dirs():
        rec = load_index(tool_dir)
        if not rec or str(rec.get("status") or "") != _STATUS_READY:
            continue
        blob = " ".join(
            [
                str(rec.get("name") or tool_dir.name),
                str(rec.get("entry") or ""),
                str(rec.get("description") or ""),
            ]
        ).lower()
        if q and q not in blob:
            continue
        item = public_tool_record(rec)
        if not item["name"]:
            item["name"] = tool_dir.name
        if not item["dir"]:
            item["dir"] = str(tool_dir)
        hits.append(item)
    return hits


def mark_index_failed(tool_dir: Path, reason: str, *, fingerprint: str | None = None) -> dict[str, Any]:
    fp = fingerprint if fingerprint is not None else dir_fingerprint(tool_dir)
    rec = {
        "name": tool_dir.name,
        "dir": str(tool_dir.resolve()),
        "path": "",
        "entry": "",
        "description": "",
        "status": _STATUS_FAILED,
        "error": (reason or "索引失败").strip()[:8000],
        "fingerprint": fp,
        "indexed_at": _ts(),
    }
    write_index(tool_dir, rec)
    return rec


def write_ready_index(
    tool_dir: Path,
    *,
    entry: str,
    entry_path: Path,
    description: str,
    fingerprint: str | None = None,
    rounds: int | None = None,
) -> dict[str, Any]:
    rec: dict[str, Any] = {
        "name": tool_dir.name,
        "dir": str(tool_dir.resolve()),
        "entry": entry,
        "path": str(entry_path.resolve()),
        "description": (description or "").strip(),
        "status": _STATUS_READY,
        "error": None,
        "fingerprint": fingerprint or dir_fingerprint(tool_dir),
        "indexed_at": _ts(),
    }
    if rounds is not None:
        rec["rounds"] = int(rounds)
    write_index(tool_dir, rec)
    return rec


def write_conclude(tool_dir: Path, text: str) -> Path:
    path = tool_dir / CONCLUDE_FILENAME
    path.write_text((text or "").strip() + "\n", encoding="utf-8")
    return path


def _index_one(tool_dir: Path) -> None:
    from ..agent.loop import AgentLoop

    fp = dir_fingerprint(tool_dir)
    log_file = log_path_for(tool_dir)
    write_index(
        tool_dir,
        {
            "name": tool_dir.name,
            "dir": str(tool_dir.resolve()),
            "path": "",
            "entry": "",
            "description": "",
            "status": _STATUS_INDEXING,
            "error": None,
            "fingerprint": fp,
            "indexed_at": _ts(),
        },
    )
    _write_lock(tool_dir)
    file_event_log(log_file).system(
        0,
        f"开始索引 CLI 工具 {tool_dir.name}",
        phase="cli-indexer",
        role="cli_indexer",
        session_start=True,
    )
    system = load_prompt("cli_indexer.md")
    user = render_prompt(
        "initial/cli_indexer.md",
        tool_name=tool_dir.name,
        tool_dir=str(tool_dir.resolve()),
        max_turns=MAX_INDEX_TURNS,
    )
    cancel = threading.Event()
    loop = AgentLoop(
        project_id=0,
        role="cli_indexer",
        phase="cli-indexer",
        system_prompt=system,
        user_prompt=user,
        timeout_sec=int(settings.timeout_cli_index),
        stop_when=lambda state: bool(state.get("index_done")),
        silent=True,
        log_path=log_file,
        workspace_root=tool_dir,
        max_turns=MAX_INDEX_TURNS,
        summary_dir=tool_dir,
        cancel_event=cancel,
    )
    try:
        result = loop.run()
    except Exception as e:  # noqa: BLE001
        mark_index_failed(tool_dir, f"索引 Agent 异常: {e}", fingerprint=fp)
        write_conclude(tool_dir, f"索引 Agent 异常: {e}")
        file_event_log(log_file).error(0, str(e), phase="cli-indexer", role="cli_indexer")
        return
    finally:
        _clear_lock(tool_dir)

    rec = load_index(tool_dir)
    if rec and str(rec.get("status") or "") == _STATUS_READY:
        file_event_log(log_file).system(
            0,
            f"索引完成 entry={rec.get('entry')}",
            phase="cli-indexer",
            role="cli_indexer",
        )
        return
    reason_parts = [
        f"未能在 {MAX_INDEX_TURNS} 轮内 FinishIndex。",
        f"stop_reason={result.stop_reason or 'unknown'}",
    ]
    if result.error:
        reason_parts.append(str(result.error))
    if result.round_summary:
        reason_parts.append(result.round_summary.strip()[:4000])
    conclude = tool_dir / CONCLUDE_FILENAME
    if conclude.is_file():
        extra = conclude.read_text(encoding="utf-8", errors="replace").strip()
        if extra:
            reason_parts.append(extra[:4000])
    reason = "\n".join(p for p in reason_parts if p)
    mark_index_failed(tool_dir, reason, fingerprint=fp)
    if not conclude.is_file():
        write_conclude(tool_dir, reason)
    file_event_log(log_file).error(0, reason, phase="cli-indexer", role="cli_indexer")


def scan_once(root: Path | None = None) -> list[Path]:
    """Index at most one pending tool directory. Returns dirs that still need indexing."""
    pending = [d for d in discover_tool_dirs(root) if needs_index(d)]
    if not pending:
        return []
    target = pending[0]
    key = str(target)
    with _index_lock:
        if key in _indexing:
            return pending
        _indexing.add(key)
    try:
        _index_one(target)
    finally:
        with _index_lock:
            _indexing.discard(key)
    return [d for d in discover_tool_dirs(root) if needs_index(d)]


def _poll_loop() -> None:
    while not _poll_stop.is_set() and not is_shutting_down():
        try:
            if not is_shutting_down():
                scan_once()
        except Exception:  # noqa: BLE001
            pass
        _poll_stop.wait(max(3, int(settings.cli_tools_poll_sec)))


def start_cli_tool_scanner() -> None:
    global _poll_thread
    if _poll_thread is not None and _poll_thread.is_alive():
        return
    _poll_stop.clear()
    _poll_thread = threading.Thread(target=_poll_loop, name="vh-cli-tool-scan", daemon=True)
    _poll_thread.start()


def stop_cli_tool_scanner() -> None:
    global _poll_thread
    _poll_stop.set()
    t = _poll_thread
    if t is not None and t.is_alive() and t is not threading.current_thread():
        t.join(timeout=2)
    _poll_thread = None


def default_cli_tools_dir_display() -> str:
    path = resolve_cli_tools_dir()
    try:
        return path.relative_to(ROOT_DIR).as_posix()
    except ValueError:
        return str(path)

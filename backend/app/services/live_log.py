"""Live event log — aligned with AutoPoc live_log shapes."""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .paths import live_events_path

# worker=挖掘页全部；mine=仅挖掘 Worker；fix=仅修复 Worker
PHASE_GROUPS: dict[str, frozenset[str]] = {
    "recon": frozenset({"recon", "recon-mark", "recon_mark", "recon-old-vuln", "recon_old_vuln"}),
    "recon-map": frozenset({"recon"}),
    "recon-old-vuln": frozenset({"recon-old-vuln", "recon_old_vuln"}),
    "recon-mark": frozenset({"recon-mark", "recon_mark"}),
    "worker": frozenset({"worker", "fix"}),
    "mine": frozenset({"worker"}),
    "fix": frozenset({"fix"}),
    "reviewer": frozenset({"reviewer"}),
}

CONTROL_PHASES = ("recon", "worker", "reviewer")
_SESSION_START_MARK = "新开对话"

_CST = timezone(timedelta(hours=8))
_lock = threading.Lock()
_session_lock = threading.Lock()
_cache_lock = threading.Lock()
_sessions: dict[tuple[int, str], int] = {}
_session_used: dict[tuple[int, str], bool] = {}
_hydrated_paths: set[str] = set()
_event_cache: dict[str, _EventCache] = {}
_seq_cache: dict[str, int] = {}
_CMD_OUTPUT_LIMIT = 4000
_CMD_ARGS_LIMIT = 1500


@dataclass
class _EventCache:
    mtime_ns: int = 0
    size: int = 0
    byte_offset: int = 0
    file_end: int = 0
    line_count: int = 0
    events: list[tuple[int, dict[str, Any]]] = field(default_factory=list)
    session_max: dict[str, int] = field(default_factory=dict)


def _ts() -> str:
    return datetime.now(_CST).strftime("%H:%M:%S")


def _clip(text: str, limit: int) -> str:
    t = text or ""
    if len(t) <= limit:
        return t
    return t[: limit - 1] + "…"


def format_tool_command(name: str, arguments: dict[str, Any] | None = None) -> str:
    args = arguments or {}
    if name in ("Bash", "PowerShell"):
        cmd = str(args.get("command") or args.get("cmd") or "").strip()
        return f"{name} {cmd}".strip() if cmd else name
    compact = json.dumps(args, ensure_ascii=False, separators=(",", ":"))
    return f"{name} {_clip(compact, _CMD_ARGS_LIMIT)}"


def format_tool_output(result: Any) -> str:
    if isinstance(result, str):
        return _clip(result, _CMD_OUTPUT_LIMIT)
    try:
        text = json.dumps(result, ensure_ascii=False)
    except TypeError:
        text = str(result)
    return _clip(text, _CMD_OUTPUT_LIMIT)


class LiveLog:
    def reset_runtime_state(self) -> None:
        with _session_lock:
            _sessions.clear()
            _session_used.clear()
            _hydrated_paths.clear()
        with _cache_lock:
            _event_cache.clear()
            _seq_cache.clear()

    def _events_path(self, project_id: int, phase: str, session: int) -> Path:
        return _phase_session_events_path(project_id, phase, session)

    def begin_session(self, project_id: int, phase: str, *, if_used: bool = False) -> int:
        """该控制阶段进入下一轮日志页。

        if_used=True 时：当前页还没有任何事件则保持页码（第一轮对话留在第 1 页）。
        用户点「新跑」走默认（无条件翻页）；调度器新开 AgentLoop 走 if_used。
        """
        cp = control_phase_of_filter(phase) or control_phase_of(phase)
        if not cp:
            return 1
        self._hydrate_sessions(project_id)
        with _session_lock:
            key = (project_id, cp)
            cur = _sessions.get(key, 1)
            if if_used and not _session_used.get(key, False):
                return cur
            nxt = cur + 1
            _sessions[key] = nxt
            _session_used[key] = False
            return nxt

    def current_session(self, project_id: int, phase: str | None) -> int:
        cp = control_phase_of_filter(phase) or control_phase_of(phase)
        if not cp:
            return 1
        self._hydrate_sessions(project_id)
        with _session_lock:
            return _sessions.get((project_id, cp), 1)

    def _hydrate_sessions(self, project_id: int) -> None:
        path_key = str(_live_events_dir(project_id))
        with _session_lock:
            if path_key in _hydrated_paths:
                return
            seen: set[str] = set()
        parsed = _load_project_events(project_id, None)
        maxes = _annotate_sessions(parsed)
        for _, ev in parsed:
            cp = control_phase_of(str(ev.get("phase") or ev.get("role") or ""))
            if cp:
                seen.add(cp)
        with _session_lock:
            if path_key in _hydrated_paths:
                return
            for key in [k for k in _sessions if k[0] == project_id]:
                del _sessions[key]
            for key in [k for k in _session_used if k[0] == project_id]:
                del _session_used[key]
            for cp, n in maxes.items():
                _sessions[(project_id, cp)] = n
                _session_used[(project_id, cp)] = cp in seen
            _hydrated_paths.add(path_key)

    def emit(self, project_id: int, event: dict[str, Any]) -> None:
        ev = dict(event)
        ev.setdefault("ts", _ts())
        phase = ev.get("phase") or ev.get("role")
        if "session" not in ev and phase:
            ev["session"] = self.current_session(project_id, str(phase))
        cp = control_phase_of(str(phase or ""))
        if cp:
            with _session_lock:
                _session_used[(project_id, cp)] = True
        split_phase = cp or "system"
        session = int(ev.get("session") or 1)
        with _lock:
            ev["seq"] = _next_event_seq(project_id)
            path = self._events_path(project_id, split_phase, session)
            line = json.dumps(ev, ensure_ascii=False) + "\n"
            path.parent.mkdir(parents=True, exist_ok=True)
            try:
                before_size = path.stat().st_size
            except FileNotFoundError:
                before_size = 0
            with path.open("a", encoding="utf-8") as f:
                f.write(line)
                byte_offset = f.tell()
            stat = path.stat()
        _append_cached_event(str(path), before_size, stat.st_size, stat.st_mtime_ns, byte_offset, ev)

    def agent(
        self,
        project_id: int,
        text: str,
        *,
        phase: str | None = None,
        role: str | None = None,
    ) -> None:
        body = (text or "").strip()
        if not body:
            return
        ev: dict[str, Any] = {"kind": "agent", "text": body, "phase": phase}
        if role:
            ev["role"] = role
        self.emit(project_id, ev)

    def reasoning(
        self,
        project_id: int,
        text: str,
        *,
        phase: str | None = None,
        role: str | None = None,
    ) -> None:
        body = (text or "").strip()
        if not body:
            return
        ev: dict[str, Any] = {"kind": "reasoning", "text": body, "phase": phase}
        if role:
            ev["role"] = role
        self.emit(project_id, ev)

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
        self.emit(project_id, ev)

    def error(self, project_id: int, text: str, *, phase: str | None = None, role: str | None = None) -> None:
        ev: dict[str, Any] = {"kind": "error", "text": text, "phase": phase}
        if role:
            ev["role"] = role
        self.emit(project_id, ev)

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
            "output": _clip(output, _CMD_OUTPUT_LIMIT) if output else "",
            "exit_code": exit_code,
            "phase": phase,
        }
        if tool:
            ev["tool"] = tool
        if role:
            ev["role"] = role
        self.emit(project_id, ev)

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
        self.emit(project_id, ev)

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
        """Dedicated live event for local tool execution failures."""
        err = ""
        tb = ""
        if isinstance(result, dict):
            err = str(result.get("error") or "")
            tb = str(result.get("traceback") or "")
        ev: dict[str, Any] = {
            "kind": "tool_exec_error",
            "tool": name,
            "command": format_tool_command(name, arguments),
            "text": err or format_tool_output(result),
            "output": format_tool_output(result),
            "exit_code": 1,
            "phase": phase,
        }
        if role:
            ev["role"] = role
        if duration_ms is not None:
            ev["duration_ms"] = duration_ms
        if phase_run_id is not None:
            ev["phase_run_id"] = phase_run_id
        if tb:
            ev["traceback"] = _clip(tb, 2000)
        self.emit(project_id, ev)

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
        """Log a tool invocation in AutoPoc cmd shape: command + output + exit_code."""
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

    def read_events(
        self,
        project_id: int,
        offset: int = 0,
        limit: int = 500,
        *,
        tail: bool = False,
        before: int | None = None,
        phase: str | None = None,
        session: int | None = None,
    ) -> EventsPage:
        control = control_phase_of_filter(phase)
        if control:
            session_count = _session_count(project_id, control)
            wanted = session_count if session is None else session
            all_events = _load_project_events(project_id, phase, wanted)
        else:
            all_events = _load_project_events(project_id, phase)
            session_max = _annotate_sessions(all_events)
            session_count = max(session_max.values(), default=1)
            wanted = session
        if not all_events:
            return EventsPage(session=wanted or session_count, session_count=session_count)
        session_max = _annotate_sessions(all_events)
        file_end = max((idx + 1 for idx, _ in all_events), default=0)
        if not control:
            session_count = max(session_max.values(), default=session_count)
        parsed = [(idx, ev) for idx, ev in all_events if event_matches_phase(ev, phase)]
        if wanted is not None:
            parsed = [(idx, ev) for idx, ev in parsed if int(ev.get("session") or 0) == wanted]
        else:
            wanted = session_count
        total = len(parsed)
        if not parsed:
            return EventsPage(
                total=0,
                done=True,
                file_end=file_end,
                session=wanted,
                session_count=session_count,
            )

        if tail:
            start = max(0, total - max(1, limit))
            chunk = parsed[start:]
        elif before is not None:
            end = 0
            for i, (idx, _) in enumerate(parsed):
                if idx >= before:
                    end = i
                    break
            else:
                end = total
            start = max(0, end - max(1, limit))
            chunk = parsed[start:end]
        else:
            start = 0
            for i, (idx, _) in enumerate(parsed):
                if idx >= offset:
                    start = i
                    break
            else:
                start = total
            chunk = parsed[start : start + max(1, limit)]

        events = [ev for _, ev in chunk]
        oldest = chunk[0][0] if chunk else 0
        # 追平文件末尾时保持 offset，绝不能回 0，否则 SSE 会从文件头重放。
        newest = chunk[-1][0] + 1 if chunk else max(offset, file_end)
        first_idx = parsed[0][0]
        last_idx = parsed[-1][0]
        has_older = bool(chunk) and oldest > first_idx
        done = not chunk or newest > last_idx
        return EventsPage(
            events=events,
            offset=newest,
            done=done,
            oldest=oldest,
            has_older=has_older,
            total=total,
            file_end=file_end,
            session=wanted,
            session_count=session_count,
        )


def event_matches_phase(ev: dict[str, Any], phase: str | None) -> bool:
    """phase 为空不过滤。recon=侦察三子阶段；recon-map / recon-old-vuln / recon-mark 为子阶段。worker=挖掘+修复。"""
    if not phase:
        return True
    wanted = PHASE_GROUPS.get(phase, frozenset({phase}))
    p = str(ev.get("phase") or ev.get("role") or "").strip()
    return p in wanted


def control_phase_of(phase: str | None) -> str | None:
    p = (phase or "").strip()
    if p in PHASE_GROUPS["recon"]:
        return "recon"
    if p in PHASE_GROUPS["worker"]:
        return "worker"
    if p == "reviewer":
        return "reviewer"
    return None


def control_phase_of_filter(phase: str | None) -> str | None:
    if not phase:
        return None
    if phase in ("recon", "recon-map", "recon-old-vuln", "recon-mark"):
        return "recon"
    if phase in ("worker", "mine", "fix"):
        return "worker"
    if phase == "reviewer":
        return "reviewer"
    return control_phase_of(phase)


def is_session_start(ev: dict[str, Any]) -> bool:
    if ev.get("session_start"):
        return True
    if ev.get("kind") != "system":
        return False
    return _SESSION_START_MARK in str(ev.get("text") or "")


def _live_events_dir(project_id: int) -> Path:
    return live_events_path(project_id).parent / "live-events"


def _event_seq_path(project_id: int) -> Path:
    return _live_events_dir(project_id) / ".seq"


def _safe_phase_dir(phase: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in ("-", "_") else "-" for ch in phase.strip().lower())
    return cleaned or "system"


def _phase_session_events_path(project_id: int, phase: str, session: int) -> Path:
    n = max(1, int(session or 1))
    return _live_events_dir(project_id) / _safe_phase_dir(phase) / f"round-{n}.jsonl"


def _round_no(path: Path) -> int | None:
    stem = path.stem
    if not stem.startswith("round-"):
        return None
    try:
        n = int(stem.removeprefix("round-"))
    except ValueError:
        return None
    return n if n > 0 else None


def _split_event_paths(project_id: int, phase: str | None, session: int | None = None) -> list[Path]:
    base = _live_events_dir(project_id)
    if not base.exists():
        return []
    control = control_phase_of_filter(phase)
    if control:
        root = base / _safe_phase_dir(control)
        if not root.exists():
            return []
        if session is not None:
            path = root / f"round-{max(1, int(session))}.jsonl"
            return [path] if path.exists() else []
        return sorted(root.glob("round-*.jsonl"))
    return sorted(base.glob("*/round-*.jsonl"))


def _legacy_session_max(project_id: int, control: str) -> int:
    legacy = live_events_path(project_id)
    if not legacy.exists():
        return 1
    _, parsed, _ = _load_cached_events(legacy)
    return _annotate_sessions(parsed).get(control, 1)


def _session_count(project_id: int, control: str) -> int:
    root = _live_events_dir(project_id) / _safe_phase_dir(control)
    from_files = 1
    if root.exists():
        from_files = max((_round_no(path) or 1 for path in root.glob("round-*.jsonl")), default=1)
    return max(from_files, _legacy_session_max(project_id, control))


def _load_project_events(
    project_id: int,
    phase: str | None,
    session: int | None = None,
) -> list[tuple[int, dict[str, Any]]]:
    paths = _split_event_paths(project_id, phase, session)
    legacy = live_events_path(project_id)
    if legacy.exists():
        paths.append(legacy)

    events: list[tuple[int, dict[str, Any]]] = []
    seen_paths: set[str] = set()
    for path in paths:
        key = str(path)
        if key in seen_paths:
            continue
        seen_paths.add(key)
        _, parsed, _ = _load_cached_events(path)
        events.extend(parsed)
    events.sort(key=lambda item: item[0])
    return events


def _project_next_seq_from_files(project_id: int) -> int:
    events = _load_project_events(project_id, None)
    return max((idx + 1 for idx, _ in events), default=0)


def _next_event_seq(project_id: int) -> int:
    seq_path = _event_seq_path(project_id)
    key = str(seq_path)
    cached = _seq_cache.get(key)
    if cached is None:
        try:
            cached = int(seq_path.read_text(encoding="utf-8").strip())
        except (FileNotFoundError, ValueError, OSError):
            cached = _project_next_seq_from_files(project_id)
    seq = max(0, cached)
    _seq_cache[key] = seq + 1
    try:
        seq_path.parent.mkdir(parents=True, exist_ok=True)
        seq_path.write_text(str(seq + 1), encoding="utf-8")
    except OSError:
        pass
    return seq


def _parse_event_line(raw: str, idx: int) -> dict[str, Any] | None:
    line = raw.strip()
    if not line:
        return None
    try:
        ev = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(ev, dict):
        return None
    item = dict(ev)
    raw_seq = item.get("seq")
    item["seq"] = raw_seq if isinstance(raw_seq, int) and raw_seq >= 0 else idx
    return item


def _default_session_max() -> dict[str, int]:
    return {cp: 1 for cp in CONTROL_PHASES}


def _read_events_from_start(path) -> tuple[int, int, int, list[tuple[int, dict[str, Any]]]]:
    events: list[tuple[int, dict[str, Any]]] = []
    file_end = 0
    line_count = 0
    with path.open("r", encoding="utf-8") as f:
        while True:
            raw = f.readline()
            if not raw:
                break
            ev = _parse_event_line(raw, line_count)
            if ev:
                seq = int(ev["seq"])
                events.append((seq, ev))
                file_end = max(file_end, seq + 1)
            line_count += 1
        byte_offset = f.tell()
    return file_end, line_count, byte_offset, events


def _load_cached_events(path) -> tuple[int, list[tuple[int, dict[str, Any]]], dict[str, int]]:
    path_key = str(path)
    if not path.exists():
        with _cache_lock:
            _event_cache[path_key] = _EventCache(session_max=_default_session_max())
            cached = _event_cache[path_key]
            return cached.file_end, cached.events, cached.session_max

    stat = path.stat()
    with _cache_lock:
        cached = _event_cache.get(path_key)
        if cached and cached.size == stat.st_size and cached.mtime_ns == stat.st_mtime_ns:
            return cached.file_end, cached.events, cached.session_max

        if cached and stat.st_size >= cached.size:
            events = list(cached.events)
            file_end = cached.file_end
            line_count = cached.line_count
            try:
                with path.open("r", encoding="utf-8") as f:
                    f.seek(cached.byte_offset)
                    while True:
                        raw = f.readline()
                        if not raw:
                            break
                        ev = _parse_event_line(raw, line_count)
                        if ev:
                            seq = int(ev["seq"])
                            events.append((seq, ev))
                            file_end = max(file_end, seq + 1)
                        line_count += 1
                    byte_offset = f.tell()
            except OSError:
                file_end, line_count, byte_offset, events = _read_events_from_start(path)
        else:
            file_end, line_count, byte_offset, events = _read_events_from_start(path)

        session_max = _annotate_sessions(events)
        cached = _EventCache(
            mtime_ns=stat.st_mtime_ns,
            size=stat.st_size,
            byte_offset=byte_offset,
            file_end=file_end,
            line_count=line_count,
            events=events,
            session_max=session_max,
        )
        _event_cache[path_key] = cached
        return cached.file_end, cached.events, cached.session_max


def _append_cached_event(
    path_key: str,
    before_size: int,
    size: int,
    mtime_ns: int,
    byte_offset: int,
    ev: dict[str, Any],
) -> None:
    with _cache_lock:
        cached = _event_cache.get(path_key)
        if not cached:
            return
        if cached.size != before_size:
            _event_cache.pop(path_key, None)
            return
        item = dict(ev)
        seq = int(item.get("seq") if isinstance(item.get("seq"), int) else cached.file_end)
        item["seq"] = seq
        cached.events.append((seq, item))
        cached.file_end = max(cached.file_end, seq + 1)
        cached.line_count += 1
        cached.session_max = dict(cached.session_max or _default_session_max())
        cp = control_phase_of(str(item.get("phase") or item.get("role") or ""))
        if cp:
            cached.session_max[cp] = max(cached.session_max.get(cp, 1), int(item.get("session") or 1))
        cached.mtime_ns = mtime_ns
        cached.size = size
        cached.byte_offset = byte_offset


def _annotate_sessions(parsed: list[tuple[int, dict[str, Any]]]) -> dict[str, int]:
    """给每条事件补 session；返回各控制阶段当前最大轮次。"""
    curs = {cp: 1 for cp in CONTROL_PHASES}
    for _, ev in parsed:
        cp = control_phase_of(str(ev.get("phase") or ev.get("role") or ""))
        if not cp:
            continue
        raw = ev.get("session")
        if isinstance(raw, int) and raw > 0:
            curs[cp] = max(curs[cp], raw)
            continue
        if is_session_start(ev):
            curs[cp] += 1
        ev["session"] = curs[cp]
    return curs


@dataclass
class EventsPage:
    events: list[dict[str, Any]] = field(default_factory=list)
    offset: int = 0
    done: bool = False
    oldest: int = 0
    has_older: bool = False
    total: int = 0
    file_end: int = 0
    session: int = 1
    session_count: int = 1


live_log = LiveLog()

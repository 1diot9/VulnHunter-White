from __future__ import annotations

import asyncio
import logging
import os
import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from dap_client import DapClient, DapError

logger = logging.getLogger(__name__)

MAX_EVENT_HISTORY = 200

SINK_CATEGORIES: dict[str, list[str]] = {
    "deserialization": [
        "pickle.loads", "pickle.load", "_pickle.loads",
        "yaml.unsafe_load", "yaml.load",
        "marshal.loads", "shelve.open",
        "jsonpickle.decode",
    ],
    "command_injection": [
        "os.system", "os.popen", "os.popen2", "os.popen3", "os.popen4",
        "subprocess.call", "subprocess.run", "subprocess.Popen",
        "subprocess.check_output", "subprocess.check_call",
        "commands.getoutput", "commands.getstatusoutput",
    ],
    "code_execution": [
        "eval", "exec", "compile", "execfile",
        "__import__",
    ],
    "file_access": [
        "open", "os.remove", "os.unlink", "os.rename",
        "shutil.rmtree", "shutil.copy", "shutil.move",
    ],
    "ssrf": [
        "urllib.request.urlopen",
        "requests.get", "requests.post", "requests.put", "requests.delete",
        "http.client.HTTPConnection", "http.client.HTTPSConnection",
        "httpx.get", "httpx.post",
    ],
    "xxe": [
        "xml.etree.ElementTree.parse", "xml.etree.ElementTree.fromstring",
        "lxml.etree.parse", "lxml.etree.fromstring",
        "xml.dom.minidom.parse", "xml.dom.minidom.parseString",
        "xml.sax.parse",
    ],
}


class SessionState(str, Enum):
    DISCONNECTED = "disconnected"
    ATTACHING = "attaching"
    RUNNING = "running"
    SUSPENDED = "suspended"
    TERMINATED = "terminated"
    ERROR = "error"


@dataclass
class ManagedBreakpoint:
    id: str
    file: str
    line: int
    condition: str | None = None
    hit_condition: str | None = None
    log_message: str | None = None
    verified: bool = False
    dap_id: int | None = None


@dataclass
class ManagedFunctionBreakpoint:
    id: str
    function_name: str
    condition: str | None = None
    hit_condition: str | None = None
    log_message: str | None = None
    verified: bool = False
    dap_id: int | None = None


@dataclass
class StopEvent:
    reason: str
    thread_id: int
    description: str = ""
    file: str = ""
    line: int = 0
    function: str = ""
    timestamp: float = field(default_factory=time.time)


class DebugSessionManager:
    """High-level debug session wrapping a DAP client talking to debugpy.adapter."""

    def __init__(self) -> None:
        self._dap = DapClient()
        self._state = SessionState.DISCONNECTED
        self._capabilities: dict[str, Any] = {}
        self._lock = asyncio.Lock()

        self._next_bp_id = 1
        self._next_fbp_id = 1
        self._breakpoints: dict[str, ManagedBreakpoint] = {}
        self._file_breakpoints: dict[str, list[str]] = {}
        self._function_breakpoints: dict[str, ManagedFunctionBreakpoint] = {}
        self._exception_filters: list[str] = []

        self._active_thread_id: int | None = None
        self._thread_names: dict[int, str] = {}

        self._last_stop_event: StopEvent | None = None
        self._event_history: list[dict[str, Any]] = []
        self._event_id_counter = 0

        self._stop_future: asyncio.Future | None = None
        self._config_done_sent: bool = True

    @property
    def state(self) -> SessionState:
        return self._state

    # ── launch / attach ──

    async def launch(
        self,
        program: str,
        args: list[str] | None = None,
        cwd: str | None = None,
        python: str | None = None,
        stop_on_entry: bool = False,
    ) -> dict[str, Any]:
        if self._state in (SessionState.TERMINATED, SessionState.ERROR):
            await self.detach()
        if self._state != SessionState.DISCONNECTED:
            raise RuntimeError(f"Session already in state {self._state.value}")

        self._state = SessionState.ATTACHING
        try:
            await self._dap.start(python=python)
            self._register_event_handlers()

            await self._initialize_dap()

            init_event = asyncio.create_task(self._dap.wait_for_event("initialized"))

            launch_args: dict[str, Any] = {
                "program": os.path.abspath(program),
                "console": "internalConsole",
                "justMyCode": False,
                "stopOnEntry": stop_on_entry,
            }
            if args:
                launch_args["args"] = args
            if cwd:
                launch_args["cwd"] = cwd
            if python:
                launch_args["python"] = python

            if stop_on_entry:
                self._stop_future = asyncio.get_running_loop().create_future()

            launch_task = asyncio.create_task(
                self._dap.send_request("launch", launch_args, timeout=30)
            )

            await asyncio.wait_for(init_event, timeout=15)
            await self._sync_all_breakpoints()
            await self._dap.send_request("configurationDone")
            await launch_task

            if stop_on_entry and self._stop_future:
                try:
                    await asyncio.wait_for(self._stop_future, timeout=10)
                except asyncio.TimeoutError:
                    pass
                finally:
                    self._stop_future = None
            else:
                self._state = SessionState.RUNNING

            self._record_event("launched", {"program": program})
            return {"status": "launched", "program": program}

        except Exception as e:
            self._state = SessionState.DISCONNECTED
            await self._dap.stop()
            raise ConnectionError(f"Failed to launch: {e}") from e

    async def attach(self, host: str, port: int, python: str | None = None) -> dict[str, Any]:
        if self._state in (SessionState.TERMINATED, SessionState.ERROR):
            await self.detach()
        if self._state != SessionState.DISCONNECTED:
            raise RuntimeError(f"Session already in state {self._state.value}")

        self._state = SessionState.ATTACHING
        try:
            await self._dap.start(python=python)
            self._register_event_handlers()

            await self._initialize_dap()

            init_event = asyncio.create_task(self._dap.wait_for_event("initialized"))

            asyncio.create_task(
                self._dap.send_request("attach", {
                    "connect": {"host": host, "port": port},
                    "justMyCode": False,
                }, timeout=60)
            )

            await asyncio.wait_for(init_event, timeout=15)
            await self._sync_all_breakpoints()

            self._config_done_sent = False
            self._state = SessionState.SUSPENDED
            self._record_event("attached", {"host": host, "port": port})
            return {"status": "attached", "host": host, "port": port}

        except Exception as e:
            self._state = SessionState.DISCONNECTED
            await self._dap.stop()
            raise ConnectionError(f"Failed to attach to {host}:{port}: {e}") from e

    async def attach_tcp(self, host: str, port: int) -> dict[str, Any]:
        """Attach via direct TCP to a debugpy server's DAP port.

        Unlike attach(), this connects directly to the debugpy server's DAP
        interface over TCP without spawning a local adapter subprocess. This
        works for Docker containers and other remote environments where the
        adapter's reverse-connection model fails.

        The target must be started with debugpy in DAP-server mode, e.g.:
          python -m debugpy --listen 0.0.0.0:5678 --wait-for-client script.py
        """
        if self._state in (SessionState.TERMINATED, SessionState.ERROR):
            await self.detach()
        if self._state != SessionState.DISCONNECTED:
            raise RuntimeError(f"Session already in state {self._state.value}")

        self._state = SessionState.ATTACHING
        try:
            await self._dap.connect_tcp(host, port)
            self._register_event_handlers()

            await self._initialize_dap()

            init_event = asyncio.create_task(self._dap.wait_for_event("initialized"))

            asyncio.create_task(
                self._dap.send_request("attach", {
                    "justMyCode": False,
                }, timeout=60)
            )

            await asyncio.wait_for(init_event, timeout=15)
            await self._sync_all_breakpoints()

            self._config_done_sent = False
            self._state = SessionState.SUSPENDED
            self._record_event("attached_tcp", {"host": host, "port": port})
            return {"status": "attached", "host": host, "port": port, "mode": "direct_tcp"}

        except Exception as e:
            self._state = SessionState.DISCONNECTED
            await self._dap.stop()
            raise ConnectionError(f"Failed to attach via TCP to {host}:{port}: {e}") from e

    async def detach(self) -> dict[str, Any]:
        if self._state == SessionState.DISCONNECTED:
            return {"status": "already disconnected"}
        try:
            await self._dap.send_request("disconnect", {"restart": False}, timeout=5)
        except Exception:
            pass
        await self._dap.stop()
        old_state = self._state
        self._reset()
        return {"status": "detached", "previousState": old_state.value}

    async def status(self) -> dict[str, Any]:
        result: dict[str, Any] = {"state": self._state.value}
        if self._state not in (SessionState.DISCONNECTED, SessionState.TERMINATED):
            result["breakpointCount"] = len(self._breakpoints)
            result["activeThreadId"] = self._active_thread_id
        if self._last_stop_event:
            result["lastStop"] = _stop_event_to_dict(self._last_stop_event)
        return result

    # ── initialization ──

    async def _initialize_dap(self) -> None:
        self._capabilities = await self._dap.send_request("initialize", {
            "clientID": "python-debug-mcp",
            "clientName": "Python Debug MCP",
            "adapterID": "debugpy",
            "pathFormat": "path",
            "linesStartAt1": True,
            "columnsStartAt1": True,
            "supportsVariableType": True,
        })

    def _register_event_handlers(self) -> None:
        self._dap.on_event("stopped", self._on_stopped)
        self._dap.on_event("continued", self._on_continued)
        self._dap.on_event("terminated", self._on_terminated)
        self._dap.on_event("exited", self._on_exited)
        self._dap.on_event("output", self._on_output)
        self._dap.on_event("thread", self._on_thread)

    # ── breakpoints ──

    async def set_breakpoint(
        self,
        file: str,
        line: int,
        condition: str | None = None,
        hit_condition: str | None = None,
        log_message: str | None = None,
    ) -> dict[str, Any]:
        async with self._lock:
            bp_id = f"bp-{self._next_bp_id}"
            self._next_bp_id += 1

            bp = ManagedBreakpoint(
                id=bp_id, file=os.path.abspath(file), line=line,
                condition=condition, hit_condition=hit_condition, log_message=log_message,
            )
            self._breakpoints[bp_id] = bp
            self._file_breakpoints.setdefault(bp.file, []).append(bp_id)

            if self._is_connected():
                await self._sync_file_breakpoints(bp.file)
            self._record_event("breakpointSet", {"id": bp_id, "file": bp.file, "line": line})
            return _bp_to_dict(bp)

    async def remove_breakpoint(self, breakpoint_id: str) -> dict[str, Any]:
        self._ensure_connected()
        async with self._lock:
            if breakpoint_id.startswith("fbp-"):
                fbp = self._function_breakpoints.pop(breakpoint_id, None)
                if fbp is None:
                    raise ValueError(f"Function breakpoint '{breakpoint_id}' not found")
                await self._sync_function_breakpoints()
                self._record_event("breakpointRemoved", {"id": breakpoint_id})
                return {"removed": breakpoint_id}

            bp = self._breakpoints.pop(breakpoint_id, None)
            if bp is None:
                raise ValueError(f"Breakpoint '{breakpoint_id}' not found")
            file_bps = self._file_breakpoints.get(bp.file, [])
            if breakpoint_id in file_bps:
                file_bps.remove(breakpoint_id)
            await self._sync_file_breakpoints(bp.file)
            self._record_event("breakpointRemoved", {"id": breakpoint_id})
            return {"removed": breakpoint_id}

    async def list_breakpoints(self) -> list[dict[str, Any]]:
        result = [_bp_to_dict(bp) for bp in self._breakpoints.values()]
        result.extend(_fbp_to_dict(fbp) for fbp in self._function_breakpoints.values())
        return result

    async def set_function_breakpoint(
        self,
        function_name: str,
        condition: str | None = None,
        hit_condition: str | None = None,
        log_message: str | None = None,
    ) -> dict[str, Any]:
        async with self._lock:
            fbp_id = f"fbp-{self._next_fbp_id}"
            self._next_fbp_id += 1

            fbp = ManagedFunctionBreakpoint(
                id=fbp_id, function_name=function_name,
                condition=condition, hit_condition=hit_condition,
                log_message=log_message,
            )
            self._function_breakpoints[fbp_id] = fbp

            if self._is_connected():
                await self._sync_function_breakpoints()
            self._record_event("breakpointSet", {
                "id": fbp_id, "functionName": function_name,
            })
            return _fbp_to_dict(fbp)

    async def _sync_function_breakpoints(self) -> None:
        dap_bps = []
        fbp_ids = list(self._function_breakpoints.keys())
        for fbp_id in fbp_ids:
            fbp = self._function_breakpoints[fbp_id]
            spec: dict[str, Any] = {"name": fbp.function_name}
            if fbp.condition:
                spec["condition"] = fbp.condition
            if fbp.hit_condition:
                spec["hitCondition"] = fbp.hit_condition
            if fbp.log_message:
                spec["logMessage"] = fbp.log_message
            dap_bps.append(spec)

        response = await self._dap.send_request("setFunctionBreakpoints", {
            "breakpoints": dap_bps,
        })

        for i, dap_bp in enumerate(response.get("breakpoints", [])):
            if i < len(fbp_ids):
                fbp = self._function_breakpoints[fbp_ids[i]]
                fbp.verified = dap_bp.get("verified", False)
                fbp.dap_id = dap_bp.get("id")

    async def _sync_all_breakpoints(self) -> None:
        for file in list(self._file_breakpoints.keys()):
            if self._file_breakpoints[file]:
                await self._sync_file_breakpoints(file)
        if self._function_breakpoints:
            await self._sync_function_breakpoints()
        if self._exception_filters:
            await self._dap.send_request("setExceptionBreakpoints", {
                "filters": self._exception_filters,
            })

    async def _sync_file_breakpoints(self, file: str) -> None:
        bp_ids = self._file_breakpoints.get(file, [])
        dap_bps = []
        for bp_id in bp_ids:
            bp = self._breakpoints[bp_id]
            spec: dict[str, Any] = {"line": bp.line}
            if bp.condition:
                spec["condition"] = bp.condition
            if bp.hit_condition:
                spec["hitCondition"] = bp.hit_condition
            if bp.log_message:
                spec["logMessage"] = bp.log_message
            dap_bps.append(spec)

        response = await self._dap.send_request("setBreakpoints", {
            "source": {"path": file},
            "breakpoints": dap_bps,
        })

        for i, dap_bp in enumerate(response.get("breakpoints", [])):
            if i < len(bp_ids):
                bp = self._breakpoints[bp_ids[i]]
                bp.verified = dap_bp.get("verified", False)
                bp.dap_id = dap_bp.get("id")
                if dap_bp.get("line"):
                    bp.line = dap_bp["line"]

    # ── sink watch ──

    async def watch_sinks(
        self,
        categories: list[str] | None = None,
        custom_sinks: list[str] | None = None,
        log_only: bool = True,
    ) -> dict[str, Any]:
        if categories is None:
            categories = list(SINK_CATEGORIES.keys())

        sink_names: list[str] = []
        for cat in categories:
            if cat not in SINK_CATEGORIES:
                raise ValueError(
                    f"Unknown sink category '{cat}'. "
                    f"Available: {', '.join(SINK_CATEGORIES.keys())}"
                )
            sink_names.extend(SINK_CATEGORIES[cat])
        if custom_sinks:
            sink_names.extend(custom_sinks)

        sink_names = list(dict.fromkeys(sink_names))

        results = []
        for name in sink_names:
            log_msg = f"[SINK] {name} called" if log_only else None
            result = await self.set_function_breakpoint(
                function_name=name,
                log_message=log_msg,
            )
            results.append(result)

        return {
            "categories": categories,
            "sinksWatched": len(results),
            "logOnly": log_only,
            "sinks": results,
        }

    # ── exception breakpoints ──

    async def set_exception_breakpoints(
        self,
        filters: list[str] | None = None,
        exception_paths: list[str] | None = None,
    ) -> dict[str, Any]:
        self._ensure_connected()
        self._exception_filters = filters or ["raised", "uncaught"]
        request: dict[str, Any] = {"filters": self._exception_filters}

        if exception_paths:
            request["exceptionOptions"] = [{
                "path": [{"names": exception_paths, "negate": False}],
                "breakMode": "always",
            }]

        await self._dap.send_request("setExceptionBreakpoints", request)
        result: dict[str, Any] = {"filters": self._exception_filters}
        if exception_paths:
            result["exceptionPaths"] = exception_paths
        return result

    async def clear_exception_breakpoints(self) -> dict[str, Any]:
        self._ensure_connected()
        self._exception_filters = []
        await self._dap.send_request("setExceptionBreakpoints", {"filters": []})
        return {"cleared": True}

    # ── execution control ──

    async def continue_execution(
        self, thread_id: int | None = None, wait_timeout: float = 30.0
    ) -> dict[str, Any]:
        self._ensure_suspended_or_running()

        self._stop_future = asyncio.get_running_loop().create_future()
        self._state = SessionState.RUNNING

        if not self._config_done_sent:
            self._config_done_sent = True
            await self._dap.send_request("configurationDone")
        else:
            tid = thread_id or self._active_thread_id or 0
            await self._dap.send_request("continue", {"threadId": tid})

        return await self._wait_for_stop_or_timeout(wait_timeout)

    async def step(
        self, kind: str = "over", thread_id: int | None = None, wait_timeout: float = 30.0
    ) -> dict[str, Any]:
        self._ensure_suspended()
        tid = thread_id or self._active_thread_id
        if tid is None:
            raise RuntimeError("No suspended thread")

        command_map = {"into": "stepIn", "over": "next", "out": "stepOut"}
        command = command_map.get(kind)
        if not command:
            raise ValueError(f"Invalid step kind '{kind}'. Use: into, over, out")

        self._stop_future = asyncio.get_running_loop().create_future()
        self._state = SessionState.RUNNING

        await self._dap.send_request(command, {"threadId": tid})

        return await self._wait_for_stop_or_timeout(wait_timeout)

    async def pause(self, thread_id: int | None = None) -> dict[str, Any]:
        self._ensure_connected()
        tid = thread_id or 0
        await self._dap.send_request("pause", {"threadId": tid})
        return {"status": "pause requested"}

    async def _wait_for_stop_or_timeout(self, timeout: float) -> dict[str, Any]:
        assert self._stop_future is not None
        try:
            stop = await asyncio.wait_for(self._stop_future, timeout=timeout)
            return stop
        except asyncio.TimeoutError:
            return {"status": "running", "waitTimedOut": True}
        finally:
            self._stop_future = None

    # ── inspection ──

    async def list_threads(self) -> list[dict[str, Any]]:
        self._ensure_connected()
        response = await self._dap.send_request("threads")
        threads = []
        for t in response.get("threads", []):
            self._thread_names[t["id"]] = t.get("name", "")
            threads.append({
                "id": t["id"],
                "name": t.get("name", ""),
                "isCurrent": t["id"] == self._active_thread_id,
            })
        return threads

    async def list_modules(self) -> list[dict[str, Any]]:
        self._ensure_connected()
        response = await self._dap.send_request("modules", {
            "startModule": 0,
            "moduleCount": 0,
        })
        modules = []
        for m in response.get("modules", []):
            modules.append({
                "id": m.get("id", ""),
                "name": m.get("name", ""),
                "path": m.get("path", ""),
                "version": m.get("version", ""),
                "isOptimized": m.get("isOptimized", False),
            })
        return modules

    async def get_stack_trace(
        self, thread_id: int | None = None, max_frames: int = 20
    ) -> list[dict[str, Any]]:
        self._ensure_suspended()
        tid = thread_id or self._active_thread_id
        if tid is None:
            raise RuntimeError("No suspended thread")

        response = await self._dap.send_request("stackTrace", {
            "threadId": tid,
            "startFrame": 0,
            "levels": max_frames,
        })

        frames = []
        for f in response.get("stackFrames", []):
            source = f.get("source", {})
            frames.append({
                "id": f["id"],
                "name": f.get("name", ""),
                "file": source.get("path", source.get("name", "<unknown>")),
                "line": f.get("line", 0),
                "column": f.get("column", 0),
            })
        return frames

    async def get_locals(
        self, frame_index: int = 0, thread_id: int | None = None
    ) -> dict[str, Any]:
        self._ensure_suspended()
        frames = await self.get_stack_trace(thread_id, max_frames=frame_index + 1)
        if frame_index >= len(frames):
            raise ValueError(f"Frame index {frame_index} out of range (have {len(frames)} frames)")

        frame_id = frames[frame_index]["id"]
        scopes_response = await self._dap.send_request("scopes", {"frameId": frame_id})

        result: dict[str, Any] = {"frame": frames[frame_index], "scopes": {}}
        for scope in scopes_response.get("scopes", []):
            scope_name = scope.get("name", "Unknown")
            variables = await self._get_variables(scope["variablesReference"])
            result["scopes"][scope_name] = variables

        return result

    async def inspect_variable(
        self, variables_reference: int, max_children: int = 50
    ) -> list[dict[str, Any]]:
        self._ensure_connected()
        return await self._get_variables(variables_reference, max_children)

    async def set_variable(
        self,
        name: str,
        value: str,
        frame_index: int = 0,
        thread_id: int | None = None,
    ) -> dict[str, Any]:
        self._ensure_suspended()
        frames = await self.get_stack_trace(thread_id, max_frames=frame_index + 1)
        if frame_index >= len(frames):
            raise ValueError(f"Frame index {frame_index} out of range")

        frame_id = frames[frame_index]["id"]
        scopes_response = await self._dap.send_request("scopes", {"frameId": frame_id})

        for scope in scopes_response.get("scopes", []):
            if scope.get("name") in ("Locals", "Arguments"):
                try:
                    response = await self._dap.send_request("setVariable", {
                        "variablesReference": scope["variablesReference"],
                        "name": name,
                        "value": value,
                    })
                    return _format_variable_response(response)
                except Exception:
                    continue

        raise ValueError(f"Could not set variable '{name}' — not found in local scopes")

    async def evaluate_expression(
        self,
        expression: str,
        frame_index: int = 0,
        thread_id: int | None = None,
        context: str = "repl",
        capture_output: bool = False,
    ) -> dict[str, Any]:
        self._ensure_suspended()
        frames = await self.get_stack_trace(thread_id, max_frames=frame_index + 1)
        if frame_index >= len(frames):
            raise ValueError(f"Frame index {frame_index} out of range")

        frame_id = frames[frame_index]["id"]

        if capture_output:
            is_compound = ";" in expression or "\n" in expression
            if is_compound:
                expression = (
                    "(lambda: ("
                    "(_b := __import__('io').StringIO()),"
                    "(_cm := __import__('contextlib').redirect_stdout(_b)),"
                    "_cm.__enter__(),"
                    f"exec({expression!r}),"
                    "_cm.__exit__(None, None, None),"
                    "_b.getvalue()"
                    "))()[-1]"
                )
            else:
                expression = (
                    "(lambda: ("
                    "(_b := __import__('io').StringIO()),"
                    "(_cm := __import__('contextlib').redirect_stdout(_b)),"
                    "_cm.__enter__(),"
                    f"(_r := ({expression})),"
                    "_cm.__exit__(None, None, None),"
                    "(_r if _r is not None else _b.getvalue())"
                    "))()[-1]"
                )

        response = await self._dap.send_request("evaluate", {
            "expression": expression,
            "frameId": frame_id,
            "context": context,
        })
        return _format_variable_response(response)

    async def _get_variables(
        self, variables_reference: int, max_children: int = 50
    ) -> list[dict[str, Any]]:
        if variables_reference == 0:
            return []
        response = await self._dap.send_request("variables", {
            "variablesReference": variables_reference,
            "count": max_children,
        })
        return [_format_variable(v) for v in response.get("variables", [])]

    # ── events ──

    def get_events(self, limit: int = 50, since_id: int | None = None) -> list[dict[str, Any]]:
        events = self._event_history
        if since_id is not None:
            events = [e for e in events if e["id"] > since_id]
        return events[-limit:]

    def get_last_stop_event(self) -> dict[str, Any] | None:
        if self._last_stop_event is None:
            return None
        return _stop_event_to_dict(self._last_stop_event)

    # ── event handlers ──

    def _on_stopped(self, body: dict[str, Any]) -> None:
        thread_id = body.get("threadId", 0)
        self._active_thread_id = thread_id
        self._state = SessionState.SUSPENDED

        stop = StopEvent(
            reason=body.get("reason", "unknown"),
            thread_id=thread_id,
            description=body.get("description", ""),
        )
        self._last_stop_event = stop

        asyncio.create_task(self._enrich_and_emit_stop(stop))

    async def _enrich_and_emit_stop(self, stop: StopEvent) -> None:
        try:
            response = await self._dap.send_request("stackTrace", {
                "threadId": stop.thread_id,
                "startFrame": 0,
                "levels": 1,
            }, timeout=5)
            frames = response.get("stackFrames", [])
            if frames:
                top = frames[0]
                source = top.get("source", {})
                stop.file = source.get("path", source.get("name", ""))
                stop.line = top.get("line", 0)
                stop.function = top.get("name", "")
        except Exception:
            logger.debug("Failed to enrich stop event with stack trace")

        event_data = _stop_event_to_dict(stop)
        self._record_event("stopped", event_data)

        if self._stop_future and not self._stop_future.done():
            self._stop_future.set_result(event_data)

    def _on_continued(self, body: dict[str, Any]) -> None:
        if body.get("allThreadsContinued", True):
            self._state = SessionState.RUNNING

    def _on_terminated(self, body: dict[str, Any]) -> None:
        self._state = SessionState.TERMINATED
        self._record_event("terminated", body)
        if self._stop_future and not self._stop_future.done():
            self._stop_future.set_result({"status": "terminated"})

    def _on_exited(self, body: dict[str, Any]) -> None:
        self._state = SessionState.TERMINATED
        self._record_event("exited", {"exitCode": body.get("exitCode")})
        if self._stop_future and not self._stop_future.done():
            self._stop_future.set_result({"status": "exited", "exitCode": body.get("exitCode")})

    def _on_output(self, body: dict[str, Any]) -> None:
        category = body.get("category", "console")
        output = body.get("output", "")
        if output.strip():
            self._record_event("output", {"category": category, "output": output.strip()})

    def _on_thread(self, body: dict[str, Any]) -> None:
        tid = body.get("threadId", 0)
        reason = body.get("reason", "")
        if reason == "started":
            self._thread_names.setdefault(tid, f"Thread-{tid}")
        elif reason == "exited":
            self._thread_names.pop(tid, None)

    # ── helpers ──

    def _ensure_connected(self) -> None:
        if self._state in (SessionState.DISCONNECTED, SessionState.TERMINATED):
            raise RuntimeError(f"No active debug session (state: {self._state.value})")

    def _is_connected(self) -> bool:
        return self._state not in (SessionState.DISCONNECTED, SessionState.TERMINATED)

    def _ensure_suspended(self) -> None:
        if self._state != SessionState.SUSPENDED:
            raise RuntimeError(
                f"Debuggee is not suspended (state: {self._state.value}). "
                "Set a breakpoint and wait for it to be hit, or use pause."
            )

    def _ensure_suspended_or_running(self) -> None:
        if self._state not in (SessionState.SUSPENDED, SessionState.RUNNING):
            raise RuntimeError(f"No active debug session (state: {self._state.value})")

    def _record_event(self, event_type: str, data: dict[str, Any]) -> None:
        self._event_id_counter += 1
        self._event_history.append({
            "id": self._event_id_counter,
            "type": event_type,
            "timestamp": time.time(),
            "data": data,
        })
        if len(self._event_history) > MAX_EVENT_HISTORY:
            self._event_history = self._event_history[-MAX_EVENT_HISTORY:]

    def _reset(self) -> None:
        self._state = SessionState.DISCONNECTED
        self._capabilities = {}
        self._breakpoints.clear()
        self._file_breakpoints.clear()
        self._function_breakpoints.clear()
        self._exception_filters.clear()
        self._active_thread_id = None
        self._thread_names.clear()
        self._last_stop_event = None
        self._event_history.clear()
        self._event_id_counter = 0
        self._stop_future = None
        self._next_bp_id = 1
        self._next_fbp_id = 1
        self._config_done_sent = True


# ── formatting helpers ──

def _bp_to_dict(bp: ManagedBreakpoint) -> dict[str, Any]:
    d: dict[str, Any] = {"id": bp.id, "file": bp.file, "line": bp.line, "verified": bp.verified}
    if bp.condition:
        d["condition"] = bp.condition
    if bp.hit_condition:
        d["hitCondition"] = bp.hit_condition
    if bp.log_message:
        d["logMessage"] = bp.log_message
    return d


def _fbp_to_dict(fbp: ManagedFunctionBreakpoint) -> dict[str, Any]:
    d: dict[str, Any] = {
        "id": fbp.id, "functionName": fbp.function_name, "verified": fbp.verified,
    }
    if fbp.condition:
        d["condition"] = fbp.condition
    if fbp.hit_condition:
        d["hitCondition"] = fbp.hit_condition
    if fbp.log_message:
        d["logMessage"] = fbp.log_message
    return d


def _stop_event_to_dict(stop: StopEvent) -> dict[str, Any]:
    return {
        "reason": stop.reason,
        "threadId": stop.thread_id,
        "description": stop.description,
        "file": stop.file,
        "line": stop.line,
        "function": stop.function,
    }


def _format_variable(v: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "name": v.get("name", ""),
        "value": v.get("value", ""),
        "type": v.get("type", ""),
    }
    ref = v.get("variablesReference", 0)
    if ref > 0:
        result["variablesReference"] = ref
        result["hasChildren"] = True
    if v.get("type") == "bytes":
        _enrich_bytes_variable(result)
    return result


def _enrich_bytes_variable(result: dict[str, Any]) -> None:
    value = result.get("value", "")
    try:
        raw = eval(value)  # noqa: S307 — safe: debugpy-provided bytes repr
        if isinstance(raw, bytes):
            result["length"] = len(raw)
            hex_str = raw[:128].hex()
            result["hex"] = " ".join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))
            if len(raw) > 128:
                result["hex"] += " ..."
    except Exception:
        pass


def _format_variable_response(resp: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "result": resp.get("result", resp.get("value", "")),
        "type": resp.get("type", ""),
    }
    ref = resp.get("variablesReference", 0)
    if ref > 0:
        result["variablesReference"] = ref
        result["hasChildren"] = True
    return result

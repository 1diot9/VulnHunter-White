"""Tool registry, ACL, dispatch, and logging."""

from __future__ import annotations

import json
import os
import shutil
import sys
import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from ..models import SessionLocal, ToolLog
from ..services.live_log import live_log

ToolHandler = Callable[["ToolContext", dict[str, Any]], dict[str, Any]]

# Tools that may run in parallel within one assistant turn
PARALLEL_SAFE = frozenset({"Read", "Grep", "Glob", "SearchOldVuln", "WebSearch"})

SHELL_TOOLS = frozenset({"Bash", "PowerShell"})


def native_shell_tool() -> str:
    """Detect the host-native shell tool. Inject exactly one of Bash / PowerShell."""
    windows = os.name == "nt" or sys.platform.startswith(("win", "cygwin"))
    has_powershell = bool(shutil.which("powershell") or shutil.which("pwsh"))
    has_bash = bool(Path("/bin/bash").exists() or shutil.which("bash"))
    if windows:
        if has_powershell:
            return "PowerShell"
        if has_bash:
            return "Bash"
        return "PowerShell"
    if has_bash:
        return "Bash"
    if has_powershell:
        return "PowerShell"
    return "Bash"


def tools_allowed_for_role(role: str) -> frozenset[str]:
    """Role ACL with the non-native shell stripped so the model only sees one."""
    allowed = ROLE_ACL.get(role, frozenset())
    native = native_shell_tool()
    return frozenset(name for name in allowed if name not in SHELL_TOOLS or name == native)


ROLE_ACL: dict[str, frozenset[str]] = {
    "recon": frozenset(
        {
            "Read",
            "Grep",
            "Glob",
            "Write",
            "Bash",
            "PowerShell",
            "TodoWrite",
            "MarkSource",
        }
    ),
    "recon_old_vuln": frozenset(
        {
            "Read",
            "Grep",
            "Glob",
            "TodoWrite",
            "WebSearch",
            "SearchOldVuln",
            "WriteOldVuln",
            "SearchGHSA",
        }
    ),
    "recon_mark": frozenset(
        {
            "MarkSource",
            "MarkWeight",
            "MarkSkip",
        }
    ),
    "worker": frozenset(
        {
            "Read",
            "Grep",
            "Glob",
            "Write",
            "Bash",
            "PowerShell",
            "TodoWrite",
            "SearchOldVuln",
            "SubmitVuln",
            "FinishFile",
            "FinishRound",
            "FinishFix",
        }
    ),
    "reviewer": frozenset(
        {
            "Read",
            "Grep",
            "Glob",
            "Write",
            "Bash",
            "PowerShell",
            "TodoWrite",
            "SearchOldVuln",
            "SearchGHSA",
            "ConfirmVuln",
            "ReturnToWorker",
        }
    ),
    "fix": frozenset(
        {
            "Read",
            "Grep",
            "Glob",
            "Write",
            "Bash",
            "PowerShell",
            "TodoWrite",
            "SearchOldVuln",
            "FinishFix",
            "SubmitVuln",
        }
    ),
}


@dataclass
class ToolContext:
    project_id: int
    role: str
    phase: str
    phase_run_id: int | None = None
    worker_id: str | None = None
    vuln_id: int | None = None
    file_path: str | None = None
    cancel_requested: Callable[[], bool] = field(default=lambda: False)
    state: dict[str, Any] = field(default_factory=dict)


@dataclass
class ToolSpec:
    name: str
    description: str
    parameters: dict[str, Any]
    handler: ToolHandler
    parallel_safe: bool = False


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}

    def register(self, spec: ToolSpec) -> None:
        self._tools[spec.name] = spec

    def get(self, name: str) -> ToolSpec | None:
        return self._tools.get(name)

    def openai_tools_for_role(self, role: str) -> list[dict[str, Any]]:
        allowed = tools_allowed_for_role(role)
        out: list[dict[str, Any]] = []
        for name in sorted(allowed):
            spec = self._tools.get(name)
            if not spec:
                continue
            out.append(
                {
                    "type": "function",
                    "function": {
                        "name": spec.name,
                        "description": spec.description,
                        "parameters": spec.parameters,
                    },
                }
            )
        return out

    def dispatch(self, ctx: ToolContext, name: str, arguments: dict[str, Any] | str) -> dict[str, Any]:
        allowed = tools_allowed_for_role(ctx.role)
        if name not in allowed:
            if name in SHELL_TOOLS:
                result = {
                    "ok": False,
                    "error": f"当前系统仅注入 {native_shell_tool()}，未提供 {name}",
                    "error_class": "call",
                }
            else:
                result = {
                    "ok": False,
                    "error": f"角色 {ctx.role} 无权调用工具 {name}",
                    "error_class": "call",
                }
            live_log.tool(ctx.project_id, name, {}, result, phase=ctx.phase, role=ctx.role)
            return result
        spec = self._tools.get(name)
        if not spec:
            result = {"ok": False, "error": f"未知工具: {name}", "error_class": "call"}
            live_log.tool(ctx.project_id, name, {}, result, phase=ctx.phase, role=ctx.role)
            return result
        if isinstance(arguments, str):
            try:
                arguments = json.loads(arguments) if arguments.strip() else {}
            except json.JSONDecodeError as e:
                result = {"ok": False, "error": f"参数 JSON 无效: {e}", "error_class": "call"}
                live_log.tool(ctx.project_id, name, {}, result, phase=ctx.phase, role=ctx.role)
                return result
        if not isinstance(arguments, dict):
            result = {"ok": False, "error": "参数必须是对象", "error_class": "call"}
            live_log.tool(ctx.project_id, name, {}, result, phase=ctx.phase, role=ctx.role)
            return result

        if name in ("Bash", "PowerShell"):
            live_log.tool(ctx.project_id, name, arguments, None, phase=ctx.phase, role=ctx.role, started=True)

        started = time.time()
        try:
            result = spec.handler(ctx, arguments)
            if not isinstance(result, dict):
                result = {"ok": True, "result": result}
            if "ok" not in result:
                result = {"ok": True, **result}
        except Exception as e:  # noqa: BLE001
            result = {
                "ok": False,
                "error": str(e),
                "error_class": "local",
                "traceback": traceback.format_exc()[-2000:],
            }
        duration_ms = (time.time() - started) * 1000
        if not result.get("ok") and result.get("error_class") == "local":
            self._log_local_exec_error(ctx, name, arguments, result, duration_ms)
            live_log.tool_exec_error(
                ctx.project_id,
                name,
                arguments,
                result,
                phase=ctx.phase,
                role=ctx.role,
                duration_ms=duration_ms,
                phase_run_id=ctx.phase_run_id,
            )
        self._log(ctx, name, arguments, result, duration_ms)
        live_log.tool(
            ctx.project_id,
            name,
            arguments,
            result,
            phase=ctx.phase,
            role=ctx.role,
        )
        return result

    def _log_local_exec_error(
        self,
        ctx: ToolContext,
        name: str,
        arguments: dict[str, Any],
        result: dict[str, Any],
        duration_ms: float,
    ) -> None:
        try:
            from ..services.paths import tool_exec_errors_path

            path = tool_exec_errors_path(ctx.project_id)
            path.parent.mkdir(parents=True, exist_ok=True)
            row = {
                "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "phase": ctx.phase,
                "role": ctx.role,
                "tool": name,
                "args": json.dumps(arguments, ensure_ascii=False)[:4000],
                "error": str(result.get("error") or "")[:2000],
                "traceback": str(result.get("traceback") or "")[:2000],
                "duration_ms": duration_ms,
                "phase_run_id": ctx.phase_run_id,
            }
            with path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(row, ensure_ascii=False) + "\n")
        except Exception:  # noqa: BLE001
            pass

    def _log(
        self,
        ctx: ToolContext,
        name: str,
        arguments: dict[str, Any],
        result: dict[str, Any],
        duration_ms: float,
    ) -> None:
        try:
            error_class = result.get("error_class")
            if result.get("ok"):
                error_class = None
            elif error_class not in ("local", "call"):
                error_class = None
            with SessionLocal() as db:
                db.add(
                    ToolLog(
                        project_id=ctx.project_id,
                        phase_run_id=ctx.phase_run_id,
                        tool_name=name,
                        role=ctx.role,
                        input_json=json.dumps(arguments, ensure_ascii=False)[:20000],
                        output_json=json.dumps(result, ensure_ascii=False)[:50000],
                        success=bool(result.get("ok", False)),
                        error=str(result.get("error") or "")[:2000] or None,
                        error_class=error_class,
                        duration_ms=duration_ms,
                    )
                )
                db.commit()
        except Exception:  # noqa: BLE001
            pass


registry = ToolRegistry()


def register_all_tools() -> None:
    """Import tool modules so they self-register."""
    from . import common  # noqa: F401
    from . import phase_recon  # noqa: F401
    from . import phase_worker  # noqa: F401
    from . import phase_reviewer  # noqa: F401

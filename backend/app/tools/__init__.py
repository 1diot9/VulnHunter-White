"""Tool registry, ACL, dispatch, and logging."""

from __future__ import annotations

import json
import os
import queue
import shutil
import sys
import threading
import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from ..models import SessionLocal, ToolLog
from ..services.live_log import live_log

ToolHandler = Callable[["ToolContext", dict[str, Any]], dict[str, Any]]

# Tools that may run in parallel within one assistant turn
PARALLEL_SAFE = frozenset({"Read", "Grep", "Glob", "SearchOldVuln", "SearchTools", "WebSearch"})

SHELL_TOOLS = frozenset({"Bash", "PowerShell"})
# Hidden and rejected when a pending vuln has hit consecutive reviewer timeouts.
_STATIC_FORCED_BLOCKED_TOOLS = frozenset(
    {"Bash", "PowerShell", "CollectLabFingerprints", "RunCode"}
)
_SHELL_DISPATCH_TIMEOUT_DEFAULT = 120
_SHELL_DISPATCH_TIMEOUT_MAX = 180
_SHELL_DISPATCH_TIMEOUT_GRACE = 10


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
            "FinishReconMap",
        }
    ),
    "recon_source_ext": frozenset(
        {
            "Read",
            "Grep",
            "Glob",
            "TodoWrite",
            "AddSourceExt",
        }
    ),
    "recon_old_vuln": frozenset(
        {
            "Read",
            "TodoWrite",
            "SearchOldVuln",
            "WriteOldVuln",
        }
    ),
    "recon_old_vuln_ghsa": frozenset(
        {
            "Read",
            "TodoWrite",
            "WebSearch",
            "SearchOldVuln",
            "WriteOldVuln",
            "SearchGHSA",
            "SearchGitHubIssues",
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
            "ReadCveRecord",
            "SetCveRecordField",
            "AppendAffectedLocations",
            "FinishFile",
            "FinishRound",
            "FinishFix",
        }
    ),
    "fast_worker": frozenset(
        {
            "Read",
            "Grep",
            "Glob",
            "SearchOldVuln",
            "SubmitVuln",
            "ReadCveRecord",
            "SetCveRecordField",
            "AppendAffectedLocations",
            "FinishSink",
        }
    ),
    "bypass_worker": frozenset(
        {
            "Read",
            "Grep",
            "Glob",
            "SearchOldVuln",
            "SubmitVuln",
            "ReadCveRecord",
            "SetCveRecordField",
            "AppendAffectedLocations",
            "FinishBypass",
        }
    ),
    "sink_triage": frozenset({"FinishSinkTriage"}),
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
            "SearchTools",
            "SearchGHSA",
            "ConfirmVuln",
            "CollectLabFingerprints",
            "MergeIntoVuln",
            "MarkFalsePositive",
            "ReturnToWorker",
            "RequestLabRebuild",
            "RunCode",
            "ReadCveRecord",
            "SetCveRecordField",
        }
    ),
    "reviewer_lab": frozenset(
        {
            "Read",
            "Grep",
            "Glob",
            "Write",
            "Bash",
            "PowerShell",
            "TodoWrite",
            "FinishLab",
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
            "ReadCveRecord",
            "SetCveRecordField",
            "AppendAffectedLocations",
        }
    ),
    "verifier": frozenset(
        {
            "Read",
            "Grep",
            "Glob",
            "Write",
            "Bash",
            "PowerShell",
            "TodoWrite",
            "FofaSearch",
            "AskUser",
            "FinishVerifier",
        }
    ),
    "attack_chain": frozenset(
        {
            "Read",
            "Grep",
            "Write",
            "Bash",
            "PowerShell",
            "TodoWrite",
            "SearchOldVuln",
            "SubmitAttackChain",
            "IndexAttackChain",
            "FinishAttackChain",
        }
    ),
    "cli_indexer": frozenset(
        {
            "Read",
            "Grep",
            "Glob",
            "Bash",
            "PowerShell",
            "FinishIndex",
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
    workspace_root: str | None = None
    silent: bool = False
    log_path: str | None = None
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

    def _shell_dispatch_timeout(self, arguments: dict[str, Any]) -> int:
        try:
            requested = int(arguments.get("timeout") or _SHELL_DISPATCH_TIMEOUT_DEFAULT)
        except (TypeError, ValueError):
            requested = _SHELL_DISPATCH_TIMEOUT_DEFAULT
        return max(1, min(requested, _SHELL_DISPATCH_TIMEOUT_MAX)) + _SHELL_DISPATCH_TIMEOUT_GRACE

    def _dispatch_shell_with_hard_timeout(
        self,
        spec: ToolSpec,
        ctx: ToolContext,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        """Keep AgentLoop moving even if a shell child process defeats the shell runner."""
        timeout = self._shell_dispatch_timeout(arguments)
        done: queue.Queue[tuple[str, Any]] = queue.Queue(maxsize=1)

        def _target() -> None:
            try:
                done.put(("result", spec.handler(ctx, arguments)), block=False)
            except Exception as e:  # noqa: BLE001
                done.put(("error", (e, traceback.format_exc()[-2000:])), block=False)

        t = threading.Thread(
            target=_target,
            name=f"vh-tool-{spec.name}-{ctx.project_id}-{ctx.phase_run_id or 'na'}",
            daemon=True,
        )
        t.start()
        t.join(timeout)
        if t.is_alive():
            return {
                "ok": False,
                "error": (
                    f"工具调用硬超时 ({timeout}s)，已返回失败让 Agent 继续；"
                    "底层 shell 可能仍在系统回收中。请给 curl/docker/网络命令设置自身超时后重试。"
                ),
                "error_class": "local",
                "hard_timeout": True,
            }
        try:
            kind, payload = done.get_nowait()
        except queue.Empty:
            return {"ok": False, "error": "工具线程无结果返回", "error_class": "local"}
        if kind == "error":
            err, tb = payload
            return {
                "ok": False,
                "error": str(err),
                "error_class": "local",
                "traceback": tb,
            }
        return payload

    def openai_tools_for_role(
        self,
        role: str,
        *,
        project_id: int | None = None,
        vuln_id: int | None = None,
    ) -> list[dict[str, Any]]:
        allowed = tools_allowed_for_role(role)
        hide_run_code = role == "reviewer"
        hide_dynamic_tools = False
        if role == "reviewer" and project_id is not None:
            from ..dynamic_verify import project_is_harness, vuln_forces_static_review

            hide_run_code = not project_is_harness(project_id)
            hide_dynamic_tools = vuln_forces_static_review(project_id=project_id, vuln_id=vuln_id)
            if hide_dynamic_tools:
                hide_run_code = True
        out: list[dict[str, Any]] = []
        for name in sorted(allowed):
            if name == "RunCode" and hide_run_code:
                continue
            if hide_dynamic_tools and name in _STATIC_FORCED_BLOCKED_TOOLS:
                continue
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

    def _event_log(self, ctx: ToolContext):
        if getattr(ctx, "silent", False) and getattr(ctx, "log_path", None):
            from ..services.cli_tool_index import file_event_log

            return file_event_log(Path(str(ctx.log_path)))
        return live_log

    def dispatch(self, ctx: ToolContext, name: str, arguments: dict[str, Any] | str) -> dict[str, Any]:
        allowed = tools_allowed_for_role(ctx.role)
        events = self._event_log(ctx)
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
            events.tool(ctx.project_id, name, {}, result, phase=ctx.phase, role=ctx.role)
            return result
        if ctx.role == "reviewer" and name in _STATIC_FORCED_BLOCKED_TOOLS:
            from ..dynamic_verify import vuln_forces_static_review

            if vuln_forces_static_review(project_id=ctx.project_id, vuln_id=ctx.vuln_id):
                result = {
                    "ok": False,
                    "error": (
                        "本条漏洞已连续超时，本轮仅允许静态审核"
                        "（禁止 Shell / poc.py / docker / CollectLabFingerprints / RunCode）"
                    ),
                    "error_class": "call",
                }
                events.tool(
                    ctx.project_id,
                    name,
                    arguments if isinstance(arguments, dict) else {},
                    result,
                    phase=ctx.phase,
                    role=ctx.role,
                )
                return result
        spec = self._tools.get(name)
        if not spec:
            result = {"ok": False, "error": f"未知工具: {name}", "error_class": "call"}
            events.tool(ctx.project_id, name, {}, result, phase=ctx.phase, role=ctx.role)
            return result
        if isinstance(arguments, str):
            try:
                arguments = json.loads(arguments) if arguments.strip() else {}
            except json.JSONDecodeError as e:
                result = {"ok": False, "error": f"参数 JSON 无效: {e}", "error_class": "call"}
                events.tool(ctx.project_id, name, {}, result, phase=ctx.phase, role=ctx.role)
                return result
        if not isinstance(arguments, dict):
            result = {"ok": False, "error": "参数必须是对象", "error_class": "call"}
            events.tool(ctx.project_id, name, {}, result, phase=ctx.phase, role=ctx.role)
            return result

        if name in ("Bash", "PowerShell"):
            events.tool(ctx.project_id, name, arguments, None, phase=ctx.phase, role=ctx.role, started=True)

        started = time.time()
        try:
            if name in SHELL_TOOLS:
                result = self._dispatch_shell_with_hard_timeout(spec, ctx, arguments)
            else:
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
            events.tool_exec_error(
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
        events.tool(
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
        if getattr(ctx, "silent", False) or not ctx.project_id:
            return
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
        if getattr(ctx, "silent", False) or not ctx.project_id:
            return
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
    from . import phase_fast  # noqa: F401
    from . import phase_bypass  # noqa: F401
    from . import phase_reviewer  # noqa: F401
    from . import phase_cli_index  # noqa: F401
    from . import phase_verifier  # noqa: F401
    from . import phase_attack_chain  # noqa: F401
    from . import run_code  # noqa: F401
    from . import phase_cve_record  # noqa: F401

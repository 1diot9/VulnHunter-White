from __future__ import annotations

import json
import logging
from typing import Any

from mcp.server.fastmcp import FastMCP

from debug_session import DebugSessionManager

logger = logging.getLogger(__name__)

mcp = FastMCP("python-debug-mcp")
session = DebugSessionManager()


def _json_result(data: Any) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False, default=str)


# ── session management ──


@mcp.tool()
async def debug_launch(
    program: str,
    args: list[str] | None = None,
    cwd: str | None = None,
    python: str | None = None,
    stop_on_entry: bool = True,
) -> str:
    """Launch a Python program under debugpy and attach to it.

    Args:
        program: Path to the Python script to debug.
        args: Command-line arguments for the script.
        cwd: Working directory. Defaults to the script's directory.
        python: Python interpreter path. Defaults to the current interpreter.
        stop_on_entry: If true, pause at the first line of the program. Defaults to true.
    """
    result = await session.launch(program, args=args, cwd=cwd, python=python, stop_on_entry=stop_on_entry)
    return _json_result(result)


@mcp.tool()
async def debug_attach(host: str, port: int, python: str | None = None) -> str:
    """Attach to a running Python process that has debugpy listening.

    The target process should be started with either:
      - python -m debugpy --listen HOST:PORT --wait-for-client script.py
      - import debugpy; debugpy.listen((HOST, PORT)); debugpy.wait_for_client()

    Args:
        host: Host where debugpy is listening.
        port: Port where debugpy is listening.
        python: Python interpreter path for the local debugpy adapter subprocess.
                Use this to match the debugpy version with the remote server.
                For example, if the remote runs debugpy 1.5.x (Python 3.6),
                point this to a local venv with the same debugpy version.
    """
    result = await session.attach(host, port, python=python)
    return _json_result(result)


@mcp.tool()
async def debug_attach_tcp(host: str, port: int) -> str:
    """Attach to a remote debugpy server via direct TCP connection.

    Use this instead of debug_attach when the target runs in a Docker container
    or any environment where the debugpy adapter's reverse connection won't work
    (e.g., the adapter opens a random local port that the container can't reach).

    The target process should be started with:
      - python -m debugpy --listen 0.0.0.0:PORT --wait-for-client script.py

    Args:
        host: Host where debugpy is listening (e.g., "127.0.0.1", "localhost").
        port: Port where debugpy is listening (the port mapped from the container).
    """
    result = await session.attach_tcp(host, port)
    return _json_result(result)


@mcp.tool()
async def debug_detach() -> str:
    """Detach from the debug session and clean up."""
    result = await session.detach()
    return _json_result(result)


@mcp.tool()
async def debug_status() -> str:
    """Return the current debug session status."""
    result = await session.status()
    return _json_result(result)


# ── breakpoints ──


@mcp.tool()
async def debug_set_breakpoint(
    file: str,
    line: int,
    condition: str | None = None,
    hit_condition: str | None = None,
    log_message: str | None = None,
) -> str:
    """Set a breakpoint at a specific file and line.

    Args:
        file: Absolute path to the source file.
        line: Line number (1-based).
        condition: Optional condition expression (break only when true).
        hit_condition: Optional hit count expression (e.g., "> 5").
        log_message: If set, logs a message instead of breaking. Expressions in {}.
    """
    result = await session.set_breakpoint(
        file, line,
        condition=condition,
        hit_condition=hit_condition,
        log_message=log_message,
    )
    return _json_result(result)


@mcp.tool()
async def debug_remove_breakpoint(breakpoint_id: str) -> str:
    """Remove a breakpoint by its ID (e.g., 'bp-1').

    Args:
        breakpoint_id: The breakpoint ID returned by debug_set_breakpoint.
    """
    result = await session.remove_breakpoint(breakpoint_id)
    return _json_result(result)


@mcp.tool()
async def debug_list_breakpoints() -> str:
    """List all currently set breakpoints."""
    result = await session.list_breakpoints()
    return _json_result(result)


@mcp.tool()
async def debug_set_function_breakpoint(
    function_name: str,
    condition: str | None = None,
    hit_condition: str | None = None,
    log_message: str | None = None,
) -> str:
    """Set a function breakpoint that triggers when the named function is called.

    Unlike line breakpoints, this does not require knowing the file or line number.
    Useful for breaking on dangerous functions like pickle.loads, eval, os.system, etc.

    Args:
        function_name: Qualified function name (e.g., "pickle.loads", "os.system", "eval").
        condition: Optional condition expression (break only when true).
        hit_condition: Optional hit count expression (e.g., "> 5").
        log_message: If set, logs a message instead of breaking. Expressions in {}.
    """
    result = await session.set_function_breakpoint(
        function_name,
        condition=condition,
        hit_condition=hit_condition,
        log_message=log_message,
    )
    return _json_result(result)


# ── exception breakpoints ──


@mcp.tool()
async def debug_set_exception_breakpoints(
    filters: list[str] | None = None,
    exception_paths: list[str] | None = None,
) -> str:
    """Set exception breakpoints to pause on exceptions.

    Args:
        filters: Exception filters. Common values: "raised" (all), "uncaught" (unhandled only).
                 Defaults to ["raised", "uncaught"].
        exception_paths: Optional list of exception class names to filter on
                         (e.g., ["PermissionError", "ValueError"]). Only pauses on these types.
    """
    result = await session.set_exception_breakpoints(filters, exception_paths)
    return _json_result(result)


@mcp.tool()
async def debug_watch_sinks(
    categories: list[str] | None = None,
    custom_sinks: list[str] | None = None,
    log_only: bool = True,
) -> str:
    """Monitor calls to dangerous functions (security sinks) using function breakpoints.

    Available categories: deserialization, command_injection, code_execution,
    file_access, ssrf, xxe.

    Args:
        categories: Sink categories to watch. Defaults to all categories.
        custom_sinks: Additional function names to watch (e.g., ["myapp.unsafe_handler"]).
        log_only: If true (default), only logs sink calls without pausing. If false, pauses on each call.
    """
    result = await session.watch_sinks(categories, custom_sinks, log_only)
    return _json_result(result)


@mcp.tool()
async def debug_clear_exception_breakpoints() -> str:
    """Remove all exception breakpoints."""
    result = await session.clear_exception_breakpoints()
    return _json_result(result)


# ── execution control ──


@mcp.tool()
async def debug_continue(thread_id: int | None = None, wait_timeout: float = 30.0) -> str:
    """Continue execution until the next breakpoint or program exit.

    Args:
        thread_id: Thread to continue. Defaults to the currently suspended thread.
        wait_timeout: Max seconds to wait for the next stop. Returns early if exceeded.
    """
    result = await session.continue_execution(thread_id, wait_timeout=wait_timeout)
    return _json_result(result)


@mcp.tool()
async def debug_step(
    kind: str = "over",
    thread_id: int | None = None,
    wait_timeout: float = 30.0,
) -> str:
    """Step through code execution.

    Args:
        kind: Step kind - "into" (step into function), "over" (step over), "out" (step out of function).
        thread_id: Thread to step. Defaults to the currently suspended thread.
        wait_timeout: Max seconds to wait for the step to complete.
    """
    result = await session.step(kind, thread_id, wait_timeout=wait_timeout)
    return _json_result(result)


@mcp.tool()
async def debug_pause(thread_id: int | None = None) -> str:
    """Pause a running program.

    Args:
        thread_id: Thread to pause. Defaults to all threads.
    """
    result = await session.pause(thread_id)
    return _json_result(result)


# ── inspection ──


@mcp.tool()
async def debug_list_threads() -> str:
    """List all threads in the debugged process."""
    result = await session.list_threads()
    return _json_result(result)


@mcp.tool()
async def debug_list_modules() -> str:
    """List all loaded Python modules in the debugged process.

    Useful for identifying available libraries, attack surface, and loaded security patches.
    """
    result = await session.list_modules()
    return _json_result(result)


@mcp.tool()
async def debug_get_stack(thread_id: int | None = None, max_frames: int = 20) -> str:
    """Get the call stack of a suspended thread.

    Args:
        thread_id: Thread ID. Defaults to the currently suspended thread.
        max_frames: Maximum number of stack frames to return.
    """
    result = await session.get_stack_trace(thread_id, max_frames)
    return _json_result(result)


@mcp.tool()
async def debug_get_locals(frame_index: int = 0, thread_id: int | None = None) -> str:
    """Get local variables for a stack frame.

    Args:
        frame_index: Stack frame index (0 = top/current frame).
        thread_id: Thread ID. Defaults to the currently suspended thread.
    """
    result = await session.get_locals(frame_index, thread_id)
    return _json_result(result)


@mcp.tool()
async def debug_inspect_variable(variables_reference: int, max_children: int = 50) -> str:
    """Inspect a complex variable's children (expand an object, list, dict, etc.).

    Use the variablesReference value from debug_get_locals or a previous inspect call.

    Args:
        variables_reference: The variablesReference ID from a prior variable result.
        max_children: Maximum number of child entries to return.
    """
    result = await session.inspect_variable(variables_reference, max_children)
    return _json_result(result)


@mcp.tool()
async def debug_set_variable(
    name: str,
    value: str,
    frame_index: int = 0,
    thread_id: int | None = None,
) -> str:
    """Modify a variable's value at runtime in a suspended frame.

    Useful for iterating on exploit payloads without restarting the program.

    Args:
        name: Variable name to modify.
        value: New value as a Python expression string (e.g., "'whoami'", "42", "True").
        frame_index: Stack frame index (0 = top/current frame).
        thread_id: Thread ID. Defaults to the currently suspended thread.
    """
    result = await session.set_variable(name, value, frame_index, thread_id)
    return _json_result(result)


@mcp.tool()
async def debug_evaluate_expression(
    expression: str,
    frame_index: int = 0,
    thread_id: int | None = None,
    capture_output: bool = False,
) -> str:
    """Evaluate a Python expression in the context of a suspended frame.

    Args:
        expression: Python expression to evaluate (e.g., "len(items)", "self.name").
        frame_index: Stack frame index for evaluation context (0 = top frame).
        thread_id: Thread ID. Defaults to the currently suspended thread.
        capture_output: If true, captures stdout output from the expression.
                        Useful for functions that print instead of returning (e.g., pickletools.dis(), dis.dis()).
    """
    result = await session.evaluate_expression(
        expression, frame_index, thread_id, capture_output=capture_output,
    )
    return _json_result(result)


# ── events ──


@mcp.tool()
async def debug_get_events(limit: int = 50, since_id: int | None = None) -> str:
    """Get recent debug events (breakpoint hits, steps, output, etc.).

    Args:
        limit: Maximum number of events to return.
        since_id: Only return events with ID greater than this (for incremental polling).
    """
    result = session.get_events(limit, since_id)
    return _json_result(result)


@mcp.tool()
async def debug_get_last_stop_event() -> str:
    """Get the most recent stop event (breakpoint hit, step completed, exception, etc.)."""
    result = session.get_last_stop_event()
    if result is None:
        return _json_result({"message": "No stop events yet"})
    return _json_result(result)

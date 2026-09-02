"""Agent tools for Code Intelligence (structured call-graph queries)."""

from __future__ import annotations

from typing import Any

from ..code_intelligence.query import callees, callers, find_symbol, trace
from . import ToolSpec, registry

CODE_INTEL_TOOL_NAMES = ("FindSymbol", "FindCallers", "FindCallees", "TraceCalls")


def _int_arg(args: dict[str, Any], key: str, default: int) -> int:
    raw = args.get(key)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except (TypeError, ValueError):
        return default


def _find_symbol(ctx, args: dict[str, Any]) -> dict[str, Any]:
    return find_symbol(ctx.project_id, str(args.get("query") or ""), limit=_int_arg(args, "limit", 20))


def _find_callers(ctx, args: dict[str, Any]) -> dict[str, Any]:
    return callers(ctx.project_id, str(args.get("symbol") or ""), limit=_int_arg(args, "limit", 40))


def _find_callees(ctx, args: dict[str, Any]) -> dict[str, Any]:
    return callees(ctx.project_id, str(args.get("symbol") or ""), limit=_int_arg(args, "limit", 40))


def _trace_calls(ctx, args: dict[str, Any]) -> dict[str, Any]:
    return trace(
        ctx.project_id,
        str(args.get("source") or ""),
        str(args.get("sink") or ""),
        max_hops=_int_arg(args, "max_hops", 8),
    )


def register_code_intel_tools() -> None:
    registry.register(
        ToolSpec(
            name="FindSymbol",
            description=(
                "在代码数据库中按名称查找符号（类/方法/函数）。返回路径与行号的短列表。"
                "索引不可用时请改用 Grep。不要用它判定漏洞。"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "符号名或片段，如 UserService.process 或 Runtime.exec"},
                    "limit": {"type": "integer", "description": "最多返回条数，默认 20，上限 20"},
                },
                "required": ["query"],
            },
            handler=_find_symbol,
            parallel_safe=True,
        )
    )
    registry.register(
        ToolSpec(
            name="FindCallers",
            description=(
                "查谁调用了该符号。适合从 sink 回推 source。"
                "返回调用方名称、文件、行号。索引不可用时请 Grep。"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "symbol": {"type": "string", "description": "符号名，如 CommandService.execute 或 Runtime.exec"},
                    "limit": {"type": "integer", "description": "最多返回条数，默认 40，上限 40"},
                },
                "required": ["symbol"],
            },
            handler=_find_callers,
            parallel_safe=True,
        )
    )
    registry.register(
        ToolSpec(
            name="FindCallees",
            description=(
                "查该符号调用了谁。适合从入口沿调用链向下看。"
                "返回被调用方名称、文件、行号。索引不可用时请 Grep。"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "symbol": {"type": "string", "description": "符号名，如 AdminController.run"},
                    "limit": {"type": "integer", "description": "最多返回条数，默认 40，上限 40"},
                },
                "required": ["symbol"],
            },
            handler=_find_callees,
            parallel_safe=True,
        )
    )
    registry.register(
        ToolSpec(
            name="TraceCalls",
            description=(
                "查找 source 到 sink 的调用路径（最多 8 跳）。"
                "只返回路径上的符号与位置，不含大段源码。确认路径后再 Read 关键方法。"
                "索引不可用时请沿 FindCallers / Grep 手工回推。"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "source": {"type": "string", "description": "起点符号，如 AdminController.run"},
                    "sink": {"type": "string", "description": "终点符号，如 Runtime.exec"},
                    "max_hops": {"type": "integer", "description": "最大跳数，默认 8，上限 8"},
                },
                "required": ["source", "sink"],
            },
            handler=_trace_calls,
            parallel_safe=True,
        )
    )


register_code_intel_tools()

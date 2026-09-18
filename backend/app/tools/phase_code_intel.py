"""Agent tools for Code Intelligence (structured call-graph queries + recon choice)."""

from __future__ import annotations

from typing import Any

from ..code_intelligence.query import callees, callers, find_symbol, trace
from ..code_intelligence.service import mark_code_intel
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


def _truthy(val: Any) -> bool:
    if isinstance(val, bool):
        return val
    if val is None:
        return False
    return str(val).strip().lower() in {"1", "true", "yes", "y"}


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


def _mark_code_intel(ctx, args: dict[str, Any]) -> dict[str, Any]:
    if (ctx.role or "").strip() != "recon":
        return {"ok": False, "error": "MarkCodeIntel 仅 recon（地图/鉴权）可用"}
    return mark_code_intel(
        ctx.project_id,
        codegraph=_truthy(args.get("codegraph")),
        jar_analyzer=_truthy(args.get("jar_analyzer")),
    )


def register_code_intel_tools() -> None:
    registry.register(
        ToolSpec(
            name="FindSymbol",
            description=(
                "在代码数据库中按名称查找符号（类/方法/函数）。返回路径与行号的短列表。"
                "底层可能来自 CodeGraph（源码）或 Jar Analyzer（业务 jar 字节码），结果带 backend 字段；不要自己选库。"
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
                "返回调用方名称、文件、行号；可能来自源码图或业务 jar 字节码图（backend 字段）。"
                "索引不可用时请 Grep。"
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
                "只在同一后端（源码图或字节码图）内搜索，不做跨 jar/源码拼接。"
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
    registry.register(
        ToolSpec(
            name="MarkCodeIntel",
            description=(
                "仅 recon（地图）：项目开启了代码库时，点名要构建的后端。"
                "codegraph=true 索引 src/ 源码；jar_analyzer=true 仅对 MarkBusinessJar 点名的业务 jar 建字节码调用图；"
                "可两者都 true。至少一个为 true。未开启代码库时不要调用。"
                "点名后系统开始构建；挖掘侧仍用 FindSymbol/FindCallers 等，由平台路由，不要自己选库。"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "codegraph": {
                        "type": "boolean",
                        "description": "是否用 CodeGraph 索引 src/ 源码调用图",
                    },
                    "jar_analyzer": {
                        "type": "boolean",
                        "description": "是否对点名业务 jar 跑 Jar Analyzer 建字节码调用图",
                    },
                },
                "required": [],
            },
            handler=_mark_code_intel,
            parallel_safe=True,
        )
    )


register_code_intel_tools()

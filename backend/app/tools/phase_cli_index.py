"""CLI indexer tools: FinishIndex."""

from __future__ import annotations

from typing import Any

from ..services.cli_tool_index import dir_fingerprint, write_ready_index
from . import ToolSpec, registry
from .common import call_fail
from .sandbox import SandboxError, assert_readable, ctx_workspace_root


def _finish_index(ctx, args: dict[str, Any]) -> dict[str, Any]:
    ws = ctx_workspace_root(ctx)
    if ws is None:
        return call_fail("FinishIndex 只能在 CLI 工具索引会话中调用")
    description = str(args.get("description") or "").strip()
    entry = str(args.get("entry") or args.get("path") or "").strip()
    if not description:
        return call_fail("缺少 description")
    if not entry:
        return call_fail("缺少 entry（工具入口相对路径）")
    try:
        target = assert_readable(ctx.project_id, entry, workspace_root=ws)
    except SandboxError as e:
        return call_fail(str(e))
    if not target.exists():
        return call_fail(f"入口不存在: {entry}")
    if target.is_dir():
        return call_fail("entry 必须是可执行文件或脚本，不能是目录")
    try:
        rel = target.relative_to(ws).as_posix()
    except ValueError:
        return call_fail("入口必须位于当前工具目录内")
    rec = write_ready_index(
        ws,
        entry=rel,
        entry_path=target,
        description=description,
        fingerprint=dir_fingerprint(ws),
        rounds=int((ctx.state or {}).get("index_rounds") or 0) or None,
    )
    ctx.state["index_done"] = True
    ctx.state["index_record"] = rec
    return {
        "ok": True,
        "name": rec["name"],
        "dir": rec["dir"],
        "path": rec["path"],
        "entry": rec["entry"],
        "description": rec["description"],
        "message": "索引已落盘，本会话结束",
    }


def register_cli_index_tools() -> None:
    registry.register(
        ToolSpec(
            name="FinishIndex",
            description=(
                "完成本 CLI 工具目录的索引：写入入口路径与中文描述后结束会话。"
                "entry 为相对本目录的可执行文件或脚本；不要修改工具文件本身。"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "description": {
                        "type": "string",
                        "description": "中文说明：用途、主要参数、典型调用方式",
                    },
                    "entry": {
                        "type": "string",
                        "description": "入口可执行文件或脚本，相对本工具目录",
                    },
                    "path": {
                        "type": "string",
                        "description": "entry 的别名",
                    },
                },
                "required": ["description", "entry"],
            },
            handler=_finish_index,
        )
    )


register_cli_index_tools()

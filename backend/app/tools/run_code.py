"""RunCode: execute a Reviewer-written harness in the sibling sandbox."""

from __future__ import annotations

from typing import Any

from ..dynamic_verify import project_is_harness
from ..services.poc_script import write_harness_code
from ..services.sandbox_exec import execute_harness
from . import ToolSpec, registry


def _run_code(ctx, args: dict[str, Any]) -> dict[str, Any]:
    if ctx.role != "reviewer" or not project_is_harness(ctx.project_id):
        return {"ok": False, "error": "RunCode 仅在局部验证模式下的审核轮可用"}
    code = str(args.get("code") or "").strip()
    if not code:
        return {"ok": False, "error": "缺少 code"}
    language = str(args.get("language") or "python").strip() or "python"
    description = str(args.get("description") or "").strip()
    try:
        timeout = int(args.get("timeout") or 60)
    except (TypeError, ValueError):
        timeout = 60
    result = execute_harness(code, language=language, timeout=timeout, description=description)
    saved = ""
    if ctx.vuln_id:
        path = write_harness_code(ctx.project_id, int(ctx.vuln_id), code, language=language)
        saved = str(path.name)
        result["harness_path"] = f"vulns/{int(ctx.vuln_id)}/{saved}"
    result["language"] = language
    if description:
        result["description"] = description
    if not result.get("ok"):
        result["hint"] = (
            "沙箱失败或 mock 起不来时不要判误报。"
            "静态已能证明默认可利用则 ConfirmVuln(evidence_level=static_only)。"
        )
    return result


def register_run_code_tool() -> None:
    registry.register(
        ToolSpec(
            name="RunCode",
            description=(
                "在隔离沙箱中执行你编写的局部验证 harness（Python/PHP/JS/Ruby/Go/Java/Bash）。"
                "仅局部验证模式可用。抽出目标函数、mock 依赖、用多种 payload 观察 stdout/stderr/退出码。"
                "脚本自身打印（标签、步骤、判定）与注释必须用英语；源码/payload/回显原文不要翻译。"
                "不要在本机 shell 跑 harness。用另一种语言复述源码不算动态证据。"
                "沙箱无网、跑完即删。失败（无 Docker、缺镜像、编译错误）不要据此误报。"
                "脚本写入 harness.py，不要把同一份 mock 写进 poc.py。"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "code": {
                        "type": "string",
                        "description": "完整可执行的测试代码，不要依赖宿主机文件（源码请内联或自行简化 mock）。",
                    },
                    "language": {
                        "type": "string",
                        "description": "python / php / javascript / ruby / go / java / bash，默认 python。",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "超时秒数，默认 60，最大 180。",
                    },
                    "description": {
                        "type": "string",
                        "description": "这段 harness 在验什么，便于日志。",
                    },
                },
                "required": ["code"],
            },
            handler=_run_code,
        )
    )


register_run_code_tool()

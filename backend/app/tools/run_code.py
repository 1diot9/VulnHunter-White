"""RunCode: execute a Reviewer-written harness in the sibling sandbox."""

from __future__ import annotations

from typing import Any

from ..dynamic_verify import project_is_harness
from ..services.harness_output import harness_output_block_reason
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
    blocked = harness_output_block_reason(code, language=language)
    if blocked:
        from ..services.runcode_feedback import annotate_run_code_result

        return annotate_run_code_result(
            {"ok": False, "error": blocked, "stdout": "", "stderr": "", "exit_code": -1},
            language=language,
            code=code,
        )
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
    return result


def register_run_code_tool() -> None:
    registry.register(
        ToolSpec(
            name="RunCode",
            description=(
                "在隔离沙箱中执行你编写的局部验证 harness（Python/PHP/JS/Ruby/Go/Java/Bash/C）。"
                "C 用 language=c（gcc + glibc）。沙箱没有 rustc / g++：不要 language=rust/c++，也不要 Bash 探测 rustc；"
                "静态已能证明则 ConfirmVuln(evidence_level=static_only)，不要据此误报。"
                "仅局部验证模式可用。抽出目标函数、mock 依赖、用多种 payload 观察 stdout/stderr/退出码。"
                "最终输出必须打印运行时实际数据（返回值、查询结果、命令回显、渲染结果、异常原文）；"
                "禁止只打印固定 SUCCESS/CONFIRMED，禁止写死 success=True / {\"success\": true}，"
                "禁止把预期回显写成字面量。判定标签可以有，但必须同时打印实际数据。"
                "脚本输出须中英双语：默认英语，必须 --zh 切中文标签/步骤/判定；注释与 --help 仍用英语；源码/payload/回显原文不要翻译。"
                "JavaScript 对照表必须用 [en, zh] 数组，禁止 (en, zh)（逗号运算符会丢掉英文，--zh 打成单字）。"
                "Java harness 默认按 JDK 8 编写（javac --release 8 -encoding UTF-8）；不要用 var/record/text block 等 9+ 语法；"
                "不要在注释里写 \\uXXXX（javac 会当 Unicode 转义）。源码可直接 UTF-8。"
                "仅当目标源码需要更高版本时在文件顶部写 // java-release: 11 或 // java-release: 17。"
                "不要在本机 shell 跑 harness。用另一种语言复述源码不算动态证据。"
                "沙箱无网、跑完即删。失败（无 Docker、缺镜像、编译错误）不要据此误报。"
                "返回含 failure_class（sandbox_unavailable/image_missing/unsupported_language/compile_error/"
                "missing_dependency/runtime_error/timeout 等）、missing（缺的包/符号）、"
                "signals、hint：按这些字段改 harness，不要只看 error 字符串。"
                "unsupported_language 时按 hint 改 static_only，系统不会为此挂起「验证确认」。"
                "其它失败连续多次后系统会 AskUser，等待用户在「验证确认」页决定继续或改为仅静态。"
                "脚本写入 harness.py，不要把同一份 mock 写进 poc.py。"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "code": {
                        "type": "string",
                        "description": (
                            "完整可执行的测试代码，不要依赖宿主机文件（源码请内联或自行简化 mock）。"
                            "必须打印 sink/抽出函数的运行时实际数据；不要只打印固定成功字段或预期回显字面量。"
                        ),
                    },
                    "language": {
                        "type": "string",
                        "description": (
                            "python / php / javascript / ruby / go / java / bash / c，默认 python。"
                            "C 用 gcc。没有 rust / c++。java 默认 JDK 8 + UTF-8；更高版本须在源码顶部写 // java-release: 11 或 // java-release: 17。"
                        ),
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

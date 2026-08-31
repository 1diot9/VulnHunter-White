"""ListBytecode + DecompileJava tools."""

from __future__ import annotations

from typing import Any

from ..services.decompile_java import (
    get_job_status,
    list_bytecode,
    mark_business_jars,
    submit_decompile,
)
from . import ToolSpec, registry
from .common import call_fail


def _list_handler(ctx, args: dict[str, Any]) -> dict[str, Any]:
    include_build = bool(args.get("include_build_dirs"))
    if include_build and (getattr(ctx, "role", None) or "") != "recon":
        return call_fail("include_build_dirs=true 仅 recon 可用")
    try:
        limit = int(args.get("limit") or 200)
    except (TypeError, ValueError):
        limit = 200
    files = list_bytecode(ctx.project_id, include_build_dirs=include_build, limit=max(1, min(limit, 500)))
    return {
        "ok": True,
        "count": len(files),
        "files": files,
        "hint": (
            "无字节码则无需 DecompileJava / MarkBusinessJar。"
            if not files
            else (
                "对需要纳入定权与启发式挖掘的业务 jar 调用 MarkBusinessJar(paths=[...])；"
                "仅临时阅读用 DecompileJava（不入定权）。"
                "third_party_likely 仅为提示，勿把 spring/ant 等点进 MarkBusinessJar。"
            )
        ),
    }


def _decompile_handler(ctx, args: dict[str, Any]) -> dict[str, Any]:
    job_id = str(args.get("job_id") or "").strip()
    path = str(args.get("path") or args.get("source") or "").strip()
    class_name = str(args.get("class_name") or "").strip()
    package = str(args.get("package") or "").strip()
    force = bool(args.get("force"))
    reason = str(args.get("reason") or "").strip()

    if job_id and not path:
        st = get_job_status(ctx.project_id, job_id=job_id)
        if not st:
            return call_fail(f"未知 job_id: {job_id}")
        return st

    if not path:
        return call_fail("缺少 path（src/ 下 .class/.jar/.war）或 job_id")

    if force and not reason and False:
        # reason optional but recommended for third-party; enforced in service when third_party
        pass

    result = submit_decompile(
        ctx.project_id,
        path,
        class_name=class_name,
        package=package,
        force=force,
        reason=reason,
    )
    jid = result.get("job_id")
    if jid:
        watched = ctx.state.setdefault("decompile_jobs", [])
        if isinstance(watched, list) and jid not in watched:
            watched.append(jid)
    return result


def _mark_business_jar_handler(ctx, args: dict[str, Any]) -> dict[str, Any]:
    if (getattr(ctx, "role", None) or "") != "recon":
        return call_fail("MarkBusinessJar 仅 recon（地图/鉴权）可用")
    raw_paths = args.get("paths")
    if raw_paths is None and args.get("path"):
        raw_paths = [args.get("path")]
    paths: list[str] = []
    if isinstance(raw_paths, str):
        paths = [raw_paths]
    elif isinstance(raw_paths, list):
        paths = [str(p).strip() for p in raw_paths if str(p).strip()]
    none = bool(args.get("none") or args.get("no_findings"))
    done = bool(args.get("done") or args.get("complete"))
    note = str(args.get("note") or args.get("reason") or "").strip()
    result = mark_business_jars(
        ctx.project_id,
        paths,
        none=none,
        done=done,
        note=note,
    )
    for item in result.get("decompile") or []:
        jid = item.get("job_id")
        if jid:
            watched = ctx.state.setdefault("decompile_jobs", [])
            if isinstance(watched, list) and jid not in watched:
                watched.append(jid)
    return result


def register_decompile_tools() -> None:
    registry.register(
        ToolSpec(
            name="ListBytecode",
            description=(
                "枚举项目 src/ 下的 .class / .jar / .war（普通 Glob 会跳过这些后缀）。"
                "默认仍跳过 target/build/dist 等构建目录；仅 recon 可 include_build_dirs=true。"
                "无结果则本项目无需反编译。"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "include_build_dirs": {
                        "type": "boolean",
                        "description": "是否包含 target/build/dist（仅 recon；默认 false）",
                    },
                    "limit": {"type": "integer", "description": "最多返回条数，默认 200"},
                },
            },
            handler=_list_handler,
            parallel_safe=True,
        )
    )
    registry.register(
        ToolSpec(
            name="DecompileJava",
            description=(
                "用 jadx 反编译 .class/.jar/.war：索引命中立即返回 output_root；否则异步入队并立刻返回 "
                "queued/running。整包 jar 有大小上限（默认 80MiB），超限请传 class_name 或 package。"
                "第三方依赖默认拒绝，确认需要时 force=true 并附 reason。"
                "仅临时阅读，不会写入 FileWeight；纳入定权请用 MarkBusinessJar（recon）。"
                "queued 时不要反复同参轮询，去做其它工作；完成后系统会注入通知。也可用 job_id 查询。"
                "产物在 workspace/decompiled/，Grep/Glob 须显式指定 root。报告中写 jar!class + 反编译路径。"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "相对工作区路径，如 src/lib/app.jar 或 src/WEB-INF/classes/a/B.class",
                    },
                    "job_id": {"type": "string", "description": "查询已提交任务"},
                    "class_name": {
                        "type": "string",
                        "description": "仅反编译 jar 内该类（含内部类），如 com.example.Foo",
                    },
                    "package": {
                        "type": "string",
                        "description": "仅反编译 jar 内该包前缀，如 com.example.web",
                    },
                    "force": {
                        "type": "boolean",
                        "description": "强制第三方或失败重试",
                    },
                    "reason": {
                        "type": "string",
                        "description": "force 时的简短理由",
                    },
                },
            },
            handler=_decompile_handler,
            parallel_safe=True,
        )
    )
    registry.register(
        ToolSpec(
            name="MarkBusinessJar",
            description=(
                "点名要纳入定权与启发式挖掘的业务 .jar/.war/.class（仅 recon 地图轮）。"
                "可 paths 批量；无业务字节码覆盖时用 none=true；全部点完后 done=true。"
                "点名后系统自动反编译；每个 jar ready 后立刻把该类树 .java 写入 FileWeight，不必等全部完成。"
                "DecompileJava 只供临时阅读，不会入库。third_party_likely 仅供参考，勿点第三方。"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "单个 src/ 下字节码路径"},
                    "paths": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "批量点名",
                    },
                    "none": {
                        "type": "boolean",
                        "description": "声明无业务 jar 需纳入定权（仍须有字节码时慎用）",
                    },
                    "done": {
                        "type": "boolean",
                        "description": "业务 jar 已全部点名，结束本门闩",
                    },
                    "note": {"type": "string", "description": "可选简短说明"},
                },
            },
            handler=_mark_business_jar_handler,
            parallel_safe=True,
        )
    )


register_decompile_tools()

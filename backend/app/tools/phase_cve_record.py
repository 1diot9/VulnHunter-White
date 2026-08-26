"""CVE JSON record tools: ReadCveRecord, SetCveRecordField."""

from __future__ import annotations

from typing import Any

from ..models import SessionLocal, Vuln
from ..services.cve_record import (
    cve_record_status,
    ensure_cve_record,
    format_cve_record_json,
    set_cve_field,
)
from . import ToolSpec, registry
from .common import call_fail


def _resolve_vuln_id(ctx, args: dict[str, Any]) -> tuple[int | None, dict[str, Any] | None]:
    raw = args.get("vuln_id") or ctx.vuln_id
    if raw in (None, ""):
        return None, call_fail("缺少 vuln_id")
    try:
        vuln_id = int(raw)
    except (TypeError, ValueError):
        return None, call_fail("vuln_id 须为整数")
    with SessionLocal() as db:
        vuln = db.get(Vuln, vuln_id)
        if not vuln or vuln.project_id != ctx.project_id:
            return None, call_fail(f"漏洞 {vuln_id} 不存在或不属于本项目")
    return vuln_id, None


def _read_cve_record(ctx, args: dict[str, Any]) -> dict[str, Any]:
    vuln_id, err = _resolve_vuln_id(ctx, args)
    if err:
        return err
    assert vuln_id is not None
    ensure_cve_record(ctx.project_id, vuln_id)
    status = cve_record_status(ctx.project_id, vuln_id)
    out: dict[str, Any] = {
        "ok": True,
        "vuln_id": vuln_id,
        "placeholder": status["placeholder"],
        "fields": status["fields"],
        "required_pending": status["required_pending"],
        "all_required_filled": status["all_required_filled"],
        "message": (
            "使用 SetCveRecordField 逐字段写入；无法确定的字段保持占位符 "
            f"{status['placeholder']}，不要直接 Write 整份 cve.json。"
            " descriptions[0].value 须为英文详述（产品/版本、根因、入口→sink 链路、"
            "漏洞代码完整路径与源码原文、完整 HTTP 请求包或无 HTTP 面时的 API/调用链、危害），"
            "supportingMedia 用 HTML（漏洞代码与 PoC 放 <pre>）。"
        ),
    }
    if args.get("include_record"):
        out["record"] = format_cve_record_json(ctx.project_id, vuln_id)
    return out


def _set_cve_record_field(ctx, args: dict[str, Any]) -> dict[str, Any]:
    vuln_id, err = _resolve_vuln_id(ctx, args)
    if err:
        return err
    assert vuln_id is not None
    path = str(args.get("path") or "").strip()
    if not path:
        return call_fail("缺少 path")
    if "value" not in args:
        return call_fail("缺少 value")
    result = set_cve_field(ctx.project_id, vuln_id, path, args.get("value"))
    if not result.get("ok"):
        return result
    status = cve_record_status(ctx.project_id, vuln_id)
    return {
        **result,
        "vuln_id": vuln_id,
        "required_pending": status["required_pending"],
        "all_required_filled": status["all_required_filled"],
    }


registry.register(
    ToolSpec(
        name="ReadCveRecord",
        description=(
            "读取漏洞 CVE JSON（templates/cve.json）中需要 Agent 填写的字段及当前值。"
            "无法确定的字段应保留统一占位符，不要直接生成整份 JSON。"
        ),
        parameters={
            "type": "object",
            "properties": {
                "vuln_id": {
                    "type": "integer",
                    "description": "漏洞 ID。Reviewer 审核轮可省略，默认当前漏洞。",
                },
                "include_record": {
                    "type": "boolean",
                    "description": "为 true 时额外返回完整 cve.json 文本（默认 false，避免过长）。",
                },
            },
        },
        handler=_read_cve_record,
    )
)

registry.register(
    ToolSpec(
        name="SetCveRecordField",
        description=(
            "写入 CVE JSON 的单个字段（路径见 ReadCveRecord）。"
            "descriptions[0].value 须含漏洞链路、漏洞代码（完整路径+源码）与 HTTP/API PoC，不要一句话摘要。"
            "仅可写预定义字段；未知信息请传统一占位符，不要 Write 整份 cve.json。"
        ),
        parameters={
            "type": "object",
            "properties": {
                "vuln_id": {
                    "type": "integer",
                    "description": "漏洞 ID。Reviewer 审核轮可省略。",
                },
                "path": {
                    "type": "string",
                    "description": "字段路径，如 containers.cna.descriptions[0].value",
                },
                "value": {
                    "description": "字段值（字符串、数字、布尔或 JSON 结构）",
                },
            },
            "required": ["path", "value"],
        },
        handler=_set_cve_record_field,
    )
)

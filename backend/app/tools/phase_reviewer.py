"""Reviewer tools: ConfirmVuln, ReturnToWorker."""

from __future__ import annotations

from typing import Any

from ..config import settings
from ..models import SessionLocal, Vuln
from ..services.paths import vuln_dir
from ..services.report import upsert_report_section
from ..vuln_types import (
    REVIEW_FACTOR_LABELS,
    SEVERITY_LABELS,
    SeverityCalibration,
    calibrate_review_severity,
)
from . import ToolSpec, registry

_FP_HEADING = "## 误报判定"
_REVIEW_HEADING = "## 审核标注"

_SURFACE_ALIASES = {
    "frontend": "frontend",
    "前台": "frontend",
    "public": "frontend",
    "unauth": "frontend",
    "unauthenticated": "frontend",
    "none": "frontend",
    "backend": "backend",
    "后台": "backend",
    "auth": "backend",
    "authenticated": "backend",
}
_ACCOUNT_ALIASES = {
    "user": "user",
    "普通": "user",
    "普通权限": "user",
    "普通账号": "user",
    "普通用户": "user",
    "regular": "user",
    "admin": "admin",
    "管理员": "admin",
    "管理员账号": "admin",
    "administrator": "admin",
}
_SURFACE_LABELS = {"frontend": "前台", "backend": "后台"}
_ACCOUNT_LABELS = {"user": "普通权限", "admin": "管理员"}


def _alias_key(raw: Any) -> str:
    s = str(raw or "").strip()
    for suffix in ("漏洞", "账号"):
        if s.endswith(suffix) and len(s) > len(suffix):
            s = s[: -len(suffix)].strip()
    return s.lower() if s.isascii() else s


def _normalize_attack_surface(raw: Any) -> str | None:
    return _SURFACE_ALIASES.get(_alias_key(raw))


def _normalize_required_account(raw: Any) -> str | None:
    key = _alias_key(raw)
    if not key:
        return None
    return _ACCOUNT_ALIASES.get(key)


def _review_label_body(
    surface: str,
    account: str | None,
    calibration: SeverityCalibration,
    previous_severity: str,
) -> str:
    lines = [f"- 攻击面：{_SURFACE_LABELS[surface]}"]
    if surface == "backend" and account:
        lines.append(f"- 所需账号：{_ACCOUNT_LABELS[account]}")
    previous_label = SEVERITY_LABELS.get(previous_severity, previous_severity)
    lines.extend(
        [
            f"- 严重度：{calibration.severity_label}（{calibration.severity}）",
            f"- 原始类型映射严重度：{previous_label}（{previous_severity}）",
            f"- 校准得分：{calibration.score}",
            f"- 可达性：{REVIEW_FACTOR_LABELS['reachability'][calibration.reachability]}",
            f"- 影响范围：{REVIEW_FACTOR_LABELS['impact'][calibration.impact]}",
            f"- 利用复杂度：{REVIEW_FACTOR_LABELS['exploit_complexity'][calibration.exploit_complexity]}",
            f"- 防护状态：{REVIEW_FACTOR_LABELS['defense_status'][calibration.defense_status]}",
        ]
    )
    return "\n".join(lines)


def _append_false_positive_reason(project_id: int, vuln_id: int, reason: str) -> None:
    upsert_report_section(vuln_dir(project_id, vuln_id) / "report.md", _FP_HEADING, reason.strip())


def _commit_false_positive(ctx, db, vuln: Vuln, vuln_id: int, reason: str, message: str) -> dict[str, Any]:
    vuln.status = "false_positive"
    vuln.return_reason = reason
    _append_false_positive_reason(vuln.project_id, int(vuln_id), reason)
    db.commit()
    ctx.state["review_done"] = True
    ctx.state["review_verdict"] = "false_positive"
    return {"ok": True, "vuln_id": int(vuln_id), "status": "false_positive", "message": message}


def _confirm_vuln(ctx, args: dict[str, Any]) -> dict[str, Any]:
    vuln_id = args.get("vuln_id") or ctx.vuln_id
    if not vuln_id:
        return {"ok": False, "error": "缺少 vuln_id"}
    evidence = (args.get("evidence_level") or "dynamic").strip()
    if evidence not in ("dynamic", "static_only", "mcp"):
        return {"ok": False, "error": "evidence_level 须为 dynamic|static_only|mcp"}
    surface = _normalize_attack_surface(args.get("attack_surface"))
    if not surface:
        return {"ok": False, "error": "必须标注 attack_surface=frontend|backend（前台/后台）"}
    account = _normalize_required_account(args.get("required_account"))
    if surface == "backend":
        if not account:
            return {"ok": False, "error": "后台漏洞必须标注 required_account=user|admin（普通权限/管理员）"}
    else:
        account = None
    try:
        calibration = calibrate_review_severity(
            attack_surface=surface,
            required_account=account,
            impact=args.get("impact"),
            exploit_complexity=args.get("exploit_complexity"),
            defense_status=args.get("defense_status"),
        )
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}
    note = args.get("note") or ""
    with SessionLocal() as db:
        vuln = db.get(Vuln, int(vuln_id))
        if not vuln or vuln.project_id != ctx.project_id:
            return {"ok": False, "error": "漏洞不存在"}
        previous_severity = vuln.severity
        if vuln.intended_behavior and evidence != "static_only":
            # still allow confirm but flag
            pass
        if evidence == "static_only":
            vuln.status = "static_only"
        else:
            vuln.status = "confirmed"
        vuln.evidence_level = evidence
        vuln.attack_surface = surface
        vuln.required_account = account
        vuln.severity = calibration.severity
        if note:
            vuln.return_reason = None
        upsert_report_section(
            vuln_dir(vuln.project_id, int(vuln_id)) / "report.md",
            _REVIEW_HEADING,
            _review_label_body(surface, account, calibration, previous_severity),
        )
        db.commit()
        status = vuln.status
    ctx.state["review_done"] = True
    ctx.state["review_verdict"] = status
    out: dict[str, Any] = {
        "ok": True,
        "vuln_id": int(vuln_id),
        "status": status,
        "evidence_level": evidence,
        "attack_surface": surface,
        "attack_surface_label": _SURFACE_LABELS[surface],
        "required_account": account,
        "severity": calibration.severity,
        "severity_label": calibration.severity_label,
        "severity_score": calibration.score,
    }
    if account:
        out["required_account_label"] = _ACCOUNT_LABELS[account]
    return out


def _return_to_worker(ctx, args: dict[str, Any]) -> dict[str, Any]:
    vuln_id = args.get("vuln_id") or ctx.vuln_id
    reason = (args.get("reason") or args.get("failure_reason") or "").strip()
    if not vuln_id:
        return {"ok": False, "error": "缺少 vuln_id"}
    if not reason:
        return {"ok": False, "error": "打回必须附带失败原因 reason"}
    false_positive = bool(args.get("false_positive") or args.get("is_false_positive"))
    with SessionLocal() as db:
        vuln = db.get(Vuln, int(vuln_id))
        if not vuln or vuln.project_id != ctx.project_id:
            return {"ok": False, "error": "漏洞不存在"}
        if false_positive or vuln.intended_behavior:
            return _commit_false_positive(ctx, db, vuln, vuln_id, reason, "已判误报")
        vuln.review_rounds = int(vuln.review_rounds or 0) + 1
        if vuln.review_rounds > settings.max_review_rejects:
            fp_reason = f"超过最大打回次数({settings.max_review_rejects}): {reason}"
            return _commit_false_positive(ctx, db, vuln, vuln_id, fp_reason, "超过打回上限，判为误报")
        vuln.status = "returned"
        vuln.return_reason = reason
        db.commit()
        rounds = vuln.review_rounds
    ctx.state["review_done"] = True
    ctx.state["review_verdict"] = "returned"
    ctx.state["return_vuln_id"] = int(vuln_id)
    return {
        "ok": True,
        "vuln_id": int(vuln_id),
        "status": "returned",
        "review_rounds": rounds,
        "message": "已打回 Worker 修改",
    }


def register_reviewer_tools() -> None:
    registry.register(
        ToolSpec(
            name="ConfirmVuln",
            description=(
                "确认漏洞，并按审核证据校准最终严重度。"
                "必须标注 attack_surface=frontend|backend（前台/后台）；"
                "后台漏洞必须再标 required_account=user|admin（普通权限账号/管理员账号）。"
                "evidence_level=static_only|dynamic|mcp。"
                "还必须标注 impact、exploit_complexity、defense_status。"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "vuln_id": {"type": "integer"},
                    "evidence_level": {
                        "type": "string",
                        "description": "dynamic | static_only | mcp，默认 dynamic",
                    },
                    "attack_surface": {
                        "type": "string",
                        "description": "必填。frontend=前台，backend=后台。也可写中文：前台 / 后台",
                    },
                    "required_account": {
                        "type": "string",
                        "description": "后台必填。user=普通权限账号，admin=管理员账号。也可写中文：普通权限 / 管理员",
                    },
                    "impact": {
                        "type": "string",
                        "description": (
                            "必填。影响范围：rce_or_full_data=RCE/全库/完整控制；"
                            "sensitive_data_or_privilege=敏感数据/权限提升/部分数据；"
                            "limited_info=有限信息泄露/信息收集。也可写中文。"
                        ),
                    },
                    "exploit_complexity": {
                        "type": "string",
                        "description": (
                            "必填。利用复杂度：single_request=单请求/简单；"
                            "multi_step=多步骤；specific_environment=依赖特定环境。也可写中文。"
                        ),
                    },
                    "defense_status": {
                        "type": "string",
                        "description": (
                            "必填。防护状态：none=无有效防护；bypassable=有防护但可绕过；"
                            "conditional=有防护且绕过需额外条件。也可写中文。"
                        ),
                    },
                    "note": {"type": "string"},
                },
                "required": [
                    "attack_surface",
                    "impact",
                    "exploit_complexity",
                    "defense_status",
                ],
            },
            handler=_confirm_vuln,
        )
    )
    registry.register(
        ToolSpec(
            name="ReturnToWorker",
            description="打回 Worker 修改报告，或直接判误报",
            parameters={
                "type": "object",
                "properties": {
                    "vuln_id": {"type": "integer"},
                    "reason": {"type": "string"},
                    "failure_reason": {"type": "string"},
                    "false_positive": {"type": "boolean"},
                },
            },
            handler=_return_to_worker,
        )
    )


register_reviewer_tools()

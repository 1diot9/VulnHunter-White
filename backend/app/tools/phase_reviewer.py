"""Reviewer tools: ConfirmVuln, MergeIntoVuln, MarkFalsePositive, ReturnToWorker, FinishLab."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from ..audit_mode import AUDIT_MODE_BOUNTY, bounty_confirm_block_reason, normalize_audit_mode
from ..config import settings
from ..dynamic_verify import (
    EVIDENCE_DYNAMIC,
    EVIDENCE_MCP,
    EVIDENCE_STATIC,
    VERIFY_MODE_LAB,
    VERIFY_MODE_OFF,
    coerce_evidence_level,
    normalize_evidence_level,
    project_verify_mode,
    static_after_review_timeouts,
)
from ..models import Project, SessionLocal, Vuln
from ..services.cli_tool_index import search_cli_tools
from ..services.affected_locations import (
    append_affected_locations,
    location_from_vuln,
    parse_locations,
)
from ..services.asset_proof import (
    apply_asset_proof,
    collect_lab_fingerprints,
    maybe_enrich_asset_proof,
    upgrade_project_fingerprints,
)
from ..services.lab import (
    clear_lab_bring_up_failed,
    lab_bring_up_failed,
    lab_ready,
    load_env,
    mark_lab_bring_up_failed,
    mark_lab_setup_finished,
)
from ..services.paths import vuln_dir
from ..services.poc_run import resolve_lab_target_url, verify_landed_poc
from ..services.poc_script import poc_cli_block_reason, read_poc_code, write_harness_code, write_poc_code
from ..services.report import upsert_report_section, write_advisory_md
from ..services.duplicate_guard import soft_duplicate_gate
from ..services.root_cause import (
    canonical_root_cause_key,
    mismatched_root_cause_key_error,
    stamp_root_cause_on_parent,
)
from ..vuln_types import (
    REVIEW_FACTOR_LABELS,
    SeverityCalibration,
    SubmissionTierDecision,
    calibrate_review_severity,
    config_premise_label,
    normalize_config_premise,
    normalize_root_cause_key,
    normalize_submission_decision,
)
from . import ToolSpec, registry
from .common import call_fail

_FP_HEADING = "## 误报判定"
_REVIEW_HEADING = "## 审核标注"
_MERGE_OK_TARGET = frozenset({"pending_review", "confirmed", "static_only"})

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
    submission: SubmissionTierDecision,
    config_premise: str | None = None,
) -> str:
    lines = [f"- 攻击面：{_SURFACE_LABELS[surface]}"]
    if surface == "backend" and account:
        lines.append(f"- 所需账号：{_ACCOUNT_LABELS[account]}")
    premise_label = config_premise_label(config_premise)
    if premise_label:
        lines.append(f"- 配置前提：{premise_label}")
    lines.extend(
        [
            f"- 严重度：{calibration.severity_label}（{calibration.severity}）",
            f"- 校准得分：{calibration.score}",
            f"- 可达性：{REVIEW_FACTOR_LABELS['reachability'][calibration.reachability]}",
            f"- 影响范围：{REVIEW_FACTOR_LABELS['impact'][calibration.impact]}",
            f"- 利用复杂度：{REVIEW_FACTOR_LABELS['exploit_complexity'][calibration.exploit_complexity]}",
            f"- 防护状态：{REVIEW_FACTOR_LABELS['defense_status'][calibration.defense_status]}",
            f"- 价值分层：{submission.tier_label}（{submission.tier}）",
            f"- 分层理由：{submission.reason}",
        ]
    )
    if submission.root_cause_key:
        lines.append(f"- 根因合并键：{submission.root_cause_key}")
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


def _check_surface_match(target: Vuln, args: dict[str, Any]) -> str | None:
    """If target already has attack_surface, require matching declaration in args."""
    if not (target.attack_surface or "").strip():
        return None
    surface = _normalize_attack_surface(args.get("attack_surface"))
    if not surface:
        return (
            f"目标 #{target.id} 已标注 attack_surface={target.attack_surface}，"
            "MergeIntoVuln 须传入相同的 attack_surface 声明一致"
        )
    if surface != target.attack_surface:
        return (
            f"攻击面不一致：目标为 {target.attack_surface}，传入为 {surface}；"
            "危害/鉴权不同请单独 Confirm，不要并入"
        )
    if surface == "backend":
        account = _normalize_required_account(args.get("required_account"))
        if target.required_account:
            if not account:
                return (
                    f"目标 #{target.id} 已标注 required_account={target.required_account}，"
                    "须传入相同的 required_account"
                )
            if account != target.required_account:
                return (
                    f"所需账号不一致：目标为 {target.required_account}，传入为 {account}；"
                    "不要并入"
                )
    return None


def _resolve_merge_locations(
    args: dict[str, Any], sources: list[Vuln]
) -> tuple[list[dict[str, Any]], str | None]:
    raw = args.get("locations")
    if raw is not None:
        return parse_locations(raw)
    locs: list[dict[str, Any]] = []
    for src in sources:
        loc = location_from_vuln(src)
        if loc:
            locs.append(loc)
    if not locs:
        return [], "缺少 locations，且无法从源漏洞推导 file_path"
    return locs, None


def _stamp_merged(child: Vuln, parent: Vuln, root_key: str | None, reason: str) -> None:
    child.status = "merged"
    child.merged_into_id = parent.id
    child.submission_tier = None
    child.submission_reason = reason
    child.return_reason = reason
    if root_key:
        child.root_cause_key = root_key
        if not (parent.root_cause_key or "").strip():
            parent.root_cause_key = root_key


def _merge_into_vuln(ctx, args: dict[str, Any]) -> dict[str, Any]:
    current_id = args.get("vuln_id") or ctx.vuln_id
    if not current_id:
        return {"ok": False, "error": "缺少 vuln_id"}
    into_raw = args.get("into")
    absorb_raw = args.get("absorb")
    has_into = into_raw is not None and into_raw != ""
    has_absorb = absorb_raw is not None and absorb_raw != "" and absorb_raw != []
    if has_into == has_absorb:
        return {"ok": False, "error": "须二选一：into=主报告id 或 absorb=[兄弟id...]"}
    reason = str(args.get("reason") or args.get("submission_reason") or "同根因并入主报告").strip()
    root_key = normalize_root_cause_key(args.get("root_cause_key"))

    with SessionLocal() as db:
        current = db.get(Vuln, int(current_id))
        if not current or current.project_id != ctx.project_id:
            return {"ok": False, "error": "漏洞不存在"}
        if current.status != "pending_review":
            return {"ok": False, "error": f"仅 pending_review 可合并，当前为 {current.status}"}

        if has_into:
            parent = db.get(Vuln, int(into_raw))
            if not parent or parent.project_id != ctx.project_id:
                return {"ok": False, "error": "并入目标不存在"}
            if parent.id == current.id:
                return {"ok": False, "error": "不能并入自己"}
            if parent.status not in _MERGE_OK_TARGET:
                return {
                    "ok": False,
                    "error": (
                        "并入目标 status 须为 pending_review|confirmed|static_only，"
                        f"当前为 {parent.status}"
                    ),
                }
            if parent.vuln_type != current.vuln_type:
                return {
                    "ok": False,
                    "error": f"vuln_type 不一致：当前 {current.vuln_type}，目标 {parent.vuln_type}",
                }
            surface_err = _check_surface_match(parent, args)
            if surface_err:
                return {"ok": False, "error": surface_err}
            parent_key = (parent.root_cause_key or "").strip()
            if parent_key:
                if root_key and canonical_root_cause_key(root_key) != canonical_root_cause_key(
                    parent_key
                ):
                    return {
                        "ok": False,
                        "error": f"须原样复用目标 root_cause_key={parent_key}，不要另写新键",
                    }
                root_key = parent_key
            elif not root_key:
                root_key = normalize_root_cause_key(current.root_cause_key)
            locations, loc_err = _resolve_merge_locations(args, [current])
            if loc_err:
                return {"ok": False, "error": loc_err}
            report_path = vuln_dir(ctx.project_id, parent.id) / "report.md"
            stats = append_affected_locations(report_path, locations)
            _stamp_merged(current, parent, root_key, reason)
            db.commit()
            ctx.state["review_done"] = True
            ctx.state["review_verdict"] = "merged"
            return {
                "ok": True,
                "vuln_id": current.id,
                "status": "merged",
                "merged_into_id": parent.id,
                "root_cause_key": root_key,
                **stats,
                "message": f"已将 #{current.id} 并入主报告 #{parent.id}，本会话结束",
            }

        if isinstance(absorb_raw, (int, str)):
            absorb_ids = [int(absorb_raw)]
        elif isinstance(absorb_raw, list):
            try:
                absorb_ids = [int(x) for x in absorb_raw]
            except (TypeError, ValueError):
                return {"ok": False, "error": "absorb 须为整数 id 列表"}
        else:
            return {"ok": False, "error": "absorb 须为整数 id 列表"}
        if not absorb_ids:
            return {"ok": False, "error": "absorb 不能为空"}
        if current.id in absorb_ids:
            return {"ok": False, "error": "absorb 不能包含当前漏洞自身"}

        siblings: list[Vuln] = []
        for sid in absorb_ids:
            sib = db.get(Vuln, sid)
            if not sib or sib.project_id != ctx.project_id:
                return {"ok": False, "error": f"absorb 目标 #{sid} 不存在"}
            if sib.status != "pending_review":
                return {
                    "ok": False,
                    "error": f"absorb 目标 #{sid} 须为 pending_review，当前为 {sib.status}",
                }
            if sib.vuln_type != current.vuln_type:
                return {
                    "ok": False,
                    "error": f"vuln_type 不一致：当前 {current.vuln_type}，#{sid} 为 {sib.vuln_type}",
                }
            siblings.append(sib)

        if not root_key:
            for item in [current, *siblings]:
                if (item.root_cause_key or "").strip():
                    root_key = item.root_cause_key
                    break
        locations, loc_err = _resolve_merge_locations(args, siblings)
        if loc_err:
            return {"ok": False, "error": loc_err}
        report_path = vuln_dir(ctx.project_id, current.id) / "report.md"
        stats = append_affected_locations(report_path, locations)
        if root_key and not (current.root_cause_key or "").strip():
            current.root_cause_key = root_key
        for sib in siblings:
            _stamp_merged(sib, current, root_key, reason)
        db.commit()
        return {
            "ok": True,
            "vuln_id": current.id,
            "status": current.status,
            "absorbed": [s.id for s in siblings],
            "root_cause_key": current.root_cause_key,
            **stats,
            "message": (
                f"已将 {len(siblings)} 条并入当前主报告 #{current.id}；"
                "请继续 ConfirmVuln 完成本条审核"
            ),
        }


def _confirm_vuln(ctx, args: dict[str, Any]) -> dict[str, Any]:
    vuln_id = args.get("vuln_id") or ctx.vuln_id
    if not vuln_id:
        return {"ok": False, "error": "缺少 vuln_id"}
    evidence_raw = str(args.get("evidence_level") or "").strip()
    if evidence_raw and normalize_evidence_level(evidence_raw) is None:
        return {"ok": False, "error": "evidence_level 须为 dynamic|static_only|mcp|harness"}
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
        submission = normalize_submission_decision(
            submission_tier=args.get("submission_tier"),
            submission_reason=args.get("submission_reason"),
            root_cause_key=args.get("root_cause_key"),
        )
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}
    config_premise = None
    if args.get("config_premise") not in (None, ""):
        try:
            config_premise = normalize_config_premise(args.get("config_premise"))
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}
    note = args.get("note") or ""
    poc_code = args.get("poc_code")
    advisory_md = args.get("advisory_md")
    harness_code = args.get("harness_code")
    harness_language = str(args.get("harness_language") or "python").strip() or "python"
    stored_poc = ""
    verify_mode = VERIFY_MODE_OFF
    evidence = EVIDENCE_STATIC
    if poc_code:
        poc_blocked = poc_cli_block_reason(str(poc_code))
        if poc_blocked:
            return {"ok": False, "error": poc_blocked}
    with SessionLocal() as db:
        vuln = db.get(Vuln, int(vuln_id))
        if not vuln or vuln.project_id != ctx.project_id:
            return {"ok": False, "error": "漏洞不存在"}
        if vuln.status == "merged":
            return {"ok": False, "error": "该漏洞已并入其他报告，不能 Confirm"}
        proj = db.get(Project, ctx.project_id)
        stored_poc = vuln.poc_code or ""
        verify_mode = project_verify_mode(proj)
        if static_after_review_timeouts(vuln.review_timeout_streak) or lab_bring_up_failed(
            ctx.project_id
        ):
            verify_mode = VERIFY_MODE_OFF
        evidence = coerce_evidence_level(evidence_raw, mode=verify_mode)
        audit_mode = normalize_audit_mode(None if not proj else proj.audit_mode)
        if audit_mode == AUDIT_MODE_BOUNTY:
            blocked = bounty_confirm_block_reason(
                vuln_type=str(vuln.vuln_type or ""),
                submission_tier=submission.tier,
                file_path=str(vuln.file_path or ""),
                impact=calibration.impact,
            )
            if blocked:
                return {"ok": False, "error": blocked}
        if submission.tier == "duplicate_grouped":
            siblings = (
                db.query(Vuln)
                .filter(Vuln.project_id == vuln.project_id, Vuln.id != vuln.id)
                .all()
            )
            probe = SimpleNamespace(
                id=vuln.id,
                project_id=vuln.project_id,
                vuln_type=vuln.vuln_type,
                file_path=vuln.file_path,
                submission_tier="duplicate_grouped",
                status=vuln.status,
                root_cause_key=submission.root_cause_key,
                severity_score=vuln.severity_score,
            )
            reused = mismatched_root_cause_key_error(probe, siblings, submission.root_cause_key)
            if reused:
                return {"ok": False, "error": reused}
        soft_file = str(vuln.file_path or "")
        soft_type = str(vuln.vuln_type or "")
        soft_root = submission.root_cause_key or normalize_root_cause_key(vuln.root_cause_key)

    soft = soft_duplicate_gate(
        ctx,
        args,
        tool="ConfirmVuln",
        file_path=soft_file,
        vuln_type=soft_type,
        root_cause_key=soft_root,
        exclude_vuln_id=int(vuln_id),
        action_hint="用 MergeIntoVuln(into=主报告id) 并入，不要 Confirm 成多份",
    )
    if soft:
        return soft

    poc_run: dict[str, Any] | None = None
    if verify_mode == VERIFY_MODE_LAB:
        landed = (str(poc_code).strip() if poc_code else "") or (
            read_poc_code(ctx.project_id, int(vuln_id), fallback=stored_poc) or ""
        )
        target = resolve_lab_target_url(ctx.project_id)
        if target:
            poc_run = verify_landed_poc(ctx.project_id, int(vuln_id), landed)
            if not poc_run.get("ok"):
                return {
                    "ok": False,
                    "error": str(poc_run.get("error") or "落盘 poc.py 未能利用成功"),
                    "target_url": poc_run.get("target_url") or target,
                    "exit_code": poc_run.get("exit_code"),
                    "stdout": poc_run.get("stdout") or "",
                    "stderr": poc_run.get("stderr") or "",
                    "hint": poc_run.get("hint") or "",
                }
            if evidence == EVIDENCE_STATIC:
                evidence = EVIDENCE_DYNAMIC
        elif evidence in (EVIDENCE_DYNAMIC, EVIDENCE_MCP):
            evidence = EVIDENCE_STATIC

    proof = maybe_enrich_asset_proof(
        ctx.project_id,
        int(vuln_id),
        fofa=args.get("fofa_fingerprint"),
        x=args.get("x_fingerprint"),
    )
    if not proof.get("ok"):
        return {"ok": False, "error": proof.get("error") or "互联网资产证明写入失败"}
    with SessionLocal() as db:
        vuln = db.get(Vuln, int(vuln_id))
        if not vuln or vuln.project_id != ctx.project_id:
            return {"ok": False, "error": "漏洞不存在"}
        if vuln.status == "merged":
            return {"ok": False, "error": "该漏洞已并入其他报告，不能 Confirm"}
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
        vuln.severity_score = calibration.score
        vuln.submission_tier = submission.tier
        vuln.submission_reason = submission.reason
        vuln.root_cause_key = submission.root_cause_key
        if config_premise:
            vuln.config_premise = config_premise
        stamp_root_cause_on_parent(db, vuln)
        if poc_code:
            vuln.poc_code = str(poc_code)
            write_poc_code(ctx.project_id, int(vuln_id), str(poc_code))
        if advisory_md not in (None, ""):
            write_advisory_md(vuln_dir(vuln.project_id, int(vuln_id)) / "advisory.md", str(advisory_md))
        if harness_code:
            write_harness_code(
                ctx.project_id,
                int(vuln_id),
                str(harness_code),
                language=harness_language,
            )
        if note:
            vuln.return_reason = None
        upsert_report_section(
            vuln_dir(vuln.project_id, int(vuln_id)) / "report.md",
            _REVIEW_HEADING,
            _review_label_body(
                surface,
                account,
                calibration,
                submission,
                config_premise=vuln.config_premise,
            ),
        )
        db.commit()
        status = vuln.status
    queued = False
    skip_reason = ""
    if surface == "frontend" and status in ("confirmed", "static_only"):
        from ..services.verifier import enqueue_frontend_vuln

        result = enqueue_frontend_vuln(ctx.project_id, int(vuln_id))
        queued = bool(result.get("queued"))
        skip_reason = str(result.get("reason") or "")
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
        "submission_tier": submission.tier,
        "submission_tier_label": submission.tier_label,
        "submission_reason": submission.reason,
        "root_cause_key": submission.root_cause_key,
        "verifier_queued": queued,
        "asset_proof_updated": bool(proof.get("updated")),
    }
    if poc_run:
        out["poc_run"] = {
            "ok": True,
            "target_url": poc_run.get("target_url"),
            "exit_code": poc_run.get("exit_code"),
            "stdout": poc_run.get("stdout") or "",
            "stderr": poc_run.get("stderr") or "",
        }
    if proof.get("fofa"):
        out["fofa_fingerprint"] = proof["fofa"]
    if proof.get("x"):
        out["x_fingerprint"] = proof["x"]
    if queued:
        out["message"] = "已确认前台漏洞，已排队 Verifier 做互联网复测"
    elif skip_reason:
        out["verifier_skip_reason"] = skip_reason
        out["message"] = f"已确认前台漏洞。未做互联网复测：{skip_reason}"
    if account:
        out["required_account_label"] = _ACCOUNT_LABELS[account]
    return out


def _collect_lab_fingerprints(ctx, args: dict[str, Any]) -> dict[str, Any]:
    collected = collect_lab_fingerprints(
        ctx.project_id,
        url=str(args.get("url") or "").strip() or None,
        path=str(args.get("path") or "").strip() or None,
    )
    if not collected.get("ok"):
        extras = {k: v for k, v in collected.items() if k not in {"ok", "error"}}
        return call_fail(str(collected.get("error") or "采集失败"), **extras)
    upgrade_project_fingerprints(ctx.project_id, collected, origin="lab")
    if not bool(args.get("apply")):
        collected["project_fingerprint_updated"] = True
        return collected
    vuln_id = args.get("vuln_id") or ctx.vuln_id
    if not vuln_id:
        return call_fail("apply=true 时缺少 vuln_id")
    with SessionLocal() as db:
        vuln = db.get(Vuln, int(vuln_id))
        if not vuln or vuln.project_id != ctx.project_id:
            return call_fail("漏洞不存在")
        if vuln.status not in ("pending_review", "returned", "static_only") and not (
            vuln.status == "confirmed" and (vuln.evidence_level or "") == "static_only"
        ):
            return call_fail(
                f"仅 pending_review/returned/static_only 可回写资产证明，当前为 {vuln.status}"
            )
    applied = apply_asset_proof(
        ctx.project_id,
        int(vuln_id),
        fofa=args.get("fofa_fingerprint") or collected.get("fofa"),
        x=args.get("x_fingerprint") or collected.get("x"),
    )
    if not applied.get("ok"):
        return call_fail(str(applied.get("error") or "写入失败"))
    collected["applied"] = True
    collected["path"] = applied["path"]
    collected["fofa"] = applied["fofa"]
    collected["x"] = applied["x"]
    upgrade_project_fingerprints(ctx.project_id, collected, origin="lab")
    collected["message"] = f"已写入 {applied['path']} 的「互联网资产证明」，并升级项目共享指纹"
    return collected


def _mark_false_positive(ctx, args: dict[str, Any]) -> dict[str, Any]:
    vuln_id = args.get("vuln_id") or ctx.vuln_id
    reason = (args.get("reason") or args.get("failure_reason") or "").strip()
    if not vuln_id:
        return {"ok": False, "error": "缺少 vuln_id"}
    if not reason:
        return {"ok": False, "error": "误报必须附带原因 reason"}
    with SessionLocal() as db:
        vuln = db.get(Vuln, int(vuln_id))
        if not vuln or vuln.project_id != ctx.project_id:
            return {"ok": False, "error": "漏洞不存在"}
        return _commit_false_positive(ctx, db, vuln, vuln_id, reason, "已判误报")


def _return_to_worker(ctx, args: dict[str, Any]) -> dict[str, Any]:
    vuln_id = args.get("vuln_id") or ctx.vuln_id
    reason = (args.get("reason") or args.get("failure_reason") or "").strip()
    if not vuln_id:
        return {"ok": False, "error": "缺少 vuln_id"}
    if not reason:
        return {"ok": False, "error": "打回必须附带失败原因 reason"}
    if bool(args.get("false_positive") or args.get("is_false_positive")):
        return _mark_false_positive(ctx, args)
    with SessionLocal() as db:
        vuln = db.get(Vuln, int(vuln_id))
        if not vuln or vuln.project_id != ctx.project_id:
            return {"ok": False, "error": "漏洞不存在"}
        if vuln.intended_behavior:
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
        "message": "已打回 Worker 补分析债务",
    }


def _finish_lab(ctx, args: dict[str, Any]) -> dict[str, Any]:
    skipped = bool(args.get("skipped"))
    reason = str(args.get("reason") or args.get("notes") or "").strip()
    env = load_env(ctx.project_id)
    bringup = str(ctx.phase or "") in ("reviewer-lab-bringup", "reviewer_lab_bringup")
    if not skipped and not lab_ready(env):
        return call_fail(
            "靶场尚未 accepted=true 且 status=running。先启动 Docker 并 Write env/env.json，"
            "或 FinishLab(skipped=true, reason=无法搭建的原因)"
        )
    if bringup and skipped:
        env = mark_lab_bring_up_failed(
            ctx.project_id,
            reason=reason or "拉起轮 FinishLab(skipped)",
            via="FinishLab-bringup",
        )
    else:
        if bringup and not skipped:
            clear_lab_bring_up_failed(ctx.project_id)
        env = mark_lab_setup_finished(
            ctx.project_id,
            skipped=skipped,
            notes=reason or None,
            via="FinishLab-bringup" if bringup else "FinishLab",
        )
    ctx.state["lab_done"] = True
    return {
        "ok": True,
        "skipped": skipped,
        "lab_ready": lab_ready(env),
        "lab_doc_path": "docs/lab.md",
        "setup_finished": True,
        "bring_up_failed": bool(env.get("bring_up_failed")),
    }


def _search_tools(ctx, args: dict[str, Any]) -> dict[str, Any]:
    query = str(args.get("query") or args.get("search_term") or args.get("q") or "").strip()
    tools = search_cli_tools(query)
    return {
        "ok": True,
        "query": query,
        "count": len(tools),
        "tools": tools,
        "hint": (
            "空 query 列出全部已索引工具。"
            "path 是入口绝对路径，dir 是工具目录；用 Bash/PowerShell 按绝对路径执行。"
            if tools
            else "没有匹配的已索引工具。用户须在设置页 CLI 工具目录下按「一目录一工具」放置，并等待后台索引完成。"
        ),
    }


def register_reviewer_tools() -> None:
    registry.register(
        ToolSpec(
            name="SearchTools",
            description=(
                "搜索后台已索引的用户 CLI 工具（设置页目录，默认 tools/cli；一目录一工具）。"
                "返回 name、dir（工具目录）、path（入口绝对路径）、entry（相对入口）、description。"
                "空 query 列出全部已索引项。找到后用 Bash/PowerShell 按 path 绝对路径执行；"
                "不要用本工具代替确认/误报。"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "关键词，匹配名称与描述；空则列出全部已索引工具",
                    },
                    "search_term": {"type": "string"},
                },
            },
            handler=_search_tools,
            parallel_safe=True,
        )
    )
    registry.register(
        ToolSpec(
            name="ConfirmVuln",
            description=(
                "确认漏洞，并按审核证据校准最终严重度与价值分层。"
                "只确认默认/官方部署下攻击者可单独利用、且能打出可观察有害冲击的问题；"
                "不要把仅 sink 可达、靠 docker exec 种文件/组合独立写原语才成立、"
                "或项目配置/文档/.env/compose 里用户可改的默认密码弱口令标成漏洞。"
                "有服务端机密危害的源码硬编码密钥（JWT/HMAC 签名密钥、接口签名 secret、"
                "私钥、第三方 API Key 等）可以确认；"
                "前端传输混淆 AES/公开下发密钥应误报。"
                "必须标注 attack_surface=frontend|backend（前台/后台）；"
                "后台漏洞必须再标 required_account=user|admin（普通权限账号/管理员账号）。"
                "evidence_level=static_only|dynamic|mcp|harness。"
                "关闭时必须 static_only；靶场动态默认 dynamic。"
                "靶场可用时系统会执行即将落盘的 poc.py（python poc.py -u <target_url>），"
                "退出码非 0 则拒绝确认；不要用 static_only 跳过。"
                "仅当用 debug MCP 改写/调试 PoC 后复现成功才标 mcp；"
                "局部验证打通时标 harness，不要标 dynamic。"
                "还必须标注 impact、exploit_complexity、defense_status、"
                "submission_tier、submission_reason。"
                "核对 Worker 的 config_premise；错误则 Confirm 时传入纠正。"
                "specific 不含官方已明确警示会导致安全风险的配置；仅在此类开关下才成立则误报。"
                "同一根因同一危害的重复条请用 MergeIntoVuln 并入主报告，不要 Confirm 成多份；"
                "duplicate_grouped 仅留给危害/鉴权不同但仍相关的变体，且必须原样复用 root_cause_key。"
                "若与已有洞同 file_path+vuln_type 或同 root_cause_key，首次 Confirm 会提醒复查合并；"
                "确认危害/鉴权不同仍要单独确认时，再次调用并传 confirm_not_duplicate=true"
                "（仅本会话提醒过一次后才接受）。"
                "严重度只按利用上下文校准，不沿用漏洞类型。"
                "SSRF 须按观察面确认：有回显才能写可读元数据/内网正文；"
                "仅状态码/时延/报错差别只算内网端口探测，impact 用 limited_info。"
                "有漏洞环境时若项目指纹仍缺，用 CollectLabFingerprints 升级项目共享指纹，"
                "再传入 fofa_fingerprint / x_fingerprint；未传且报告仍是占位语句时会写入 docs/app-fingerprints.json 的共享指纹。"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "vuln_id": {"type": "integer"},
                    "evidence_level": {
                        "type": "string",
                        "description": (
                            "static_only | dynamic | mcp | harness。"
                            "关闭时仅 static_only；靶场动态默认 dynamic（HTTP PoC）。"
                            "靶场可用时系统会跑落盘 poc.py，失败则拒绝确认。"
                            "mcp 仅在 debug MCP 改写/调试 PoC 后复现成功时使用；"
                            "局部验证打通用 harness。"
                        ),
                    },
                    "attack_surface": {
                        "type": "string",
                        "description": "必填。frontend=前台，backend=后台。也可写中文：前台 / 后台",
                    },
                    "required_account": {
                        "type": "string",
                        "description": "后台必填。user=普通权限账号，admin=管理员账号。也可写中文：普通权限 / 管理员",
                    },
                    "config_premise": {
                        "type": "string",
                        "description": (
                            "可选。纠正配置前提：default=默认配置即可利用；"
                            "specific=须改应用自身配置才可利用。也可写中文。"
                            "官方已警示的风险配置不算 specific；仅在此类开关下才成立应误报。"
                        ),
                    },
                    "impact": {
                        "type": "string",
                        "description": (
                            "必填。影响范围：rce_or_full_data=RCE/全库/完整控制；"
                            "sensitive_data_or_privilege=敏感数据/权限提升/部分数据；"
                            "limited_info=有限信息泄露/信息收集。也可写中文。"
                            "SSRF：有回显且能读元数据/内网敏感正文用 sensitive_data_or_privilege；"
                            "仅响应差别探测内网端口用 limited_info，不要按凭据窃取。"
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
                    "submission_tier": {
                        "type": "string",
                        "description": (
                            "必填。价值分层：cve_candidate=有 CVE 价值；"
                            "low_impact=低危害难利用。"
                            "流程标记：duplicate_grouped=危害/鉴权不同的相关变体（不是并入）。"
                            "缺动态复现请用 evidence_level=static_only，不要另造价值分层。也可写中文。"
                        ),
                    },
                    "submission_reason": {
                        "type": "string",
                        "description": "必填。说明为何进入该价值分层（有无 CVE 价值、为何算低危害难利用、如何合并）。",
                    },
                    "root_cause_key": {
                        "type": "string",
                        "description": (
                            "同一根因的合并键，格式 类型:稳定锚点，如 idor:SysCommentController。"
                            "主报告与后续变体必须完全相同。"
                            "duplicate_grouped 时必填，且必须原样复用 SearchOldVuln kind=found 已有键，"
                            "禁止按接口/方法另造新键。"
                        ),
                    },
                    "confirm_not_duplicate": {
                        "type": "boolean",
                        "description": (
                            "疑似重复提醒后仍确认单独 Confirm 时传 true。"
                            "仅本会话已因同一指纹被提醒过一次后才接受；首次带上会被拒绝。"
                        ),
                    },
                    "fofa_fingerprint": {
                        "type": "string",
                        "description": (
                            "可选。写入报告「互联网资产证明」的 FOFA 语句。"
                            "有靶场时应据 CollectLabFingerprints 结果填写；禁止「或」/||。"
                        ),
                    },
                    "x_fingerprint": {
                        "type": "string",
                        "description": (
                            "可选。写入报告「互联网资产证明」的 X 情报社区资产测绘语句。"
                            "禁止「或」/||。"
                        ),
                    },
                    "poc_code": {
                        "type": "string",
                        "description": (
                            "可选。本轮改写后的完整 poc.py（CLI 形态，须含 --proxy；"
                            "有代理时 127.0.0.1 也须强制走代理；以及同链上的 payload 校准），"
                            "系统会回写 vulns/{id}/poc.py。PoC 由 Reviewer 收口，不要打回 Worker 改 PoC。"
                        ),
                    },
                    "advisory_md": {
                        "type": "string",
                        "description": (
                            "可选。英文 GitHub Advisory 填表稿，结构对齐 templates/vuln-advisory.md。"
                            "Severity/CWE 须含 CVSS 3.1 与 CVSS 4.0（基础分、严重度标签与向量字符串）。"
                            "系统会回写 vulns/{id}/advisory.md。也可本轮 Write 该文件后 Confirm。"
                        ),
                    },
                    "harness_code": {
                        "type": "string",
                        "description": (
                            "可选。局部验证的 mock/harness 源码，写入 vulns/{id}/harness.*，"
                            "不要放进 poc.py。"
                        ),
                    },
                    "harness_language": {
                        "type": "string",
                        "description": "harness_code 的语言，默认 python。",
                    },
                    "note": {"type": "string"},
                },
                "required": [
                    "attack_surface",
                    "impact",
                    "exploit_complexity",
                    "defense_status",
                    "submission_tier",
                    "submission_reason",
                ],
            },
            handler=_confirm_vuln,
        )
    )
    registry.register(
        ToolSpec(
            name="CollectLabFingerprints",
            description=(
                "从当前漏洞环境采集应用指纹并**升级项目共享指纹**（docs/app-fingerprints.json），"
                "全项目只识别一次，后续漏洞复用。"
                "有 Docker 靶场或人工靶场地址时，仅当共享指纹仍缺标题/hash 才调用；"
                "apply=true 时同时写回本条 pending 报告的「互联网资产证明」。"
                "不要把漏洞路径当唯一指纹，不要编造 hash。"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "可选。须与 env.json target_url 或人工靶场说明中的地址同 origin",
                    },
                    "path": {
                        "type": "string",
                        "description": "可选。相对路径，如 /login",
                    },
                    "apply": {
                        "type": "boolean",
                        "description": "true 时把建议语句写入本条漏洞 report.md",
                    },
                    "vuln_id": {
                        "type": "integer",
                        "description": "apply 时写入的漏洞；默认本会话",
                    },
                    "fofa_fingerprint": {
                        "type": "string",
                        "description": "可选。覆盖自动建议的 FOFA 语句后再写入",
                    },
                    "x_fingerprint": {
                        "type": "string",
                        "description": "可选。覆盖自动建议的 X 情报社区语句后再写入",
                    },
                },
            },
            handler=_collect_lab_fingerprints,
        )
    )
    registry.register(
        ToolSpec(
            name="MergeIntoVuln",
            description=(
                "将同根因、同危害的重复报告并入主报告（系统追加「同根因受影响点」并关闭重复条）。"
                "二选一：into=主报告id（把当前条并入目标，当前条 status=merged，会话结束）；"
                "或 absorb=[兄弟id...]（把队列里的 pending 兄弟并入当前主报告，然后继续 ConfirmVuln）。"
                "不要用打回或误报来「合并」；不要 Write 已确认 report.md。"
                "PoC/报告包装由本轮 Reviewer 自己改，不要为此 ReturnToWorker。"
                "危害或攻击面不同时不要调用本工具。"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "vuln_id": {"type": "integer", "description": "当前审核漏洞；默认本会话"},
                    "into": {
                        "type": "integer",
                        "description": "把当前条并入该主报告 id",
                    },
                    "absorb": {
                        "type": "array",
                        "items": {"type": "integer"},
                        "description": "把这些 pending 兄弟并入当前条",
                    },
                    "locations": {
                        "type": "array",
                        "description": "可选。追加到主报告的受影响点；省略则用源漏洞 file_path:line_no",
                        "items": {
                            "type": "object",
                            "properties": {
                                "file_path": {"type": "string"},
                                "line_no": {"type": "integer"},
                                "method": {"type": "string"},
                                "note": {"type": "string"},
                            },
                        },
                    },
                    "root_cause_key": {"type": "string"},
                    "attack_surface": {
                        "type": "string",
                        "description": "目标已有攻击面时必须传入相同值声明一致",
                    },
                    "required_account": {
                        "type": "string",
                        "description": "目标已有 required_account 时必须传入相同值",
                    },
                    "reason": {"type": "string"},
                    "submission_reason": {"type": "string"},
                },
            },
            handler=_merge_into_vuln,
        )
    )
    registry.register(
        ToolSpec(
            name="MarkFalsePositive",
            description=(
                "判定误报并结束本审核会话。用于成立性不成立、赏金禁止类型、"
                "需种文件/第二个独立漏洞才成立、默认口令、前端传输混淆密钥等。"
                "不要用来改 PoC、降危害口径或合并同根因。"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "vuln_id": {"type": "integer"},
                    "reason": {"type": "string", "description": "误报原因，写入报告底部"},
                    "failure_reason": {"type": "string"},
                },
            },
            handler=_mark_false_positive,
        )
    )
    registry.register(
        ToolSpec(
            name="ReturnToWorker",
            description=(
                "仅当入口/sink/根因分析错了、需要 Worker 重新读源码补分析债务时打回。"
                "不要用来改 PoC、CLI 形态、指纹、危害口径或报告文案——那些由本轮 Reviewer Write 后 ConfirmVuln。"
                "误报请用 MarkFalsePositive。不要用打回做同根因合并。"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "vuln_id": {"type": "integer"},
                    "reason": {
                        "type": "string",
                        "description": "必须写清缺哪一块分析（错误入口/sink/根因），不要只写 PoC 跑不通",
                    },
                    "failure_reason": {"type": "string"},
                },
            },
            handler=_return_to_worker,
        )
    )
    registry.register(
        ToolSpec(
            name="FinishLab",
            description=(
                "结束独立的 Docker 靶场搭建轮。靶场已 accepted 且 running 时调用；"
                "无法搭建时 FinishLab(skipped=true, reason=...)。不要用本工具审核漏洞。"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "skipped": {
                        "type": "boolean",
                        "description": "无法搭建时为 true，本轮仍结束",
                    },
                    "reason": {
                        "type": "string",
                        "description": "跳过或备注原因",
                    },
                    "notes": {"type": "string"},
                },
            },
            handler=_finish_lab,
        )
    )


register_reviewer_tools()

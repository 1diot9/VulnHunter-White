"""Reviewer tools: ConfirmVuln, MergeIntoVuln, MarkFalsePositive, ReturnToWorker, RequestLabRebuild, FinishLab."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from ..audit_mode import bounty_confirm_block_reason, normalize_audit_mode, uses_bounty_gates
from ..config import settings
from ..dynamic_verify import (
    EVIDENCE_DYNAMIC,
    EVIDENCE_HARNESS,
    EVIDENCE_MCP,
    EVIDENCE_STATIC,
    VERIFY_MODE_HARNESS,
    VERIFY_MODE_LAB,
    VERIFY_MODE_OFF,
    coerce_evidence_level,
    is_harness_mode,
    is_lab_mode,
    normalize_evidence_level,
    project_verify_mode,
    static_after_review_timeouts,
)
from ..harness_depth import (
    HARNESS_DEPTH_INTEGRATION,
    is_integration_depth,
    parse_harness_depth,
)
from ..models import Project, SessionLocal, Vuln
from ..mining_paths import MINING_PATH_UNCONSTRAINED, normalize_mining_path
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
    append_lab_repair_record,
    clear_lab_bring_up_failed,
    handoff_lab_for_repair,
    lab_bring_up_failed,
    lab_ready,
    lab_setup_finished,
    load_env,
    mark_lab_setup_finished,
)
from ..services.paths import vuln_dir
from ..services.integration_verify import verify_landed_integration
from ..services.poc_run import resolve_lab_target_url, verify_landed_poc
from ..services.harness_output import harness_output_block_reason
from ..services.poc_script import (
    POC_CODE_TOOL_DESCRIPTION,
    find_harness_path,
    harness_language_from_path,
    poc_cli_block_reason,
    read_poc_code,
    write_harness_code,
    write_poc_code,
)
from ..services.report import (
    harness_local_section_gap,
    harness_vuln_code_gap,
    upsert_report_section,
    write_advisory_md,
)
from ..services.duplicate_guard import soft_duplicate_gate
from ..services.root_cause import (
    canonical_root_cause_key,
    mismatched_root_cause_key_error,
    stamp_root_cause_on_parent,
)
from ..target_kind import normalize_target_kind
from ..cvss31 import (
    Cvss31Error,
    Cvss31Result,
    apply_cvss31_to_cve_record,
    cvss_pr_alignment_error,
    parse_cvss31,
    stamp_advisory_cvss31,
)
from ..exposure_mode import (
    EXPOSURE_DIRECT,
    EXPOSURE_INDIRECT_CONSUMER,
    cvss_indirect_consumer_error,
    exposure_mode_label,
    indirect_attack_surface_error,
    indirect_exposure_section_gap,
    indirect_submission_tier_error,
    normalize_exposure_mode,
    parse_upstream_chain_proven,
)
from ..prompts import cvss_scoring_prompt
from ..services.cve_record import ensure_cve_record, write_cve_record
from ..vuln_types import (
    SubmissionTierDecision,
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
    cvss: Cvss31Result,
    submission: SubmissionTierDecision,
    config_premise: str | None = None,
    *,
    exposure_mode: str | None = None,
    upstream_chain_proven: bool = False,
) -> str:
    lines = [f"- 攻击面：{_SURFACE_LABELS[surface]}"]
    if surface == "backend" and account:
        lines.append(f"- 所需账号：{_ACCOUNT_LABELS[account]}")
    mode_label = exposure_mode_label(exposure_mode)
    if mode_label and exposure_mode != EXPOSURE_DIRECT:
        lines.append(f"- 暴露模式：{mode_label}（{exposure_mode}）")
        if upstream_chain_proven:
            lines.append("- 上游利用链：已在真实业务入口证明")
        else:
            lines.append("- 上游利用链：未在真实业务入口证明（评分与分层已按间接消费型约束）")
    premise_label = config_premise_label(config_premise)
    if premise_label:
        lines.append(f"- 配置前提：{premise_label}")
    lines.extend(
        [
            f"- 严重度：{cvss.severity_label}（{cvss.severity}）",
            f"- CVSS 3.1：{cvss.score:.1f}",
            f"- 评分向量：{cvss.vector}",
            f"- 价值分层：{submission.tier_label}（{submission.tier}）",
            f"- 分层理由：{submission.reason}",
        ]
    )
    if submission.root_cause_key:
        lines.append(f"- 根因合并键：{submission.root_cause_key}")
    return "\n".join(lines)


def _append_false_positive_reason(project_id: int, vuln_id: int, reason: str) -> None:
    upsert_report_section(vuln_dir(project_id, vuln_id) / "report.md", _FP_HEADING, reason.strip())


FP_KIND_TIMEOUT = "timeout"


def mark_timeout_give_up(vuln: Vuln, streak: int) -> str:
    """Stop retrying a pending review after the static timeout retry also failed."""
    reason = (
        f"审核连续超时 {int(streak)} 轮（失败后已重试一轮仍未 ConfirmVuln / MarkFalsePositive），"
        "系统停止重试并标为误报"
    )
    vuln.status = "false_positive"
    vuln.fp_kind = FP_KIND_TIMEOUT
    vuln.return_reason = reason
    vuln.review_timeout_streak = int(streak)
    _append_false_positive_reason(vuln.project_id, int(vuln.id), reason)
    return reason


def _stamp_cvss_artifacts(project_id: int, vuln_id: int, cvss: Cvss31Result) -> None:
    """Write computed CVSS 3.1 score into advisory.md and cve.json."""
    adv_path = vuln_dir(project_id, vuln_id) / "advisory.md"
    if adv_path.is_file():
        stamped = stamp_advisory_cvss31(
            adv_path.read_text(encoding="utf-8", errors="ignore"),
            cvss,
        )
        write_advisory_md(adv_path, stamped)
    record = ensure_cve_record(project_id, vuln_id)
    apply_cvss31_to_cve_record(record, cvss)
    write_cve_record(project_id, vuln_id, record)


def _commit_false_positive(ctx, db, vuln: Vuln, vuln_id: int, reason: str, message: str) -> dict[str, Any]:
    vuln.status = "false_positive"
    vuln.fp_kind = None
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


def _parse_rce_effect(raw: Any) -> bool | None:
    if raw is None or (isinstance(raw, str) and not str(raw).strip()):
        return None
    if isinstance(raw, bool):
        return raw
    s = str(raw).strip().lower()
    if s in {"1", "true", "yes", "on"}:
        return True
    if s in {"0", "false", "no", "off"}:
        return False
    raise ValueError("rce_effect 须为 true 或 false")


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
        cvss = parse_cvss31(args.get("cvss_vector"))
        submission = normalize_submission_decision(
            submission_tier=args.get("submission_tier"),
            submission_reason=args.get("submission_reason"),
            root_cause_key=args.get("root_cause_key"),
        )
    except (Cvss31Error, ValueError) as exc:
        return {"ok": False, "error": str(exc)}
    pr_mismatch = cvss_pr_alignment_error(cvss, surface, account)
    if pr_mismatch:
        return {"ok": False, "error": pr_mismatch}
    try:
        exposure_mode = normalize_exposure_mode(args.get("exposure_mode"))
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}
    upstream_chain_proven = parse_upstream_chain_proven(args.get("upstream_chain_proven"))
    if exposure_mode == EXPOSURE_INDIRECT_CONSUMER:
        cvss_indirect = cvss_indirect_consumer_error(
            cvss,
            upstream_chain_proven=upstream_chain_proven,
        )
        if cvss_indirect:
            return {"ok": False, "error": cvss_indirect}
        surface_indirect = indirect_attack_surface_error(
            surface,
            upstream_chain_proven=upstream_chain_proven,
        )
        if surface_indirect:
            return {"ok": False, "error": surface_indirect}
        tier_indirect = indirect_submission_tier_error(
            submission.tier,
            upstream_chain_proven=upstream_chain_proven,
        )
        if tier_indirect:
            return {"ok": False, "error": tier_indirect}
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
    try:
        harness_depth = parse_harness_depth(args.get("harness_depth"))
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}
    integration_setup = args.get("integration_setup")
    integration_start = str(args.get("integration_start") or "").strip()
    stored_poc = ""
    verify_mode = VERIFY_MODE_OFF
    evidence = EVIDENCE_STATIC
    prior_confirmed_harness = False
    integration_verified = False
    integration_runtime: str | None = None
    if poc_code:
        kind = normalize_target_kind(None)
        with SessionLocal() as db:
            proj = db.get(Project, ctx.project_id)
            kind = normalize_target_kind(getattr(proj, "target_kind", None) if proj else None)
        poc_blocked = poc_cli_block_reason(str(poc_code), target_kind=kind)
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
        prior_evidence = (vuln.evidence_level or "").strip().lower()
        prior_confirmed_harness = (
            prior_evidence == EVIDENCE_HARNESS and vuln.status == "confirmed"
        )
        evidence = coerce_evidence_level(
            evidence_raw,
            mode=verify_mode,
            harness_depth=harness_depth,
            integration_verified=False,
        )
        audit_mode = normalize_audit_mode(None if not proj else proj.audit_mode)
        mining_path = normalize_mining_path(None if not vuln else vuln.mining_path)
        try:
            rce_effect = _parse_rce_effect(args.get("rce_effect"))
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}
        if mining_path == MINING_PATH_UNCONSTRAINED:
            if rce_effect is None:
                return {
                    "ok": False,
                    "error": (
                        "无约束扫描产出须标注 rce_effect=true|false。"
                        "由你判定本条前台漏洞是否达成 RCE 效果（不必看 vuln_type 是否为 rce）；"
                        "true 且前台确认后路径结束，当前挖掘轮仍会跑完。"
                    ),
                }
            if rce_effect and surface != "frontend":
                return {
                    "ok": False,
                    "error": (
                        "无约束扫描结束条件只计前台可利用且达成 RCE 效果的漏洞。"
                        "后台请标 rce_effect=false。"
                    ),
                }
        if uses_bounty_gates(audit_mode=audit_mode, mining_path=mining_path):
            blocked = bounty_confirm_block_reason(
                vuln_type=str(vuln.vuln_type or ""),
                submission_tier=submission.tier,
                file_path=str(vuln.file_path or ""),
                cvss=cvss,
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
                cvss_score=vuln.cvss_score,
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
    integration_run: dict[str, Any] | None = None
    if verify_mode == VERIFY_MODE_HARNESS and is_integration_depth(harness_depth):
        landed = (str(poc_code).strip() if poc_code else "") or (
            read_poc_code(ctx.project_id, int(vuln_id), fallback=stored_poc) or ""
        )
        if not landed:
            return {"ok": False, "error": "harness_depth=integration 须提供 poc_code 或已有 poc.py"}
        report_path = vuln_dir(ctx.project_id, int(vuln_id)) / "report.md"
        report_text = (
            report_path.read_text(encoding="utf-8", errors="ignore")
            if report_path.is_file()
            else ""
        )
        local_gap = harness_local_section_gap(report_text)
        if local_gap:
            return {"ok": False, "error": local_gap}
        setup_cmds: list[str] = []
        if isinstance(integration_setup, list):
            setup_cmds = [str(x).strip() for x in integration_setup if str(x).strip()]
        elif integration_setup not in (None, ""):
            setup_cmds = [
                line.strip()
                for line in str(integration_setup).splitlines()
                if line.strip()
            ]
        integration_run = verify_landed_integration(
            ctx.project_id,
            int(vuln_id),
            landed,
            setup_commands=setup_cmds,
            start_command=integration_start,
        )
        if not integration_run.get("ok"):
            return {
                "ok": False,
                "error": str(integration_run.get("error") or "integration 验证未通过"),
                "target_url": integration_run.get("target_url"),
                "exit_code": integration_run.get("exit_code"),
                "stdout": integration_run.get("stdout") or "",
                "stderr": integration_run.get("stderr") or "",
                "hint": integration_run.get("hint") or "",
                "runtime": integration_run.get("runtime"),
            }
        integration_verified = True
        integration_runtime = str(integration_run.get("runtime") or "").strip() or None
        evidence = coerce_evidence_level(
            evidence_raw or EVIDENCE_DYNAMIC,
            mode=verify_mode,
            harness_depth=harness_depth,
            integration_verified=True,
        )
    elif verify_mode == VERIFY_MODE_LAB:
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

    # Lab follow-up from harness: do not silently downgrade when the target is unavailable.
    if prior_confirmed_harness and evidence == EVIDENCE_STATIC:
        evidence = EVIDENCE_HARNESS

    if evidence == EVIDENCE_HARNESS:
        report_path = vuln_dir(ctx.project_id, int(vuln_id)) / "report.md"
        report_text = (
            report_path.read_text(encoding="utf-8", errors="ignore")
            if report_path.is_file()
            else ""
        )
        code_gap = harness_vuln_code_gap(report_text, file_path=soft_file)
        if code_gap:
            return {"ok": False, "error": code_gap}
        check_code = str(harness_code).strip() if harness_code else ""
        check_lang = harness_language
        if not check_code:
            existing = find_harness_path(ctx.project_id, int(vuln_id))
            if existing is not None:
                check_code = existing.read_text(encoding="utf-8", errors="ignore")
                check_lang = harness_language_from_path(existing)
        if check_code:
            blocked_harness = harness_output_block_reason(check_code, language=check_lang)
            if blocked_harness:
                return {"ok": False, "error": blocked_harness}

    report_path = vuln_dir(ctx.project_id, int(vuln_id)) / "report.md"
    report_text = (
        report_path.read_text(encoding="utf-8", errors="ignore")
        if report_path.is_file()
        else ""
    )
    if exposure_mode == EXPOSURE_INDIRECT_CONSUMER:
        indirect_gap = indirect_exposure_section_gap(report_text)
        if indirect_gap:
            return {"ok": False, "error": indirect_gap}

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
        vuln.fp_kind = None
        vuln.evidence_level = evidence
        vuln.harness_depth = harness_depth
        if integration_runtime:
            vuln.integration_runtime = integration_runtime
        vuln.attack_surface = surface
        vuln.required_account = account
        vuln.exposure_mode = exposure_mode
        vuln.upstream_chain_proven = upstream_chain_proven
        vuln.severity = cvss.severity
        vuln.cvss_vector = cvss.vector
        vuln.cvss_score = cvss.score
        vuln.severity_score = None
        vuln.submission_tier = submission.tier
        vuln.submission_reason = submission.reason
        vuln.root_cause_key = submission.root_cause_key
        if config_premise:
            vuln.config_premise = config_premise
        if rce_effect is not None:
            vuln.rce_effect = rce_effect
        stamp_root_cause_on_parent(db, vuln)
        if poc_code:
            vuln.poc_code = str(poc_code)
            write_poc_code(ctx.project_id, int(vuln_id), str(poc_code))
        if advisory_md not in (None, ""):
            write_advisory_md(vuln_dir(vuln.project_id, int(vuln_id)) / "advisory.md", str(advisory_md))
        _stamp_cvss_artifacts(ctx.project_id, int(vuln_id), cvss)
        if harness_code:
            write_harness_code(
                ctx.project_id,
                int(vuln_id),
                str(harness_code),
                language=harness_language,
            )
        if note:
            vuln.return_reason = None
            vuln.fp_kind = None
        upsert_report_section(
            vuln_dir(vuln.project_id, int(vuln_id)) / "report.md",
            _REVIEW_HEADING,
            _review_label_body(
                surface,
                account,
                cvss,
                submission,
                config_premise=vuln.config_premise,
                exposure_mode=exposure_mode,
                upstream_chain_proven=upstream_chain_proven,
            ),
        )
        db.commit()
        status = vuln.status
        mining_path = normalize_mining_path(vuln.mining_path)
        surface_saved = vuln.attack_surface
    queued = False
    skip_reason = ""
    if surface == "frontend" and status in ("confirmed", "static_only"):
        from ..services.verifier import enqueue_frontend_vuln

        result = enqueue_frontend_vuln(ctx.project_id, int(vuln_id))
        queued = bool(result.get("queued"))
        skip_reason = str(result.get("reason") or "")
    ctx.state["review_done"] = True
    ctx.state["review_verdict"] = status
    unconstrained_ended = False
    if (
        mining_path == MINING_PATH_UNCONSTRAINED
        and rce_effect
        and surface_saved == "frontend"
        and status in ("confirmed", "static_only")
    ):
        from .phase_worker import mark_unconstrained_done
        from ..services.live_log import live_log

        unconstrained_ended = mark_unconstrained_done(ctx.project_id)
        if unconstrained_ended:
            live_log.system(
                ctx.project_id,
                f"无约束扫描：漏洞 #{int(vuln_id)} 经 Reviewer 判定达成前台 RCE 效果，"
                "当前挖掘轮结束后不再新开本路径",
                phase="unconstrained-worker",
            )
    out: dict[str, Any] = {
        "ok": True,
        "vuln_id": int(vuln_id),
        "status": status,
        "evidence_level": evidence,
        "attack_surface": surface,
        "attack_surface_label": _SURFACE_LABELS[surface],
        "exposure_mode": exposure_mode,
        "exposure_mode_label": exposure_mode_label(exposure_mode),
        "upstream_chain_proven": upstream_chain_proven,
        "required_account": account,
        "severity": cvss.severity,
        "severity_label": cvss.severity_label,
        "severity_score": cvss.score,
        "cvss_vector": cvss.vector,
        "submission_tier": submission.tier,
        "submission_tier_label": submission.tier_label,
        "submission_reason": submission.reason,
        "root_cause_key": submission.root_cause_key,
        "rce_effect": rce_effect,
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
    if unconstrained_ended:
        out["unconstrained_path_done"] = True
        extra = "无约束扫描路径将在当前挖掘轮结束后关闭。"
        out["message"] = f"{out['message']} {extra}" if out.get("message") else extra
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


def _request_lab_rebuild(ctx, args: dict[str, Any]) -> dict[str, Any]:
    reason = str(args.get("reason") or "").strip()
    if not reason:
        return call_fail("交回搭建必须说明靶场故障原因 reason")
    with SessionLocal() as db:
        proj = db.get(Project, ctx.project_id)
        if not proj or not is_lab_mode(project_verify_mode(proj)):
            return call_fail("仅靶场动态可交回搭建")
    if not lab_setup_finished(ctx.project_id):
        return call_fail("环境搭建轮已在进行")
    env = handoff_lab_for_repair(ctx.project_id, reason, source="reviewer")
    ctx.state["review_done"] = True
    ctx.state["review_verdict"] = "lab_rebuild"
    return {
        "ok": True,
        "setup_finished": False,
        "reason": reason,
        "message": "已标记靶场需修复，本轮审核结束，将交回环境搭建 Agent（超时计数已重置）",
    }


def _record_lab_repair(ctx, args: dict[str, Any]) -> dict[str, Any]:
    failure_reason = str(args.get("failure_reason") or args.get("reason") or "").strip()
    solution = str(args.get("solution") or args.get("fix") or "").strip()
    if not failure_reason or not solution:
        return call_fail("须同时提供 failure_reason 与 solution")
    path = append_lab_repair_record(
        ctx.project_id,
        failure_reason=failure_reason,
        solution=solution,
        source="reviewer",
    )
    return {
        "ok": True,
        "path": "docs/lab-repairs.md",
        "message": "已写入靶场修复记录，可继续漏洞审核",
    }


def _finish_lab(ctx, args: dict[str, Any]) -> dict[str, Any]:
    skipped = bool(args.get("skipped"))
    reason = str(args.get("reason") or args.get("notes") or "").strip()
    env = load_env(ctx.project_id)
    if not skipped and not lab_ready(env):
        return call_fail(
            "靶场尚未 accepted=true 且 status=running。先启动 Docker 并 Write env/env.json，"
            "或 FinishLab(skipped=true, reason=无法搭建的原因)"
        )
    if not skipped:
        clear_lab_bring_up_failed(ctx.project_id)
    env = mark_lab_setup_finished(
        ctx.project_id,
        skipped=skipped,
        notes=reason or None,
        via="FinishLab",
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
                "确认漏洞，按 CVSS 3.1 向量由系统计分，并标注价值分层。"
                "只确认默认/官方部署下攻击者可单独利用、且能打出可观察有害冲击的问题；"
                "不要把仅 sink 可达、靠 docker exec 种文件/组合独立写原语才成立、"
                "或项目配置/文档/.env/compose 里用户可改的默认密码弱口令标成漏洞。"
                "有服务端机密危害的源码硬编码密钥（JWT/HMAC 签名密钥、接口签名 secret、"
                "私钥、第三方 API Key 等）可以确认；"
                "前端传输混淆 AES/公开下发密钥应误报。"
                "必须标注 attack_surface=frontend|backend（前台/后台）；"
                "Worker 声称前台时须独立核验无认证可达，不要照抄 auth_premise；"
                "核完其实要登录则标 backend，不要硬标 frontend。"
                "后台漏洞必须再标 required_account=user|admin（普通权限账号/管理员账号）。"
                "evidence_level=static_only|dynamic|mcp|harness。"
                "关闭动态验证、或本条已因连续超时/搭建失败被强制仅静态时必须 static_only；"
                "靶场动态且未强制静态时默认 dynamic。"
                "靶场可用且未强制静态时系统会执行即将落盘的 poc.py（python poc.py -u <target_url>），"
                "退出码非 0 则拒绝确认；不要用 static_only 跳过。"
                "仅当用 debug MCP 改写/调试 PoC 后复现成功才标 mcp；"
                "局部验证打通时标 harness，不要标 dynamic；"
                "harness 确认前报告须含「### 漏洞代码」（完整文件路径 + 源码原文）。"
                "harness 必须打印运行时实际数据，禁止写死 SUCCESS/success=true 或预期回显字面量。"
                "还必须标注 cvss_vector（CVSS 3.1 基础向量，只填度量不要填分数）、"
                "submission_tier、submission_reason（分层理由须用中文）。"
                "核对 Worker 的 config_premise；错误则 Confirm 时传入纠正。"
                "specific 不含官方已明确警示会导致安全风险的配置；仅在此类开关下才成立则误报。"
                "同一根因同一危害的重复条请用 MergeIntoVuln 并入主报告，不要 Confirm 成多份；"
                "duplicate_grouped 仅留给危害/鉴权不同但仍相关的变体，且必须原样复用 root_cause_key。"
                "若与已有洞同 file_path+vuln_type 或同 root_cause_key，首次 Confirm 会提醒复查合并；"
                "确认危害/鉴权不同仍要单独确认时，再次调用并传 confirm_not_duplicate=true"
                "（仅本会话提醒过一次后才接受）。"
                "无约束扫描产出必须传 rce_effect=true|false：由你判定本条前台漏洞是否达成 RCE 效果"
                "（不必看 vuln_type 是否为 rce）；true 且前台确认后该路径结束，当前挖掘轮仍会跑完。"
                "无约束扫描产出始终走赏金闸门。"
                "严重度按 CVSS 3.1 向量由系统计分，不要手填分数，也不要按漏洞类型映射。"
                "PR 必须与 attack_surface / required_account 一致，否则拒绝确认。"
                "SSRF 须按观察面确认：有回显或外带内网信息才能写可读元数据/内网正文（二者危害同级）；"
                "仅状态码/时延/报错差别、或仅出网回调不含内网内容，只算内网端口探测，向量 C/I/A 不要按凭据窃取标 H。"
                "间接消费型（组件库/JDBC 防火墙/解析器等无直接 HTTP 入口、须上游应用传入输入）"
                "须 exposure_mode=indirect_consumer，报告「### 触发条件」须写明上游依赖，"
                "CVSS 须 AC:H 且 AV 不得为 N，未证明完整上游业务链时 C/I/A 至多一项 H、"
                "不得标 frontend/cve_candidate；harness 直调 API 不算上游链，须传 upstream_chain_proven=true 才能放宽。"
                "有漏洞环境时若项目指纹仍缺，用 CollectLabFingerprints 升级项目共享指纹，"
                "再传入 fofa_fingerprint / x_fingerprint；未传且报告仍是占位语句时会写入 docs/app-fingerprints.json 的共享指纹。"
                "\n\n"
                + cvss_scoring_prompt()
            ),
            parameters={
                "type": "object",
                "properties": {
                    "vuln_id": {"type": "integer"},
                    "evidence_level": {
                        "type": "string",
                        "description": (
                            "static_only | dynamic | mcp | harness。"
                            "关闭或强制仅静态时必须 static_only；靶场动态且未强制静态时默认 dynamic。"
                            "靶场可用且未强制静态时系统会跑落盘 poc.py，失败则拒绝确认。"
                            "mcp 仅在 debug MCP 改写/调试 PoC 后复现成功时使用；"
                            "局部验证打通用 harness；"
                            "harness 确认前报告须含「### 漏洞代码」（完整文件路径 + 源码原文）；"
                            "脚本须打印运行时实际数据，禁止写死成功字段。"
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
                    "exposure_mode": {
                        "type": "string",
                        "description": (
                            "可选，默认 direct。"
                            "indirect_consumer=间接消费型：组件本身无直接 HTTP/RPC 入口，"
                            "完整利用依赖上游业务应用把攻击者输入传入 sink（如 Druid WallFilter、JDBC 包装器）。"
                            "须写报告「### 触发条件」（上游依赖与不能直接向组件发请求），"
                            "并按间接消费型 CVSS/分层约束。"
                        ),
                    },
                    "upstream_chain_proven": {
                        "type": "boolean",
                        "description": (
                            "仅 exposure_mode=indirect_consumer 时有效。"
                            "true=已在真实业务 HTTP/API 入口打通上游→组件 sink 全链；"
                            "false=仅静态/harness 直调组件 API 证明缺陷存在。"
                            "false 时不得标 frontend/cve_candidate，CVSS 的 C/I/A 至多一项 H。"
                        ),
                    },
                    "config_premise": {
                        "type": "string",
                        "description": (
                            "可选。纠正配置前提：default=默认配置即可利用；"
                            "specific=须改应用自身配置才可利用。也可写中文。"
                            "官方已警示的风险配置不算 specific；仅在此类开关下才成立应误报。"
                        ),
                    },
                    "cvss_vector": {
                        "type": "string",
                        "description": (
                            "必填。CVSS 3.1 基础评分向量，只填度量，不要填分数。"
                            "格式 CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H。"
                            "PR 必须与 attack_surface 一致：前台 PR:N，后台 user PR:L，admin PR:H，否则拒绝。"
                            "XSS 默认 UI:R/S:C/C:L/I:L/A:N，不要因 Cookie/账户接管把 C/I 标 H。"
                            "SSRF 仅端口探测时 C/I/A 不要标成已窃取凭据（H）；"
                            "有回显或外带内网信息并读到元数据/内网正文才可将 C 标 H。"
                            "完整度量标准见本工具描述。"
                            "\n\n"
                            + cvss_scoring_prompt()
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
                        "description": (
                            "必填。用中文 1–3 句说明为何进入该价值分层"
                            "（有无 CVE 价值、为何算低危害难利用、如何合并）；"
                            "产品名/类名/CVE 编号可保留英文。"
                        ),
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
                    "rce_effect": {
                        "type": "boolean",
                        "description": (
                            "无约束扫描产出必填。本条前台漏洞是否达成 RCE 效果，由 Reviewer 判定，"
                            "不由 vuln_type 是否为 rce 决定。true 且 attack_surface=frontend 时结束该路径。"
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
                            "可选。" + POC_CODE_TOOL_DESCRIPTION
                            + "系统会回写 vulns/{id}/poc.py。PoC 由 Reviewer 收口，不要打回 Worker 改 PoC。"
                        ),
                    },
                    "advisory_md": {
                        "type": "string",
                        "description": (
                            "可选。英文 GitHub Advisory 填表稿，结构对齐 templates/vuln-advisory.md。"
                            "Severity/CWE 须含 CVSS 3.1 向量；基础分由系统按向量计算，不要手填分数。"
                            "须含 ### Vulnerable code（完整相对路径 + 源码原文）。"
                            "系统会回写 vulns/{id}/advisory.md。也可本轮 Write 该文件后 Confirm。"
                        ),
                    },
                    "harness_code": {
                        "type": "string",
                        "description": (
                            "可选。局部验证的 mock/harness 源码，写入 vulns/{id}/harness.*。"
                            "不要把内联/mock 脚本放进 poc.py，也不要复制同一套测试矩阵。"
                            "必须打印 sink/抽出函数的运行时实际数据；禁止只打印固定 SUCCESS/CONFIRMED，"
                            "禁止写死 success=True / {\"success\": true}，禁止把预期回显写成字面量。"
                            "脚本输出须中英双语：默认英语，必须 --zh 切中文；注释仍用英语。"
                        ),
                    },
                    "harness_language": {
                        "type": "string",
                        "description": "harness_code 的语言，默认 python。",
                    },
                    "harness_depth": {
                        "type": "string",
                        "description": (
                            "局部验证深度：sink（默认，函数/mock）、module（同进程模块链）、"
                            "integration（L3：系统于 integration 沙箱起 loopback 服务并跑 poc.py，"
                            "通过后 evidence_level=dynamic）。"
                            "integration 须已有报告「### 局部验证」章节，并传 integration_start；"
                            "可选 integration_setup（多行 shell 或字符串数组，如 npm ci）。"
                        ),
                    },
                    "integration_setup": {
                        "type": "string",
                        "description": (
                            "harness_depth=integration 时可选。容器内 /workspace 执行的安装命令，"
                            "多行 shell 或后续支持数组；如 npm ci。"
                        ),
                    },
                    "integration_start": {
                        "type": "string",
                        "description": (
                            "harness_depth=integration 时必填（除非已配置 env local_service_url 走 fallback）。"
                            "后台启动命令，须监听 127.0.0.1:$PORT（$PORT 由系统注入），"
                            "如：node bin/whistle.js start -p $PORT"
                        ),
                    },
                    "note": {"type": "string"},
                },
                "required": [
                    "attack_surface",
                    "cvss_vector",
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
            name="RecordLabRepair",
            description=(
                "靶场修复成功后，记录本次失效原因与解决方案到 docs/lab-repairs.md。"
                "须在验证靶场健康后、ConfirmVuln 前调用（修复交回后的首轮审核必填）。"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "failure_reason": {
                        "type": "string",
                        "description": "本次靶场失效原因（可与 RequestLabRebuild 的 reason 一致或更详）",
                    },
                    "solution": {
                        "type": "string",
                        "description": "本次如何修复（命令、配置变更、重建步骤等）",
                    },
                },
                "required": ["failure_reason", "solution"],
            },
            handler=_record_lab_repair,
        )
    )
    registry.register(
        ToolSpec(
            name="RequestLabRebuild",
            description=(
                "靶场故障时交回环境搭建 Agent：容器不存在、假就绪（404/无法登录）、"
                "依赖 sidecar 退出等。须附 reason；系统重置搭建超时计数并结束本轮审核。"
                "修复成功后先用 RecordLabRepair 记录失效原因与解决方案，再继续漏洞验证。"
                "不要自己修 Docker，也不要用 static_only 硬过闸门（除非项目已强制静态）。"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "reason": {
                        "type": "string",
                        "description": "必须写清假就绪现象（如 /portal 404、数据库容器已退出）",
                    },
                },
                "required": ["reason"],
            },
            handler=_request_lab_rebuild,
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

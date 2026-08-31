"""Worker-phase tools: SubmitVuln, AppendAffectedLocations, FinishFile, FinishRound, FinishFix."""

from __future__ import annotations

from typing import Any

from ..audit_mode import AUDIT_MODE_BOUNTY, bounty_submit_block_reason, normalize_audit_mode
from ..mining_paths import (
    HEURISTIC_LITE_WEIGHT,
    heuristic_lite_active,
    mining_path_from_role,
    normalize_mining_path,
)
from ..models import FileWeight, Project, SessionLocal, Sink, Vuln
from ..services.affected_locations import (
    AFFECTED_LOCATIONS_HEADING,
    append_affected_locations,
    format_location_line,
    parse_locations,
)
from ..services.duplicate_guard import soft_duplicate_gate
from ..services.paths import vuln_dir
from ..services.poc_script import (
    POC_CODE_TOOL_DESCRIPTION,
    poc_cli_block_reason,
    poc_required_for_submit,
    write_poc_code,
)
from ..services.cve_record import initialize_cve_record
from ..services.report import (
    chinese_title_block_reason,
    default_advisory_md,
    ensure_search_fingerprint_section,
    missing_report_headings,
    write_advisory_md,
    write_report_md,
)
from ..target_kind import normalize_target_kind
from ..vuln_types import (
    PENDING_SEVERITY,
    config_premise_label,
    normalize_config_premise,
    normalize_root_cause_key,
    normalize_vuln_type,
    refine_vuln_type,
)
from . import ToolSpec, registry


REQUIRED_SUBMIT_FIELDS = (
    "title",
    "vuln_type",
    "cwe",
    "file_path",
    "line_no",
    "source_sink",
    "auth_premise",
    "config_premise",
    "http_request",
    "poc_code",
    "expected_evidence",
)


def _resolve_mining_path(ctx) -> str | None:
    """Map Worker role → mining path; Fix inherits the returned vuln's path when possible."""
    path = mining_path_from_role(ctx.role)
    if path:
        return path
    if (ctx.role or "").strip().lower() != "fix":
        return None
    vid = ctx.vuln_id
    if vid is None:
        return None
    with SessionLocal() as db:
        src = db.get(Vuln, int(vid))
        return normalize_mining_path(None if not src else src.mining_path)


FINISH_FILE_CONTINUE_MSG = (
    "FinishFile 不等于结束本轮。请继续按角色分析一开始注入的焦点文件；"
    "仅当该焦点已按本轮角色分析完后再调用 FinishRound。"
)
FINISH_FILE_NON_ENTRY_MSG = (
    "已标记其它文件，本轮未结束。禁止立刻 FinishRound。"
    "请继续分析一开始注入的焦点文件。"
)
FINISH_FILE_ENTRY_MSG = (
    "已标记本轮注入焦点。若已按角色分析完毕，现在可以 FinishRound；"
    "否则继续分析，不要仅因 FinishFile 而结束本轮。"
)
FINISH_ROUND_NEED_FILE = "FinishRound 前本轮必须先调用过 FinishFile"
FINISH_ROUND_NEED_ENTRY = (
    "本轮注入焦点 {injected} 尚未 FinishFile，不能结束本轮。"
    "中途 FinishFile 的是其它文件，请继续分析注入焦点；"
    "仅当该焦点已按角色分析完并 FinishFile 后再 FinishRound。"
)


def _norm_audit_path(p: str) -> str:
    p = str(p).replace("\\", "/").lstrip("/")
    if p.startswith("src/"):
        p = p[4:]
    return p


def _injected_path(ctx) -> str | None:
    raw = getattr(ctx, "file_path", None) or (ctx.state or {}).get("injected_file")
    if not raw:
        return None
    return _norm_audit_path(str(raw))


def _heuristic_lite(proj: Project | None) -> bool:
    if not proj:
        return False
    return heuristic_lite_active(
        heuristic_enabled=bool(getattr(proj, "heuristic_enabled", True)),
        heuristic_lite=bool(getattr(proj, "heuristic_lite", False)),
    )


def _pending_heuristic_entries(db, project_id: int, *, lite: bool) -> int:
    q = db.query(FileWeight).filter(
        FileWeight.project_id == project_id,
        FileWeight.skipped.is_(False),
        FileWeight.audited.is_(False),
    )
    if lite:
        q = q.filter(FileWeight.weight == HEURISTIC_LITE_WEIGHT)
    return q.count()


def heuristic_complete(project_id: int) -> bool:
    """Heuristic path done, or the path is off.

    Lite mode only waits on weight-100 entry files; unmarked / lower-weight
    files can still be FinishFile'd along a call chain but do not block.
    """
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        if not proj:
            return False
        if not bool(getattr(proj, "heuristic_enabled", True)):
            return True
        return _pending_heuristic_entries(db, project_id, lite=_heuristic_lite(proj)) <= 0


def mining_complete(project_id: int) -> bool:
    """recon_done + enabled mining paths finished + no returned/fixing."""
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        if not proj or not proj.recon_done:
            return False
        if bool(getattr(proj, "heuristic_enabled", True)):
            left = _pending_heuristic_entries(db, project_id, lite=_heuristic_lite(proj))
            if left > 0:
                return False
        if bool(getattr(proj, "fast_enabled", False)):
            if not bool(getattr(proj, "fast_queue_frozen", False)):
                return False
            open_n = (
                db.query(Sink)
                .filter(Sink.project_id == project_id, Sink.status.in_(("queued", "claimed")))
                .count()
            )
            if open_n > 0:
                return False
        if bool(getattr(proj, "bypass_enabled", False)):
            if not bool(getattr(proj, "bypass_queue_frozen", False)):
                return False
            from ..models import BypassTarget

            open_n = (
                db.query(BypassTarget)
                .filter(BypassTarget.project_id == project_id, BypassTarget.status.in_(("queued", "claimed")))
                .count()
            )
            if open_n > 0:
                return False
        bounced = (
            db.query(Vuln)
            .filter(
                Vuln.project_id == project_id,
                Vuln.status.in_(("returned", "fixing")),
            )
            .count()
        )
        return bounced == 0


def project_complete_gates(project_id: int) -> bool:
    """Mining done + no pending_review/returned/fixing."""
    if not mining_complete(project_id):
        return False
    with SessionLocal() as db:
        pending = (
            db.query(Vuln)
            .filter(
                Vuln.project_id == project_id,
                Vuln.status.in_(("pending_review", "returned", "fixing")),
            )
            .count()
        )
        if pending > 0:
            return False
        proj = db.get(Project, project_id)
        if proj and bool(proj.verifier_enabled):
            vpending = (
                db.query(Vuln)
                .filter(
                    Vuln.project_id == project_id,
                    Vuln.verifier_status == "pending",
                    Vuln.status.in_(("confirmed", "static_only")),
                    Vuln.attack_surface == "frontend",
                )
                .count()
            )
            if vpending > 0:
                return False
        if proj and bool(getattr(proj, "attack_chain_enabled", False)):
            if not bool(getattr(proj, "attack_chain_done", False)):
                return False
        return True


def _ensure_affected_section(report: str, args: dict[str, Any]) -> str:
    """Ensure report has 同根因受影响点; seed with primary location if missing."""
    if AFFECTED_LOCATIONS_HEADING in report or "## 同根因受影响点" in report:
        return report
    primary = {
        "file_path": str(args.get("file_path") or "").replace("\\", "/"),
        "line_no": args.get("line_no"),
        "method": None,
        "note": "代表点",
    }
    section = f"{AFFECTED_LOCATIONS_HEADING}\n\n{format_location_line(primary)}\n"
    for marker in ("\n## 复现证明\n", "\n## 修复方案\n", "\n## 备注\n"):
        idx = report.find(marker)
        if idx != -1:
            return report[:idx].rstrip() + "\n\n" + section + report[idx:]
    return report.rstrip() + "\n\n" + section


def _project_target_kind(project_id: int) -> str:
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        return normalize_target_kind(getattr(proj, "target_kind", None) if proj else None)


def _submit_vuln(ctx, args: dict[str, Any]) -> dict[str, Any]:
    if ctx.role == "worker" and mining_complete(ctx.project_id):
        return {
            "ok": False,
            "error": "挖掘阶段已完成（入口均已审计且无打回），禁止再 SubmitVuln；修复请走 Fix 流程",
        }
    kind = _project_target_kind(ctx.project_id)
    poc_text = str(args.get("poc_code") or "")
    required = list(REQUIRED_SUBMIT_FIELDS)
    if not poc_required_for_submit(
        target_kind=kind,
        http_request=str(args.get("http_request") or ""),
        poc_code=poc_text,
    ):
        required = [f for f in required if f != "poc_code"]
    missing = [f for f in required if args.get(f) in (None, "")]
    if missing:
        return {"ok": False, "error": f"SubmitVuln 缺少必填字段: {', '.join(missing)}"}
    title_blocked = chinese_title_block_reason(str(args.get("title") or ""))
    if title_blocked:
        return {"ok": False, "error": title_blocked}
    poc_blocked = poc_cli_block_reason(poc_text, target_kind=kind)
    if poc_blocked:
        return {"ok": False, "error": poc_blocked}
    vtype = refine_vuln_type(
        normalize_vuln_type(str(args.get("vuln_type"))),
        title=str(args.get("title") or ""),
        source_sink=str(args.get("source_sink") or ""),
    )
    intended = bool(args.get("intended_behavior") or False)
    try:
        config_premise = normalize_config_premise(args.get("config_premise"))
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}
    try:
        line_no = int(args.get("line_no"))
    except (TypeError, ValueError):
        return {"ok": False, "error": "line_no 必须是整数"}
    root_key = normalize_root_cause_key(args.get("root_cause_key"))
    file_path = str(args.get("file_path") or "").replace("\\", "/")

    with SessionLocal() as db:
        proj = db.get(Project, ctx.project_id)
        mode = normalize_audit_mode(None if not proj else proj.audit_mode)
        if mode == AUDIT_MODE_BOUNTY:
            blocked = bounty_submit_block_reason(vtype, file_path=file_path)
            if blocked:
                return {"ok": False, "error": blocked}

    soft = soft_duplicate_gate(
        ctx,
        args,
        tool="SubmitVuln",
        file_path=file_path,
        vuln_type=vtype,
        root_cause_key=root_key,
        action_hint="用 AppendAffectedLocations 追加到 pending 主报告，或等 Reviewer MergeIntoVuln",
    )
    if soft:
        return soft

    mining_path = _resolve_mining_path(ctx)
    report_md_raw = args.get("report_md")
    if report_md_raw:
        report_title_blocked = chinese_title_block_reason(report_md=str(report_md_raw))
        if report_title_blocked:
            return {"ok": False, "error": report_title_blocked}
    if mining_path == "bypass" and report_md_raw:
        missing = missing_report_headings(str(report_md_raw), bypass=True)
        if missing:
            return {
                "ok": False,
                "error": (
                    "历史漏洞绕过 report_md 须对齐 templates/vuln-report-bypass.md，"
                    f"缺少: {', '.join(missing)}"
                ),
            }

    with SessionLocal() as db:
        vuln = Vuln(
            project_id=ctx.project_id,
            title=str(args["title"]).strip(),
            vuln_type=vtype,
            severity=PENDING_SEVERITY,
            cwe=str(args["cwe"]).strip(),
            file_path=file_path,
            line_no=line_no,
            source_sink=str(args["source_sink"]),
            auth_premise=str(args["auth_premise"]),
            config_premise=config_premise,
            http_request=str(args["http_request"]),
            poc_code=poc_text,
            expected_evidence=str(args["expected_evidence"]),
            intended_behavior=intended,
            root_cause_key=root_key,
            mining_path=mining_path,
            status="pending_review",
        )
        db.add(vuln)
        db.commit()
        db.refresh(vuln)
        vuln_id = vuln.id
        vdir = vuln_dir(ctx.project_id, vuln_id)
        report = report_md_raw or _default_report(args, vtype, mining_path=mining_path)
        report = _ensure_affected_section(str(report), args)
        from ..services.asset_proof import (
            ensure_project_fingerprints,
            overlay_project_fingerprints,
            upgrade_project_fingerprints,
        )
        from ..services.report import is_placeholder_query

        ensure_project_fingerprints(ctx.project_id)
        worker_fofa = args.get("fofa_fingerprint")
        worker_x = args.get("x_fingerprint")
        if worker_fofa and not is_placeholder_query(worker_fofa):
            upgrade_project_fingerprints(
                ctx.project_id,
                {"fofa": worker_fofa, "x": worker_x or "", "ok": True},
                origin="manual",
            )
        report = ensure_search_fingerprint_section(
            str(report),
            fofa=worker_fofa,
            x=worker_x,
            basis=args.get("fingerprint_basis"),
        )
        report = overlay_project_fingerprints(report, ctx.project_id)
        write_report_md(vdir / "report.md", report, vuln.created_at)
        write_advisory_md(vdir / "advisory.md", str(args.get("advisory_md") or default_advisory_md(args)))
        initialize_cve_record(ctx.project_id, vuln_id)
        (vdir / "request.http").write_text(str(args["http_request"]), encoding="utf-8")
        if poc_text.strip():
            write_poc_code(ctx.project_id, vuln_id, poc_text)
        vuln.report_path = f"vulns/{vuln_id}/report.md"
        db.commit()

    ctx.state.setdefault("submitted_vulns", []).append(vuln_id)
    ctx.state["review_queue_notify"] = True
    out: dict[str, Any] = {
        "ok": True,
        "vuln_id": vuln_id,
        "status": "pending_review",
        "message": "已入审核队列，Worker 可继续审计",
    }
    if root_key:
        out["root_cause_key"] = root_key
    if mining_path:
        out["mining_path"] = mining_path
    out["config_premise"] = config_premise
    return out


def _append_affected_locations(ctx, args: dict[str, Any]) -> dict[str, Any]:
    vuln_id = args.get("vuln_id")
    if not vuln_id:
        return {"ok": False, "error": "缺少 vuln_id"}
    locations, err = parse_locations(args.get("locations"))
    if err:
        return {"ok": False, "error": err}
    with SessionLocal() as db:
        vuln = db.get(Vuln, int(vuln_id))
        if not vuln or vuln.project_id != ctx.project_id:
            return {"ok": False, "error": "漏洞不存在"}
        if vuln.status != "pending_review":
            return {
                "ok": False,
                "error": (
                    f"仅 status=pending_review 可 AppendAffectedLocations，当前为 {vuln.status}；"
                    "已确认报告请交新条由 Reviewer MergeIntoVuln，不要自行改写"
                ),
            }
        root_key = normalize_root_cause_key(args.get("root_cause_key"))
        if root_key and not (vuln.root_cause_key or "").strip():
            vuln.root_cause_key = root_key
            db.commit()
        report_path = vuln_dir(ctx.project_id, vuln.id) / "report.md"
        stats = append_affected_locations(report_path, locations)
        return {
            "ok": True,
            "vuln_id": vuln.id,
            "status": vuln.status,
            "root_cause_key": vuln.root_cause_key,
            **stats,
            "message": f"已追加 {stats['added']} 个受影响点到漏洞 #{vuln.id}",
        }


def _default_report(
    args: dict[str, Any],
    vtype: str,
    mining_path: str | None = None,
) -> str:
    primary = format_location_line(
        {
            "file_path": str(args.get("file_path") or "").replace("\\", "/"),
            "line_no": args.get("line_no"),
            "method": None,
            "note": "代表点",
        }
    )
    bypass = mining_path == "bypass"
    patch_bypass_section = (
        "\n### 补丁绕过简析\n待补全：原漏洞与官方补丁/修复方式；当前源码中绕过或未修复原因。\n"
        if bypass
        else ""
    )
    desc_second = (
        f"第二段：该漏洞位于 `{args.get('file_path')}:{args.get('line_no')}`，"
        f"数据流为 {args.get('source_sink')}；说明与历史漏洞文档的关系（原 CVE/补丁与当前变体或仍可利用点）。"
        if bypass
        else f"第二段：该漏洞位于 `{args.get('file_path')}:{args.get('line_no')}`，数据流为 {args.get('source_sink')}。"
    )
    return f"""---
title: {args.get('title')}
summary: {args.get('source_sink', '')[:200]}
---

# {args.get('title')}

## 摘要
- 漏洞技术类型：{vtype}
- 严重度：待 Reviewer 填写 CVSS 3.1 向量（分数由系统计算，不按类型映射）
- CWE：{args.get('cwe')}
- 位置：{args.get('file_path')}:{args.get('line_no')}
- 配置前提：{config_premise_label(args.get('config_premise')) or args.get('config_premise')}

## 漏洞描述
第一段：待根据厂商与产品资料补全系统介绍。

{desc_second}

## 漏洞危害
- 已证明危害：{args.get('expected_evidence')}
- 潜在危害：待根据漏洞类型补全。
- SQL 注入须明确：是否能获取 OS-Shell：未验证
- SSRF 须明确：观察面：有回显 / 仅响应差别（内网端口探测） / 不适用

## 漏洞厂商全称
暂未明确

## 已知受影响产品及版本
暂未明确

## 漏洞技术细节
{patch_bypass_section}
### Source → Sink
{args.get('source_sink')}

### 完整 PoC 描述
{("可运行脚本见同目录 `poc.py`（有 HTTP 面时 `python poc.py -u <目标>`；纯库洞为已安装包的公开 API 调用，不要与 `harness.py` 重复）。" if str(args.get("poc_code") or "").strip() else "无独立 `poc.py`：纯库洞无 HTTP/安装面时以 API 调用配方为准；局部验证证据在 `harness.py`。")}

```http
{args.get('http_request')}
```

### 触发条件
配置前提：{config_premise_label(args.get('config_premise')) or args.get('config_premise')}
{args.get('auth_premise')}

## 同根因受影响点
{primary}

## 复现证明

### 基础环境搭建
详见项目文档 `docs/lab.md`。

### 漏洞触发操作
（按实际验证方式填写，删去不适用的部分。）

#### 局部验证（harness）

harness 脚本（`harness.py`）在沙箱中执行结果如下（粘贴 stdout 关键输出，截取关键行）：

```text

```

**为何 harness 能证明漏洞存在**：分析 harness 如何构造输入、调用了哪些源码函数、最终观察到了什么运行时行为（如异常/返回值的危险变化、状态篡改、敏感数据外泄等），说明该行为在源码层面与漏洞根因的对应关系。不要写 PoC 的使用方法。

#### 动态验证（靶场 PoC）

关键利用 HTTP 请求（`Host` 用 `TARGET`；body 中长字符串用占位符）：

```http

```

PoC 使用方法（`python poc.py -u <目标>`；RCE 另 `-c/--cmd`；代理用 `--proxy`）：

```text
python poc.py -u http://TARGET:PORT
python poc.py -u http://TARGET:PORT --zh
python poc.py -u http://TARGET:PORT --proxy http://127.0.0.1:8080
python poc.py -u http://TARGET:PORT -c "id"
```

**为何 PoC 能利用该漏洞**：分析请求中哪一字段/参数为攻击者可控输入，经过源码哪条链路最终到达 sink，造成何种危害。说明 PoC 输出的实际结果（响应正文、日志、文件或权限变化）与危害的对应关系。

### 预期证据
{args.get('expected_evidence')}

### 复现注意事项
-

## 修复方案
-

## 备注
无
"""


def _finish_file_message(ctx, done: list[str]) -> str:
    injected = _injected_path(ctx)
    done_norm = {_norm_audit_path(p) for p in done}
    if injected and done_norm and injected not in done_norm:
        return FINISH_FILE_NON_ENTRY_MSG
    if injected and injected in done_norm:
        return FINISH_FILE_ENTRY_MSG
    return FINISH_FILE_CONTINUE_MSG


def _finish_file(ctx, args: dict[str, Any]) -> dict[str, Any]:
    paths = args.get("paths") or args.get("path") or args.get("files")
    if isinstance(paths, str):
        paths = [paths]
    if not paths:
        return {"ok": False, "error": "缺少 path/paths"}
    done = []
    with SessionLocal() as db:
        for p in paths:
            p = _norm_audit_path(p)
            fw = (
                db.query(FileWeight)
                .filter(FileWeight.project_id == ctx.project_id, FileWeight.path == p)
                .first()
            )
            if not fw:
                continue
            fw.audited = True
            fw.claimed_by = None
            fw.claimed_at = None
            done.append(p)
        db.commit()
    ctx.state.setdefault("finished_files_this_round", [])
    ctx.state["finished_files_this_round"].extend(done)
    return {
        "ok": True,
        "finished": done,
        "count": len(done),
        "message": _finish_file_message(ctx, done),
    }


def _finish_round(ctx, args: dict[str, Any]) -> dict[str, Any]:
    finished = ctx.state.get("finished_files_this_round") or []
    if not finished:
        return {"ok": False, "error": FINISH_ROUND_NEED_FILE}
    injected = _injected_path(ctx)
    if injected:
        finished_norm = {_norm_audit_path(p) for p in finished}
        if injected not in finished_norm:
            return {"ok": False, "error": FINISH_ROUND_NEED_ENTRY.format(injected=injected)}
    report = args.get("report") or args.get("summary") or ""
    if report:
        from ..agent.compression import strip_followup_section
        from .sandbox import assert_writable

        path = assert_writable(ctx.project_id, f"workspace/rounds/round-{ctx.state.get('round_id', 0)}.md")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(strip_followup_section(str(report)), encoding="utf-8")
    ctx.state["round_finished"] = True
    ctx.state["finished_files_this_round"] = []
    return {"ok": True, "message": "本轮审计结束"}


def _finish_fix(ctx, args: dict[str, Any]) -> dict[str, Any]:
    vuln_id = args.get("vuln_id") or ctx.vuln_id
    if not vuln_id:
        return {"ok": False, "error": "缺少 vuln_id"}
    report_md = args.get("report_md")
    with SessionLocal() as db:
        vuln = db.get(Vuln, int(vuln_id))
        if not vuln or vuln.project_id != ctx.project_id:
            return {"ok": False, "error": "漏洞不存在"}
        if vuln.status not in ("returned", "fixing"):
            return {"ok": False, "error": f"仅 status=returned/fixing 可 FinishFix，当前为 {vuln.status}"}
        if args.get("poc_code"):
            poc_blocked = poc_cli_block_reason(
                str(args["poc_code"]),
                target_kind=_project_target_kind(ctx.project_id),
            )
            if poc_blocked:
                return {"ok": False, "error": poc_blocked}
        title_blocked = chinese_title_block_reason(
            None if args.get("title") is None else str(args.get("title") or ""),
            report_md=None if not report_md else str(report_md),
        )
        if title_blocked:
            return {"ok": False, "error": title_blocked}
        # optional field updates
        for key in (
            "title",
            "source_sink",
            "auth_premise",
            "http_request",
            "poc_code",
            "expected_evidence",
            "cwe",
        ):
            if args.get(key) is not None:
                setattr(vuln, key, args[key])
        if args.get("config_premise") not in (None, ""):
            try:
                vuln.config_premise = normalize_config_premise(args.get("config_premise"))
            except ValueError as exc:
                return {"ok": False, "error": str(exc)}
        if args.get("line_no") is not None:
            vuln.line_no = int(args["line_no"])
        if args.get("file_path"):
            vuln.file_path = str(args["file_path"])
        if report_md:
            vdir = vuln_dir(ctx.project_id, vuln.id)
            report = ensure_search_fingerprint_section(
                str(report_md),
                fofa=args.get("fofa_fingerprint"),
                x=args.get("x_fingerprint"),
                basis=args.get("fingerprint_basis"),
            )
            from ..services.asset_proof import ensure_project_fingerprints, overlay_project_fingerprints

            ensure_project_fingerprints(ctx.project_id)
            report = overlay_project_fingerprints(report, ctx.project_id)
            write_report_md(vdir / "report.md", report, vuln.created_at)
        if args.get("advisory_md") not in (None, ""):
            write_advisory_md(vuln_dir(ctx.project_id, vuln.id) / "advisory.md", str(args["advisory_md"]))
        if args.get("http_request"):
            (vuln_dir(ctx.project_id, vuln.id) / "request.http").write_text(str(args["http_request"]), encoding="utf-8")
        if args.get("poc_code"):
            poc_blocked = poc_cli_block_reason(
                str(args["poc_code"]),
                target_kind=_project_target_kind(ctx.project_id),
            )
            if poc_blocked:
                return {"ok": False, "error": poc_blocked}
            write_poc_code(ctx.project_id, vuln.id, str(args["poc_code"]))
        vuln.status = "pending_review"
        vuln.return_reason = None
        vuln.fp_kind = None
        db.commit()
        vid = vuln.id
    ctx.state["fix_finished"] = True
    return {"ok": True, "vuln_id": vid, "status": "pending_review", "message": "已修改并重新入队"}


def register_worker_tools() -> None:
    registry.register(
        ToolSpec(
            name="SubmitVuln",
            description=(
                "提交待审核漏洞（必填字段齐全才入库）。"
                "仅当默认配置或只改应用自身配置（config_premise=default|specific）下，"
                "攻击者只凭自身权限与用户可控输入"
                "（HTTP / WebSocket / RPC / MQ / 回调等）就能打出可观察有害冲击时才提交；"
                "source→sink 可达但默认环境无冲击、需要额外写文件/独立漏洞/非默认目录布局、"
                "或只是配置/文档/compose/.env 里用户可改的默认密码弱口令的不要提交。"
                "有服务端机密危害的源码硬编码密钥（JWT/HMAC 签名密钥、接口签名 secret、"
                "私钥、第三方 API Key 等）可以提交；"
                "前端传输混淆 AES/公开下发密钥不要提交。"
                "同一根因同一危害只交一份：先 Grep 同类其余方法写入报告「同根因受影响点」；"
                "已有 pending 同根因条目请用 AppendAffectedLocations，不要再 SubmitVuln。"
                "应填写 root_cause_key（类型:稳定锚点）。"
                "若与已有洞同 file_path+vuln_type 或同 root_cause_key，首次调用会提醒复查；"
                "确认仍要单独交时，再次调用并传 confirm_not_duplicate=true（仅本会话提醒过一次后才接受）。"
                "不要按漏洞类型填写严重度；入库严重度为 pending，由 Reviewer 填写 CVSS 3.1 向量，分数由系统计算。"
                "必填 config_premise=default|specific（默认配置/特定配置）。"
                "特定配置指须改应用自身配置才成立，且该配置不是官方已明确警示会导致安全风险的选项；"
                "仅在官方已警示的不安全开关下才成立的不要提交。"
                "SSRF 须在 expected_evidence 与报告危害中标明观察面："
                "有回显（响应含目标正文）或仅响应差别（内网端口探测）；"
                "不要把端口探测写成已获取云元数据凭据。"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "title": {
                        "type": "string",
                        "description": (
                            "中文标题，概括漏洞类型与位置/入口。"
                            "产品名、类名、CVE 编号可保留原文；不要只用英文。"
                            "英文标题只写在 advisory_md 的 Title。"
                        ),
                    },
                    "vuln_type": {"type": "string"},
                    "cwe": {"type": "string"},
                    "file_path": {"type": "string"},
                    "line_no": {"type": "integer"},
                    "source_sink": {"type": "string"},
                    "auth_premise": {"type": "string"},
                    "config_premise": {
                        "type": "string",
                        "description": (
                            "必填。default=默认配置即可利用；specific=须改应用自身配置才可利用。"
                            "也可写中文：默认配置 / 特定配置。"
                            "官方文档已明确警示「开启后有安全风险」的配置不算特定配置；"
                            "仅在此类开关下才成立的不要提交。"
                        ),
                    },
                    "http_request": {
                        "type": "string",
                        "description": (
                            "HTTP 报文，或组件审计时的 API 调用配方（类/方法/参数）；"
                            "无 HTTP 面时可写 API 配方，不要留空。"
                        ),
                    },
                    "poc_code": {
                        "type": "string",
                        "description": POC_CODE_TOOL_DESCRIPTION,
                    },
                    "expected_evidence": {
                        "type": "string",
                        "description": (
                            "成功利用后应观察到的冲击。"
                            "SSRF 须写清观察面：有回显则摘录目标正文；"
                            "仅响应差别则给出通/不通对照，不要写已获取云凭据。"
                        ),
                    },
                    "intended_behavior": {"type": "boolean"},
                    "root_cause_key": {
                        "type": "string",
                        "description": "同根因合并键，格式 类型:稳定锚点，如 idor:SysCommentController",
                    },
                    "confirm_not_duplicate": {
                        "type": "boolean",
                        "description": (
                            "疑似重复提醒后仍确认单独提交时传 true。"
                            "仅本会话已因同一指纹被提醒过一次后才接受；首次带上会被拒绝。"
                        ),
                    },
                    "fofa_fingerprint": {"type": "string"},
                    "x_fingerprint": {"type": "string"},
                    "fingerprint_basis": {"type": "string"},
                    "report_md": {
                        "type": "string",
                        "description": (
                            "中文报告。标题须为中文（YAML title 与一级标题）。"
                            "历史漏洞绕过须对齐 templates/vuln-report-bypass.md"
                            "（同 vuln-report.md 且 ## 漏洞技术细节 下第一节为 ### 补丁绕过简析）；"
                            "启发式/快速扫描对齐 templates/vuln-report.md。"
                        ),
                    },
                    "advisory_md": {
                        "type": "string",
                        "description": (
                            "英文 GitHub Advisory 填表稿，结构对齐 templates/vuln-advisory.md。"
                            "含 Title、Description（Summary/Details/Vulnerable code/PoC/Impact）、"
                            "Affected products、Severity/CWE（含 CVSS 3.1 向量；分数由系统计算）。"
                            "Vulnerable code 须含完整相对路径与源码原文。不要写中文报告。"
                        ),
                    },
                },
                "required": list(REQUIRED_SUBMIT_FIELDS),
            },
            handler=_submit_vuln,
        )
    )
    registry.register(
        ToolSpec(
            name="AppendAffectedLocations",
            description=(
                "向本项目已有 pending_review 报告追加同根因受影响点（方法/接口）。"
                "同一根因同一危害已有待审条目时必须用本工具，禁止再 SubmitVuln。"
                "不可对 confirmed/static_only 调用；已确认主报告的新方法请另交一条供 Reviewer 并入。"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "vuln_id": {"type": "integer"},
                    "locations": {
                        "type": "array",
                        "description": "受影响点列表，每项含 file_path，可选 line_no/method/note",
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
                    "root_cause_key": {
                        "type": "string",
                        "description": "若目标尚无 root_cause_key 可一并补写",
                    },
                },
                "required": ["vuln_id", "locations"],
            },
            handler=_append_affected_locations,
        )
    )
    registry.register(
        ToolSpec(
            name="FinishFile",
            description=(
                "中途标记已审完、不必再作为后续轮次注入焦点的文件。"
                "沿调用链确认其它文件无漏洞后立刻 FinishFile(paths=[...])，"
                "然后继续分析本轮注入焦点，禁止立刻 FinishRound。"
                "不要因为文件不能当入口就标记。"
                "本轮注入焦点仅在按角色分析完后再标。不要只标一开始注入的文件。"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "paths": {"type": "array", "items": {"type": "string"}},
                },
            },
            handler=_finish_file,
        )
    )
    registry.register(
        ToolSpec(
            name="FinishRound",
            description=(
                "仅当一开始注入的焦点文件已按角色分析完后结束本轮。"
                "须附 report，结构对齐 templates/round-report.md（本轮入口、挖掘方向、已尝试、已排除）。不要写建议后续方向。"
                "中途 FinishFile 其它文件后禁止立刻调用；须先 FinishFile 该注入焦点。"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "report": {
                        "type": "string",
                        "description": (
                            "本轮挖掘摘要（中文），结构对齐 templates/round-report.md，"
                            "须含 ## 本轮入口、## 本轮挖掘方向、## 已尝试、"
                            "## 已排除（后续轮不要再走）。不要写建议后续方向。"
                        ),
                    },
                    "summary": {
                        "type": "string",
                        "description": "report 的别名，同样对齐 templates/round-report.md。",
                    },
                },
            },
            handler=_finish_round,
        )
    )
    registry.register(
        ToolSpec(
            name="FinishFix",
            description="完成分析债务修改，重新入审核队列。只纠正入口/sink/根因，不要去调通 PoC。",
            parameters={
                "type": "object",
                "properties": {
                    "vuln_id": {"type": "integer"},
                    "report_md": {"type": "string"},
                    "advisory_md": {
                        "type": "string",
                        "description": (
                            "可选。英文 GitHub Advisory 填表稿，结构对齐 templates/vuln-advisory.md。"
                        ),
                    },
                    "title": {
                        "type": "string",
                        "description": (
                            "可选。纠正中文标题（须为中文，可保留产品名/类名原文）。"
                        ),
                    },
                    "source_sink": {"type": "string"},
                    "auth_premise": {"type": "string"},
                    "config_premise": {
                        "type": "string",
                        "description": (
                            "可选。纠正配置前提：default=默认配置；specific=特定配置。"
                            "官方已警示的风险配置不算特定配置。"
                        ),
                    },
                    "http_request": {
                        "type": "string",
                        "description": (
                            "HTTP 报文，或组件审计时的 API 调用配方（类/方法/参数）；"
                            "无 HTTP 面时可写 API 配方，不要留空。"
                        ),
                    },
                    "poc_code": {
                        "type": "string",
                        "description": POC_CODE_TOOL_DESCRIPTION,
                    },
                    "expected_evidence": {
                        "type": "string",
                        "description": (
                            "成功利用后应观察到的冲击。"
                            "SSRF 须写清观察面：有回显则摘录目标正文；"
                            "仅响应差别则给出通/不通对照，不要写已获取云凭据。"
                        ),
                    },
                    "fofa_fingerprint": {"type": "string"},
                    "x_fingerprint": {"type": "string"},
                    "fingerprint_basis": {"type": "string"},
                    "cwe": {"type": "string"},
                    "file_path": {"type": "string"},
                    "line_no": {"type": "integer"},
                },
            },
            handler=_finish_fix,
        )
    )


register_worker_tools()

"""Park Reviewer when RunCode fails repeatedly; resume after the user answers."""

from __future__ import annotations

import json
from typing import Any

from ..models import PhaseRun, SessionLocal, Vuln

HARNESS_ASK_NONE = "none"
HARNESS_ASK_AWAITING = "awaiting_user"

SKIP_MESSAGE = (
    "用户选择停止局部验证。"
    "请改为 ConfirmVuln(evidence_level=static_only)（静态已能证明默认可利用时），"
    "或按成立性 MarkFalsePositive。"
    "不要再调用 RunCode。"
)

CONTINUE_MESSAGE = (
    "用户同意继续局部验证。"
    "请按用户指示调整 harness 后再次 RunCode；"
    "不要把沙箱/依赖问题当成误报。"
)


def is_harness_ask_awaiting(vuln: Vuln | None) -> bool:
    if vuln is None:
        return False
    return str(getattr(vuln, "harness_ask_status", "") or "").strip() == HARNESS_ASK_AWAITING


def awaiting_harness_count(project_id: int | None = None) -> int:
    with SessionLocal() as db:
        q = db.query(Vuln).filter(Vuln.harness_ask_status == HARNESS_ASK_AWAITING)
        if project_id is not None:
            q = q.filter(Vuln.project_id == int(project_id))
        return int(q.count() or 0)


def list_awaiting_harness_vulns(project_id: int | None = None) -> list[Vuln]:
    with SessionLocal() as db:
        q = db.query(Vuln).filter(Vuln.harness_ask_status == HARNESS_ASK_AWAITING)
        if project_id is not None:
            q = q.filter(Vuln.project_id == int(project_id))
        rows = q.order_by(Vuln.id.asc()).all()
        for row in rows:
            db.expunge(row)
        return rows


def park_harness_ask_user(
    project_id: int,
    vuln_id: int,
    *,
    reason: str,
) -> dict[str, Any]:
    reason_text = str(reason or "").strip()
    if not reason_text:
        return {"ok": False, "error": "AskUser 必须提供 reason"}
    with SessionLocal() as db:
        vuln = db.get(Vuln, int(vuln_id))
        if not vuln or vuln.project_id != project_id:
            return {"ok": False, "error": "漏洞不存在"}
        vuln.harness_ask_status = HARNESS_ASK_AWAITING
        vuln.harness_ask_reason = reason_text
        db.commit()
    return {
        "ok": True,
        "awaiting_user": True,
        "ask_kind": "runcode_fail",
        "vuln_id": int(vuln_id),
        "reason": reason_text,
        "message": "已挂起等待用户确认是否继续局部验证。本轮暂停，不要再 RunCode。",
    }


def format_runcode_ask_reason(state: dict[str, Any], *, streak: int) -> str:
    last = state.get("runcode_last_failure") if isinstance(state.get("runcode_last_failure"), dict) else {}
    klass = str(last.get("failure_class") or "nonzero_exit")
    err = str(last.get("error") or "").strip()
    hint = str(last.get("hint") or "").strip()
    missing = last.get("missing") or []
    miss = "、".join(str(x) for x in missing[:8] if x)
    parts = [
        f"局部验证 RunCode 已连续失败 {streak} 次（最近：{klass}）。",
        "继续则按你的指示改 harness 再跑；停止则改为仅静态确认或按成立性误报，不要空转。",
    ]
    if miss:
        parts.append(f"缺符号/依赖：{miss}")
    if err:
        parts.append(err[:800])
    if hint:
        parts.append(hint[:400])
    return "\n".join(parts)


def resolve_harness_consent(
    vuln_id: int,
    *,
    action: str,
    instruction: str = "",
) -> dict[str, Any]:
    """Apply skip (static-only) / continue for a parked harness AskUser."""
    from ..agent.checkpoint import load_checkpoint, save_checkpoint
    from .pipeline import kick_reviewer
    from .verifier import _find_open_ask_user_call

    action_key = str(action or "").strip().lower()
    if action_key not in ("skip", "continue"):
        return {"ok": False, "error": "action 须为 skip|continue"}
    instruction_text = str(instruction or "").strip()

    with SessionLocal() as db:
        vuln = db.get(Vuln, int(vuln_id))
        if not vuln:
            return {"ok": False, "error": "漏洞不存在"}
        if str(vuln.harness_ask_status or "") != HARNESS_ASK_AWAITING:
            return {"ok": False, "error": "该漏洞当前不在局部验证待确认状态"}
        project_id = int(vuln.project_id)
        phase_run = (
            db.query(PhaseRun)
            .filter(
                PhaseRun.project_id == project_id,
                PhaseRun.phase == "reviewer",
                PhaseRun.vuln_id == int(vuln_id),
                PhaseRun.status == "awaiting_user",
            )
            .order_by(PhaseRun.id.desc())
            .first()
        )
        phase_run_id = int(phase_run.id) if phase_run else None
        vuln.harness_ask_status = HARNESS_ASK_NONE
        vuln.harness_user_instruction = instruction_text or None
        db.commit()

    if phase_run_id is None:
        return {
            "ok": False,
            "error": "找不到等待中的审核会话，请稍后重试或重新开启审核",
        }
    cp = load_checkpoint(project_id, phase_run_id)
    if not cp:
        return {"ok": False, "error": "找不到审核检查点，无法续跑"}
    tool_call_id, _ = _find_open_ask_user_call(cp.messages)
    if not tool_call_id:
        return {"ok": False, "error": "检查点中没有未答复的 AskUser 调用"}

    if action_key == "skip":
        payload = {
            "ok": True,
            "decision": "skip",
            "instruction": instruction_text,
            "message": SKIP_MESSAGE
            + (f"\n用户说明：{instruction_text}" if instruction_text else ""),
        }
    else:
        payload = {
            "ok": True,
            "decision": "continue",
            "instruction": instruction_text,
            "message": CONTINUE_MESSAGE
            + (f"\n自定义指示：{instruction_text}" if instruction_text else ""),
        }
    cp.messages.append(
        {
            "role": "tool",
            "tool_call_id": tool_call_id,
            "content": json.dumps(payload, ensure_ascii=False),
        }
    )
    cp.state["awaiting_user"] = False
    cp.state["runcode_fail_streak"] = 0
    if instruction_text:
        cp.state["user_instruction"] = instruction_text
    if action_key == "skip":
        cp.state["harness_ask_skip"] = True
    save_checkpoint(cp, status="paused")
    kick_reviewer(project_id)
    return {
        "ok": True,
        "action": action_key,
        "vuln_id": int(vuln_id),
        "instruction": instruction_text or None,
        "message": "已停止局部验证，审核将按仅静态继续" if action_key == "skip" else "已继续局部验证",
    }

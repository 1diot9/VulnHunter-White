from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..agent.anthropic_compat import (
    anthropic_headers,
    anthropic_url,
    build_anthropic_body,
    consume_anthropic_stream,
    is_anthropic_wire,
)
from ..agent.checkpoint import LoopCheckpoint, load_checkpoint
from ..agent.chat_stream import ChatStreamError, ChatStreamProviderError, consume_chat_stream
from ..config import settings
from ..models import PhaseRun, SessionLocal, Vuln
from ..services.http_client import chat_http_client, chat_http_timeout
from ..services.llm_settings import resolve_llm
from .paths import project_root, vuln_dir
from .report import stamp_produced_at


class FollowUpError(RuntimeError):
    pass


class FollowUpNotFound(FollowUpError):
    pass


class ReviewerContextMissing(FollowUpError):
    pass


class FollowUpLlmError(FollowUpError):
    pass


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)


def _context_path(project_id: int, vuln_id: int, phase_run_id: int) -> Path:
    return vuln_dir(project_id, vuln_id) / f"reviewer-context-{phase_run_id}.json"


def _thread_path(project_id: int, vuln_id: int) -> Path:
    return vuln_dir(project_id, vuln_id) / "followups.json"


def archive_reviewer_checkpoint(project_id: int, phase_run_id: int) -> Path | None:
    """Keep the completed Reviewer checkpoint beside the vulnerability report."""
    cp = load_checkpoint(project_id, phase_run_id)
    if not cp or cp.phase != "reviewer" or cp.vuln_id is None:
        return None
    path = _context_path(project_id, int(cp.vuln_id), phase_run_id)
    payload = cp.to_dict()
    payload["archived_at"] = _now_iso()
    _write_json(path, payload)
    return path


def _load_json(path: Path, default: dict[str, Any]) -> dict[str, Any]:
    if not path.is_file():
        return default
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default
    return data if isinstance(data, dict) else default


def _load_archived_context(project_id: int, vuln_id: int) -> dict[str, Any] | None:
    candidates: list[tuple[int, Path]] = []
    for path in vuln_dir(project_id, vuln_id).glob("reviewer-context-*.json"):
        stem = path.stem.removeprefix("reviewer-context-")
        try:
            run_id = int(stem)
        except ValueError:
            continue
        candidates.append((run_id, path))
    for _run_id, path in sorted(candidates, reverse=True):
        data = _load_json(path, {})
        if data.get("messages") and data.get("vuln_id") is not None:
            return data
    return None


def _load_active_context(project_id: int, vuln_id: int) -> dict[str, Any] | None:
    with SessionLocal() as db:
        rows = (
            db.query(PhaseRun)
            .filter(
                PhaseRun.project_id == project_id,
                PhaseRun.phase == "reviewer",
                PhaseRun.vuln_id == vuln_id,
            )
            .order_by(PhaseRun.id.desc())
            .all()
        )
        ids = [r.id for r in rows]
    for run_id in ids:
        cp = load_checkpoint(project_id, run_id)
        if cp and cp.vuln_id == vuln_id:
            data = cp.to_dict()
            data["archived_at"] = None
            return data
    return None


def latest_reviewer_context(project_id: int, vuln_id: int) -> dict[str, Any] | None:
    return _load_archived_context(project_id, vuln_id) or _load_active_context(project_id, vuln_id)


def _get_vuln(vuln_id: int) -> Vuln:
    with SessionLocal() as db:
        vuln = db.get(Vuln, vuln_id)
        if not vuln:
            raise FollowUpNotFound("漏洞不存在")
        db.expunge(vuln)
        return vuln


def _read_report_md(vuln: Vuln) -> str:
    if vuln.report_path:
        path = project_root(vuln.project_id) / vuln.report_path
    else:
        path = vuln_dir(vuln.project_id, vuln.id) / "report.md"
    if not path.is_file():
        return ""
    try:
        return stamp_produced_at(
            path.read_text(encoding="utf-8", errors="ignore"),
            vuln.created_at,
        )
    except OSError:
        return ""


def _load_thread(project_id: int, vuln_id: int) -> dict[str, Any]:
    data = _load_json(_thread_path(project_id, vuln_id), {})
    messages = data.get("messages")
    if not isinstance(messages, list):
        messages = []
    return {"messages": messages, "updated_at": data.get("updated_at")}


def _save_thread(project_id: int, vuln_id: int, messages: list[dict[str, Any]]) -> None:
    _write_json(
        _thread_path(project_id, vuln_id),
        {"messages": messages, "updated_at": _now_iso()},
    )


def list_followups(vuln_id: int) -> dict[str, Any]:
    vuln = _get_vuln(vuln_id)
    ctx = latest_reviewer_context(vuln.project_id, vuln.id)
    thread = _load_thread(vuln.project_id, vuln.id)
    return {
        "vuln_id": vuln.id,
        "project_id": vuln.project_id,
        "reviewer_phase_run_id": int(ctx["phase_run_id"]) if ctx else None,
        "reviewer_context_available": bool(ctx),
        "messages": thread["messages"],
    }


def ask_followup(vuln_id: int, question: str) -> dict[str, Any]:
    question = (question or "").strip()
    if not question:
        raise ValueError("追问内容不能为空")
    vuln = _get_vuln(vuln_id)
    ctx = latest_reviewer_context(vuln.project_id, vuln.id)
    if not ctx:
        raise ReviewerContextMissing("暂无该漏洞的 Reviewer 上下文归档，需等待新审核轮次完成后再追问")
    thread = _load_thread(vuln.project_id, vuln.id)
    history = list(thread["messages"])
    run_id = int(ctx["phase_run_id"])
    user_msg = {
        "id": uuid.uuid4().hex,
        "role": "user",
        "content": question,
        "created_at": _now_iso(),
        "reviewer_phase_run_id": run_id,
    }
    answer = _call_reviewer_llm(
        project_id=vuln.project_id,
        messages=_build_chat_messages(vuln, ctx, history, question),
    )
    assistant_msg = {
        "id": uuid.uuid4().hex,
        "role": "assistant",
        "content": answer,
        "created_at": _now_iso(),
        "reviewer_phase_run_id": run_id,
    }
    history.extend([user_msg, assistant_msg])
    _save_thread(vuln.project_id, vuln.id, history)
    return {
        "vuln_id": vuln.id,
        "project_id": vuln.project_id,
        "reviewer_phase_run_id": run_id,
        "reviewer_context_available": True,
        "messages": history,
    }


def _message_text(message: dict[str, Any]) -> str:
    content = message.get("content")
    if isinstance(content, list):
        parts: list[str] = []
        for part in content:
            if isinstance(part, str):
                parts.append(part)
            elif isinstance(part, dict):
                parts.append(str(part.get("text") or part.get("content") or ""))
        text = "\n".join(p for p in parts if p)
    else:
        text = "" if content is None else str(content)
    calls = message.get("tool_calls") or []
    if isinstance(calls, list) and calls:
        names = []
        for call in calls:
            if isinstance(call, dict):
                fn = call.get("function") or {}
                name = str(fn.get("name") or "").strip()
                if name:
                    names.append(name)
        if names:
            text = (text + "\n" if text else "") + "[工具调用] " + ", ".join(names)
    return text.strip()


def _followup_history_text(history: list[dict[str, Any]]) -> str:
    blocks: list[str] = []
    turn = 0
    for item in history:
        if not isinstance(item, dict):
            continue
        role = item.get("role")
        content = str(item.get("content") or "").strip()
        if not content or role not in ("user", "assistant"):
            continue
        if role == "user":
            turn += 1
            blocks.append(f"### 追问 {turn}\n{content}")
        else:
            blocks.append(f"### 答复 {turn or 1}\n{content}")
    if not blocks:
        return ""
    joined = "\n\n".join(blocks)
    if len(joined) > 20000:
        joined = "（已有追问较长，已保留最近记录）\n\n" + joined[-20000:]
    return "## 已有追问记录\n" + joined


def _reviewer_transcript_text(ctx: dict[str, Any]) -> str:
    lines: list[str] = []
    for item in ctx.get("messages") or []:
        if not isinstance(item, dict):
            continue
        role = str(item.get("role") or "").strip()
        if role == "system":
            continue
        text = _message_text(item)
        if not text:
            continue
        lines.append(f"### {role or 'message'}\n{text}")
    joined = "\n\n".join(lines)
    if len(joined) > 60000:
        joined = joined[-60000:]
        joined = "（前文较长，已保留 Reviewer 轮次最近上下文）\n\n" + joined
    return joined


def _build_chat_messages(
    vuln: Vuln,
    ctx: dict[str, Any],
    history: list[dict[str, Any]],
    question: str,
) -> list[dict[str, str]]:
    system = str(ctx.get("system_prompt") or "").strip() or "你是 VulnHunter 的 Reviewer。"
    system += (
        "\n\n现在进入漏洞报告追问模式。请基于下方 Reviewer 轮次上下文、漏洞报告和已有追问记录回答。"
        "必须结合此前的追问与答复连贯作答，不要当成互不相关的单轮问答。"
        "不要调用工具，不要改变漏洞状态；如果证据不足，请明确指出仍缺少什么。"
    )
    report_md = _read_report_md(vuln)
    context = (
        f"漏洞 #{vuln.id}: {vuln.title}\n"
        f"Reviewer phase_run_id: {ctx.get('phase_run_id')}\n\n"
        "## 漏洞报告\n"
        f"{report_md or '（无 report.md，以下以上下文字段为准）'}\n\n"
        "## Reviewer 轮次上下文\n"
        f"{_reviewer_transcript_text(ctx) or '（无可读上下文）'}"
    )
    history_text = _followup_history_text(history)
    if history_text:
        context += "\n\n" + history_text
    messages: list[dict[str, str]] = [
        {"role": "system", "content": system},
        {"role": "user", "content": context},
        {
            "role": "assistant",
            "content": "已加载该漏洞的 Reviewer 轮次上下文和已有追问记录。请继续提问。",
        },
    ]
    for item in history:
        role = item.get("role")
        if role not in ("user", "assistant"):
            continue
        content = str(item.get("content") or "").strip()
        if content:
            messages.append({"role": role, "content": content})
    messages.append({"role": "user", "content": question})
    return messages


def _call_reviewer_llm(project_id: int, messages: list[dict[str, str]]) -> str:
    llm = resolve_llm("reviewer", project_id=project_id)
    if is_anthropic_wire(llm.wire_api):
        url = anthropic_url(llm.base_url)
        headers = anthropic_headers(llm.api_key)
        body: dict[str, Any] = build_anthropic_body(
            model=llm.model,
            messages=list(messages),
            stream=True,
            temperature=settings.temperature,
        )
        consume = consume_anthropic_stream
    else:
        url = llm.base_url.rstrip("/") + "/chat/completions"
        headers = {
            "Authorization": f"Bearer {llm.api_key}",
            "Content-Type": "application/json",
        }
        body = {
            "model": llm.model,
            "messages": messages,
            "temperature": settings.temperature,
            "stream": True,
            "stream_options": {"include_usage": True},
        }
        consume = consume_chat_stream
    timeout = chat_http_timeout(float(settings.timeout_reviewer_static or 180), 0)
    try:
        with chat_http_client(timeout=timeout) as client:
            for _attempt in range(2):
                with client.stream("POST", url, headers=headers, json=body) as res:
                    if res.status_code == 400 and body.get("stream_options"):
                        body.pop("stream_options", None)
                        continue
                    if res.status_code == 401:
                        raise FollowUpLlmError("401 密钥无效，请检查设置页模型配置")
                    if res.status_code >= 400:
                        text = res.read().decode("utf-8", errors="replace")
                        raise FollowUpLlmError(f"LLM HTTP {res.status_code}: {text[:300]}")
                    data = consume(res.iter_lines())
                    choice = (data.get("choices") or [None])[0] or {}
                    msg = choice.get("message") or {}
                    content = msg.get("content")
                    if isinstance(content, list):
                        content = "\n".join(
                            str(p.get("text") or p.get("content") or "")
                            for p in content
                            if isinstance(p, dict)
                        )
                    answer = str(content or "").strip()
                    if not answer:
                        raise FollowUpLlmError("模型返回空回答")
                    return answer
    except ChatStreamProviderError as e:
        raise FollowUpLlmError(str(e)) from e
    except ChatStreamError as e:
        raise FollowUpLlmError(str(e)) from e
    raise FollowUpLlmError("模型请求失败")

"""Context compression helpers."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from ..config import settings
from ..services.paths import docs_dir, find_security_policy_path, src_dir, summaries_dir, workspace_dir


def _str_tokens(text: str) -> int:
    """CJK ≈ 1 token/char; ASCII ≈ 4 chars/token. char/4 alone undercounts 中文 system prompts."""
    if not text:
        return 0
    cjk = 0
    other = 0
    for ch in text:
        o = ord(ch)
        if 0x2E80 <= o <= 0x9FFF or 0xF900 <= o <= 0xFAFF or 0xFF00 <= o <= 0xFFEF:
            cjk += 1
        else:
            other += 1
    return cjk + (other + 3) // 4


def _json_tokens(obj: Any) -> int:
    if obj is None:
        return 0
    if isinstance(obj, str):
        return _str_tokens(obj)
    try:
        return _str_tokens(json.dumps(obj, ensure_ascii=False))
    except TypeError:
        return _str_tokens(str(obj))


def estimate_tokens(messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None = None) -> int:
    """Estimate request tokens: messages + optional tools schema."""
    total = 0
    for m in messages:
        total += _json_tokens(m.get("content"))
        if m.get("tool_calls"):
            total += _json_tokens(m["tool_calls"])
    if tools:
        total += _json_tokens(tools)
    return max(1, total)


def needs_compress(
    messages: list[dict[str, Any]],
    context_window: int,
    tools: list[dict[str, Any]] | None = None,
    last_prompt_tokens: int = 0,
) -> bool:
    threshold = int(context_window * settings.context_compress_ratio)
    if last_prompt_tokens >= threshold:
        return True
    return estimate_tokens(messages, tools) >= threshold


_SUMMARY_REST = re.compile(r"^(rescue-|round-)?\d+\.md$")
_ROUND_FILE = re.compile(r"^round-(\d+)\.md$")
_FAST_ROUND_FILE = re.compile(r"^fast-round-(\d+)\.md$")
_BYPASS_ROUND_FILE = re.compile(r"^bypass-round-(\d+)\.md$")
_WORKER_ROUND_SUMMARY = re.compile(r"^(\d+)\.md$")
_FOLLOWUP_HEADING = re.compile(r"^##[ \t]*建议后续方向[ \t]*\r?$", re.MULTILINE)
_NEXT_H2 = re.compile(r"^##[ \t]+\S", re.MULTILINE)


def _phase_summary_files(d: Path, phase: str, *, rescue: bool | None = None) -> list[Path]:
    """Files that belong to this phase only (recon-1.md, not recon-old-vuln-1.md)."""
    prefix = f"{phase}-"
    out: list[Path] = []
    if not d.exists():
        return out
    for p in d.glob(f"{prefix}*.md"):
        rest = p.name[len(prefix) :]
        if not _SUMMARY_REST.match(rest):
            continue
        is_rescue = rest.startswith("rescue-")
        if rescue is True and not is_rescue:
            continue
        if rescue is False and is_rescue:
            continue
        out.append(p)
    return out


def write_summary(project_id: int, phase: str, summary: str) -> str:
    d = summaries_dir(project_id)
    d.mkdir(parents=True, exist_ok=True)
    name = f"{phase}-{len(_phase_summary_files(d, phase)) + 1}.md"
    path = d / name
    path.write_text(summary, encoding="utf-8")
    return f"docs/summaries/{name}"


def latest_summary(project_id: int, phase: str) -> str | None:
    """Prefer newest {phase}-rescue-N.md, else newest {phase}-N.md / {phase}-round-N.md."""
    d = summaries_dir(project_id)
    if not d.exists():
        return None
    rescue = sorted(_phase_summary_files(d, phase, rescue=True), key=lambda p: p.stat().st_mtime, reverse=True)
    if rescue:
        return rescue[0].read_text(encoding="utf-8", errors="replace")
    candidates = _phase_summary_files(d, phase, rescue=False)
    if not candidates:
        return None
    newest = max(candidates, key=lambda p: p.stat().st_mtime)
    return newest.read_text(encoding="utf-8", errors="replace")


def _read_capped(path: Path, max_chars: int) -> str | None:
    if not path.is_file() or path.stat().st_size <= 0:
        return None
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        return None
    if len(text) > max_chars:
        return text[:max_chars] + f"\n...[truncated {len(text) - max_chars} chars]"
    return text


def strip_followup_section(text: str) -> str:
    """Drop ## 建议后续方向 so historical advice cannot steer the next Worker round."""
    match = _FOLLOWUP_HEADING.search(text)
    if not match:
        return text
    rest = text[match.end() :]
    next_h2 = _NEXT_H2.search(rest)
    tail = rest[next_h2.start() :] if next_h2 else ""
    head = text[: match.start()].rstrip()
    if tail.strip():
        return f"{head}\n{tail.lstrip()}"
    return f"{head}\n"


def _read_round_for_inject(path: Path, max_chars: int) -> str:
    """Read a round report/summary for Worker inject; always strip follow-up advice before capping."""
    if not path.is_file() or path.stat().st_size <= 0:
        return "（空）"
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        return "（空）"
    text = strip_followup_section(text)
    if len(text) > max_chars:
        return text[:max_chars] + f"\n...[truncated {len(text) - max_chars} chars]"
    return text


def _numbered_markdown(files: list[Path], rest_re: re.Pattern[str]) -> list[tuple[int, Path]]:
    found: list[tuple[int, Path]] = []
    for path in files:
        if not path.is_file() or path.stat().st_size <= 0:
            continue
        match = rest_re.match(path.name)
        if not match:
            continue
        found.append((int(match.group(1)), path))
    found.sort(key=lambda item: item[0])
    return found


def list_recent_round_reports(project_id: int, limit: int | None = None) -> list[tuple[int, Path]]:
    """FinishRound reports under workspace/rounds, oldest-of-window first."""
    cap = settings.worker_round_history if limit is None else limit
    rounds = workspace_dir(project_id) / "rounds"
    if not rounds.is_dir():
        return []
    found = _numbered_markdown(list(rounds.glob("round-*.md")), _ROUND_FILE)
    return found[-cap:] if cap >= 0 else found


def max_round_report_no(project_id: int) -> int:
    """Highest existing workspace/rounds/round-N.md index, or 0."""
    found = list_recent_round_reports(project_id, limit=-1)
    return found[-1][0] if found else 0


def _security_policy_inject_parts(project_id: int, doc_cap: int) -> list[str]:
    """SECURITY.md body for Worker / Reviewer initial context."""
    path = find_security_policy_path(project_id)
    if not path:
        return []
    text = _read_capped(path, doc_cap)
    if not text:
        return []
    rel = "src/" + path.relative_to(src_dir(project_id)).as_posix()
    return [
        f"### {rel}（项目安全策略 / SECURITY.md）\n"
        "以下为仓库官方安全策略，评判漏洞时须对照：尤其注意「不接收 / 不在范围 / out of scope」等声明，"
        "此类问题应误报或标 low_impact，不要 SubmitVuln / ConfirmVuln。\n"
        f"{text}\n"
    ]


def inject_security_policy_block(project_id: int) -> str:
    """Standalone SECURITY.md block for Reviewer (and other phases that skip recon docs)."""
    doc_cap = settings.recon_doc_inject_max_chars
    parts = _security_policy_inject_parts(project_id, doc_cap)
    if not parts:
        return ""
    body = (
        "## 项目安全策略（SECURITY.md）\n"
        "以下为仓库官方安全策略，审核漏洞时须对照。\n\n"
        + parts[0]
    )
    return body.strip() + "\n\n"


def _inject_recon_docs_header(worker_detail: bool) -> str:
    if worker_detail:
        return (
            "## 侦察产物（已完成，禁止再梳理项目结构）\n"
            "以下是侦察阶段落盘的代码地图与鉴权文档。直接使用，不要再 Glob/Read 去重建模块划分、"
            "HTTP / 非 HTTP 入口或鉴权模型。\n"
        )
    return (
        "## 侦察产物（已完成，禁止再梳理项目结构）\n"
        "以下是侦察阶段落盘的代码地图与鉴权文档。直接使用。\n"
    )


def _append_recon_doc_parts(
    project_id: int,
    parts: list[str],
    *,
    worker_detail: bool = False,
) -> bool:
    """Append code-map, auth, and SECURITY.md when present."""
    docs = docs_dir(project_id)
    doc_cap = settings.recon_doc_inject_max_chars
    map_text = _read_capped(docs / "code-map.md", doc_cap)
    auth_text = _read_capped(docs / "auth.md", doc_cap)
    security_parts = _security_policy_inject_parts(project_id, doc_cap)
    if not (map_text or auth_text or security_parts):
        return False
    parts.append(_inject_recon_docs_header(worker_detail))
    if map_text:
        parts.append(f"### docs/code-map.md\n{map_text}\n")
    if auth_text:
        parts.append(f"### docs/auth.md\n{auth_text}\n")
    parts.extend(security_parts)
    return True


def list_recent_fast_round_reports(project_id: int, limit: int | None = None) -> list[tuple[int, Path]]:
    cap = settings.worker_round_history if limit is None else limit
    rounds = workspace_dir(project_id) / "rounds"
    if not rounds.is_dir():
        return []
    found = _numbered_markdown(list(rounds.glob("fast-round-*.md")), _FAST_ROUND_FILE)
    return found[-cap:] if cap >= 0 else found


def max_fast_round_report_no(project_id: int) -> int:
    found = list_recent_fast_round_reports(project_id, limit=-1)
    return found[-1][0] if found else 0


def inject_fast_prior_block(project_id: int) -> str:
    """Recon docs plus recent FinishSink round reports."""
    parts: list[str] = []
    _append_recon_doc_parts(project_id, parts)
    reports = list_recent_fast_round_reports(project_id)
    if reports:
        n = len(reports)
        parts.append(
            f"## 最近 {n} 条已完成 Sink（不要重复）\n"
            "以下为 FinishSink 落盘的回推结论。已否决或已提交的 Sink 不要再分析。\n"
        )
        round_cap = settings.round_report_inject_max_chars
        for num, path in reports:
            text = _read_round_for_inject(path, round_cap)
            parts.append(f"### 快速轮 {num} · workspace/rounds/{path.name}\n{text}\n")
    if not parts:
        return ""
    return "\n".join(parts).strip() + "\n\n"


def list_recent_bypass_round_reports(project_id: int, limit: int | None = None) -> list[tuple[int, Path]]:
    cap = settings.worker_round_history if limit is None else limit
    rounds = workspace_dir(project_id) / "rounds"
    if not rounds.is_dir():
        return []
    found = _numbered_markdown(list(rounds.glob("bypass-round-*.md")), _BYPASS_ROUND_FILE)
    return found[-cap:] if cap >= 0 else found


def max_bypass_round_report_no(project_id: int) -> int:
    found = list_recent_bypass_round_reports(project_id, limit=-1)
    return found[-1][0] if found else 0


def inject_bypass_prior_block(project_id: int) -> str:
    """Recon docs plus recent FinishBypass round reports."""
    parts: list[str] = []
    _append_recon_doc_parts(project_id, parts)
    reports = list_recent_bypass_round_reports(project_id)
    if reports:
        n = len(reports)
        parts.append(
            f"## 最近 {n} 条已完成历史漏洞绕过（不要重复）\n"
            "以下为 FinishBypass 落盘的结论。已否决或已提交的条目不要再分析。\n"
        )
        round_cap = settings.round_report_inject_max_chars
        for num, path in reports:
            text = _read_round_for_inject(path, round_cap)
            parts.append(f"### 绕过轮 {num} · workspace/rounds/{path.name}\n{text}\n")
    if not parts:
        return ""
    return "\n".join(parts).strip() + "\n\n"


def list_recent_worker_round_summaries(project_id: int, limit: int | None = None) -> list[tuple[int, Path]]:
    """worker-round-N.md compression summaries, used when FinishRound reports are absent."""
    cap = settings.worker_round_history if limit is None else limit
    files = _phase_summary_files(summaries_dir(project_id), "worker-round", rescue=False)
    found: list[tuple[int, Path]] = []
    prefix = "worker-round-"
    for path in files:
        rest = path.name[len(prefix) :]
        match = _WORKER_ROUND_SUMMARY.match(rest)
        if not match or not path.is_file() or path.stat().st_size <= 0:
            continue
        found.append((int(match.group(1)), path))
    found.sort(key=lambda item: item[0])
    return found[-cap:] if cap >= 0 else found


def inject_worker_prior_block(project_id: int) -> str:
    """Recon architecture/auth plus recent mining round summaries for a new Worker round."""
    parts: list[str] = []
    _append_recon_doc_parts(project_id, parts, worker_detail=True)

    reports = list_recent_round_reports(project_id)
    if reports:
        n = len(reports)
        parts.append(
            f"## 最近 {n} 轮挖掘摘要（不要重复已尝试路径）\n"
            "以下为 FinishRound 落盘的单轮报告。已审计文件、已走调用链、已否决方向不要再分析一遍；"
            "从本轮焦点按角色继续，不要按历史摘要里的建议改方向。\n"
        )
        round_cap = settings.round_report_inject_max_chars
        for num, path in reports:
            text = _read_round_for_inject(path, round_cap)
            parts.append(f"### 第 {num} 轮 · workspace/rounds/{path.name}\n{text}\n")
    else:
        summaries = list_recent_worker_round_summaries(project_id)
        if summaries:
            n = len(summaries)
            parts.append(
                f"## 最近 {n} 轮挖掘摘要（不要重复已尝试路径）\n"
                "尚无 FinishRound 报告，改注入最近的轮次压缩摘要。已完成工作与已尝试路径不要再走一遍；"
                "从本轮注入入口继续，不要按历史摘要里的建议改方向。\n"
            )
            round_cap = settings.round_report_inject_max_chars
            for num, path in summaries:
                text = _read_round_for_inject(path, round_cap)
                parts.append(f"### 第 {num} 轮压缩摘要 · docs/summaries/{path.name}\n{text}\n")

    if not parts:
        return ""
    return "\n".join(parts).strip() + "\n\n"


SUMMARY_MESSAGE_TAIL = 100
SUMMARY_MESSAGE_MAX_CHARS = 4000
_TODO_EMPTY_PLACEHOLDER = "（空）"


def clip_text_for_summary(text: str, limit: int = SUMMARY_MESSAGE_MAX_CHARS) -> str:
    raw = text if isinstance(text, str) else str(text)
    cap = max(1, int(limit))
    if len(raw) <= cap:
        return raw
    return raw[:cap] + f"\n...[truncated {len(raw) - cap} chars]"


def _clip_tool_call(tc: Any, limit: int) -> Any:
    if not isinstance(tc, dict):
        return tc
    out = dict(tc)
    fn = out.get("function")
    if isinstance(fn, dict):
        fn = dict(fn)
        args = fn.get("arguments")
        if isinstance(args, str):
            fn["arguments"] = clip_text_for_summary(args, limit)
        elif args is not None:
            fn["arguments"] = clip_text_for_summary(json.dumps(args, ensure_ascii=False), limit)
        out["function"] = fn
    return out


def _clip_message_content(content: Any, limit: int) -> Any:
    if isinstance(content, str):
        return clip_text_for_summary(content, limit)
    if isinstance(content, list):
        parts: list[Any] = []
        for part in content:
            if isinstance(part, dict) and isinstance(part.get("text"), str):
                item = dict(part)
                item["text"] = clip_text_for_summary(str(part.get("text") or ""), limit)
                parts.append(item)
            elif isinstance(part, str):
                parts.append(clip_text_for_summary(part, limit))
            else:
                parts.append(part)
        return parts
    if content is None:
        return content
    return clip_text_for_summary(json.dumps(content, ensure_ascii=False), limit)


def clip_summary_message(message: Any, limit: int = SUMMARY_MESSAGE_MAX_CHARS) -> dict[str, Any]:
    """Keep message structure; truncate content / tool arguments, do not drop the message."""
    if not isinstance(message, dict):
        return {"role": "unknown", "content": clip_text_for_summary(str(message), limit)}
    out = dict(message)
    if "content" in out:
        out["content"] = _clip_message_content(out.get("content"), limit)
    tcs = out.get("tool_calls")
    if isinstance(tcs, list):
        out["tool_calls"] = [_clip_tool_call(tc, limit) for tc in tcs]
    return out


def clip_messages_for_summary(
    messages: list[dict[str, Any]] | None,
    *,
    last_n: int = SUMMARY_MESSAGE_TAIL,
    per_message_chars: int = SUMMARY_MESSAGE_MAX_CHARS,
) -> list[dict[str, Any]]:
    """Keep the last N messages; truncate each message instead of the whole dump."""
    rows = list(messages or [])
    n = max(1, int(last_n))
    cap = max(1, int(per_message_chars))
    return [clip_summary_message(m, cap) for m in rows[-n:]]


def format_todo_list_block(todos: list[Any] | None, *, include_empty: bool = False) -> str:
    """Canonical TodoList markdown for compression / conclude summaries. Never truncated."""
    if not isinstance(todos, list) or not todos:
        return f"## TodoList\n{_TODO_EMPTY_PLACEHOLDER}" if include_empty else ""
    lines = ["## TodoList"]
    for item in todos:
        if isinstance(item, dict):
            status = str(item.get("status") or "pending").strip() or "pending"
            content = str(item.get("content") or "").strip()
            tid = str(item.get("id") or "").strip()
            label = f"{tid}: {content}" if tid and content else (tid or content or "(空)")
            lines.append(f"- [{status}] {label}")
        else:
            text = str(item).strip() or "(空)"
            lines.append(f"- {text}")
    return "\n".join(lines)


def attach_todo_list(
    summary: str | None,
    todos: list[Any] | None,
    *,
    include_empty: bool = False,
) -> str:
    """Append the current complete TodoList so compression cannot drop it."""
    block = format_todo_list_block(todos, include_empty=include_empty)
    text = (summary or "").rstrip()
    if not block:
        return text
    if block in text:
        return text
    if not text:
        return block
    return f"{text}\n\n{block}"


def inject_summary_block(summary: str | None, *, for_file: bool = False) -> str:
    if not summary or not summary.strip():
        return ""
    hint = (
        "只接续与当前焦点文件相关的部分；与当前任务无关则忽略。\n"
        if for_file
        else "若摘要与当前任务无关则忽略。\n"
    )
    return (
        "## 上一轮摘要（从这里接续，不要重复已完成工作）\n"
        f"{summary.strip()}\n\n"
        f"{hint}\n"
    )


def build_compressed_messages(
    system: str,
    summary: str,
    bootstrap: str,
    recent_messages: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    tail = list(recent_messages[-12:])
    return [
        {"role": "system", "content": system},
        {
            "role": "user",
            "content": (
                "以下是上下文压缩后的摘要与当前任务注入包。请从摘要处继续，不要重复已完成工作。\n\n"
                f"## 摘要\n{summary}\n\n## 当前注入\n{bootstrap}"
            ),
        },
        *tail,
    ]

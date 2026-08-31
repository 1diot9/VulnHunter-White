"""Chat Completions agent loop with AutoPoc-aligned error handling."""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from sqlalchemy.exc import OperationalError

from ..config import settings
from ..models import PhaseRun, SessionLocal, TokenUsage, utcnow
from ..services.http_client import chat_http_client, chat_http_timeout, conclude_http_timeout
from ..services.live_log import live_log
from ..services.llm_gate import llm_gate, llm_slot
from ..services.llm_thread import SlotHandle, llm_thread_limiter, llm_thread_slot
from ..services.llm_settings import (
    ResolvedLlm,
    bind_llm_to_endpoint,
    llm_role_for_agent,
    pool_endpoints_resolved,
    resolve_llm,
)
from ..tools import ToolContext, registry
from ..tools.common import load_todos
from .checkpoint import LoopCheckpoint, save_checkpoint
from .anthropic_compat import (
    anthropic_headers,
    anthropic_message_to_openai,
    anthropic_url,
    build_anthropic_body,
    consume_anthropic_stream,
    is_anthropic_wire,
)
from .llm_compat import (
    param_to_drop,
    prepare_chat_body,
    preserves_assistant_reasoning,
    sampling_temperature,
    strip_reasoning_fields,
)
from .chat_stream import (
    ChatStreamCancelled,
    ChatStreamProviderError,
    consume_chat_stream,
)
from .compression import (
    attach_todo_list,
    build_compressed_messages,
    clip_messages_for_summary,
    estimate_tokens,
    format_todo_list_block,
    needs_compress,
    write_summary,
)
from .review_wrapup import (
    mark_grace_used,
    note_tool_for_wrapup,
    should_grant_wrapup_grace,
    wrapup_grace_nudge,
)
from .watchdog import (
    AgentWatchdog,
    identical_abort_nudge,
    identical_redirect_nudge,
    identical_tool_nudge,
)
from ..services.conversation_archive import db_phase_to_log_phase
from ..services.conversation_steer import (
    STEER_USER_PREFIX,
    consume_steer_messages,
    register_loop,
    unregister_loop,
)

INTERRUPT_RESUME = (
    "刚才因暂停或进程中断。请从中断处继续完成任务，不要无故重来。"
)
TRANSIENT_RESUME = (
    "上一轮模型请求因网络中断失败，请基于已有工具结果继续，不要从头再分析。"
)
CHAT_WAIT_LOG_AFTER = 20.0
CHAT_WAIT_LOG_EVERY = 30.0


def _tool_call_names(tool_calls: list[Any] | None) -> list[str]:
    names: list[str] = []
    for tc in tool_calls or []:
        if not isinstance(tc, dict):
            continue
        fn = tc.get("function") or {}
        n = str(fn.get("name") or "").strip()
        if n:
            names.append(n)
    return names


@dataclass
class LoopResult:
    ok: bool
    stop_reason: str = ""
    timed_out: bool = False
    cancelled: bool = False
    loop_aborted: bool = False
    rate_limited_exhausted: bool = False
    tokens_input: int = 0
    tokens_output: int = 0
    tokens_cached: int = 0
    tokens_total: int = 0
    state: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    round_summary: str | None = None
    summary_path: str | None = None


def _content_text(message: dict[str, Any]) -> str:
    content = message.get("content")
    if isinstance(content, list):
        parts: list[str] = []
        for part in content:
            if isinstance(part, str):
                parts.append(part)
            elif isinstance(part, dict):
                parts.append(str(part.get("text") or part.get("content") or ""))
        return "\n".join(p for p in parts if p).strip()
    if content is None:
        return ""
    return str(content).strip()


def _sanitize_chat_messages(
    messages: list[dict[str, Any]],
    *,
    model: str | None = None,
) -> list[dict[str, Any]]:
    """Coerce null/missing content to empty string for OpenAI-compatible gateways.

    OpenAI allows assistant ``content=null`` with ``tool_calls``. Qwen/DashScope
    and several compatible gateways reject that as "content field is a required
    field" (HTTP 400). Empty string is accepted by both.

    Kimi K2.5+ / K3 require the complete assistant message (including
    ``reasoning_content``) on later turns; other providers may 400 on that field.
    """
    keep_reasoning = preserves_assistant_reasoning(model)
    out: list[dict[str, Any]] = []
    for m in messages:
        if not isinstance(m, dict):
            continue
        nm = dict(m) if keep_reasoning else strip_reasoning_fields(m)
        if nm.get("content") is None:
            nm["content"] = ""
        out.append(nm)
    return out


def _reasoning_text(message: dict[str, Any]) -> str:
    for key in ("reasoning_content", "reasoning", "thinking"):
        val = message.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
        if isinstance(val, dict):
            text = str(val.get("content") or val.get("text") or "").strip()
            if text:
                return text
    return ""


def _looks_like_rate_limit(text: str) -> bool:
    t = (text or "").lower()
    if not t:
        return False
    if "too many request" in t:
        return True
    if "rate_limit" in t or "ratelimit" in t:
        return True
    if "rate limit" in t and ("exceed" in t or "429" in t or "error" in t):
        return True
    if "429" in t and ("too many" in t or "rate" in t):
        return True
    return False


def _looks_like_quota_exhausted(text: str) -> bool:
    t = (text or "").lower()
    if not t:
        return False
    if "insufficient_quota" in t or "exceeded your current quota" in t:
        return True
    if "quota" in t and ("exceed" in t or "exhaust" in t or "用尽" in t or "不足" in t):
        return True
    if "余额不足" in (text or "") or "额度用尽" in (text or "") or "欠费" in (text or ""):
        return True
    return False


def _is_rate_limit_response(status_code: int, text: str) -> bool:
    """Only HTTP 429, or other 4xx whose body is clearly a rate-limit error.

    Do not treat 200/5xx bodies that happen to mention 429/rate as限流.
    """
    if status_code == 429:
        return True
    if 400 <= status_code < 500:
        return _looks_like_rate_limit(text) and not _looks_like_quota_exhausted(text)
    return False


def _is_quota_response(status_code: int, text: str) -> bool:
    if status_code == 402:
        return True
    if 400 <= status_code < 500:
        return _looks_like_quota_exhausted(text)
    return False


def _interruptible_sleep(seconds: float, cancel_event: threading.Event | None) -> float:
    end = time.time() + max(0.0, seconds)
    slept = 0.0
    while True:
        if cancel_event is not None and cancel_event.is_set():
            break
        remaining = end - time.time()
        if remaining <= 0:
            break
        wait = min(1.0, remaining)
        time.sleep(wait)
        slept += wait
    return slept


class AgentLoop:
    def __init__(
        self,
        *,
        project_id: int,
        role: str,
        phase: str,
        system_prompt: str,
        user_prompt: str,
        phase_run_id: int | None = None,
        worker_id: str | None = None,
        vuln_id: int | None = None,
        cancel_event: threading.Event | None = None,
        pause_event: threading.Event | None = None,
        timeout_sec: int | None = None,
        context_window: int | None = None,
        stop_when: Callable[[dict[str, Any]], bool] | None = None,
        llm: ResolvedLlm | None = None,
        messages: list[dict[str, Any]] | None = None,
        resumed: bool = False,
        file_path: str | None = None,
        silent: bool = False,
        log_path: Path | str | None = None,
        workspace_root: Path | str | None = None,
        max_turns: int | None = None,
        summary_dir: Path | str | None = None,
    ) -> None:
        self.project_id = project_id
        self.role = role
        self.phase = phase
        self.system_prompt = system_prompt
        self.user_prompt = user_prompt
        self.phase_run_id = phase_run_id
        self.worker_id = worker_id
        self.vuln_id = vuln_id
        self.file_path = file_path
        self.silent = bool(silent)
        self.log_path = Path(log_path) if log_path else None
        self.workspace_root = str(workspace_root) if workspace_root else None
        self.max_turns = int(max_turns) if max_turns else None
        self.summary_dir = Path(summary_dir) if summary_dir else None
        self.cancel_event = cancel_event or threading.Event()
        self.pause_event = pause_event
        self.timeout_sec = timeout_sec or settings.timeout_worker_round
        self.context_window = context_window or settings.default_context_window
        self.stop_when = stop_when
        self._llm_injected = llm is not None
        self.llm = llm or resolve_llm(llm_role_for_agent(role), project_id=project_id or None)
        self._slot_handle: SlotHandle | None = None
        self.state: dict[str, Any] = {}
        self.watchdog = AgentWatchdog(phase=phase, project_id=project_id)
        self._last_prompt_tokens = 0
        self._initial_messages = messages
        self._resumed = resumed
        self._announce_next_chat = bool(resumed)
        self._rate_limit_retries = 0
        self._transient_retries = 0
        if self.silent and self.log_path:
            from ..services.cli_tool_index import file_event_log

            self._live = file_event_log(self.log_path)
        else:
            self._live = live_log

    def _bind_slot_endpoint(self, handle: SlotHandle) -> None:
        """Apply acquired pool endpoint credentials onto self.llm."""
        self._slot_handle = handle
        if self._llm_injected and not handle.endpoint_id.startswith("ep-"):
            # Test / anonymous override bucket — keep injected ResolvedLlm as-is
            if handle.endpoint_id == "_anon":
                return
        url, key, model = llm_thread_limiter.endpoint_creds(handle.endpoint_id)
        if not url:
            # Fall back to resolved pool entry
            for ep in pool_endpoints_resolved():
                if ep.id == handle.endpoint_id:
                    self.llm = bind_llm_to_endpoint(self.llm, ep)
                    return
            return
        from ..services.llm_settings import PoolEndpoint

        self.llm = bind_llm_to_endpoint(
            self.llm,
            PoolEndpoint(
                id=handle.endpoint_id,
                base_url=url,
                api_key=key or self.llm.api_key,
                model=model,
                max_inflight=1,
            ),
        )

    @classmethod
    def from_checkpoint(
        cls,
        cp: LoopCheckpoint,
        *,
        cancel_event: threading.Event | None = None,
        pause_event: threading.Event | None = None,
        stop_when: Callable[[dict[str, Any]], bool] | None = None,
        context_window: int | None = None,
        timeout_sec: int | None = None,
        llm: ResolvedLlm | None = None,
        resumed: bool = True,
    ) -> AgentLoop:
        loop = cls(
            project_id=cp.project_id,
            role=cp.role,
            phase=cp.phase,
            system_prompt=cp.system_prompt,
            user_prompt=cp.user_prompt,
            phase_run_id=cp.phase_run_id,
            worker_id=cp.worker_id,
            vuln_id=cp.vuln_id,
            cancel_event=cancel_event,
            pause_event=pause_event,
            timeout_sec=timeout_sec or cp.timeout_sec,
            context_window=context_window,
            stop_when=stop_when,
            llm=llm,
            messages=list(cp.messages),
            resumed=resumed,
            file_path=cp.file_path,
        )
        loop.state = dict(cp.state or {})
        loop.watchdog = AgentWatchdog.restore(cp.watchdog)
        if not loop.watchdog.project_id:
            loop.watchdog.project_id = cp.project_id
        loop._last_prompt_tokens = cp.last_prompt_tokens
        loop._rate_limit_retries = cp.rate_limit_retries
        loop._transient_retries = cp.transient_retries
        return loop

    def _cancelled(self) -> bool:
        return self.cancel_event.is_set()

    def _paused(self) -> bool:
        return self.pause_event is not None and self.pause_event.is_set()

    def _phase_run_active(self) -> bool:
        """False if this run was cancelled/finished externally (e.g. heuristic reset)."""
        if not self.phase_run_id:
            return True
        try:
            with SessionLocal() as db:
                pr = db.get(PhaseRun, self.phase_run_id)
                if not pr:
                    return False
                return pr.status in ("running", "paused")
        except Exception:  # noqa: BLE001
            return True

    def _wait_while_paused(self) -> bool:
        if self.pause_event is None:
            return True
        while self.pause_event.is_set():
            if self._cancelled():
                return False
            # Event.wait() returns immediately when already set; sleep until cleared.
            time.sleep(0.05)
        return not self._cancelled()

    def _persist(self, messages: list[dict[str, Any]], *, status: str = "running") -> None:
        if not self.phase_run_id:
            return
        from ..services.decompile_store import app_db_write

        try:
            with app_db_write():
                save_checkpoint(
                    LoopCheckpoint(
                        project_id=self.project_id,
                        phase_run_id=self.phase_run_id,
                        role=self.role,
                        phase=self.phase,
                        system_prompt=self.system_prompt,
                        user_prompt=self.user_prompt,
                        messages=list(messages),
                        state=dict(self.state),
                        worker_id=self.worker_id,
                        vuln_id=self.vuln_id,
                        file_path=self.file_path,
                        watchdog=self.watchdog.snapshot(),
                        last_prompt_tokens=self._last_prompt_tokens,
                        timeout_sec=self.timeout_sec,
                        rate_limit_retries=self._rate_limit_retries,
                        transient_retries=self._transient_retries,
                    ),
                    status=status,
                )
        except Exception as e:  # noqa: BLE001
            try:
                self._live.system(
                    self.project_id,
                    f"检查点保存失败（已跳过，本轮继续）: {e}",
                    phase=self.phase,
                    role=self.role,
                )
            except Exception:  # noqa: BLE001
                pass

    def _maybe_grant_review_wrapup_grace(
        self, messages: list[dict[str, Any]], remaining: float
    ) -> bool:
        """One-shot deadline extension when reviewer is wrapping up after verify."""
        if not should_grant_wrapup_grace(
            self.state, phase=self.phase, remaining=remaining
        ):
            return False
        grace = max(1, int(getattr(settings, "timeout_reviewer_wrapup_grace", 600) or 600))
        verified = bool(self.state.get("review_verified"))
        mark_grace_used(self.state)
        nudge = wrapup_grace_nudge(verified=verified, grace_sec=grace)
        messages.append({"role": "user", "content": nudge})
        self._live.system(
            self.project_id,
            f"审核收尾宽限 {grace}s（漏洞已验证或文档收尾中，催立刻 ConfirmVuln）",
            phase=self.phase,
            role=self.role,
        )
        return True

    def run(self) -> LoopResult:
        prefer = self.llm.endpoint_id if (self.llm.endpoint_id and not self._llm_injected) else None
        with llm_thread_slot(
            self.cancel_event,
            project_id=self.project_id,
            phase=self.phase,
            role=self.role,
            prefer_endpoint=prefer,
        ) as handle:
            if handle is None:
                result = LoopResult(ok=False, state=self.state)
                result.cancelled = True
                result.stop_reason = "cancelled"
                return result
            if not self._llm_injected:
                self._bind_slot_endpoint(handle)
            else:
                self._slot_handle = handle
            return self._run_loop()

    def _run_loop(self) -> LoopResult:
        if not self.silent:
            register_loop(self)
        try:
            return self._run_loop_inner()
        except OperationalError as e:
            if "locked" not in str(e).lower() and "busy" not in str(e).lower():
                raise
            try:
                self._live.system(
                    self.project_id,
                    "数据库忙，本轮保留检查点稍后继续",
                    phase=self.phase,
                    role=self.role,
                )
            except Exception:  # noqa: BLE001
                pass
            result = LoopResult(ok=False, state=self.state)
            result.cancelled = True
            result.error = str(e)
            result.stop_reason = "db_locked"
            return result
        finally:
            if not self.silent:
                unregister_loop(self)

    def _run_loop_inner(self) -> LoopResult:
        deadline = time.time() + max(60, self.timeout_sec)
        if self._initial_messages:
            messages: list[dict[str, Any]] = list(self._initial_messages)
        else:
            messages = [
                {"role": "system", "content": self.system_prompt},
                {"role": "user", "content": self.user_prompt},
            ]
        if self._resumed:
            last = messages[-1] if messages else {}
            if last.get("role") != "user" or last.get("content") != INTERRUPT_RESUME:
                messages.append({"role": "user", "content": INTERRUPT_RESUME})
            self._resumed = False
        tools = registry.openai_tools_for_role(
            self.role, project_id=self.project_id, vuln_id=self.vuln_id
        )
        result = LoopResult(ok=False, state=self.state)
        self._persist(messages)

        while True:
            if self._cancelled():
                result.cancelled = True
                result.stop_reason = "cancelled"
                return result
            if self._paused():
                self._persist(messages, status="paused")
                paused_at = time.time()
                if not self._wait_while_paused():
                    result.cancelled = True
                    result.stop_reason = "cancelled"
                    return result
                if not self._phase_run_active():
                    result.cancelled = True
                    result.stop_reason = "cancelled"
                    return result
                deadline += time.time() - paused_at
                self._persist(messages, status="running")
                continue
            if self._enforce_token_budget():
                continue
            remaining = deadline - time.time()
            if self._maybe_grant_review_wrapup_grace(messages, remaining):
                grace = max(
                    1, int(getattr(settings, "timeout_reviewer_wrapup_grace", 600) or 600)
                )
                deadline += grace
                remaining = deadline - time.time()
                self._persist(messages)
                continue
            if remaining <= 0:
                result.timed_out = True
                result.stop_reason = "timeout"
                self._rescue_conclude(messages)
                return result

            est = estimate_tokens(messages, tools)
            if needs_compress(
                messages,
                self.context_window,
                tools=tools,
                last_prompt_tokens=self._last_prompt_tokens,
            ):
                self._live.system(
                    self.project_id,
                    (
                        f"上下文压缩：估计 {est} token / 窗口 {self.context_window}"
                        f"（上回 API prompt {self._last_prompt_tokens}），已落盘并新开上下文"
                    ),
                    phase=self.phase,
                )
                messages = self._compress(messages)
                self._last_prompt_tokens = 0
                self._persist(messages)

            self._maybe_inject_todolist(messages)
            self._maybe_inject_steer(messages)
            self._maybe_inject_decompile_notices(messages)

            try:
                resp, usage, retry_after = self._chat(messages, tools, remaining)
            except AuthError as e:
                eid = self.llm.endpoint_id or (self._slot_handle.endpoint_id if self._slot_handle else "")
                llm_gate.note_error(eid, "auth", message=str(e))
                # Try another endpoint before giving up
                if self._slot_handle is not None and not self._llm_injected:
                    rebound = llm_thread_limiter.rebind(
                        self._slot_handle,
                        cancel_event=self.cancel_event,
                        project_id=self.project_id,
                        phase=self.phase,
                        role=self.role,
                        reason="401 密钥无效",
                    )
                    if rebound is not None and rebound.endpoint_id != self._slot_handle.endpoint_id:
                        self._bind_slot_endpoint(rebound)
                        self._live.system(
                            self.project_id,
                            f"端点密钥无效，已切换到 {rebound.endpoint_id}",
                            phase=self.phase,
                            role=self.role,
                        )
                        self._persist(messages)
                        continue
                result.error = str(e)
                result.stop_reason = "auth_error"
                self._live.error(self.project_id, str(e), phase=self.phase)
                self._persist(messages, status="paused")
                return result
            except RateLimitError as e:
                eid = self.llm.endpoint_id or (self._slot_handle.endpoint_id if self._slot_handle else "")
                kind = "quota" if getattr(e, "quota", False) else "rate_limit"
                llm_gate.note_error(
                    eid,
                    kind,
                    retry_after=e.retry_after,
                    message=str(e),
                )
                if self._rate_limit_retries >= settings.rate_limit_max_retries:
                    result.rate_limited_exhausted = True
                    result.error = str(e)
                    result.stop_reason = "rate_limit_exhausted"
                    self._rescue_conclude(messages)
                    return result
                self._rate_limit_retries += 1
                # Prefer immediate failover to another healthy endpoint
                if self._slot_handle is not None and not self._llm_injected:
                    rebound = llm_thread_limiter.rebind(
                        self._slot_handle,
                        cancel_event=self.cancel_event,
                        project_id=self.project_id,
                        phase=self.phase,
                        role=self.role,
                        reason="额度用尽" if kind == "quota" else "429 限流",
                    )
                    if rebound is not None:
                        if rebound.endpoint_id != eid:
                            self._bind_slot_endpoint(rebound)
                        self._persist(messages)
                        continue
                sleep_sec = e.retry_after or settings.rate_limit_sleep_sec
                if kind == "quota":
                    sleep_sec = min(float(sleep_sec), 60.0)
                self._live.system(
                    self.project_id,
                    f"检测到 API {'额度' if kind == 'quota' else '429'}，休眠 {sleep_sec:.0f}s 后继续"
                    f"（{self._rate_limit_retries}/{settings.rate_limit_max_retries}）",
                    phase=self.phase,
                )
                slept = _interruptible_sleep(float(sleep_sec), self.cancel_event)
                deadline += slept
                self._persist(messages)
                continue
            except TransientError as e:
                if self._transient_retries >= settings.request_backoff_retries:
                    result.error = str(e)
                    result.stop_reason = "transient_error"
                    self._live.error(self.project_id, str(e), phase=self.phase)
                    self._rescue_conclude(messages)
                    return result
                self._transient_retries += 1
                self._live.system(
                    self.project_id,
                    (
                        f"模型请求中断，保留上下文继续"
                        f"（{self._transient_retries}/{settings.request_backoff_retries}）: {e}"
                    ),
                    phase=self.phase,
                    role=self.role,
                )
                last = messages[-1] if messages else {}
                if last.get("role") != "user" or last.get("content") != TRANSIENT_RESUME:
                    messages.append({"role": "user", "content": TRANSIENT_RESUME})
                self._persist(messages)
                continue

            self._transient_retries = 0
            self._accumulate_tokens(result, usage)
            self._enforce_token_budget()
            self._last_prompt_tokens = usage.get("prompt_tokens", 0)
            self._live.tokens(
                self.project_id,
                input_tokens=usage.get("prompt_tokens", 0),
                output_tokens=usage.get("completion_tokens", 0),
                cached=usage.get("cached_tokens", 0),
                total=usage.get("total_tokens", 0),
                phase=self.phase,
                role=self.role,
            )

            choice = (resp.get("choices") or [None])[0]
            if not choice:
                self._live.system(self.project_id, "空 choices，重试一次", phase=self.phase)
                messages.append({"role": "user", "content": "上一轮模型返回空 choices，请继续任务。"})
                self._persist(messages)
                continue

            message = choice.get("message") or {}
            content = _content_text(message)
            reasoning = _reasoning_text(message)
            tool_calls = message.get("tool_calls") or []
            tool_names = _tool_call_names(tool_calls)
            if reasoning:
                self._live.reasoning(self.project_id, reasoning, phase=self.phase, role=self.role)
            if content:
                self._live.agent(self.project_id, content, phase=self.phase, role=self.role)
            if tool_names:
                self._live.agent(
                    self.project_id,
                    "调用工具: " + ", ".join(tool_names),
                    phase=self.phase,
                    role=self.role,
                )
            assistant_msg: dict[str, Any] = {"role": "assistant", "content": content}
            if tool_calls:
                assistant_msg["tool_calls"] = tool_calls
            if reasoning:
                assistant_msg["reasoning_content"] = reasoning
            messages.append(assistant_msg)
            self._persist(messages)
            persist_nudge = self.watchdog.note_turn(tool_names)

            if not tool_calls:
                if self.stop_when and self.stop_when(self.state):
                    result.ok = True
                    result.stop_reason = "stop_when"
                    return result
                nudge, kind = self.watchdog.nudge_for_text_turn()
                self._live.system(
                    self.project_id,
                    self.watchdog.text_turn_log(kind),
                    phase=self.phase,
                    role=self.role,
                )
                if persist_nudge:
                    nudge = f"{nudge}\n\n{persist_nudge}"
                    self._live.system(
                        self.project_id,
                        self.watchdog.persist_nudge_log(),
                        phase=self.phase,
                        role=self.role,
                    )
                messages.append({"role": "user", "content": nudge})
                self._persist(messages)
                continue

            parsed_calls = []
            parse_failed = False
            for tc in tool_calls:
                fn = tc.get("function") or {}
                name = fn.get("name") or ""
                raw_args = fn.get("arguments") or "{}"
                try:
                    args = json.loads(raw_args) if isinstance(raw_args, str) else (raw_args or {})
                except json.JSONDecodeError:
                    parse_failed = True
                    args = {}
                    tool_result = {"ok": False, "error": "tool arguments JSON 无效"}
                    self._live.cmd(
                        self.project_id,
                        f"{name} {raw_args}",
                        output="tool arguments JSON 无效",
                        exit_code=1,
                        phase=self.phase,
                        tool=name or None,
                        role=self.role,
                    )
                    messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": tc.get("id") or name,
                            "content": json.dumps(tool_result, ensure_ascii=False),
                        }
                    )
                    self._persist(messages)
                    continue
                parsed_calls.append({"name": name, "arguments": args, "id": tc.get("id")})

            loop_reason = self.watchdog.observe_tools(parsed_calls)
            if loop_reason:
                tool_name = (loop_reason.split(":")[-1] or "").strip() or (
                    parsed_calls[0]["name"] if parsed_calls else "unknown"
                )
                # DecompileJava pending polls: soft redirect, do not burn abort budget
                pending_decompile = False
                if tool_name == "DecompileJava" and parsed_calls:
                    try:
                        from ..services.decompile_java import is_pending_decompile_query

                        pending_decompile = all(
                            c.get("name") == "DecompileJava"
                            and is_pending_decompile_query(c.get("arguments") or {}, self.project_id)
                            for c in parsed_calls
                        )
                    except Exception:  # noqa: BLE001
                        pending_decompile = False
                if pending_decompile:
                    self.watchdog.identical_threshold_hits = max(
                        0, int(self.watchdog.identical_threshold_hits) - 1
                    )
                    redirect = (
                        "看门狗导向：DecompileJava 任务仍在排队/运行中，请不要反复同参查询。"
                        "请立刻去做 Read/Grep/写文档或其它分析；完成后系统会注入通知，也可用 job_id 稍后再查。"
                    )
                    self._live.system(
                        self.project_id,
                        "看门狗导向：DecompileJava 仍在运行，已提示改做其它工作（不计入终止额度）",
                        phase=self.phase,
                        role=self.role,
                    )
                    for call in parsed_calls:
                        messages.append(
                            {
                                "role": "tool",
                                "tool_call_id": call.get("id") or call["name"],
                                "content": json.dumps(
                                    {
                                        "ok": True,
                                        "status": "running",
                                        "hint": redirect,
                                    },
                                    ensure_ascii=False,
                                ),
                            }
                        )
                    messages.append({"role": "user", "content": redirect})
                    self._persist(messages)
                    continue
                err_text = identical_tool_nudge(tool_name, self.watchdog.max_same_tool_calls)
                hit = self.watchdog.identical_threshold_hits
                max_hits = self.watchdog.max_identical_threshold_hits
                aborting = self.watchdog.identical_loop_exhausted()
                self._live.system(
                    self.project_id,
                    (
                        f"看门狗终止：{loop_reason}，本轮已 {hit} 次触达阈值，结束本轮"
                        if aborting
                        else (
                            f"看门狗导向：{loop_reason}（本轮第 {hit}/{max_hits} 次），"
                            "已重置拦截窗口"
                        )
                    ),
                    phase=self.phase,
                    role=self.role,
                )
                tool_result = {"ok": False, "error": err_text}
                for call in parsed_calls:
                    self._live.cmd(
                        self.project_id,
                        f"{call['name']} {json.dumps(call.get('arguments') or {}, ensure_ascii=False)}",
                        output=err_text,
                        exit_code=1,
                        phase=self.phase,
                        tool=call["name"] or None,
                        role=self.role,
                    )
                    messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": call.get("id") or call["name"],
                            "content": json.dumps(tool_result, ensure_ascii=False),
                        }
                    )
                if aborting:
                    abort_text = identical_abort_nudge(tool_name, hit)
                    messages.append({"role": "user", "content": abort_text})
                    self._persist(messages)
                    result.ok = False
                    result.loop_aborted = True
                    result.stop_reason = "identical_tool_loop"
                    result.error = abort_text
                    self._rescue_conclude(messages)
                    return result
                redirect = identical_redirect_nudge(tool_name, hit, max_hits)
                if persist_nudge:
                    self._live.system(
                        self.project_id,
                        self.watchdog.persist_nudge_log(),
                        phase=self.phase,
                        role=self.role,
                    )
                    redirect = f"{redirect}\n\n{persist_nudge}"
                self.watchdog.note_tool_results(failed=True)
                messages.append({"role": "user", "content": redirect})
                self._persist(messages)
                continue

            # Dispatch: parallel-safe first batch then serial
            any_failed = parse_failed
            ctx = ToolContext(
                project_id=self.project_id,
                role=self.role,
                phase=self.phase,
                phase_run_id=self.phase_run_id,
                worker_id=self.worker_id,
                vuln_id=self.vuln_id,
                file_path=self.file_path,
                workspace_root=self.workspace_root,
                silent=self.silent,
                log_path=str(self.log_path) if self.log_path else None,
                cancel_requested=self._cancelled,
                state=self.state,
            )
            for call in parsed_calls:
                if self._cancelled():
                    result.cancelled = True
                    result.stop_reason = "cancelled"
                    return result
                tr = registry.dispatch(ctx, call["name"], call["arguments"])
                # AskUser parks without a tool result; the consent API appends it later.
                if ctx.state.get("awaiting_user") and call["name"] == "AskUser":
                    self._persist(messages, status="awaiting_user")
                    self._live.system(
                        self.project_id,
                        f"Verifier 等待用户确认互联网复测 vuln={self.vuln_id}",
                        phase=self.phase,
                        role=self.role,
                    )
                    result.ok = True
                    result.stop_reason = "awaiting_user"
                    result.state = self.state
                    return result
                if self.phase == "reviewer":
                    note_tool_for_wrapup(
                        self.state,
                        name=call["name"],
                        arguments=call.get("arguments") or {},
                        result=tr if isinstance(tr, dict) else {},
                        vuln_id=self.vuln_id,
                    )
                if isinstance(tr, dict) and tr.get("ok") is False:
                    any_failed = True
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": call.get("id") or call["name"],
                        "content": json.dumps(tr, ensure_ascii=False),
                    }
                )
            self._persist(messages)
            self.watchdog.note_tool_results(failed=any_failed)

            if self.stop_when and self.stop_when(self.state):
                result.ok = True
                result.stop_reason = "stop_when"
                result.state = self.state
                if self.state.get("round_finished") and self.phase == "worker":
                    path, summary = self._conclude_round(messages)
                    result.summary_path = path
                    result.round_summary = summary
                    result.stop_reason = "round_finished"
                return result

            # Terminal tool flags
            if self.state.get("recon_finished") or self.state.get("audit_finished") or self.state.get("review_done") or self.state.get("fix_finished") or self.state.get("round_finished") or self.state.get("index_done"):
                # round_finished alone shouldn't end entire worker process — scheduler decides
                if self.state.get("round_finished") and self.phase == "worker":
                    result.ok = True
                    result.stop_reason = "round_finished"
                    path, summary = self._conclude_round(messages)
                    result.summary_path = path
                    result.round_summary = summary
                    return result
                if self.state.get("recon_finished") or self.state.get("audit_finished") or self.state.get("review_done") or self.state.get("fix_finished") or self.state.get("index_done"):
                    result.ok = True
                    result.stop_reason = "phase_tool_finished"
                    return result

            if persist_nudge:
                self._live.system(
                    self.project_id,
                    self.watchdog.persist_nudge_log(),
                    phase=self.phase,
                    role=self.role,
                )
                messages.append({"role": "user", "content": persist_nudge})
                self._persist(messages)

            if self.max_turns:
                self.state["index_rounds"] = self.watchdog.turn_count
                left = self.max_turns - self.watchdog.turn_count
                if self.watchdog.turn_count >= self.max_turns:
                    if self.stop_when and self.stop_when(self.state):
                        result.ok = True
                        result.stop_reason = "stop_when"
                        result.state = self.state
                        return result
                    result.ok = False
                    result.stop_reason = "max_turns"
                    result.error = f"超过 {self.max_turns} 轮仍未完成"
                    result.state = self.state
                    self._rescue_conclude(messages)
                    conclude = (self.summary_dir / "conclude.md") if self.summary_dir else None
                    if conclude and conclude.is_file():
                        result.summary_path = str(conclude)
                        result.round_summary = conclude.read_text(encoding="utf-8", errors="replace")
                    return result
                if left in (5, 1):
                    if self.phase in ("reviewer-lab", "reviewer_lab"):
                        warn = (
                            f"还剩 {left} 轮。若靶场仍不可用，FinishLab(skipped=true, reason=...)；"
                            "否则 FinishLab() 结束搭建。"
                        )
                    else:
                        warn = (
                            f"还剩 {left} 轮，请立刻 FinishIndex(description=..., entry=...)。"
                            "超时将 conclude 并落盘失败原因。"
                        )
                    self._live.system(self.project_id, warn, phase=self.phase, role=self.role)
                    messages.append({"role": "user", "content": warn})
                    self._persist(messages)

    def _chat_endpoint_label(self) -> str:
        eid = self.llm.endpoint_id or (
            self._slot_handle.endpoint_id if self._slot_handle else ""
        )
        return eid or "default"

    def _rebuild_chat_request(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> tuple[bool, str, dict[str, str], dict[str, Any], Any]:
        anthropic = is_anthropic_wire(self.llm.wire_api)
        if anthropic:
            url = anthropic_url(self.llm.base_url)
            headers = anthropic_headers(self.llm.api_key)
            body = build_anthropic_body(
                model=self.llm.model,
                messages=messages,
                tools=tools,
                stream=True,
                temperature=sampling_temperature(self.llm.model, settings.temperature),
            )
            return True, url, headers, body, consume_anthropic_stream
        url = self.llm.base_url.rstrip("/") + "/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.llm.api_key}",
            "Content-Type": "application/json",
        }
        body = {
            "model": self.llm.model,
            "messages": _sanitize_chat_messages(messages, model=self.llm.model),
            "tools": tools,
            "tool_choice": "auto",
            "stream": True,
            "stream_options": {"include_usage": True},
        }
        prepare_chat_body(body, self.llm.model, temperature=settings.temperature)
        return False, url, headers, body, consume_chat_stream

    def _try_rebind_endpoint(self, reason: str) -> bool:
        """Cool current endpoint already noted; switch slot to another if possible."""
        if self._slot_handle is None or self._llm_injected:
            return False
        old_id = self._slot_handle.endpoint_id
        rebound = llm_thread_limiter.rebind(
            self._slot_handle,
            cancel_event=self.cancel_event,
            project_id=self.project_id,
            phase=self.phase,
            role=self.role,
            reason=reason,
        )
        if rebound is None:
            return False
        if rebound.endpoint_id != old_id:
            self._bind_slot_endpoint(rebound)
        # Same endpoint after cooldown wait: still retry the request
        return True

    def _chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        remaining: float,
    ) -> tuple[dict[str, Any], dict[str, int], float | None]:
        last_err: Exception | None = None
        est_tokens = estimate_tokens(messages, tools)
        # Allow extra attempts when failing over across endpoints
        max_attempts = max(
            settings.request_backoff_retries,
            settings.request_backoff_retries + max(0, len(pool_endpoints_resolved()) - 1),
        )
        for attempt in range(max_attempts):
            if self._cancelled():
                raise TransientError("cancelled")
            _anthropic, url, headers, body, consume = self._rebuild_chat_request(messages, tools)
            for drop_key in list(self.state.get("_chat_drop_keys") or []):
                body.pop(drop_key, None)
            eid = self._chat_endpoint_label()
            try:
                timeout = chat_http_timeout(remaining, est_tokens)
                cd = llm_gate.cooldown_remaining(eid)
                if cd > 0 and cd != float("inf"):
                    # Prefer failover over waiting when another endpoint is free
                    if self._try_rebind_endpoint("当前端点冷却中"):
                        continue
                    self._live.system(
                        self.project_id,
                        f"端点 {eid} 冷却中，约 {cd:.0f}s 后请求模型",
                        phase=self.phase,
                        role=self.role,
                    )
                if attempt > 0:
                    self._live.system(
                        self.project_id,
                        f"正在重新请求模型（{attempt + 1}/{max_attempts}，端点 {eid}）",
                        phase=self.phase,
                        role=self.role,
                    )
                    self._announce_next_chat = False
                if self._announce_next_chat:
                    self._live.system(
                        self.project_id,
                        f"正在请求模型（流式，端点 {eid}，估计 {est_tokens} token，读超时 {timeout.read:.0f}s）",
                        phase=self.phase,
                        role=self.role,
                    )
                    self._announce_next_chat = False
                with llm_slot(self.cancel_event) as got_slot:
                    if not got_slot:
                        raise TransientError("cancelled")
                    with chat_http_client(timeout=timeout) as client:
                        status, header_map, data, err_text = self._stream_chat_with_heartbeat(
                            client, url, headers, body, est_tokens, consume=consume
                        )
                if status == 401:
                    llm_gate.note_error(eid, "auth", message=(err_text or "")[:240])
                    if self._try_rebind_endpoint("401 密钥无效"):
                        continue
                    raise AuthError("401 密钥无效，请检查设置页模型配置")
                if _is_quota_response(status, err_text or ""):
                    self._live.system(
                        self.project_id,
                        f"LLM HTTP {status} 额度用尽：{(err_text or '')[:240]}",
                        phase=self.phase,
                        role=self.role,
                    )
                    llm_gate.note_error(eid, "quota", message=(err_text or "")[:240])
                    if self._try_rebind_endpoint("额度用尽"):
                        continue
                    raise RateLimitError("quota exhausted", quota=True)
                if _is_rate_limit_response(status, err_text or ""):
                    retry_after = None
                    ra = header_map.get("retry-after") or header_map.get("Retry-After")
                    if ra:
                        try:
                            retry_after = float(ra)
                        except ValueError:
                            retry_after = None
                    self._live.system(
                        self.project_id,
                        f"LLM HTTP {status} 限流：{(err_text or '')[:240]}",
                        phase=self.phase,
                        role=self.role,
                    )
                    llm_gate.note_error(
                        eid, "rate_limit", retry_after=retry_after, message=(err_text or "")[:240]
                    )
                    if self._try_rebind_endpoint("429 限流"):
                        continue
                    raise RateLimitError("429 rate limited", retry_after=retry_after)
                if status >= 500:
                    llm_gate.note_error(
                        eid, "transient", message=f"HTTP {status}: {(err_text or '')[:200]}"
                    )
                    if self._try_rebind_endpoint(f"HTTP {status}"):
                        continue
                    raise TransientError(f"HTTP {status}: {(err_text or '')[:300]}")
                if status == 400:
                    drop_key = param_to_drop(body, err_text)
                    if drop_key:
                        # Mutate for next rebuild — prepare_chat_body may re-add; strip after rebuild
                        self._live.system(
                            self.project_id,
                            f"HTTP 400，去掉 {drop_key} 后重试：{(err_text or '')[:180]}",
                            phase=self.phase,
                            role=self.role,
                        )
                        # Retry same endpoint with stripped field via body patch on next loop:
                        # apply strip after rebuild by stashing
                        self.state.setdefault("_chat_drop_keys", [])
                        if drop_key not in self.state["_chat_drop_keys"]:
                            self.state["_chat_drop_keys"].append(drop_key)
                        continue
                if status >= 400:
                    raise TransientError(f"HTTP {status}: {(err_text or '')[:300]}")
                if not data:
                    raise TransientError(err_text or "empty chat response")
                llm_gate.note_success(eid)
                usage_raw = data.get("usage") or {}
                cached = 0
                details = usage_raw.get("prompt_tokens_details") or {}
                if isinstance(details, dict):
                    cached = int(details.get("cached_tokens") or 0)
                if not cached:
                    cached = int(usage_raw.get("cached_tokens") or 0)
                usage = {
                    "prompt_tokens": int(usage_raw.get("prompt_tokens") or 0),
                    "completion_tokens": int(usage_raw.get("completion_tokens") or 0),
                    "cached_tokens": cached,
                    "total_tokens": int(usage_raw.get("total_tokens") or 0),
                }
                return data, usage, None
            except (AuthError, RateLimitError):
                raise
            except ChatStreamCancelled:
                raise TransientError("cancelled")
            except ChatStreamProviderError as e:
                text = str(e)
                if _looks_like_quota_exhausted(text):
                    llm_gate.note_error(eid, "quota", message=text[:240])
                    if self._try_rebind_endpoint("额度用尽"):
                        continue
                    raise RateLimitError("quota exhausted", quota=True) from e
                if _looks_like_rate_limit(text):
                    self._live.system(
                        self.project_id,
                        f"LLM 流式限流：{text[:240]}",
                        phase=self.phase,
                        role=self.role,
                    )
                    llm_gate.note_error(eid, "rate_limit", message=text[:240])
                    if self._try_rebind_endpoint("429 限流"):
                        continue
                    raise RateLimitError("429 rate limited") from e
                llm_gate.note_error(eid, "transient", message=text[:240])
                if self._try_rebind_endpoint("流式错误"):
                    continue
                last_err = e
                backoff = 1 * (4 ** min(attempt, 3))
                self._live.system(
                    self.project_id,
                    f"请求失败，{backoff}s 后重试（{attempt + 1}/{max_attempts}）: {e}",
                    phase=self.phase,
                    role=self.role,
                )
                _interruptible_sleep(float(backoff), self.cancel_event)
            except Exception as e:  # noqa: BLE001
                last_err = e
                backoff = 1 * (4 ** min(attempt, 3))
                self._live.system(
                    self.project_id,
                    f"请求失败，{backoff}s 后重试（{attempt + 1}/{max_attempts}）: {e}",
                    phase=self.phase,
                    role=self.role,
                )
                _interruptible_sleep(float(backoff), self.cancel_event)
        raise TransientError(str(last_err) if last_err else "chat failed")

    def _stream_chat_with_heartbeat(
        self,
        client,
        url: str,
        headers: dict[str, str],
        body: dict[str, Any],
        est_tokens: int,
        *,
        consume=consume_chat_stream,
    ) -> tuple[int, dict[str, str], dict[str, Any] | None, str]:
        stop_hb = threading.Event()
        first_payload = threading.Event()
        started = time.time()

        def _hb() -> None:
            if stop_hb.wait(CHAT_WAIT_LOG_AFTER):
                return
            while not stop_hb.is_set():
                elapsed = int(time.time() - started)
                if first_payload.is_set():
                    self._live.system(
                        self.project_id,
                        f"仍在接收流式响应（已 {elapsed}s）",
                        phase=self.phase,
                        role=self.role,
                    )
                else:
                    self._live.system(
                        self.project_id,
                        f"仍在等待模型响应（已 {elapsed}s，估计 {est_tokens} token）",
                        phase=self.phase,
                        role=self.role,
                    )
                if stop_hb.wait(CHAT_WAIT_LOG_EVERY):
                    return

        def _on_first_payload() -> None:
            first_payload.set()
            elapsed = time.time() - started
            if elapsed >= CHAT_WAIT_LOG_AFTER:
                self._live.system(
                    self.project_id,
                    f"已开始接收流式响应（已 {int(elapsed)}s）",
                    phase=self.phase,
                    role=self.role,
                )

        hb = threading.Thread(
            target=_hb,
            name=f"vh-chat-hb-{self.project_id}-{self.phase}",
            daemon=True,
        )
        hb.start()
        try:
            with client.stream("POST", url, headers=headers, json=body) as r:
                header_map = {str(k): str(v) for k, v in r.headers.items()}
                status = int(r.status_code)
                if status != 200:
                    err_text = r.read().decode("utf-8", errors="replace")
                    return status, header_map, None, err_text
                data = consume(
                    r.iter_lines(),
                    cancel_check=self._cancelled,
                    on_first_payload=_on_first_payload,
                )
                return status, header_map, data, ""
        finally:
            first_payload.set()
            stop_hb.set()

    def _enforce_token_budget(self) -> bool:
        """Pause the project when input+output spend hits the configured cap."""
        if self.silent or not self.project_id:
            return False
        try:
            from ..services.token_budget import maybe_pause_for_token_budget

            return maybe_pause_for_token_budget(self.project_id)
        except Exception:  # noqa: BLE001
            return False

    def _accumulate_tokens(self, result: LoopResult, usage: dict[str, int]) -> None:
        result.tokens_input += usage.get("prompt_tokens", 0)
        result.tokens_output += usage.get("completion_tokens", 0)
        result.tokens_cached += usage.get("cached_tokens", 0)
        result.tokens_total = result.tokens_input + result.tokens_output
        if self.silent or not self.project_id:
            return
        from ..services.decompile_store import app_db_write

        try:
            with app_db_write():
                with SessionLocal() as db:
                    db.add(
                        TokenUsage(
                            project_id=self.project_id,
                            phase=self.phase,
                            role=self.role,
                            tokens_input=usage.get("prompt_tokens", 0),
                            tokens_output=usage.get("completion_tokens", 0),
                            tokens_cached=usage.get("cached_tokens", 0),
                            tokens_total=usage.get("total_tokens", 0)
                            or (usage.get("prompt_tokens", 0) + usage.get("completion_tokens", 0)),
                        )
                    )
                    if self.phase_run_id:
                        pr = db.get(PhaseRun, self.phase_run_id)
                        if pr:
                            pr.tokens_input = (pr.tokens_input or 0) + usage.get("prompt_tokens", 0)
                            pr.tokens_output = (pr.tokens_output or 0) + usage.get("completion_tokens", 0)
                            pr.tokens_cached = (pr.tokens_cached or 0) + usage.get("cached_tokens", 0)
                            pr.tokens_total = (pr.tokens_input or 0) + (pr.tokens_output or 0)
                    db.commit()
        except Exception:  # noqa: BLE001
            pass

    def _store_summary(self, name: str, summary: str) -> str:
        if self.summary_dir is not None:
            self.summary_dir.mkdir(parents=True, exist_ok=True)
            filename = "conclude.md" if "rescue" in name or name == "conclude" else f"{name}.md"
            path = self.summary_dir / filename
            path.write_text(summary or "", encoding="utf-8")
            return str(path)
        return write_summary(self.project_id, name, summary)

    def _attach_current_todos(self, summary: str) -> str:
        return attach_todo_list(summary, load_todos(self), include_empty=True)

    def _maybe_inject_steer(self, messages: list[dict[str, Any]]) -> None:
        if self.silent:
            return
        log_phase = db_phase_to_log_phase(self.phase)
        pending = consume_steer_messages(self.project_id, log_phase)
        if not pending:
            return
        for text in pending:
            block = f"{STEER_USER_PREFIX}{text}\n\n请按以上用户引导调整后续行动，不要无故重来。"
            messages.append({"role": "user", "content": block})
            preview = text[:120] + ("…" if len(text) > 120 else "")
            self._live.system(
                self.project_id,
                f"用户引导：{preview}",
                phase=self.phase,
                role=self.role,
            )
        self._persist(messages)

    def _maybe_inject_decompile_notices(self, messages: list[dict[str, Any]]) -> None:
        watched = self.state.get("decompile_jobs")
        if not isinstance(watched, list) or not watched:
            return
        already = self.state.setdefault("decompile_notified", [])
        if not isinstance(already, list):
            already = []
            self.state["decompile_notified"] = already
        try:
            from ..services.decompile_java import format_completion_inject, take_finished_notices

            notices = take_finished_notices(self.project_id, watched, set(already))
        except Exception:  # noqa: BLE001
            return
        if not notices:
            return
        for n in notices:
            jid = n.get("job_id")
            if jid and jid not in already:
                already.append(jid)
        messages.append({"role": "user", "content": format_completion_inject(notices)})
        self._live.system(
            self.project_id,
            f"反编译完成通知 {len(notices)} 条",
            phase=self.phase,
            role=self.role,
        )
        self._persist(messages)

    def _maybe_inject_todolist(self, messages: list[dict[str, Any]]) -> None:
        interval = max(0, int(getattr(settings, "todo_inject_interval", 50) or 0))
        n = int(self.watchdog.turn_count or 0)
        if interval <= 0 or n <= 0 or n % interval != 0:
            return
        if int(self.state.get("todo_injected_turn") or 0) == n:
            return
        block = format_todo_list_block(load_todos(self), include_empty=True)
        messages.append(
            {
                "role": "user",
                "content": (
                    f"当前 TodoList（每 {interval} 轮自动注入，请按此待办继续，不要丢项）：\n"
                    f"{block}"
                ),
            }
        )
        self.state["todo_injected_turn"] = n
        self._live.system(
            self.project_id,
            f"已注入 TodoList（第 {n} 轮）",
            phase=self.phase,
            role=self.role,
        )
        self._persist(messages)

    def _compress(self, messages: list[dict[str, Any]], force_summary: str | None = None) -> list[dict[str, Any]]:
        # Ask model briefly, or synthesize
        summary = self._attach_current_todos(force_summary or self._request_summary(messages))
        path = self._store_summary("compress" if self.silent else self.phase, summary)
        self._live.system(self.project_id, f"总结已落盘: {path}", phase=self.phase)
        bootstrap = self.user_prompt[:4000]
        return build_compressed_messages(self.system_prompt, summary, bootstrap, messages)

    def _request_summary(self, messages: list[dict[str, Any]], *, rescue: bool = False) -> str:
        todos = load_todos(self)
        todo_block = format_todo_list_block(todos, include_empty=True)
        try:
            clipped = clip_messages_for_summary(messages)
            dumped = json.dumps(clipped, ensure_ascii=False)
            user_content = (
                f"请总结以下对话。已保留最近 {len(clipped)} 条消息，过长内容已按条截断：\n{dumped}"
                "\n\n当前 Agent 的 TodoList 如下，必须写入摘要并保留全部条目与状态：\n"
                f"{todo_block}"
            )
            prompt_msgs = [
                {
                    "role": "system",
                    "content": (
                        "你是上下文压缩助手。用中文输出结构化摘要，保留关键路径、已完成工作、未完成待办、当前焦点。"
                        "必须先阅读上面的 TodoList，把全部条目与状态写入摘要，不要省略。"
                    ),
                },
                {"role": "user", "content": user_content},
            ]
            timeout_budget = float(
                settings.timeout_conclude_rescue if rescue else settings.timeout_conclude
            )
            try:
                self._live.system(
                    self.project_id,
                    "正在压缩上下文",
                    phase=self.phase,
                    role=self.role,
                )
            except Exception:  # noqa: BLE001
                pass
            if is_anthropic_wire(self.llm.wire_api):
                url = anthropic_url(self.llm.base_url)
                headers = anthropic_headers(self.llm.api_key)
                payload: dict[str, Any] = build_anthropic_body(
                    model=self.llm.model,
                    messages=prompt_msgs,
                    temperature=sampling_temperature(self.llm.model, 0.2),
                    max_tokens=1024,
                )
            else:
                url = self.llm.base_url.rstrip("/") + "/chat/completions"
                headers = {
                    "Authorization": f"Bearer {self.llm.api_key}",
                    "Content-Type": "application/json",
                }
                payload = {"model": self.llm.model, "messages": prompt_msgs}
                prepare_chat_body(payload, self.llm.model, temperature=0.2)
            with llm_slot(self.cancel_event) as got_slot:
                if not got_slot:
                    return self._attach_current_todos("（自动摘要取消）")
                with chat_http_client(timeout=conclude_http_timeout(timeout_budget)) as client:
                    r = client.post(url, headers=headers, json=payload)
                    r.raise_for_status()
                    data = r.json()
            if is_anthropic_wire(self.llm.wire_api) or (
                isinstance(data, dict) and data.get("type") == "message"
            ):
                data = anthropic_message_to_openai(data if isinstance(data, dict) else {})
            summary = ((data.get("choices") or [{}])[0].get("message") or {}).get("content") or "（空摘要）"
            return self._attach_current_todos(summary)
        except Exception as e:  # noqa: BLE001
            return self._attach_current_todos(
                f"（自动摘要失败: {e}）\n最近消息数: {len(messages)}，估算 token: {estimate_tokens(messages)}"
            )

    def _conclude_round(self, messages: list[dict[str, Any]]) -> tuple[str | None, str | None]:
        """Compress finished worker round for next-round handoff."""
        try:
            summary = self._request_summary(messages)
            path = self._store_summary("conclude" if self.silent else "worker-round", summary)
            self._live.system(self.project_id, f"本轮结束，上下文已压缩落盘: {path}", phase=self.phase)
            return path, summary
        except Exception as e:  # noqa: BLE001
            self._live.error(self.project_id, f"轮次压缩失败: {e}", phase=self.phase)
            return None, None

    def _rescue_conclude(self, messages: list[dict[str, Any]]) -> None:
        try:
            summary = self._request_summary(messages, rescue=True)
            self._store_summary("conclude" if self.silent else f"{self.phase}-rescue", summary)
            self._live.system(self.project_id, "失败后已执行 conclude 抢救落盘", phase=self.phase)
        except Exception as e:  # noqa: BLE001
            self._live.error(self.project_id, f"conclude 抢救失败: {e}", phase=self.phase)
            try:
                fallback = json.dumps(clip_messages_for_summary(messages), ensure_ascii=False)
                self._store_summary(
                    "conclude" if self.silent else f"{self.phase}-rescue",
                    self._attach_current_todos(f"（抢救摘要失败，按条截断消息）\n{fallback}"),
                )
            except Exception:  # noqa: BLE001
                pass


class AuthError(Exception):
    pass


class RateLimitError(Exception):
    def __init__(
        self,
        msg: str,
        retry_after: float | None = None,
        *,
        quota: bool = False,
    ) -> None:
        super().__init__(msg)
        self.retry_after = retry_after
        self.quota = quota


class TransientError(Exception):
    pass

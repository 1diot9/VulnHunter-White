"""Watchdog: require tool calls; reject identical-tool loops without aborting.

Phase timeout is the wall-clock bound. Recon / worker / reviewer all share
AgentLoop, so this applies to every phase. A text-only turn yields no new
code or environment info — nudge the model to call tools instead of
killing the run after N rounds.

Identical tool+args streaks are not executed: the loop returns an error so
the model can change arguments or switch tools. The session keeps running.

Historical-vuln recon sessions get a persist reminder after N consecutive
turns without WriteOldVuln. Worker mining gets a FinishFile reminder after
M consecutive turns without FinishFile. Calling the corresponding tool
resets the idle counter. Unrelated tools (Read/Grep/…) do not. Code-map
and auth recon sessions are not nudged to persist.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

LAB_NO_TOOL_NUDGE = (
    "你这一轮没有调用任何工具。本轮是独立的 Docker 靶场搭建，请立刻 Read/Glob 找 Dockerfile/compose，"
    "用 shell 构建并启动，Write env/env.json；完成后 FinishLab。"
    "无法搭建则 FinishLab(skipped=true, reason=...)。不要审核漏洞。"
)

VERIFIER_NO_TOOL_NUDGE = (
    "你这一轮没有调用任何工具。请立刻 Read 漏洞报告。"
    "若本项目已有共享 FOFA 结果，直接按这些目标复测，不要再 FofaSearch；"
    "否则 FofaSearch 一次（一个项目只搜一次，结果给全部漏洞共享）。"
    "任一成功即 FinishVerifier(verdict=success, verified_url=..., poc=..., response=..., fofa_query=...)。不要空转。"
)

NO_TOOL_NUDGE = (
    "你这一轮没有调用任何工具。纯文字回复无法读取代码、执行命令或落盘结果，对任务没有进展。"
    "请立即调用工具继续工作；若本阶段门闩已满足，系统会自动结束，无需调用已移除的结束工具。"
    "挖掘轮次：非入口文件立刻 FinishFile（禁止因此立刻 FinishRound）；仅当一开始注入的入口已完整分析后才 FinishRound；"
    "审核请 ConfirmVuln（须标前台/后台、影响、复杂度、防护状态、价值分层；后台再标普通权限或管理员） / ReturnToWorker；"
    "互联网验证请复用项目共享 FOFA 结果或 FofaSearch 一次 / FinishVerifier；修复请 FinishFix。"
)

IDENTICAL_TOOL_NUDGE = (
    "看门狗拦截：连续 {n} 次调用了完全相同的工具（{name}）且参数未变，本次未执行。"
    "请根据已有结果修改参数、换工具或继续下一步，不要原样重试。"
)

RECON_PERSIST_INTERVAL = 50
RECON_PERSIST_PHASES = frozenset({"recon-old-vuln", "recon-old-vuln-ghsa", "recon-source-ext"})

RECON_OLD_VULN_PERSIST_NUDGE = (
    "看门狗提醒：侦察（历史漏洞）已连续 {n} 轮未调用 WriteOldVuln。"
    "请立刻把已确认的条目落盘，不要等全部检索完再写——"
    "每确认一条立刻 WriteOldVuln（落盘不会结束本会话）；"
    "若无公开历史漏洞立刻 WriteOldVuln(no_findings=true)；"
    "本轮完成后 WriteOldVuln(done=true, keyword=产品短名)。"
    "不要调用 SearchGHSA（随后由系统爬虫补漏）。不要改写 code-map/auth，不要标权重。"
    "上下文会被压缩，延迟写入会丢失。"
)

RECON_OLD_VULN_GHSA_PERSIST_NUDGE = (
    "看门狗提醒：侦察（历史漏洞/GHSA补漏）已连续 {n} 轮未调用 WriteOldVuln。"
    "请立刻核验 workspace/ghsa_new.json 候选并落盘符合口径的条目——"
    "每确认一条立刻 WriteOldVuln（落盘不会结束本会话）；"
    "无关/已修复/未使用的不要建档；"
    "全部核验完再 WriteOldVuln(done=true)；无符合口径则 no_findings=true。"
    "不要改写 code-map/auth，不要标权重。上下文会被压缩，延迟写入会丢失。"
)

RECON_SOURCE_EXT_PERSIST_NUDGE = (
    "看门狗提醒：侦察（扩展名）已连续 {n} 轮未调用 AddSourceExt。"
    "请根据 docs/code-map.md 立刻追加模板/映射扩展名，不要空转——"
    "有执行面文件立刻 AddSourceExt(exts=[...])（落盘不会结束本会话）；"
    "无需追加立刻 AddSourceExt(none=true)；"
    "全部确认后再 AddSourceExt(done=true)。"
    "不要改写 code-map/auth，不要标权重。"
)

WORKER_FINISH_INTERVAL = 50

WORKER_FINISH_NUDGE = (
    "看门狗提醒：挖掘已连续 {n} 轮未调用 FinishFile。沿调用链已确认不能作为入口点的文件请立刻 "
    "FinishFile(paths=[...])，不要只标一开始注入的入口文件，也不要等收工再攒着——"
    "未标记的非入口文件会被再次注入。FinishFile 之后继续分析本轮注入入口，禁止立刻 FinishRound。"
    "仅当一开始注入的入口文件 source→sink 已完整分析后，才 FinishFile 它并 FinishRound；report 对齐 templates/round-report.md。"
    "仍有未查清的入口链路可继续，但不要重复已读代码或无限扩读。上下文会被压缩，拖延标记会丢失进展。"
)

# Consecutive idle turns reset when any of these tools is called this turn.
PERSIST_TOOLS: dict[str, frozenset[str]] = {
    "recon-old-vuln": frozenset({"WriteOldVuln"}),
    "recon-old-vuln-ghsa": frozenset({"WriteOldVuln"}),
    "recon-source-ext": frozenset({"AddSourceExt"}),
    "worker": frozenset({"FinishFile"}),
}


@dataclass
class AgentWatchdog:
    max_same_tool_calls: int = 4
    persist_nudge_interval: int = RECON_PERSIST_INTERVAL
    worker_finish_interval: int = WORKER_FINISH_INTERVAL
    phase: str = ""
    turn_count: int = 0
    idle_turns: int = 0
    consecutive_no_tool_turns: int = 0
    recent_tool_keys: list[str] = field(default_factory=list)
    reason: str | None = None

    def _persist_interval(self) -> int:
        if self.phase == "worker":
            return self.worker_finish_interval
        if self.phase in RECON_PERSIST_PHASES:
            return self.persist_nudge_interval
        return 0

    def note_turn(self, tool_names: list[str] | None = None) -> str | None:
        """Count a model turn. Persist/FinishFile idle resets if a target tool was called."""
        self.turn_count += 1
        targets = PERSIST_TOOLS.get(self.phase)
        interval = self._persist_interval()
        if not targets or interval <= 0:
            return None
        names = {str(n).strip() for n in (tool_names or []) if str(n).strip()}
        if names & targets:
            self.idle_turns = 0
            return None
        self.idle_turns += 1
        if self.idle_turns % interval == 0:
            if self.phase == "worker":
                return WORKER_FINISH_NUDGE.format(n=self.idle_turns)
            if self.phase == "recon-old-vuln":
                return RECON_OLD_VULN_PERSIST_NUDGE.format(n=self.idle_turns)
            if self.phase == "recon-old-vuln-ghsa":
                return RECON_OLD_VULN_GHSA_PERSIST_NUDGE.format(n=self.idle_turns)
            if self.phase == "recon-source-ext":
                return RECON_SOURCE_EXT_PERSIST_NUDGE.format(n=self.idle_turns)
        return None

    def persist_nudge_log(self) -> str:
        n = self.idle_turns
        if self.phase == "worker":
            return f"看门狗：挖掘连续 {n} 轮未 FinishFile，已提醒立刻标记非入口文件"
        if self.phase == "recon-old-vuln":
            return f"看门狗：侦察（历史漏洞）连续 {n} 轮未 WriteOldVuln，已提醒立即落盘"
        if self.phase == "recon-old-vuln-ghsa":
            return f"看门狗：侦察（历史漏洞/GHSA补漏）连续 {n} 轮未 WriteOldVuln，已提醒立即落盘"
        if self.phase == "recon-source-ext":
            return f"看门狗：侦察（扩展名）连续 {n} 轮未 AddSourceExt，已提醒立即落盘"
        return f"看门狗：连续 {n} 轮未落盘，已提醒"

    def note_no_tools(self) -> str:
        """Record a text-only turn and return the reminder to inject."""
        self.consecutive_no_tool_turns += 1
        if self.phase in ("reviewer-lab", "reviewer_lab"):
            return LAB_NO_TOOL_NUDGE
        if self.phase == "verifier":
            return VERIFIER_NO_TOOL_NUDGE
        return NO_TOOL_NUDGE

    def snapshot(self) -> dict[str, Any]:
        return {
            "phase": self.phase,
            "turn_count": self.turn_count,
            "idle_turns": self.idle_turns,
            "consecutive_no_tool_turns": self.consecutive_no_tool_turns,
            "recent_tool_keys": list(self.recent_tool_keys),
            "reason": self.reason,
            "max_same_tool_calls": self.max_same_tool_calls,
            "persist_nudge_interval": self.persist_nudge_interval,
            "worker_finish_interval": self.worker_finish_interval,
        }

    @classmethod
    def restore(cls, data: dict[str, Any] | None) -> AgentWatchdog:
        data = data or {}
        wd = cls(
            max_same_tool_calls=int(data.get("max_same_tool_calls") or 4),
            persist_nudge_interval=int(data.get("persist_nudge_interval") or RECON_PERSIST_INTERVAL),
            worker_finish_interval=int(data.get("worker_finish_interval") or WORKER_FINISH_INTERVAL),
            phase=str(data.get("phase") or ""),
            turn_count=int(data.get("turn_count") or 0),
            idle_turns=int(data.get("idle_turns") or 0),
            consecutive_no_tool_turns=int(data.get("consecutive_no_tool_turns") or 0),
            recent_tool_keys=list(data.get("recent_tool_keys") or []),
            reason=data.get("reason"),
        )
        return wd

    def observe_tools(self, tool_calls: list[dict[str, Any]]) -> str | None:
        """Return a nudge if the latest window is one identical call; do not latch/abort."""
        if not tool_calls:
            return None
        self.consecutive_no_tool_turns = 0
        for tc in tool_calls:
            name = tc.get("name") or ""
            args = tc.get("arguments") or {}
            if isinstance(args, str):
                args_s = args
            else:
                args_s = json.dumps(args, sort_keys=True, ensure_ascii=False)
            key = hashlib.sha1(f"{name}:{args_s}".encode()).hexdigest()[:16]
            self.recent_tool_keys.append(f"{name}:{key}")
        window = self.max_same_tool_calls
        if window > 0 and len(self.recent_tool_keys) >= window:
            recent = self.recent_tool_keys[-window:]
            if len(set(recent)) == 1:
                self.reason = f"repeated identical tool call: {recent[0].split(':')[0]}"
                return self.reason
        self.reason = None
        return None


def identical_tool_nudge(name: str, n: int = 4) -> str:
    return IDENTICAL_TOOL_NUDGE.format(name=name or "unknown", n=n)

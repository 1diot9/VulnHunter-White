"""Exposure mode for vulnerabilities whose sink is not directly reachable.

Some components (e.g. JDBC pools, SQL firewalls, parsers) act as consumers: they
do not expose their own HTTP/RPC attack surface. Exploitation depends on an
upstream application passing attacker-controlled input into the vulnerable API.
"""

from __future__ import annotations

import re
from typing import Any

from .cvss31 import Cvss31Result

EXPOSURE_DIRECT = "direct"
EXPOSURE_INDIRECT_CONSUMER = "indirect_consumer"

EXPOSURE_MODE_LABELS: dict[str, str] = {
    EXPOSURE_DIRECT: "直接暴露",
    EXPOSURE_INDIRECT_CONSUMER: "间接消费型",
}

ALLOWED_EXPOSURE_MODES = frozenset(EXPOSURE_MODE_LABELS)

_EXPOSURE_ALIASES: dict[str, str] = {
    "direct": EXPOSURE_DIRECT,
    "直接": EXPOSURE_DIRECT,
    "直接暴露": EXPOSURE_DIRECT,
    "indirect": EXPOSURE_INDIRECT_CONSUMER,
    "indirect_consumer": EXPOSURE_INDIRECT_CONSUMER,
    "consumer": EXPOSURE_INDIRECT_CONSUMER,
    "library": EXPOSURE_INDIRECT_CONSUMER,
    "间接": EXPOSURE_INDIRECT_CONSUMER,
    "间接消费": EXPOSURE_INDIRECT_CONSUMER,
    "间接消费型": EXPOSURE_INDIRECT_CONSUMER,
    "上游依赖": EXPOSURE_INDIRECT_CONSUMER,
}

TRIGGER_CONDITIONS_HEADING = "### 触发条件"
_TRIGGER_HEADING_RE = re.compile(r"(?m)^###\s+触发条件\s*$")
_INDIRECT_CONTENT_HINT_RE = re.compile(
    r"(上游|业务应用|集成方|消费方|调用方|依赖.{0,8}应用|"
    r"不能直接|无法直接|非直接|间接|注入点|SELECT.{0,12}注入|"
    r"WallFilter|过滤器|中间件|组件库|库本身.{0,6}无.{0,6}(HTTP|请求|入口))",
    re.IGNORECASE,
)
_MIN_TRIGGER_SECTION_CHARS = 40


def normalize_exposure_mode(raw: Any) -> str:
    text = str(raw or "").strip()
    if not text:
        return EXPOSURE_DIRECT
    key = text.lower() if text.isascii() else text
    resolved = _EXPOSURE_ALIASES.get(key) or _EXPOSURE_ALIASES.get(text)
    if resolved:
        return resolved
    if key in ALLOWED_EXPOSURE_MODES:
        return key
    allowed = "、".join(f"{k}（{v}）" for k, v in EXPOSURE_MODE_LABELS.items())
    raise ValueError(f"exposure_mode 无效：{text!r}。允许：{allowed}")


def exposure_mode_label(mode: str | None) -> str | None:
    key = (mode or "").strip()
    if not key:
        return None
    return EXPOSURE_MODE_LABELS.get(key)


def _extract_trigger_conditions_section(report_text: str) -> str | None:
    body = report_text or ""
    match = _TRIGGER_HEADING_RE.search(body)
    if not match:
        return None
    rest = body[match.end() :]
    nxt = re.search(r"(?m)^###\s+", rest)
    end = match.end() + nxt.start() if nxt else len(body)
    return body[match.end() : end].strip()


def indirect_exposure_section_gap(report_text: str) -> str | None:
    """Return error when indirect_consumer Confirm lacks upstream context in 触发条件."""
    section = _extract_trigger_conditions_section(report_text)
    if section is None:
        return (
            "间接消费型漏洞确认前，报告「### 触发条件」须写明：组件本身无直接攻击面、"
            "完整利用依赖上游业务应用如何把攻击者输入传入 sink，"
            "以及为何不能直接向该组件发送请求。请 Write report.md 后再 ConfirmVuln。"
        )
    plain = re.sub(r"```.*?```", " ", section, flags=re.DOTALL)
    plain = re.sub(r"`[^`]+`", " ", plain)
    plain = re.sub(r"\s+", " ", plain).strip()
    if len(plain) < _MIN_TRIGGER_SECTION_CHARS:
        return (
            "「### 触发条件」内容过短，间接消费型须具体说明上游依赖与可达条件，"
            "不要只写占位符。"
        )
    if not _INDIRECT_CONTENT_HINT_RE.search(plain):
        return (
            "间接消费型须在「### 触发条件」明确写出：组件无直接 HTTP/请求入口、"
            "须在上游业务应用中找到可利用注入点（或等价用户可控链路）才能把 payload 传入 sink。"
        )
    return None


def indirect_trigger_conditions_hint(*, product: str = "该组件") -> str:
    """Suggested bullets for 触发条件 when exposure_mode=indirect_consumer."""
    return (
        f"- **直接攻击面**：{product} 本身通常不直接接收外部 HTTP/RPC 请求，而是作为 JDBC 连接池 / "
        f"SQL 防火墙 / 解析库等被业务应用集成调用；攻击者不能单独向 {product} 发送恶意请求完成利用。\n"
        f"- **完整利用前提**：须在上游业务应用的正常功能点中找到能把攻击者可控 SQL/参数传入 {product} "
        "校验链路的注入点（例如 SELECT 型 SQL 注入且语句会经过 WallFilter）。缺少该上游注入点时，"
        "本缺陷在真实环境中通常不可直接打成。\n"
        "- **利用复杂度**：除发现组件缺陷外，还需定位并打通上游注入链，排查成本高、场景依赖强；"
        "评分与价值分层应按「间接消费型」处理，不要按可直接远程打穿的 Web 洞高估。"
    )


def cvss_indirect_consumer_error(
    cvss: Cvss31Result,
    *,
    upstream_chain_proven: bool = False,
) -> str | None:
    """CVSS constraints for indirect consumer exposure."""
    m = cvss.metrics
    issues: list[str] = []
    if m.get("AC") != "H":
        issues.append("间接消费型须 AC:H（完整利用依赖上游注入链/特定语句形态，攻击者无法单独准备）")
    if m.get("AV") == "N":
        issues.append(
            "间接消费型不得 AV:N（组件本身无直接网络入口）；"
            "应写 AV:L（经上游应用本地/集成调用链触发）或 AV:A（相邻网络）"
        )
    high_cia = sum(1 for key in ("C", "I", "A") if m.get(key) == "H")
    if high_cia > 1 and not upstream_chain_proven:
        issues.append(
            "未证明完整上游利用链时，C/I/A 至多一项标 H；"
            "其余按已证明冲击标 L/N。若已在真实业务入口打通全链，Confirm 时传 upstream_chain_proven=true"
        )
    if not issues:
        return None
    return "间接消费型 CVSS 约束：" + "；".join(issues)


def indirect_attack_surface_error(
    attack_surface: str,
    *,
    upstream_chain_proven: bool = False,
) -> str | None:
    if upstream_chain_proven:
        return None
    if attack_surface == "frontend":
        return (
            "间接消费型且未证明完整上游利用链时，不得标 attack_surface=frontend。"
            "组件本身无公开前台入口；若仅 harness/单测直调 API 打出冲击，"
            "应标 backend 或 low_impact，并在「### 触发条件」说明真实环境依赖。"
        )
    return None


def indirect_submission_tier_error(
    submission_tier: str,
    *,
    upstream_chain_proven: bool = False,
) -> str | None:
    if upstream_chain_proven:
        return None
    if submission_tier == "cve_candidate":
        return (
            "间接消费型且未证明完整上游业务入口→sink 利用链时，"
            "价值分层应标 low_impact，不要标 cve_candidate。"
            "若已在真实业务 HTTP/API 入口复现全链，Confirm 时传 upstream_chain_proven=true。"
        )
    return None


def parse_upstream_chain_proven(raw: Any) -> bool:
    if raw in (True, 1, "1", "true", "True", "yes", "是"):
        return True
    return False

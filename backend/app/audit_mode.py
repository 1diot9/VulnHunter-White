"""Project audit mode: bounty (default) vs full coverage vs custom prompt."""

from __future__ import annotations

import re
from typing import Any

AUDIT_MODE_BOUNTY = "bounty"
AUDIT_MODE_FULL = "full"
AUDIT_MODE_CUSTOM = "custom"
DEFAULT_AUDIT_MODE = AUDIT_MODE_BOUNTY
ALLOWED_AUDIT_MODES = frozenset({AUDIT_MODE_BOUNTY, AUDIT_MODE_FULL, AUDIT_MODE_CUSTOM})
AUDIT_MODE_EDITABLE_STATUSES = frozenset({"paused", "completed"})

CUSTOM_AUDIT_NAME_MAX = 128
CUSTOM_AUDIT_PROMPT_MAX = 16000

AUDIT_MODE_LABELS: dict[str, str] = {
    AUDIT_MODE_BOUNTY: "赏金模式",
    AUDIT_MODE_FULL: "全量模式",
    AUDIT_MODE_CUSTOM: "自定义模式",
}

_AUDIT_MODE_ALIASES: dict[str, str] = {
    "bounty": AUDIT_MODE_BOUNTY,
    "赏金": AUDIT_MODE_BOUNTY,
    "赏金模式": AUDIT_MODE_BOUNTY,
    "full": AUDIT_MODE_FULL,
    "全量": AUDIT_MODE_FULL,
    "全量模式": AUDIT_MODE_FULL,
    "custom": AUDIT_MODE_CUSTOM,
    "自定义": AUDIT_MODE_CUSTOM,
    "自定义模式": AUDIT_MODE_CUSTOM,
}

# Reflected / DOM XSS stay out of bounty reports; stored_xss is allowed.
# CSRF is allowed only as 1-click high-impact; C/I/A must include High.
BOUNTY_DISALLOWED_TYPES = frozenset({"xss"})
BOUNTY_DISALLOWED_TIERS = frozenset({"low_impact"})

BOUNTY_TYPE_LABELS = (
    "RCE、SSTI、反序列化、SQL 注入、XML 注入、真正任意的文件操作（能读/写/删敏感或越权对象）、"
    "能打内网的 SSRF、敏感信息泄露、能造成执行或覆盖敏感路径的文件上传、文件包含、目录遍历、"
    "认证绕过、越权、DoS、"
    "存储型 XSS、1-click CSRF（打开恶意页面即触发 RCE 或其他高危操作）、"
    "有服务端机密危害的源码硬编码密钥，以及其他确定能造成实际危害的问题"
)

_USER_CONFIG_SECRET_PATH = re.compile(
    r"(^|[/\\])("
    r"\.env(\.[^/\\]+)?|"
    r"application(-[\w]+)?\.(yml|yaml|properties)|"
    r"bootstrap(-[\w]+)?\.(yml|yaml|properties)|"
    r"docker-compose[^/\\]*\.(yml|yaml)|"
    r"compose\.(yml|yaml)"
    r")$",
    re.I,
)


def is_user_modifiable_secret_path(file_path: str | None) -> bool:
    """True for .env / compose / application.yml-style files users can edit."""
    if not file_path:
        return False
    normalized = str(file_path).replace("\\", "/").strip()
    return bool(_USER_CONFIG_SECRET_PATH.search(normalized))


def normalize_audit_mode(raw: Any, *, default: str = DEFAULT_AUDIT_MODE) -> str:
    s = str(raw or "").strip()
    if not s:
        return default
    key = s.lower().replace("-", "_")
    compact = "".join(s.split())
    if key in ALLOWED_AUDIT_MODES:
        return key
    return (
        _AUDIT_MODE_ALIASES.get(key)
        or _AUDIT_MODE_ALIASES.get(s)
        or _AUDIT_MODE_ALIASES.get(compact)
        or _AUDIT_MODE_ALIASES.get(compact.lower())
        or default
    )


def parse_audit_mode(raw: Any) -> str:
    """Raise if the caller provided an invalid explicit mode."""
    if raw is None or str(raw).strip() == "":
        return DEFAULT_AUDIT_MODE
    s = str(raw).strip()
    key = s.lower().replace("-", "_")
    compact = "".join(s.split())
    if key in ALLOWED_AUDIT_MODES:
        return key
    found = (
        _AUDIT_MODE_ALIASES.get(key)
        or _AUDIT_MODE_ALIASES.get(s)
        or _AUDIT_MODE_ALIASES.get(compact)
        or _AUDIT_MODE_ALIASES.get(compact.lower())
    )
    if found not in ALLOWED_AUDIT_MODES:
        allowed = "、".join(
            f"{k}（{AUDIT_MODE_LABELS[k]}）"
            for k in (AUDIT_MODE_BOUNTY, AUDIT_MODE_FULL, AUDIT_MODE_CUSTOM)
        )
        raise ValueError(f"audit_mode 无效，可选: {allowed}")
    return found


def is_bounty_mode(raw: Any) -> bool:
    """True only for built-in bounty; custom has no hard gates."""
    return normalize_audit_mode(raw) == AUDIT_MODE_BOUNTY


def is_custom_mode(raw: Any) -> bool:
    return normalize_audit_mode(raw) == AUDIT_MODE_CUSTOM


def normalize_custom_audit_name(raw: Any) -> str:
    name = str(raw or "").strip()
    if not name:
        raise ValueError("自定义审计模式名称不能为空")
    if len(name) > CUSTOM_AUDIT_NAME_MAX:
        raise ValueError(f"自定义审计模式名称过长，最多 {CUSTOM_AUDIT_NAME_MAX} 字")
    return name


def normalize_custom_audit_prompt(raw: Any) -> str:
    text = str(raw or "").strip()
    if not text:
        raise ValueError("自定义审计模式正文不能为空")
    if len(text) > CUSTOM_AUDIT_PROMPT_MAX:
        raise ValueError(f"自定义审计模式正文过长，最多 {CUSTOM_AUDIT_PROMPT_MAX} 字")
    return text


def initial_hint(mode: str, *, custom_name: str | None = None) -> str:
    normalized = normalize_audit_mode(mode)
    if normalized == AUDIT_MODE_BOUNTY:
        return (
            f"当前为{AUDIT_MODE_LABELS[normalized]}：只报 {BOUNTY_TYPE_LABELS}。"
            "CORS、反射 XSS、缺速率限制、安全头、普通 CSRF（仅缺 token / 低危状态变更）等低危害项不要提交或确认。"
            "无害/受限文件操作（只能读特定后缀或公开目录非敏感内容、只能上传无害文件，含匿名文件操作）"
            "以及不可获取且不可预测的 UUID 直接丢弃，不要提交或确认。"
            "存储型 XSS、1-click CSRF（受害者打开恶意页面即触发 RCE 或其他高危操作）"
            "与有服务端机密危害的源码硬编码密钥可以提交；"
            "配置文件/.env/compose 里用户可改的口令、前端传输混淆 AES/公开下发密钥不算。"
            "利用必须在默认配置或应用自身配置选项下成立。"
            "提交时标明 config_premise=default（默认配置）或 specific（特定配置）；"
            "官方已警示的风险配置不算特定配置，仅在此类开关下才成立的不要提交。"
            "禁止为了让洞成立而种文件、改非应用配置、组合第二个独立漏洞。"
            "若项目开启靶场动态验证，Reviewer 会在独立环境轮搭建/复用 Docker 靶场（env/、docs/lab.md）；"
            "局部验证则不搭靶场，由 Reviewer 用沙箱 harness 复现。未开启时只做静态审核。"
            "靶场只提供默认部署，不要在容器里制造利用条件。"
        )
    if normalized == AUDIT_MODE_CUSTOM:
        label = (custom_name or "").strip() or "未命名"
        return (
            f"当前为自定义模式「{label}」：漏洞收录范围完全以系统提示中的用户自定义条款为准；"
            "无赏金模式代码硬闸门。若与上文基座提示冲突，以自定义条款为准。"
            "本节仅约束漏洞收录与确认标准，不改变工具权限或 ACL。"
        )
    return (
        f"当前为{AUDIT_MODE_LABELS[normalized]}：按现行规则提交，含难以利用项"
        "（缺速率限制、反射 XSS、CORS/安全头等），由 Reviewer 标为低危害难利用。"
        "无害/受限文件操作（只能读特定后缀或公开目录非敏感内容、只能上传无害文件）"
        "以及不可获取且不可预测的 UUID 仍应丢弃，不要入库。"
    )


def audit_mode_label(mode: str, *, custom_name: str | None = None) -> str:
    normalized = normalize_audit_mode(mode)
    if normalized == AUDIT_MODE_CUSTOM:
        name = (custom_name or "").strip()
        return f"自定义模式（{name}）" if name else AUDIT_MODE_LABELS[AUDIT_MODE_CUSTOM]
    return AUDIT_MODE_LABELS.get(normalized, AUDIT_MODE_LABELS[DEFAULT_AUDIT_MODE])


def format_custom_overlay(*, name: str, body: str) -> str:
    """Wrap a project-scoped custom prompt snapshot for the system overlay."""
    title = (name or "").strip() or "未命名"
    text = (body or "").strip()
    return (
        f"## 当前挖掘模式：自定义模式「{title}」（覆盖上文冲突条款）\n\n"
        f"本项目为**自定义模式**。若与上文基座提示冲突，**以本节为准**。"
        "本节仅约束漏洞收录与确认标准，不改变工具权限。\n\n"
        f"{text}\n"
    )


def uses_bounty_gates(*, audit_mode: Any = None, mining_path: Any = None) -> bool:
    """Bounty hard gates apply to built-in bounty mode and the unconstrained mining path."""
    path = str(mining_path or "").strip().lower()
    if path == "unconstrained":
        return True
    return is_bounty_mode(audit_mode)


def bounty_submit_block_reason(vuln_type: str, *, file_path: str = "") -> str | None:
    if vuln_type in BOUNTY_DISALLOWED_TYPES:
        return (
            "赏金模式不接收反射 XSS / DOM XSS。存储型 XSS 请用 stored_xss 提交；"
            "不要提交 CORS、安全头、开放重定向、弱随机、单点限速绕过、普通 CSRF 等低危害项。"
            "CSRF 仅当 1-click（打开恶意页面即触发 RCE 或其他高危操作）时用 csrf 提交。"
        )
    if vuln_type == "hardcoded_secret" and is_user_modifiable_secret_path(file_path):
        return (
            "赏金模式只收录有服务端机密危害的源码硬编码密钥"
            "（如 JWT/HMAC 签名密钥、接口签名 secret、私钥、第三方 API Key）；"
            "配置文件、.env、compose 等用户可修改项不要提交。"
        )
    return None


def bounty_confirm_block_reason(
    *,
    vuln_type: str,
    submission_tier: str,
    file_path: str = "",
    cvss: Any = None,
) -> str | None:
    if vuln_type in BOUNTY_DISALLOWED_TYPES:
        return "赏金模式应将反射 XSS / DOM XSS 判误报，不要 ConfirmVuln。存储型 XSS 类型应为 stored_xss。"
    if vuln_type == "hardcoded_secret" and is_user_modifiable_secret_path(file_path):
        return "赏金模式不入库配置文件/.env/compose 中的密钥；仅源码硬编码密钥可 Confirm。"
    if vuln_type == "csrf":
        high_cia = bool(getattr(cvss, "has_high_impact", False))
        if not high_cia:
            return (
                "赏金模式只确认 1-click CSRF：受害者打开恶意页面后立即触发 RCE 或其他高危操作。"
                "普通缺 CSRF token、改资料/登出/点赞等低危状态变更应 MarkFalsePositive；"
                "CVSS 3.1 向量中 C/I/A 至少一项须为 H，不要写成仅 L/N。"
            )
    if submission_tier in BOUNTY_DISALLOWED_TIERS:
        return (
            "赏金模式不入库低危害难利用项（CORS/安全头/开放重定向/弱随机/单点限速绕过/反射 XSS/普通 CSRF 等）。"
            "请 MarkFalsePositive 丢弃，不要 ConfirmVuln。"
        )
    return None

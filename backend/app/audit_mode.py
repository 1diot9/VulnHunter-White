"""Project audit mode: bounty (default) vs full coverage."""

from __future__ import annotations

import re
from typing import Any

AUDIT_MODE_BOUNTY = "bounty"
AUDIT_MODE_FULL = "full"
DEFAULT_AUDIT_MODE = AUDIT_MODE_BOUNTY
ALLOWED_AUDIT_MODES = frozenset({AUDIT_MODE_BOUNTY, AUDIT_MODE_FULL})
AUDIT_MODE_EDITABLE_STATUSES = frozenset({"paused", "completed"})

AUDIT_MODE_LABELS: dict[str, str] = {
    AUDIT_MODE_BOUNTY: "赏金模式",
    AUDIT_MODE_FULL: "全量模式",
}

_AUDIT_MODE_ALIASES: dict[str, str] = {
    "bounty": AUDIT_MODE_BOUNTY,
    "赏金": AUDIT_MODE_BOUNTY,
    "赏金模式": AUDIT_MODE_BOUNTY,
    "full": AUDIT_MODE_FULL,
    "全量": AUDIT_MODE_FULL,
    "全量模式": AUDIT_MODE_FULL,
}

# Reflected / DOM XSS stay out of bounty reports; stored_xss is allowed.
BOUNTY_DISALLOWED_TYPES = frozenset({"xss"})
BOUNTY_DISALLOWED_TIERS = frozenset({"low_impact"})

BOUNTY_TYPE_LABELS = (
    "RCE、SSTI、反序列化、SQL 注入、XML 注入、任意文件操作（读/写/删/改/复制/解压穿越等）、"
    "能打内网的 SSRF、敏感信息泄露、文件上传、文件包含、目录遍历、认证绕过、越权、DoS、"
    "存储型 XSS、源码硬编码密钥，以及其他确定能造成实际危害的问题"
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
        allowed = "、".join(f"{k}（{AUDIT_MODE_LABELS[k]}）" for k in (AUDIT_MODE_BOUNTY, AUDIT_MODE_FULL))
        raise ValueError(f"audit_mode 无效，可选: {allowed}")
    return found


def is_bounty_mode(raw: Any) -> bool:
    return normalize_audit_mode(raw) == AUDIT_MODE_BOUNTY


def initial_hint(mode: str) -> str:
    normalized = normalize_audit_mode(mode)
    if normalized == AUDIT_MODE_BOUNTY:
        return (
            f"当前为{AUDIT_MODE_LABELS[normalized]}：只报 {BOUNTY_TYPE_LABELS}。"
            "CORS、反射 XSS、缺速率限制、安全头等低危害项不要提交或确认。"
            "存储型 XSS 与源码中的硬编码密钥可以提交；配置文件/.env/compose 里用户可改的口令不算。"
            "利用必须在默认配置或应用自身配置选项下成立。"
            "禁止为了让洞成立而种文件、改非应用配置、组合第二个独立漏洞。"
            "若项目开启动态验证，Reviewer 会在独立环境轮搭建/复用 Docker 靶场（env/、docs/lab.md）；未开启时只做静态审核。"
            "靶场只提供默认部署，不要在容器里制造利用条件。"
        )
    return (
        f"当前为{AUDIT_MODE_LABELS[normalized]}：按现行规则提交，含难以利用项"
        "（缺速率限制、反射 XSS、CORS/安全头等），由 Reviewer 标为低危害难利用。"
    )


def audit_mode_label(mode: str) -> str:
    return AUDIT_MODE_LABELS.get(normalize_audit_mode(mode), AUDIT_MODE_LABELS[DEFAULT_AUDIT_MODE])


def bounty_submit_block_reason(vuln_type: str, *, file_path: str = "") -> str | None:
    if vuln_type in BOUNTY_DISALLOWED_TYPES:
        return (
            "赏金模式不接收反射 XSS / DOM XSS。存储型 XSS 请用 stored_xss 提交；"
            "不要提交 CORS、安全头、开放重定向、弱随机、单点限速绕过等低危害项。"
        )
    if vuln_type == "hardcoded_secret" and is_user_modifiable_secret_path(file_path):
        return (
            "赏金模式只收录源码中的硬编码密钥（如 Java/Go 常量、JWT/AES/DES secret）；"
            "配置文件、.env、compose 等用户可修改项不要提交。"
        )
    return None


def bounty_confirm_block_reason(
    *,
    vuln_type: str,
    submission_tier: str,
    file_path: str = "",
) -> str | None:
    if vuln_type in BOUNTY_DISALLOWED_TYPES:
        return "赏金模式应将反射 XSS / DOM XSS 判误报，不要 ConfirmVuln。存储型 XSS 类型应为 stored_xss。"
    if vuln_type == "hardcoded_secret" and is_user_modifiable_secret_path(file_path):
        return "赏金模式不入库配置文件/.env/compose 中的密钥；仅源码硬编码密钥可 Confirm。"
    if submission_tier in BOUNTY_DISALLOWED_TIERS:
        return (
            "赏金模式不入库低危害难利用项（CORS/安全头/开放重定向/弱随机/单点限速绕过/反射 XSS 等）。"
            "请 ReturnToWorker(false_positive=true) 丢弃，不要 ConfirmVuln。"
        )
    return None

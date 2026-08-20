"""Vulnerability type taxonomy (ported from AutoPoc)."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any

VULN_TYPES: tuple[str, ...] = (
    "rce",
    "ssti",
    "deserialization",
    "jndi_injection",
    "jdbc_attack",
    "file_read",
    "file_upload",
    "file_delete",
    "auth_bypass",
    "sqli",
    "xxe",
    "path_traversal",
    "ssrf",
    "privilege_escalation",
    "dos",
    "xss",
    "stored_xss",
    "hardcoded_secret",
    "info_disclosure",
    "other",
)

ALLOWED_VULN_TYPES = frozenset(VULN_TYPES)
PENDING_SEVERITY = "pending"

VULN_TYPE_LABELS: dict[str, str] = {
    "rce": "RCE",
    "ssti": "SSTI",
    "deserialization": "反序列化",
    "jndi_injection": "JNDI注入",
    "jdbc_attack": "JDBC攻击",
    "file_read": "任意文件读取",
    "file_upload": "任意文件上传",
    "file_delete": "任意文件删除",
    "auth_bypass": "认证绕过",
    "sqli": "SQL注入",
    "xxe": "XXE",
    "path_traversal": "路径穿越",
    "ssrf": "SSRF",
    "privilege_escalation": "越权",
    "dos": "DoS",
    "xss": "XSS",
    "stored_xss": "存储型XSS",
    "hardcoded_secret": "硬编码密钥",
    "info_disclosure": "信息泄露",
    "other": "其他",
}

SEVERITY_LABELS: dict[str, str] = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "pending": "待校准",
}

SUBMISSION_TIERS: dict[str, str] = {
    "cve_candidate": "有 CVE 价值",
    "low_impact": "低危害难利用",
    "duplicate_grouped": "同根因重复",
}

ALLOWED_SUBMISSION_TIERS = frozenset(SUBMISSION_TIERS)
LEGACY_LOW_IMPACT_TIERS = frozenset({"low_impact", "hardening", "advisory_only"})

CONFIG_PREMISE_DEFAULT = "default"
CONFIG_PREMISE_SPECIFIC = "specific"
CONFIG_PREMISE_LABELS: dict[str, str] = {
    CONFIG_PREMISE_DEFAULT: "默认配置",
    CONFIG_PREMISE_SPECIFIC: "特定配置",
}
ALLOWED_CONFIG_PREMISES = frozenset(CONFIG_PREMISE_LABELS)

_CONFIG_PREMISE_ALIASES: dict[str, str] = {
    "default": CONFIG_PREMISE_DEFAULT,
    "default_config": CONFIG_PREMISE_DEFAULT,
    "defaults": CONFIG_PREMISE_DEFAULT,
    "out_of_box": CONFIG_PREMISE_DEFAULT,
    "stock": CONFIG_PREMISE_DEFAULT,
    "默认": CONFIG_PREMISE_DEFAULT,
    "默认配置": CONFIG_PREMISE_DEFAULT,
    "开箱": CONFIG_PREMISE_DEFAULT,
    "出厂": CONFIG_PREMISE_DEFAULT,
    "specific": CONFIG_PREMISE_SPECIFIC,
    "specific_config": CONFIG_PREMISE_SPECIFIC,
    "custom_config": CONFIG_PREMISE_SPECIFIC,
    "non_default": CONFIG_PREMISE_SPECIFIC,
    "特定": CONFIG_PREMISE_SPECIFIC,
    "特定配置": CONFIG_PREMISE_SPECIFIC,
    "非默认": CONFIG_PREMISE_SPECIFIC,
    "自定义配置": CONFIG_PREMISE_SPECIFIC,
}

_SUBMISSION_TIER_ALIASES: dict[str, str] = {
    "cve_candidate": "cve_candidate",
    "cve": "cve_candidate",
    "candidate": "cve_candidate",
    "cve候选": "cve_candidate",
    "cve 候选": "cve_candidate",
    "有cve价值": "cve_candidate",
    "有 cve 价值": "cve_candidate",
    "有CVE价值": "cve_candidate",
    "有 CVE 价值": "cve_candidate",
    "可提交cve": "cve_candidate",
    "可提交": "cve_candidate",
    "low_impact": "low_impact",
    "low_value": "low_impact",
    "low": "low_impact",
    "低危害": "low_impact",
    "难以利用": "low_impact",
    "低危害难利用": "low_impact",
    "低危害难以利用": "low_impact",
    "advisory_only": "low_impact",
    "advisory": "low_impact",
    "公告": "low_impact",
    "仅公告": "low_impact",
    "合并公告": "low_impact",
    "hardening": "low_impact",
    "harderning": "low_impact",
    "加固": "low_impact",
    "加固建议": "low_impact",
    "duplicate_grouped": "duplicate_grouped",
    "duplicate": "duplicate_grouped",
    "dup": "duplicate_grouped",
    "同根因": "duplicate_grouped",
    "同根因重复": "duplicate_grouped",
    "重复": "duplicate_grouped",
}

_REACHABILITY_SCORES: dict[str, int] = {
    "unauthenticated": 1,
    "low_privilege": 0,
    "admin": -1,
}

_IMPACT_SCORES: dict[str, int] = {
    "rce_or_full_data": 4,
    "sensitive_data_or_privilege": 2,
    "limited_info": 1,
}

_COMPLEXITY_SCORES: dict[str, int] = {
    "single_request": 0,
    "multi_step": 0,
    "specific_environment": -2,
}

_DEFENSE_SCORES: dict[str, int] = {
    "none": 0,
    "bypassable": 0,
    "conditional": -1,
}

REVIEW_FACTOR_LABELS: dict[str, dict[str, str]] = {
    "reachability": {
        "unauthenticated": "未认证可达",
        "low_privilege": "低权限可达",
        "admin": "管理员权限才可达",
    },
    "impact": {
        "rce_or_full_data": "RCE/全库读取/完整控制",
        "sensitive_data_or_privilege": "敏感数据泄露/权限提升/部分数据",
        "limited_info": "有限信息泄露/信息收集",
    },
    "exploit_complexity": {
        "single_request": "单请求或简单触发",
        "multi_step": "多步骤利用",
        "specific_environment": "依赖特定环境",
    },
    "defense_status": {
        "none": "无有效防护",
        "bypassable": "有防护但可绕过",
        "conditional": "有防护且绕过需额外条件",
    },
}

_IMPACT_ALIASES: dict[str, str] = {
    "rce_or_full_data": "rce_or_full_data",
    "rce": "rce_or_full_data",
    "full_data": "rce_or_full_data",
    "full_database": "rce_or_full_data",
    "full_db": "rce_or_full_data",
    "complete_compromise": "rce_or_full_data",
    "code_execution": "rce_or_full_data",
    "代码执行": "rce_or_full_data",
    "远程代码执行": "rce_or_full_data",
    "全库": "rce_or_full_data",
    "完整数据泄露": "rce_or_full_data",
    "完整控制": "rce_or_full_data",
    "sensitive_data_or_privilege": "sensitive_data_or_privilege",
    "sensitive_data": "sensitive_data_or_privilege",
    "partial_data": "sensitive_data_or_privilege",
    "privilege": "sensitive_data_or_privilege",
    "privilege_escalation": "sensitive_data_or_privilege",
    "敏感数据": "sensitive_data_or_privilege",
    "部分数据": "sensitive_data_or_privilege",
    "权限提升": "sensitive_data_or_privilege",
    "越权": "sensitive_data_or_privilege",
    "limited_info": "limited_info",
    "info": "limited_info",
    "information": "limited_info",
    "limited": "limited_info",
    "信息收集": "limited_info",
    "有限影响": "limited_info",
    "有限信息泄露": "limited_info",
}

_COMPLEXITY_ALIASES: dict[str, str] = {
    "single_request": "single_request",
    "single": "single_request",
    "simple": "single_request",
    "low": "single_request",
    "单请求": "single_request",
    "简单": "single_request",
    "低": "single_request",
    "multi_step": "multi_step",
    "multiple_steps": "multi_step",
    "medium": "multi_step",
    "多步骤": "multi_step",
    "中": "multi_step",
    "specific_environment": "specific_environment",
    "specific_env": "specific_environment",
    "environment": "specific_environment",
    "high": "specific_environment",
    "特定环境": "specific_environment",
    "特定条件": "specific_environment",
    "高": "specific_environment",
}

_DEFENSE_ALIASES: dict[str, str] = {
    "none": "none",
    "no_protection": "none",
    "no_effective_protection": "none",
    "absent": "none",
    "无防护": "none",
    "无有效防护": "none",
    "bypassable": "bypassable",
    "has_bypass": "bypassable",
    "bypass": "bypassable",
    "weak": "bypassable",
    "可绕过": "bypassable",
    "有防护但可绕过": "bypassable",
    "conditional": "conditional",
    "extra_condition": "conditional",
    "hard_to_bypass": "conditional",
    "partial": "conditional",
    "需额外条件": "conditional",
    "有防护且绕过需额外条件": "conditional",
}


@dataclass(frozen=True)
class SeverityCalibration:
    severity: str
    score: int
    reachability: str
    impact: str
    exploit_complexity: str
    defense_status: str

    @property
    def severity_label(self) -> str:
        return SEVERITY_LABELS[self.severity]


@dataclass(frozen=True)
class SubmissionTierDecision:
    tier: str
    reason: str
    root_cause_key: str | None = None

    @property
    def tier_label(self) -> str:
        return SUBMISSION_TIERS[self.tier]


_ALIAS_MAP: dict[str, str] = {
    "rce": "rce",
    "remote_code_execution": "rce",
    "remote code execution": "rce",
    "command_injection": "rce",
    "command injection": "rce",
    "code_injection": "rce",
    "命令注入": "rce",
    "代码注入": "rce",
    "远程代码执行": "rce",
    "ssti": "ssti",
    "template_injection": "ssti",
    "模板注入": "ssti",
    "模版注入": "ssti",
    "deserialization": "deserialization",
    "反序列化": "deserialization",
    "jndi_injection": "jndi_injection",
    "jndi": "jndi_injection",
    "jndi注入": "jndi_injection",
    "jdbc_attack": "jdbc_attack",
    "jdbc": "jdbc_attack",
    "file_read": "file_read",
    "任意文件读取": "file_read",
    "file_upload": "file_upload",
    "任意文件上传": "file_upload",
    "file_delete": "file_delete",
    "任意文件删除": "file_delete",
    "auth_bypass": "auth_bypass",
    "认证绕过": "auth_bypass",
    "鉴权绕过": "auth_bypass",
    "sqli": "sqli",
    "sql_injection": "sqli",
    "sql注入": "sqli",
    "xxe": "xxe",
    "xml_injection": "xxe",
    "xml注入": "xxe",
    "path_traversal": "path_traversal",
    "file_inclusion": "path_traversal",
    "lfi": "path_traversal",
    "rfi": "path_traversal",
    "文件包含": "path_traversal",
    "目录遍历": "path_traversal",
    "路径穿越": "path_traversal",
    "ssrf": "ssrf",
    "privilege_escalation": "privilege_escalation",
    "idor": "privilege_escalation",
    "越权": "privilege_escalation",
    "dos": "dos",
    "xss": "xss",
    "反射xss": "xss",
    "reflected_xss": "xss",
    "reflected xss": "xss",
    "dom_xss": "xss",
    "dom xss": "xss",
    "stored_xss": "stored_xss",
    "stored xss": "stored_xss",
    "persistent_xss": "stored_xss",
    "persistent xss": "stored_xss",
    "存储xss": "stored_xss",
    "存储型xss": "stored_xss",
    "hardcoded_secret": "hardcoded_secret",
    "hardcoded_credentials": "hardcoded_secret",
    "hardcoded credentials": "hardcoded_secret",
    "hard coded credentials": "hardcoded_secret",
    "hard_coded_credentials": "hardcoded_secret",
    "hardcoded_key": "hardcoded_secret",
    "hardcoded key": "hardcoded_secret",
    "jwt_secret": "hardcoded_secret",
    "硬编码密钥": "hardcoded_secret",
    "硬编码凭据": "hardcoded_secret",
    "info_disclosure": "info_disclosure",
    "信息泄露": "info_disclosure",
    "other": "other",
    "其他": "other",
}

_INFER_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"jndi", re.I), "jndi_injection"),
    (re.compile(r"jdbc", re.I), "jdbc_attack"),
    (re.compile(r"deserializ|反序列化", re.I), "deserialization"),
    (re.compile(r"ssti|template\s*injection|模[板版]注入", re.I), "ssti"),
    (re.compile(r"\brce\b|command\s*injection|命令注入|远程代码执行", re.I), "rce"),
    (re.compile(r"\bxxe\b|xml\s*injection|xml注入", re.I), "xxe"),
    (re.compile(r"sql\s*injection|\bsqli\b|sql注入", re.I), "sqli"),
    (re.compile(r"file\s*upload|任意文件上传", re.I), "file_upload"),
    (re.compile(r"file\s*delet|任意文件删除", re.I), "file_delete"),
    (re.compile(r"file\s*read|任意文件读取", re.I), "file_read"),
    (re.compile(r"path\s*traversal|file\s*inclusion|\blfi\b|\brfi\b|路径穿越|文件包含|目录遍历", re.I), "path_traversal"),
    (re.compile(r"auth(entication)?\s*bypass|认证绕过|鉴权绕过", re.I), "auth_bypass"),
    (re.compile(r"\bssrf\b", re.I), "ssrf"),
    (re.compile(r"privilege\s*escalation|\bidor\b|越权", re.I), "privilege_escalation"),
    (re.compile(r"stored\s*xss|存储(型)?\s*xss|persistent\s*xss", re.I), "stored_xss"),
    (
        re.compile(
            r"hard[-_ ]?coded\s*(secret|key|credential)|硬编码(密钥|凭据)|jwt\s*secret",
            re.I,
        ),
        "hardcoded_secret",
    ),
    (re.compile(r"\bxss\b|反射xss|dom\s*xss", re.I), "xss"),
    (re.compile(r"\bdos\b|拒绝服务", re.I), "dos"),
    (re.compile(r"information\s*disclosure|信息泄露", re.I), "info_disclosure"),
]


def normalize_vuln_type(raw: str | None) -> str:
    if not raw:
        return "other"
    s = str(raw).strip()
    if not s:
        return "other"
    key = s.lower().replace("-", "_")
    if key in ALLOWED_VULN_TYPES:
        return key
    if key in _ALIAS_MAP:
        return _ALIAS_MAP[key]
    if s in _ALIAS_MAP:
        return _ALIAS_MAP[s]
    compact = re.sub(r"[\s_\-]+", " ", s.lower()).strip()
    if compact in _ALIAS_MAP:
        return _ALIAS_MAP[compact]
    return infer_vuln_type_from_text(s)


def _factor_key(raw: Any) -> str:
    s = str(raw or "").strip()
    return re.sub(r"[\s\-]+", "_", s.lower()) if s.isascii() else s


def _normalize_review_factor(raw: Any, aliases: dict[str, str], field_name: str) -> str:
    key = _factor_key(raw)
    if not key:
        raise ValueError(f"缺少 {field_name}")
    normalized = aliases.get(key)
    if not normalized:
        allowed = "|".join(sorted(set(aliases.values())))
        raise ValueError(f"{field_name} 无效，可选: {allowed}")
    return normalized


def normalize_config_premise(raw: Any) -> str:
    return _normalize_review_factor(raw, _CONFIG_PREMISE_ALIASES, "config_premise")


def config_premise_label(raw: Any) -> str | None:
    try:
        return CONFIG_PREMISE_LABELS[normalize_config_premise(raw)]
    except ValueError:
        return None


def reachability_from_review_context(attack_surface: str, required_account: str | None) -> str:
    if attack_surface == "frontend":
        return "unauthenticated"
    if attack_surface == "backend" and required_account == "user":
        return "low_privilege"
    return "admin"


def severity_from_review_score(score: int) -> str:
    if score >= 5:
        return "critical"
    if score >= 3:
        return "high"
    if score >= 1:
        return "medium"
    return "low"


def calibrate_review_severity(
    *,
    attack_surface: str,
    required_account: str | None,
    impact: Any,
    exploit_complexity: Any,
    defense_status: Any,
) -> SeverityCalibration:
    """Calibrate final review severity from exploit context, not vulnerability type alone."""
    reachability = reachability_from_review_context(attack_surface, required_account)
    normalized_impact = _normalize_review_factor(impact, _IMPACT_ALIASES, "impact")
    normalized_complexity = _normalize_review_factor(
        exploit_complexity, _COMPLEXITY_ALIASES, "exploit_complexity"
    )
    normalized_defense = _normalize_review_factor(
        defense_status, _DEFENSE_ALIASES, "defense_status"
    )
    score = (
        _REACHABILITY_SCORES[reachability]
        + _IMPACT_SCORES[normalized_impact]
        + _COMPLEXITY_SCORES[normalized_complexity]
        + _DEFENSE_SCORES[normalized_defense]
    )
    return SeverityCalibration(
        severity=severity_from_review_score(score),
        score=score,
        reachability=reachability,
        impact=normalized_impact,
        exploit_complexity=normalized_complexity,
        defense_status=normalized_defense,
    )


def normalize_submission_tier(raw: Any) -> str:
    key = _factor_key(raw)
    if not key:
        raise ValueError("缺少 submission_tier")
    candidates = [key]
    lowered = key.lower()
    if lowered not in candidates:
        candidates.append(lowered)
    compact = re.sub(r"[\s_\-]+", "", lowered)
    if compact and compact not in candidates:
        candidates.append(compact)
    normalized = None
    for candidate in candidates:
        normalized = _SUBMISSION_TIER_ALIASES.get(candidate)
        if not normalized and candidate in ALLOWED_SUBMISSION_TIERS:
            normalized = candidate
        if normalized:
            break
    if not normalized:
        allowed = "|".join(sorted(ALLOWED_SUBMISSION_TIERS))
        raise ValueError(f"submission_tier 无效，可选: {allowed}")
    return normalized


def normalize_root_cause_key(raw: Any) -> str | None:
    if raw is None:
        return None
    s = str(raw).strip()
    if not s:
        return None
    # Keep short, stable keys for grouping.
    s = re.sub(r"\s+", " ", s)
    return s[:256]


def normalize_submission_decision(
    *,
    submission_tier: Any,
    submission_reason: Any,
    root_cause_key: Any = None,
) -> SubmissionTierDecision:
    tier = normalize_submission_tier(submission_tier)
    reason = str(submission_reason or "").strip()
    if not reason:
        raise ValueError("缺少 submission_reason（须说明为何进入该提交分层）")
    root = normalize_root_cause_key(root_cause_key)
    if tier == "duplicate_grouped" and not root:
        raise ValueError("submission_tier=duplicate_grouped 时必须提供 root_cause_key")
    return SubmissionTierDecision(tier=tier, reason=reason, root_cause_key=root)


def suggest_submission_tier(*, calibration: SeverityCalibration) -> str:
    """Heuristic hint for tests/docs; Reviewer still must choose explicitly."""
    if calibration.reachability == "admin" and calibration.impact == "limited_info":
        return "low_impact"
    if calibration.score >= 3 and calibration.reachability in ("unauthenticated", "low_privilege"):
        return "cve_candidate"
    return "low_impact"


_STORED_XSS_HINT = re.compile(r"stored\s*xss|存储(型)?\s*xss|persistent\s*xss", re.I)


def refine_vuln_type(vuln_type: str, *, title: str = "", source_sink: str = "") -> str:
    """Keep generic xss unless the report text clearly says stored/persistent XSS."""
    if vuln_type == "xss" and _STORED_XSS_HINT.search(f"{title}\n{source_sink}"):
        return "stored_xss"
    return vuln_type


def infer_vuln_type_from_text(*parts: str | None) -> str:
    text = " ".join(p for p in parts if p)
    if not text.strip():
        return "other"
    for pattern, vtype in _INFER_RULES:
        if pattern.search(text):
            return vtype
    return "other"


def resolve_vuln_type(item: dict[str, Any]) -> str:
    raw_type = item.get("vuln_type") or item.get("type") or item.get("category")
    title = str(item.get("title") or item.get("identifier") or "")
    summary = str(item.get("summary") or item.get("source_sink") or "")
    if raw_type:
        return refine_vuln_type(normalize_vuln_type(str(raw_type)), title=title, source_sink=summary)
    return infer_vuln_type_from_text(
        item.get("identifier"),
        item.get("title"),
        item.get("summary"),
    )


def prompt_type_enum() -> str:
    return "|".join(VULN_TYPES)

"""CVSS 3.1 base-vector parse, validate, and score.

Agent supplies the vector string only. Base score / severity are computed here
per FIRST CVSS v3.1 (including the specified roundup).
"""

from __future__ import annotations

from dataclasses import dataclass
import math
import re
from typing import Any

CVSS_VERSION = "3.1"
CVSS_PREFIX = "CVSS:3.1"
REQUIRED_METRICS: tuple[str, ...] = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")

METRIC_VALUES: dict[str, tuple[str, ...]] = {
    "AV": ("N", "A", "L", "P"),
    "AC": ("L", "H"),
    "PR": ("N", "L", "H"),
    "UI": ("N", "R"),
    "S": ("U", "C"),
    "C": ("H", "L", "N"),
    "I": ("H", "L", "N"),
    "A": ("H", "L", "N"),
}

METRIC_LABELS: dict[str, str] = {
    "AV": "Attack Vector（攻击向量）",
    "AC": "Attack Complexity（攻击复杂度）",
    "PR": "Privileges Required（所需权限）",
    "UI": "User Interaction（用户交互）",
    "S": "Scope（作用域）",
    "C": "Confidentiality（机密性）",
    "I": "Integrity（完整性）",
    "A": "Availability（可用性）",
}

METRIC_VALUE_HINTS: dict[str, str] = {
    "AV": "N=Network / A=Adjacent / L=Local / P=Physical",
    "AC": "L=Low / H=High",
    "PR": "N=None / L=Low / H=High",
    "UI": "N=None / R=Required",
    "S": "U=Unchanged / C=Changed",
    "C": "H=High / L=Low / N=None",
    "I": "H=High / L=Low / N=None",
    "A": "H=High / L=Low / N=None",
}

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.00}

_CVE_AV = {"N": "NETWORK", "A": "ADJACENT_NETWORK", "L": "LOCAL", "P": "PHYSICAL"}
_CVE_AC = {"L": "LOW", "H": "HIGH"}
_CVE_PR = {"N": "NONE", "L": "LOW", "H": "HIGH"}
_CVE_UI = {"N": "NONE", "R": "REQUIRED"}
_CVE_SCOPE = {"U": "UNCHANGED", "C": "CHANGED"}
_CVE_CIA = {"H": "HIGH", "L": "LOW", "N": "NONE"}

SEVERITY_EN: dict[str, str] = {
    "none": "None",
    "low": "Low",
    "medium": "Medium",
    "high": "High",
    "critical": "Critical",
}

_VECTOR_TOKEN_RE = re.compile(r"^([A-Za-z]{1,4}):([A-Za-z])$")
_ADVISORY_CVSS_LINE_RE = re.compile(r"(?m)^-\s*\*\*CVSS\s+[0-9]+(?:\.[0-9]+)?:\*\*.*\n?")
_ADVISORY_SEVERITY_LINE_RE = re.compile(r"(?m)^-\s*\*\*Severity:\*\*.*$")

CVE_VECTOR_PATH = "containers.cna.metrics[0].cvssV3_1.vectorString"
CVE_SCORE_PATH = "containers.cna.metrics[0].cvssV3_1.baseScore"
CVE_SEVERITY_PATH = "containers.cna.metrics[0].cvssV3_1.baseSeverity"
_CVE_SCORE_PATHS = frozenset({CVE_SCORE_PATH, CVE_SEVERITY_PATH})


class Cvss31Error(ValueError):
    """Invalid CVSS 3.1 vector; ``issues`` lists each problem for the Agent."""

    def __init__(self, issues: list[str]):
        cleaned = [str(item).strip() for item in issues if str(item).strip()]
        if not cleaned:
            cleaned = ["评分向量无效"]
        self.issues = cleaned
        super().__init__(format_cvss31_error(cleaned))


def format_cvss31_error(issues: list[str]) -> str:
    lines = ["CVSS 3.1 评分向量无效："]
    lines.extend(f"- {item}" for item in issues)
    lines.append(
        "正确示例：CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        "（只填这 8 个基础度量，不要手填分数；分数由系统计算）"
    )
    return "\n".join(lines)


@dataclass(frozen=True)
class Cvss31Result:
    vector: str
    metrics: dict[str, str]
    score: float
    severity: str

    @property
    def severity_en(self) -> str:
        return SEVERITY_EN[self.severity]

    @property
    def severity_label(self) -> str:
        from .vuln_types import SEVERITY_LABELS

        return SEVERITY_LABELS.get(self.severity, self.severity)

    @property
    def has_high_impact(self) -> bool:
        return any(self.metrics[key] == "H" for key in ("C", "I", "A"))

    def to_cve_metric(self) -> dict[str, Any]:
        m = self.metrics
        return {
            "version": CVSS_VERSION,
            "vectorString": self.vector,
            "attackVector": _CVE_AV[m["AV"]],
            "attackComplexity": _CVE_AC[m["AC"]],
            "privilegesRequired": _CVE_PR[m["PR"]],
            "userInteraction": _CVE_UI[m["UI"]],
            "scope": _CVE_SCOPE[m["S"]],
            "confidentialityImpact": _CVE_CIA[m["C"]],
            "integrityImpact": _CVE_CIA[m["I"]],
            "availabilityImpact": _CVE_CIA[m["A"]],
            "baseScore": self.score,
            "baseSeverity": self.severity_en.upper(),
        }


_PR_SURFACE_HINT = {
    "N": "前台未认证",
    "L": "后台普通权限",
    "H": "后台管理员",
}


def expected_pr(attack_surface: str, required_account: str | None = None) -> str | None:
    """PR required by ConfirmVuln attack_surface / required_account, or None if unknown."""
    surface = (attack_surface or "").strip()
    account = (required_account or "").strip() or None
    if surface == "frontend":
        return "N"
    if surface == "backend":
        if account == "admin":
            return "H"
        if account == "user":
            return "L"
    return None


def cvss_pr_alignment_error(
    cvss: Cvss31Result,
    attack_surface: str,
    required_account: str | None = None,
) -> str | None:
    """Reject PR that contradicts the declared attack surface."""
    expected = expected_pr(attack_surface, required_account)
    if expected is None:
        return None
    actual = cvss.metrics.get("PR")
    if actual == expected:
        return None
    surface = (attack_surface or "").strip()
    account = (required_account or "").strip() or None
    declared = "前台" if surface == "frontend" else (
        "后台管理员" if account == "admin" else "后台普通权限"
    )
    return (
        "PR 必须与 attack_surface / required_account 一致："
        f"当前标注为{declared}，须写 PR:{expected}（{_PR_SURFACE_HINT[expected]}），"
        f"向量里是 PR:{actual}。"
        "前台未认证 → PR:N；后台普通权限 → PR:L；后台管理员 → PR:H。"
        "不要用「SNMP/设备侧注入不需要应用账号」把后台洞写成 PR:N；"
        "若攻击者确实无需本应用账号且受害者页面未认证，应改标 attack_surface=frontend。"
    )


def severity_from_cvss_score(score: float) -> str:
    if score <= 0:
        return "none" if score == 0 else "low"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def _roundup(value: float) -> float:
    """CVSS 3.1 roundup: smallest one-decimal number ≥ input."""
    integer_input = int(round(value * 100000))
    if integer_input % 10000 == 0:
        return integer_input / 100000.0
    return (math.floor(integer_input / 10000) + 1) / 10.0


def canonical_vector(metrics: dict[str, str]) -> str:
    parts = [CVSS_PREFIX] + [f"{key}:{metrics[key]}" for key in REQUIRED_METRICS]
    return "/".join(parts)


def _score_metrics(metrics: dict[str, str]) -> float:
    iss = 1.0 - (
        (1.0 - _CIA[metrics["C"]])
        * (1.0 - _CIA[metrics["I"]])
        * (1.0 - _CIA[metrics["A"]])
    )
    if metrics["S"] == "U":
        impact = 6.42 * iss
        pr = _PR_UNCHANGED[metrics["PR"]]
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        pr = _PR_CHANGED[metrics["PR"]]
    exploitability = 8.22 * _AV[metrics["AV"]] * _AC[metrics["AC"]] * pr * _UI[metrics["UI"]]
    if impact <= 0:
        return 0.0
    if metrics["S"] == "U":
        raw = min(impact + exploitability, 10.0)
    else:
        raw = min(1.08 * (impact + exploitability), 10.0)
    return _roundup(raw)


def parse_cvss31(raw: Any) -> Cvss31Result:
    text = str(raw or "").strip()
    if not text:
        raise Cvss31Error(["缺少评分向量 cvss_vector"])

    compact = re.sub(r"\s+", "", text)
    issues: list[str] = []
    body = compact
    if compact.upper().startswith("CVSS:"):
        slash = compact.find("/")
        prefix = compact[:slash] if slash != -1 else compact
        prefix_upper = prefix.upper()
        if prefix_upper != CVSS_PREFIX:
            issues.append(
                f"须使用 {CVSS_PREFIX} 前缀，当前为 {prefix}。"
                "不要写 CVSS:3.0 或 CVSS:4.0"
            )
        body = compact[slash + 1 :] if slash != -1 else ""
        if slash == -1:
            issues.append("前缀后缺少度量，须为 CVSS:3.1/AV:.../AC:... 形式")
    else:
        issues.append(f"须以 {CVSS_PREFIX}/ 开头")

    seen: dict[str, str] = {}
    unknown: list[str] = []
    if body:
        for token in body.split("/"):
            if not token:
                issues.append("向量中有空的度量段（多余的 /）")
                continue
            match = _VECTOR_TOKEN_RE.match(token)
            if not match:
                issues.append(f"无法解析度量 {token!r}，须为 度量:取值，如 AV:N")
                continue
            key = match.group(1).upper()
            value = match.group(2).upper()
            if key not in METRIC_VALUES:
                unknown.append(f"{key}:{value}")
                continue
            if key in seen:
                issues.append(f"度量 {key}（{METRIC_LABELS[key]}）重复出现")
                continue
            allowed = METRIC_VALUES[key]
            if value not in allowed:
                issues.append(
                    f"度量 {key}（{METRIC_LABELS[key]}）取值 {value} 无效，可选：{METRIC_VALUE_HINTS[key]}"
                )
                continue
            seen[key] = value

    if unknown:
        extra = "、".join(unknown)
        issues.append(
            f"未知度量 {extra}；CVSS 3.1 基础向量只允许 "
            + "/".join(REQUIRED_METRICS)
            + "，不要带时序/环境度量"
        )

    missing = [key for key in REQUIRED_METRICS if key not in seen]
    if missing:
        detail = "、".join(f"{key}（{METRIC_LABELS[key]}，{METRIC_VALUE_HINTS[key]}）" for key in missing)
        issues.append(f"缺少必填度量：{detail}")

    if issues:
        raise Cvss31Error(issues)

    vector = canonical_vector(seen)
    score = _score_metrics(seen)
    severity = severity_from_cvss_score(score)
    if severity == "none":
        severity = "low"
    return Cvss31Result(vector=vector, metrics=seen, score=score, severity=severity)


def stamp_advisory_cvss31(text: str, result: Cvss31Result) -> str:
    """Replace CVSS 3.x/4.x lines in advisory.md with the computed CVSS 3.1 line."""
    body = (text or "").replace("\r\n", "\n")
    cvss_line = f"- **CVSS 3.1:** {result.score:.1f} {result.severity_en} — `{result.vector}`"
    sev_line = f"- **Severity:** {result.severity_en}"
    if _ADVISORY_SEVERITY_LINE_RE.search(body):
        body = _ADVISORY_SEVERITY_LINE_RE.sub(sev_line, body, count=1)
    if _ADVISORY_CVSS_LINE_RE.search(body):
        first = True

        def _replace(match: re.Match[str]) -> str:
            nonlocal first
            if first:
                first = False
                return cvss_line + "\n"
            return ""

        body = _ADVISORY_CVSS_LINE_RE.sub(_replace, body)
        body = re.sub(r"\n{3,}", "\n\n", body)
        return body
    marker = "## Severity / CWE"
    idx = body.find(marker)
    if idx != -1:
        insert_at = body.find("\n", idx)
        if insert_at == -1:
            insert_at = len(body)
        block = f"\n\n{sev_line}\n{cvss_line}\n"
        return body[: insert_at + 1] + block + body[insert_at + 1 :].lstrip("\n")
    return body.rstrip() + f"\n\n{marker}\n\n{sev_line}\n{cvss_line}\n"


def apply_cvss31_to_cve_record(record: dict[str, Any], result: Cvss31Result) -> None:
    cna = record.setdefault("containers", {}).setdefault("cna", {})
    metrics_list = cna.setdefault("metrics", [])
    if not metrics_list:
        metrics_list.append({"format": "CVSS", "scenarios": [{"lang": "en", "value": "GENERAL"}]})
    entry = metrics_list[0]
    if not isinstance(entry, dict):
        entry = {"format": "CVSS"}
        metrics_list[0] = entry
    entry.pop("cvssV4_0", None)
    entry.pop("cvssV3_0", None)
    entry["format"] = "CVSS"
    entry["cvssV3_1"] = result.to_cve_metric()

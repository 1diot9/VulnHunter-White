"""CVSS 4.0 base-vector parse, validate, and score.

Agent supplies the vector string only. Base score / severity are computed here
per FIRST CVSS v4.0 (macrovector lookup + severity-distance interpolation).

Lookup tables and interpolation follow the FIRST / Red Hat calculator
(BSD-2-Clause): https://github.com/FIRSTdotorg/cvss-v4-calculator
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, ROUND_HALF_UP
import math
import re
from typing import Any

from .cvss31 import SEVERITY_EN, expected_pr, severity_from_cvss_score

CVSS_VERSION = "4.0"
CVSS_PREFIX = "CVSS:4.0"
REQUIRED_METRICS: tuple[str, ...] = (
    "AV",
    "AC",
    "AT",
    "PR",
    "UI",
    "VC",
    "VI",
    "VA",
    "SC",
    "SI",
    "SA",
)

METRIC_VALUES: dict[str, tuple[str, ...]] = {
    "AV": ("N", "A", "L", "P"),
    "AC": ("L", "H"),
    "AT": ("N", "P"),
    "PR": ("N", "L", "H"),
    "UI": ("N", "P", "A"),
    "VC": ("H", "L", "N"),
    "VI": ("H", "L", "N"),
    "VA": ("H", "L", "N"),
    "SC": ("H", "L", "N"),
    "SI": ("H", "L", "N"),
    "SA": ("H", "L", "N"),
}

METRIC_LABELS: dict[str, str] = {
    "AV": "Attack Vector（攻击向量）",
    "AC": "Attack Complexity（攻击复杂度）",
    "AT": "Attack Requirements（攻击要求）",
    "PR": "Privileges Required（所需权限）",
    "UI": "User Interaction（用户交互）",
    "VC": "Vulnerable System Confidentiality（脆弱系统机密性）",
    "VI": "Vulnerable System Integrity（脆弱系统完整性）",
    "VA": "Vulnerable System Availability（脆弱系统可用性）",
    "SC": "Subsequent System Confidentiality（后续系统机密性）",
    "SI": "Subsequent System Integrity（后续系统完整性）",
    "SA": "Subsequent System Availability（后续系统可用性）",
}

METRIC_VALUE_HINTS: dict[str, str] = {
    "AV": "N=Network / A=Adjacent / L=Local / P=Physical",
    "AC": "L=Low / H=High",
    "AT": "N=None / P=Present",
    "PR": "N=None / L=Low / H=High",
    "UI": "N=None / P=Passive / A=Active",
    "VC": "H=High / L=Low / N=None",
    "VI": "H=High / L=Low / N=None",
    "VA": "H=High / L=Low / N=None",
    "SC": "H=High / L=Low / N=None",
    "SI": "H=High / L=Low / N=None",
    "SA": "H=High / L=Low / N=None",
}

_CVE_AV = {"N": "NETWORK", "A": "ADJACENT_NETWORK", "L": "LOCAL", "P": "PHYSICAL"}
_CVE_AC = {"L": "LOW", "H": "HIGH"}
_CVE_AT = {"N": "NONE", "P": "PRESENT"}
_CVE_PR = {"N": "NONE", "L": "LOW", "H": "HIGH"}
_CVE_UI = {"N": "NONE", "P": "PASSIVE", "A": "ACTIVE"}
_CVE_CIA = {"H": "HIGH", "L": "LOW", "N": "NONE"}

_VECTOR_TOKEN_RE = re.compile(r"^([A-Za-z]{1,4}):([A-Za-z])$")
_LEVELS = {
    "AV": {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3},
    "PR": {"N": 0.0, "L": 0.1, "H": 0.2},
    "UI": {"N": 0.0, "P": 0.1, "A": 0.2},
    "AC": {"L": 0.0, "H": 0.1},
    "AT": {"N": 0.0, "P": 0.1},
    "VC": {"H": 0.0, "L": 0.1, "N": 0.2},
    "VI": {"H": 0.0, "L": 0.1, "N": 0.2},
    "VA": {"H": 0.0, "L": 0.1, "N": 0.2},
    "SC": {"H": 0.1, "L": 0.2, "N": 0.3},
    "SI": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
    "SA": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
    "CR": {"H": 0.0, "M": 0.1, "L": 0.2},
    "IR": {"H": 0.0, "M": 0.1, "L": 0.2},
    "AR": {"H": 0.0, "M": 0.1, "L": 0.2},
}

CVE_VECTOR_PATH = "containers.cna.metrics[0].cvssV4_0.vectorString"
CVE_SCORE_PATH = "containers.cna.metrics[0].cvssV4_0.baseScore"
CVE_SEVERITY_PATH = "containers.cna.metrics[0].cvssV4_0.baseSeverity"

_PR_SURFACE_HINT = {
    "N": "前台未认证",
    "L": "后台普通权限",
    "H": "后台管理员",
}

# FIRST CVSS v4.0 macrovector lookup (BSD-2-Clause, FIRSTdotorg/cvss-v4-calculator).
_LOOKUP: dict[str, float] = {
    "000000": 10, "000001": 9.9, "000010": 9.8, "000011": 9.5, "000020": 9.5, "000021": 9.2,
    "000100": 10, "000101": 9.6, "000110": 9.3, "000111": 8.7, "000120": 9.1, "000121": 8.1,
    "000200": 9.3, "000201": 9, "000210": 8.9, "000211": 8, "000220": 8.1, "000221": 6.8,
    "001000": 9.8, "001001": 9.5, "001010": 9.5, "001011": 9.2, "001020": 9, "001021": 8.4,
    "001100": 9.3, "001101": 9.2, "001110": 8.9, "001111": 8.1, "001120": 8.1, "001121": 6.5,
    "001200": 8.8, "001201": 8, "001210": 7.8, "001211": 7, "001220": 6.9, "001221": 4.8,
    "002001": 9.2, "002011": 8.2, "002021": 7.2, "002101": 7.9, "002111": 6.9, "002121": 5,
    "002201": 6.9, "002211": 5.5, "002221": 2.7,
    "010000": 9.9, "010001": 9.7, "010010": 9.5, "010011": 9.2, "010020": 9.2, "010021": 8.5,
    "010100": 9.5, "010101": 9.1, "010110": 9, "010111": 8.3, "010120": 8.4, "010121": 7.1,
    "010200": 9.2, "010201": 8.1, "010210": 8.2, "010211": 7.1, "010220": 7.2, "010221": 5.3,
    "011000": 9.5, "011001": 9.3, "011010": 9.2, "011011": 8.5, "011020": 8.5, "011021": 7.3,
    "011100": 9.2, "011101": 8.2, "011110": 8, "011111": 7.2, "011120": 7, "011121": 5.9,
    "011200": 8.4, "011201": 7, "011210": 7.1, "011211": 5.2, "011220": 5, "011221": 3,
    "012001": 8.6, "012011": 7.5, "012021": 5.2, "012101": 7.1, "012111": 5.2, "012121": 2.9,
    "012201": 6.3, "012211": 2.9, "012221": 1.7,
    "100000": 9.8, "100001": 9.5, "100010": 9.4, "100011": 8.7, "100020": 9.1, "100021": 8.1,
    "100100": 9.4, "100101": 8.9, "100110": 8.6, "100111": 7.4, "100120": 7.7, "100121": 6.4,
    "100200": 8.7, "100201": 7.5, "100210": 7.4, "100211": 6.3, "100220": 6.3, "100221": 4.9,
    "101000": 9.4, "101001": 8.9, "101010": 8.8, "101011": 7.7, "101020": 7.6, "101021": 6.7,
    "101100": 8.6, "101101": 7.6, "101110": 7.4, "101111": 5.8, "101120": 5.9, "101121": 5,
    "101200": 7.2, "101201": 5.7, "101210": 5.7, "101211": 5.2, "101220": 5.2, "101221": 2.5,
    "102001": 8.3, "102011": 7, "102021": 5.4, "102101": 6.5, "102111": 5.8, "102121": 2.6,
    "102201": 5.3, "102211": 2.1, "102221": 1.3,
    "110000": 9.5, "110001": 9, "110010": 8.8, "110011": 7.6, "110020": 7.6, "110021": 7,
    "110100": 9, "110101": 7.7, "110110": 7.5, "110111": 6.2, "110120": 6.1, "110121": 5.3,
    "110200": 7.7, "110201": 6.6, "110210": 6.8, "110211": 5.9, "110220": 5.2, "110221": 3,
    "111000": 8.9, "111001": 7.8, "111010": 7.6, "111011": 6.7, "111020": 6.2, "111021": 5.8,
    "111100": 7.4, "111101": 5.9, "111110": 5.7, "111111": 5.7, "111120": 4.7, "111121": 2.3,
    "111200": 6.1, "111201": 5.2, "111210": 5.7, "111211": 2.9, "111220": 2.4, "111221": 1.6,
    "112001": 7.1, "112011": 5.9, "112021": 3, "112101": 5.8, "112111": 2.6, "112121": 1.5,
    "112201": 2.3, "112211": 1.3, "112221": 0.6,
    "200000": 9.3, "200001": 8.7, "200010": 8.6, "200011": 7.2, "200020": 7.5, "200021": 5.8,
    "200100": 8.6, "200101": 7.4, "200110": 7.4, "200111": 6.1, "200120": 5.6, "200121": 3.4,
    "200200": 7, "200201": 5.4, "200210": 5.2, "200211": 4, "200220": 4, "200221": 2.2,
    "201000": 8.5, "201001": 7.5, "201010": 7.4, "201011": 5.5, "201020": 6.2, "201021": 5.1,
    "201100": 7.2, "201101": 5.7, "201110": 5.5, "201111": 4.1, "201120": 4.6, "201121": 1.9,
    "201200": 5.3, "201201": 3.6, "201210": 3.4, "201211": 1.9, "201220": 1.9, "201221": 0.8,
    "202001": 6.4, "202011": 5.1, "202021": 2, "202101": 4.7, "202111": 2.1, "202121": 1.1,
    "202201": 2.4, "202211": 0.9, "202221": 0.4,
    "210000": 8.8, "210001": 7.5, "210010": 7.3, "210011": 5.3, "210020": 6, "210021": 5,
    "210100": 7.3, "210101": 5.5, "210110": 5.9, "210111": 4, "210120": 4.1, "210121": 2,
    "210200": 5.4, "210201": 4.3, "210210": 4.5, "210211": 2.2, "210220": 2, "210221": 1.1,
    "211000": 7.5, "211001": 5.5, "211010": 5.8, "211011": 4.5, "211020": 4, "211021": 2.1,
    "211100": 6.1, "211101": 5.1, "211110": 4.8, "211111": 1.8, "211120": 2, "211121": 0.9,
    "211200": 4.6, "211201": 1.8, "211210": 1.7, "211211": 0.7, "211220": 0.8, "211221": 0.2,
    "212001": 5.3, "212011": 2.4, "212021": 1.4, "212101": 2.4, "212111": 1.2, "212121": 0.5,
    "212201": 1, "212211": 0.3, "212221": 0.1,
}

_MAX_COMPOSED: dict[str, dict[int, Any]] = {
    "eq1": {
        0: ["AV:N/PR:N/UI:N/"],
        1: ["AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"],
        2: ["AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/"],
    },
    "eq2": {
        0: ["AC:L/AT:N/"],
        1: ["AC:H/AT:N/", "AC:L/AT:P/"],
    },
    "eq3": {
        0: {
            0: ["VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/"],
            1: ["VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/", "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/"],
        },
        1: {
            0: ["VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/", "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/"],
            1: [
                "VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/",
                "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/",
                "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/",
                "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/",
                "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/",
            ],
        },
        2: {1: ["VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/"]},
    },
    "eq4": {
        0: ["SC:H/SI:S/SA:S/"],
        1: ["SC:H/SI:H/SA:H/"],
        2: ["SC:L/SI:L/SA:L/"],
    },
    "eq5": {
        0: ["E:A/"],
        1: ["E:P/"],
        2: ["E:U/"],
    },
}

_MAX_SEVERITY = {
    "eq1": {0: 1, 1: 4, 2: 5},
    "eq2": {0: 1, 1: 2},
    "eq3eq6": {0: {0: 7, 1: 6}, 1: {0: 8, 1: 8}, 2: {1: 10}},
    "eq4": {0: 6, 1: 5, 2: 4},
    "eq5": {0: 1, 1: 1, 2: 1},
}

_EPSILON = 1e-6


class Cvss40Error(ValueError):
    """Invalid CVSS 4.0 vector; ``issues`` lists each problem for the Agent."""

    def __init__(self, issues: list[str]):
        cleaned = [str(item).strip() for item in issues if str(item).strip()]
        if not cleaned:
            cleaned = ["评分向量无效"]
        self.issues = cleaned
        super().__init__(format_cvss40_error(cleaned))


def format_cvss40_error(issues: list[str]) -> str:
    lines = ["CVSS 4.0 评分向量无效："]
    lines.extend(f"- {item}" for item in issues)
    lines.append(
        "正确示例：CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        "（只填这 11 个基础度量，不要手填分数；分数由系统计算）"
    )
    return "\n".join(lines)


@dataclass(frozen=True)
class Cvss40Result:
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
        return any(self.metrics[key] == "H" for key in ("VC", "VI", "VA"))

    def to_cve_metric(self) -> dict[str, Any]:
        m = self.metrics
        return {
            "version": CVSS_VERSION,
            "vectorString": self.vector,
            "attackVector": _CVE_AV[m["AV"]],
            "attackComplexity": _CVE_AC[m["AC"]],
            "attackRequirements": _CVE_AT[m["AT"]],
            "privilegesRequired": _CVE_PR[m["PR"]],
            "userInteraction": _CVE_UI[m["UI"]],
            "vulnConfidentialityImpact": _CVE_CIA[m["VC"]],
            "vulnIntegrityImpact": _CVE_CIA[m["VI"]],
            "vulnAvailabilityImpact": _CVE_CIA[m["VA"]],
            "subConfidentialityImpact": _CVE_CIA[m["SC"]],
            "subIntegrityImpact": _CVE_CIA[m["SI"]],
            "subAvailabilityImpact": _CVE_CIA[m["SA"]],
            "baseScore": self.score,
            "baseSeverity": self.severity_en.upper(),
        }


def cvss40_pr_alignment_error(
    cvss: Cvss40Result,
    attack_surface: str,
    required_account: str | None = None,
) -> str | None:
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
        "CVSS 4.0 的 PR 必须与 attack_surface / required_account 一致："
        f"当前标注为{declared}，须写 PR:{expected}（{_PR_SURFACE_HINT[expected]}），"
        f"向量里是 PR:{actual}。"
        "前台未认证 → PR:N；后台普通权限 → PR:L；后台管理员 → PR:H。"
    )


def canonical_vector(metrics: dict[str, str]) -> str:
    parts = [CVSS_PREFIX] + [f"{key}:{metrics[key]}" for key in REQUIRED_METRICS]
    return "/".join(parts)


def parse_cvss40(raw: Any) -> Cvss40Result:
    text = str(raw or "").strip()
    if not text:
        raise Cvss40Error(["缺少评分向量 cvss4_vector"])

    compact = re.sub(r"\s+", "", text)
    issues: list[str] = []
    body = compact
    if compact.upper().startswith("CVSS:"):
        slash = compact.find("/")
        prefix = compact[:slash] if slash != -1 else compact
        if prefix.upper() != CVSS_PREFIX:
            issues.append(
                f"须使用 {CVSS_PREFIX} 前缀，当前为 {prefix}。"
                "ConfirmVuln 的 cvss4_vector 不要写 CVSS:3.0 或 CVSS:3.1"
            )
        body = compact[slash + 1 :] if slash != -1 else ""
        if slash == -1:
            issues.append("前缀后缺少度量，须为 CVSS:4.0/AV:.../AC:... 形式")
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
            f"未知度量 {extra}；CVSS 4.0 基础向量只允许 "
            + "/".join(REQUIRED_METRICS)
            + "，不要带威胁/环境度量（E/CR/IR/AR 等）"
        )

    missing = [key for key in REQUIRED_METRICS if key not in seen]
    if missing:
        detail = "、".join(
            f"{key}（{METRIC_LABELS[key]}，{METRIC_VALUE_HINTS[key]}）" for key in missing
        )
        issues.append(f"缺少必填度量：{detail}")

    if issues:
        raise Cvss40Error(issues)

    vector = canonical_vector(seen)
    score = _score_metrics(seen)
    severity = severity_from_cvss_score(score)
    if severity == "none":
        severity = "low"
    return Cvss40Result(vector=vector, metrics=seen, score=score, severity=severity)


def apply_cvss40_to_cve_record(record: dict[str, Any], result: Cvss40Result) -> None:
    cna = record.setdefault("containers", {}).setdefault("cna", {})
    metrics_list = cna.setdefault("metrics", [])
    if not metrics_list:
        metrics_list.append({"format": "CVSS", "scenarios": [{"lang": "en", "value": "GENERAL"}]})
    entry = metrics_list[0]
    if not isinstance(entry, dict):
        entry = {"format": "CVSS"}
        metrics_list[0] = entry
    entry["format"] = "CVSS"
    entry["cvssV4_0"] = result.to_cve_metric()


def _m(metrics: dict[str, str], metric: str) -> str:
    if metric == "E":
        return "A"
    if metric in ("CR", "IR", "AR"):
        return "H"
    if metric in ("MSI", "MSA"):
        return metrics.get(metric[1:], "N")
    return metrics[metric]


def _macro_vector(metrics: dict[str, str]) -> str:
    av, pr, ui = _m(metrics, "AV"), _m(metrics, "PR"), _m(metrics, "UI")
    if av == "N" and pr == "N" and ui == "N":
        eq1 = "0"
    elif (av == "N" or pr == "N" or ui == "N") and av != "P":
        eq1 = "1"
    else:
        eq1 = "2"

    if _m(metrics, "AC") == "L" and _m(metrics, "AT") == "N":
        eq2 = "0"
    else:
        eq2 = "1"

    vc, vi, va = _m(metrics, "VC"), _m(metrics, "VI"), _m(metrics, "VA")
    if vc == "H" and vi == "H":
        eq3 = "0"
    elif vc == "H" or vi == "H" or va == "H":
        eq3 = "1"
    else:
        eq3 = "2"

    msi, msa = _m(metrics, "MSI"), _m(metrics, "MSA")
    sc, si, sa = _m(metrics, "SC"), _m(metrics, "SI"), _m(metrics, "SA")
    if msi == "S" or msa == "S":
        eq4 = "0"
    elif sc == "H" or si == "H" or sa == "H":
        eq4 = "1"
    else:
        eq4 = "2"

    eq5 = "0"

    cr, ir, ar = _m(metrics, "CR"), _m(metrics, "IR"), _m(metrics, "AR")
    if (cr == "H" and vc == "H") or (ir == "H" and vi == "H") or (ar == "H" and va == "H"):
        eq6 = "0"
    else:
        eq6 = "1"
    return eq1 + eq2 + eq3 + eq4 + eq5 + eq6


def _extract_metric(metric: str, vector: str) -> str:
    key = metric + ":"
    start = vector.index(key) + len(key)
    rest = vector[start:]
    slash = rest.find("/")
    return rest if slash == -1 else rest[:slash]


def _eq_maxes(macro: str, eq_n: int) -> Any:
    return _MAX_COMPOSED[f"eq{eq_n}"][int(macro[eq_n - 1])]


def _distance(metrics: dict[str, str], metric: str, max_vector: str) -> float:
    levels = _LEVELS[metric]
    return levels[_m(metrics, metric)] - levels[_extract_metric(metric, max_vector)]


def _round_half_up(value: float) -> float:
    return float(Decimal(str(value + _EPSILON)).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP))


def _score_metrics(metrics: dict[str, str]) -> float:
    if all(_m(metrics, key) == "N" for key in ("VC", "VI", "VA", "SC", "SI", "SA")):
        return 0.0

    macro = _macro_vector(metrics)
    value = _LOOKUP[macro]
    eq1, eq2, eq3, eq4, eq5, eq6 = (int(ch) for ch in macro)

    next1 = f"{eq1 + 1}{eq2}{eq3}{eq4}{eq5}{eq6}"
    next2 = f"{eq1}{eq2 + 1}{eq3}{eq4}{eq5}{eq6}"
    if eq3 == 1 and eq6 == 0:
        next36 = f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6 + 1}"
        score36 = _LOOKUP.get(next36, float("nan"))
    elif eq3 == 0 and eq6 == 0:
        left = _LOOKUP.get(f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6 + 1}", float("nan"))
        right = _LOOKUP.get(f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6}", float("nan"))
        score36 = max(left, right)
    else:
        next36 = f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6}"
        score36 = _LOOKUP.get(next36, float("nan"))
    next4 = f"{eq1}{eq2}{eq3}{eq4 + 1}{eq5}{eq6}"
    next5 = f"{eq1}{eq2}{eq3}{eq4}{eq5 + 1}{eq6}"

    score1 = _LOOKUP.get(next1, float("nan"))
    score2 = _LOOKUP.get(next2, float("nan"))
    score4 = _LOOKUP.get(next4, float("nan"))
    score5 = _LOOKUP.get(next5, float("nan"))

    eq1_maxes = _eq_maxes(macro, 1)
    eq2_maxes = _eq_maxes(macro, 2)
    eq3_eq6_maxes = _eq_maxes(macro, 3)[eq6]
    eq4_maxes = _eq_maxes(macro, 4)
    eq5_maxes = _eq_maxes(macro, 5)

    max_vectors = [
        a + b + c + d + e
        for a in eq1_maxes
        for b in eq2_maxes
        for c in eq3_eq6_maxes
        for d in eq4_maxes
        for e in eq5_maxes
    ]

    dist: dict[str, float] = {key: 0.0 for key in _LEVELS}
    for max_vector in max_vectors:
        candidate = {key: _distance(metrics, key, max_vector) for key in _LEVELS}
        if any(item < 0 for item in candidate.values()):
            continue
        dist = candidate
        break

    current1 = dist["AV"] + dist["PR"] + dist["UI"]
    current2 = dist["AC"] + dist["AT"]
    current36 = dist["VC"] + dist["VI"] + dist["VA"] + dist["CR"] + dist["IR"] + dist["AR"]
    current4 = dist["SC"] + dist["SI"] + dist["SA"]

    step = 0.1
    n_existing = 0
    total = 0.0

    def _accumulate(available: float, current: float, max_sev: float) -> None:
        nonlocal n_existing, total
        if isinstance(available, (float, int)) and not math.isnan(available) and available >= 0:
            n_existing += 1
            total += available * (current / max_sev if max_sev else 0.0)

    _accumulate(value - score1, current1, _MAX_SEVERITY["eq1"][eq1] * step)
    _accumulate(value - score2, current2, _MAX_SEVERITY["eq2"][eq2] * step)
    _accumulate(value - score36, current36, _MAX_SEVERITY["eq3eq6"][eq3][eq6] * step)
    _accumulate(value - score4, current4, _MAX_SEVERITY["eq4"][eq4] * step)
    _accumulate(value - score5, 0.0, _MAX_SEVERITY["eq5"][eq5] * step)

    mean = 0.0 if n_existing == 0 else total / n_existing
    value = min(10.0, max(0.0, value - mean))
    return _round_half_up(value)

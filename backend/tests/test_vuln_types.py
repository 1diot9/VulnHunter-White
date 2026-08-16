from __future__ import annotations

from app.vuln_types import (
    calibrate_review_severity,
    infer_vuln_type_from_text,
    normalize_vuln_type,
    resolve_vuln_type_and_severity,
    severity_for_type,
)


def test_normalize_aliases():
    assert normalize_vuln_type("SQL注入") == "sqli"
    assert normalize_vuln_type("command_injection") == "rce"
    assert normalize_vuln_type("jndi") == "jndi_injection"
    assert normalize_vuln_type("") == "other"


def test_severity_for_type():
    assert severity_for_type("rce") == "critical"
    assert severity_for_type("ssrf") == "medium"
    assert severity_for_type("xss") == "low"


def test_infer_from_text():
    assert infer_vuln_type_from_text("任意文件读取漏洞") == "file_read"
    assert infer_vuln_type_from_text("Log4j JNDI lookup") == "jndi_injection"


def test_resolve_prefers_explicit_type():
    vtype, sev = resolve_vuln_type_and_severity(
        {"vuln_type": "sqli", "title": "something RCE sounding"}
    )
    assert vtype == "sqli"
    assert sev == "high"


def test_review_severity_calibration_can_upgrade_default_type_mapping():
    calibration = calibrate_review_severity(
        attack_surface="frontend",
        required_account=None,
        impact="rce_or_full_data",
        exploit_complexity="single_request",
        defense_status="none",
    )
    assert calibration.score == 5
    assert calibration.severity == "critical"


def test_review_severity_calibration_can_downgrade_by_context():
    calibration = calibrate_review_severity(
        attack_surface="backend",
        required_account="admin",
        impact="limited_info",
        exploit_complexity="specific_environment",
        defense_status="conditional",
    )
    assert calibration.score == -2
    assert calibration.severity == "low"


def test_review_severity_calibration_accepts_chinese_aliases():
    calibration = calibrate_review_severity(
        attack_surface="backend",
        required_account="user",
        impact="敏感数据",
        exploit_complexity="多步骤",
        defense_status="有防护但可绕过",
    )
    assert calibration.score == 2
    assert calibration.severity == "medium"

from __future__ import annotations

from app.vuln_types import (
    PENDING_SEVERITY,
    calibrate_review_severity,
    infer_vuln_type_from_text,
    normalize_submission_decision,
    normalize_vuln_type,
    resolve_vuln_type,
    suggest_submission_tier,
)


def test_normalize_aliases():
    assert normalize_vuln_type("SQL注入") == "sqli"
    assert normalize_vuln_type("command_injection") == "rce"
    assert normalize_vuln_type("jndi") == "jndi_injection"
    assert normalize_vuln_type("") == "other"


def test_infer_from_text():
    assert infer_vuln_type_from_text("任意文件读取漏洞") == "file_read"
    assert infer_vuln_type_from_text("Log4j JNDI lookup") == "jndi_injection"


def test_resolve_prefers_explicit_type():
    vtype = resolve_vuln_type(
        {"vuln_type": "sqli", "title": "something RCE sounding"}
    )
    assert vtype == "sqli"


def test_pending_severity_constant():
    assert PENDING_SEVERITY == "pending"


def test_review_severity_calibration_can_upgrade_without_type_mapping():
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
    assert calibration.score == -3
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


def test_normalize_submission_decision_and_aliases():
    decision = normalize_submission_decision(
        submission_tier="CVE 候选",
        submission_reason="未认证任意文件读",
    )
    assert decision.tier == "cve_candidate"
    assert decision.tier_label == "CVE 候选"

    dup = normalize_submission_decision(
        submission_tier="同根因重复",
        submission_reason="同过滤器",
        root_cause_key="ssrf:checkSsrfHttpUrl",
    )
    assert dup.tier == "duplicate_grouped"
    assert dup.root_cause_key == "ssrf:checkSsrfHttpUrl"

    try:
        normalize_submission_decision(
            submission_tier="duplicate_grouped",
            submission_reason="缺 key",
        )
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "root_cause_key" in str(exc)


def test_suggest_submission_tier_hint():
    strong = calibrate_review_severity(
        attack_surface="frontend",
        required_account=None,
        impact="rce_or_full_data",
        exploit_complexity="single_request",
        defense_status="none",
    )
    assert suggest_submission_tier(calibration=strong) == "cve_candidate"

    weak = calibrate_review_severity(
        attack_surface="backend",
        required_account="admin",
        impact="limited_info",
        exploit_complexity="specific_environment",
        defense_status="conditional",
    )
    assert suggest_submission_tier(calibration=weak, evidence_level="static_only") == "needs_more_evidence"

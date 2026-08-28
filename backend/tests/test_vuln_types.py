from __future__ import annotations

from app.cvss31 import parse_cvss31
from app.vuln_types import (
    PENDING_SEVERITY,
    infer_vuln_type_from_text,
    normalize_config_premise,
    normalize_submission_decision,
    normalize_vuln_type,
    resolve_vuln_type,
    suggest_submission_tier,
)


def test_normalize_aliases():
    assert normalize_vuln_type("SQL注入") == "sqli"
    assert normalize_vuln_type("command_injection") == "rce"
    assert normalize_vuln_type("jndi") == "jndi_injection"
    assert normalize_vuln_type("xml_injection") == "xxe"
    assert normalize_vuln_type("文件包含") == "path_traversal"
    assert normalize_vuln_type("目录遍历") == "path_traversal"
    assert normalize_vuln_type("反射XSS") == "xss"
    assert normalize_vuln_type("存储型XSS") == "stored_xss"
    assert normalize_vuln_type("stored xss") == "stored_xss"
    assert normalize_vuln_type("CSRF") == "csrf"
    assert normalize_vuln_type("跨站请求伪造") == "csrf"
    assert normalize_vuln_type("1-click CSRF") == "csrf"
    assert normalize_vuln_type("硬编码密钥") == "hardcoded_secret"
    assert normalize_vuln_type("hardcoded credentials") == "hardcoded_secret"
    assert normalize_vuln_type("") == "other"


def test_infer_from_text():
    assert infer_vuln_type_from_text("任意文件读取漏洞") == "file_read"
    assert infer_vuln_type_from_text("Log4j JNDI lookup") == "jndi_injection"
    assert infer_vuln_type_from_text("Stored XSS in profile") == "stored_xss"
    assert infer_vuln_type_from_text("Cross-Site Request Forgery on plugin install") == "csrf"
    assert infer_vuln_type_from_text("hardcoded JWT secret") == "hardcoded_secret"


def test_refine_generic_xss_to_stored_when_title_says_so():
    from app.vuln_types import refine_vuln_type

    assert refine_vuln_type("xss", title="Reflected XSS") == "xss"
    assert refine_vuln_type("xss", title="存储型XSS in comment") == "stored_xss"


def test_resolve_prefers_explicit_type():
    vtype = resolve_vuln_type(
        {"vuln_type": "sqli", "title": "something RCE sounding"}
    )
    assert vtype == "sqli"


def test_pending_severity_constant():
    assert PENDING_SEVERITY == "pending"


def test_normalize_config_premise():
    assert normalize_config_premise("default") == "default"
    assert normalize_config_premise("默认配置") == "default"
    assert normalize_config_premise("specific") == "specific"
    assert normalize_config_premise("特定配置") == "specific"
    try:
        normalize_config_premise("")
        raise AssertionError("expected empty config_premise to fail")
    except ValueError as exc:
        assert "config_premise" in str(exc)
    try:
        normalize_config_premise("specific_environment")
        raise AssertionError("expected specific_environment to fail")
    except ValueError as exc:
        assert "config_premise" in str(exc)


def test_cvss31_scoring_replaces_old_review_calibration():
    critical = parse_cvss31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert critical.score == 9.8
    assert critical.severity == "critical"

    low = parse_cvss31("CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N")
    assert low.score == 2.0
    assert low.severity == "low"

    medium = parse_cvss31("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N")
    assert medium.score == 5.4
    assert medium.severity == "medium"


def test_normalize_submission_decision_and_aliases():
    decision = normalize_submission_decision(
        submission_tier="有 CVE 价值",
        submission_reason="未认证任意文件读",
    )
    assert decision.tier == "cve_candidate"
    assert decision.tier_label == "有 CVE 价值"

    low = normalize_submission_decision(
        submission_tier="加固建议",
        submission_reason="CORS",
    )
    assert low.tier == "low_impact"
    assert low.tier_label == "低危害难利用"

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

    try:
        normalize_submission_decision(
            submission_tier="证据不足",
            submission_reason="环境没打出来",
        )
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "submission_tier" in str(exc)


def test_suggest_submission_tier_hint():
    strong = parse_cvss31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert suggest_submission_tier(cvss=strong) == "cve_candidate"

    weak = parse_cvss31("CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N")
    assert suggest_submission_tier(cvss=weak) == "low_impact"

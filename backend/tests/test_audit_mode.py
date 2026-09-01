from __future__ import annotations

import pytest

from app.cvss31 import parse_cvss31
from app.audit_mode import (
    AUDIT_MODE_EDITABLE_STATUSES,
    DEFAULT_AUDIT_MODE,
    bounty_confirm_block_reason,
    bounty_submit_block_reason,
    initial_hint,
    is_user_modifiable_secret_path,
    normalize_audit_mode,
    parse_audit_mode,
    uses_bounty_gates,
)


def test_audit_mode_editable_statuses():
    assert AUDIT_MODE_EDITABLE_STATUSES == frozenset({"paused", "completed"})


def test_normalize_and_parse_audit_mode():
    assert normalize_audit_mode(None) == DEFAULT_AUDIT_MODE
    assert normalize_audit_mode("") == "bounty"
    assert normalize_audit_mode("赏金模式") == "bounty"
    assert normalize_audit_mode("全量") == "full"
    assert normalize_audit_mode("自定义") == "custom"
    assert parse_audit_mode(None) == "bounty"
    assert parse_audit_mode("full") == "full"
    assert parse_audit_mode("custom") == "custom"
    with pytest.raises(ValueError, match="audit_mode"):
        parse_audit_mode("nope")


def test_initial_hint_mentions_mode_rules():
    bounty = initial_hint("bounty")
    assert "赏金模式" in bounty
    assert "默认配置" in bounty
    assert "存储型 XSS" in bounty
    assert "1-click CSRF" in bounty
    assert "源码硬编码密钥" in bounty
    assert "服务端机密" in bounty
    assert "前端传输混淆" in bounty
    assert "禁止主动搭建漏洞利用环境" not in bounty
    assert "Docker 靶场" in bounty
    full = initial_hint("full")
    assert "全量模式" in full
    assert "低危害难利用" in full
    custom = initial_hint("custom", custom_name="demo")
    assert "自定义模式" in custom
    assert "demo" in custom
    assert "硬闸门" in custom


def test_bounty_gates_allow_stored_xss_and_source_secrets():
    assert bounty_submit_block_reason("xss")
    assert bounty_submit_block_reason("stored_xss") is None
    assert bounty_submit_block_reason("csrf") is None
    assert bounty_submit_block_reason("hardcoded_secret", file_path="src/JwtHelper.java") is None
    assert bounty_submit_block_reason("hardcoded_secret", file_path="application.yml")
    assert is_user_modifiable_secret_path("config/application-prod.yml")
    assert not is_user_modifiable_secret_path("src/main/java/util/EncryptUtils.java")
    assert bounty_confirm_block_reason(
        vuln_type="stored_xss",
        submission_tier="cve_candidate",
        file_path="CommentController.java",
    ) is None
    assert bounty_confirm_block_reason(
        vuln_type="csrf",
        submission_tier="cve_candidate",
        cvss=parse_cvss31("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"),
    ) is None
    assert bounty_confirm_block_reason(
        vuln_type="csrf",
        submission_tier="cve_candidate",
        cvss=parse_cvss31("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N"),
    ) is None
    csrf_low = bounty_confirm_block_reason(
        vuln_type="csrf",
        submission_tier="cve_candidate",
        cvss=parse_cvss31("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"),
    )
    assert csrf_low and "1-click CSRF" in csrf_low
    assert bounty_confirm_block_reason(vuln_type="xss", submission_tier="cve_candidate")
    low = bounty_confirm_block_reason(vuln_type="rce", submission_tier="low_impact")
    assert low and "MarkFalsePositive" in low


def test_uses_bounty_gates_for_unconstrained_even_on_full():
    assert uses_bounty_gates(audit_mode="bounty") is True
    assert uses_bounty_gates(audit_mode="full") is False
    assert uses_bounty_gates(audit_mode="custom") is False
    assert uses_bounty_gates(audit_mode="full", mining_path="unconstrained") is True
    assert uses_bounty_gates(audit_mode="custom", mining_path="unconstrained") is True
    assert uses_bounty_gates(audit_mode="full", mining_path="heuristic") is False
    assert uses_bounty_gates(audit_mode="bounty", mining_path="heuristic") is True

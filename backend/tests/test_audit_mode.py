from __future__ import annotations

import pytest

from app.audit_mode import (
    AUDIT_MODE_EDITABLE_STATUSES,
    DEFAULT_AUDIT_MODE,
    bounty_confirm_block_reason,
    bounty_submit_block_reason,
    initial_hint,
    is_user_modifiable_secret_path,
    normalize_audit_mode,
    parse_audit_mode,
)


def test_audit_mode_editable_statuses():
    assert AUDIT_MODE_EDITABLE_STATUSES == frozenset({"paused", "completed"})


def test_normalize_and_parse_audit_mode():
    assert normalize_audit_mode(None) == DEFAULT_AUDIT_MODE
    assert normalize_audit_mode("") == "bounty"
    assert normalize_audit_mode("赏金模式") == "bounty"
    assert normalize_audit_mode("全量") == "full"
    assert parse_audit_mode(None) == "bounty"
    assert parse_audit_mode("full") == "full"
    with pytest.raises(ValueError, match="audit_mode"):
        parse_audit_mode("nope")


def test_initial_hint_mentions_mode_rules():
    bounty = initial_hint("bounty")
    assert "赏金模式" in bounty
    assert "默认配置" in bounty
    assert "存储型 XSS" in bounty
    assert "源码硬编码密钥" in bounty
    assert "禁止主动搭建漏洞利用环境" not in bounty
    assert "Docker 靶场" in bounty
    full = initial_hint("full")
    assert "全量模式" in full
    assert "低危害难利用" in full


def test_bounty_gates_allow_stored_xss_and_source_secrets():
    assert bounty_submit_block_reason("xss")
    assert bounty_submit_block_reason("stored_xss") is None
    assert bounty_submit_block_reason("hardcoded_secret", file_path="src/JwtHelper.java") is None
    assert bounty_submit_block_reason("hardcoded_secret", file_path="application.yml")
    assert is_user_modifiable_secret_path("config/application-prod.yml")
    assert not is_user_modifiable_secret_path("src/main/java/util/EncryptUtils.java")
    assert bounty_confirm_block_reason(
        vuln_type="stored_xss",
        submission_tier="cve_candidate",
        file_path="CommentController.java",
    ) is None
    assert bounty_confirm_block_reason(vuln_type="xss", submission_tier="cve_candidate")

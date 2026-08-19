from __future__ import annotations

from app.audit_mode import (
    AUDIT_MODE_CUSTOM,
    bounty_confirm_block_reason,
    bounty_submit_block_reason,
    format_custom_overlay,
    initial_hint,
    is_bounty_mode,
    is_custom_mode,
    normalize_audit_mode,
    parse_audit_mode,
)


def test_parse_custom_audit_mode():
    assert parse_audit_mode("custom") == AUDIT_MODE_CUSTOM
    assert parse_audit_mode("自定义模式") == AUDIT_MODE_CUSTOM
    assert normalize_audit_mode("自定义") == "custom"
    assert is_custom_mode("custom")
    assert not is_bounty_mode("custom")


def test_custom_initial_hint_and_overlay():
    hint = initial_hint("custom", custom_name="只挖注入")
    assert "自定义模式" in hint
    assert "只挖注入" in hint
    assert "硬闸门" in hint
    overlay = format_custom_overlay(name="只挖注入", body="只收 SQL 注入")
    assert "自定义模式「只挖注入」" in overlay
    assert "只收 SQL 注入" in overlay
    assert "以本节为准" in overlay


def test_bounty_gates_still_only_for_structured_fields():
    assert bounty_submit_block_reason("xss")
    assert bounty_confirm_block_reason(vuln_type="xss", submission_tier="cve_candidate")
    assert bounty_confirm_block_reason(vuln_type="rce", submission_tier="low_impact")

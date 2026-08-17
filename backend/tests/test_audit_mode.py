from __future__ import annotations

import pytest

from app.audit_mode import (
    DEFAULT_AUDIT_MODE,
    initial_hint,
    normalize_audit_mode,
    parse_audit_mode,
)


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
    assert "禁止主动搭建漏洞利用环境" not in bounty
    assert "Docker 靶场" in bounty
    full = initial_hint("full")
    assert "全量模式" in full
    assert "低危害难利用" in full

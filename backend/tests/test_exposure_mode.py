from __future__ import annotations

import pytest

from app.cvss31 import parse_cvss31
from app.exposure_mode import (
    EXPOSURE_DIRECT,
    EXPOSURE_INDIRECT_CONSUMER,
    cvss_indirect_consumer_error,
    indirect_attack_surface_error,
    indirect_exposure_section_gap,
    indirect_submission_tier_error,
    normalize_exposure_mode,
)


def test_normalize_exposure_mode_aliases():
    assert normalize_exposure_mode("") == EXPOSURE_DIRECT
    assert normalize_exposure_mode("间接消费型") == EXPOSURE_INDIRECT_CONSUMER
    assert normalize_exposure_mode("indirect_consumer") == EXPOSURE_INDIRECT_CONSUMER
    with pytest.raises(ValueError, match="exposure_mode"):
        normalize_exposure_mode("unknown")


def test_indirect_section_requires_upstream_context_in_trigger_conditions():
    gap = indirect_exposure_section_gap("## 漏洞危害\n\n只有危害，没有触发条件。")
    assert gap is not None
    assert "触发条件" in gap

    ok = indirect_exposure_section_gap(
        "## 漏洞技术细节\n\n"
        "### 触发条件\n\n"
        "Druid WallFilter 本身不直接接收 HTTP 请求，须在上游业务应用中找到 SELECT 型 SQL 注入点，"
        "才能把恶意 SQL 传入 WallFilter；攻击者不能直接向 Druid 发送请求完成利用。"
    )
    assert ok is None


def test_cvss_indirect_consumer_constraints():
    bad_av = parse_cvss31("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H")
    err = cvss_indirect_consumer_error(bad_av)
    assert err is not None
    assert "AV" in err

    bad_ac = parse_cvss31("CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
    err_ac = cvss_indirect_consumer_error(bad_ac)
    assert err_ac is not None
    assert "AC" in err_ac

    bad_cia = parse_cvss31("CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H")
    err_cia = cvss_indirect_consumer_error(bad_cia, upstream_chain_proven=False)
    assert err_cia is not None
    assert "C/I/A" in err_cia

    ok = parse_cvss31("CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N")
    assert cvss_indirect_consumer_error(ok) is None

    proven = parse_cvss31("CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert cvss_indirect_consumer_error(proven, upstream_chain_proven=True) is None


def test_indirect_submission_and_surface_gates():
    assert indirect_attack_surface_error("frontend") is not None
    assert indirect_attack_surface_error("frontend", upstream_chain_proven=True) is None
    assert indirect_submission_tier_error("cve_candidate") is not None
    assert indirect_submission_tier_error("low_impact") is None


def test_indirect_consumer_cvss_score_lower_than_direct_remote():
    direct = parse_cvss31("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H")
    indirect = parse_cvss31("CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N")
    assert indirect.score < direct.score
    assert indirect.severity in {"medium", "low", "high"}

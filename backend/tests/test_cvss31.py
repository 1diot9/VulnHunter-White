from __future__ import annotations

import pytest

from app.cvss31 import (
    Cvss31Error,
    parse_cvss31,
    stamp_advisory_cvss31,
)


@pytest.mark.parametrize(
    "vector,score,severity",
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "critical"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "critical"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, "high"),
        ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", 7.2, "high"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, "medium"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N", 8.2, "high"),
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1, "high"),
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", 3.7, "low"),
        ("CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", 6.7, "medium"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N", 4.3, "medium"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, "low"),
    ],
)
def test_known_cvss31_vectors(vector, score, severity):
    result = parse_cvss31(vector)
    assert result.score == score
    assert result.severity == severity
    assert result.vector == vector


def test_accepts_shuffled_metrics_and_canonicalizes():
    result = parse_cvss31("CVSS:3.1/C:H/I:N/A:N/S:U/UI:N/PR:N/AC:L/AV:N")
    assert result.vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    assert result.score == 7.5


def test_invalid_prefix_and_version():
    with pytest.raises(Cvss31Error, match="CVSS:3.1") as exc:
        parse_cvss31("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert "3.0" in str(exc.value)


def test_missing_metric_names_the_field():
    with pytest.raises(Cvss31Error) as exc:
        parse_cvss31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H")
    text = str(exc.value)
    assert "缺少必填度量" in text
    assert "A（" in text


def test_invalid_metric_value_explains_options():
    with pytest.raises(Cvss31Error) as exc:
        parse_cvss31("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    text = str(exc.value)
    assert "AV" in text
    assert "N=Network" in text


def test_unknown_metric_rejected():
    with pytest.raises(Cvss31Error, match="未知度量") as exc:
        parse_cvss31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:H")
    assert "E:H" in str(exc.value)


def test_empty_vector():
    with pytest.raises(Cvss31Error, match="缺少评分向量"):
        parse_cvss31("  ")


def test_stamp_advisory_replaces_old_cvss_lines():
    src = (
        "## Severity / CWE\n\n"
        "- **Severity:** Low\n"
        "- **CVSS 3.0:** 7.5 High — `CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`\n"
        "- **CVSS 4.0:** 8.7 High — `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`\n"
        "- **CWE:** CWE-89\n"
    )
    result = parse_cvss31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
    out = stamp_advisory_cvss31(src, result)
    assert "**CVSS 3.1:** 7.5 High" in out
    assert result.vector in out
    assert "CVSS 3.0" not in out
    assert "CVSS 4.0" not in out
    assert "**Severity:** High" in out


def test_expected_pr_follows_attack_surface():
    from app.cvss31 import cvss_pr_alignment_error, expected_pr, parse_cvss31

    assert expected_pr("frontend") == "N"
    assert expected_pr("backend", "user") == "L"
    assert expected_pr("backend", "admin") == "H"
    assert expected_pr("backend") is None

    xss_inflated = parse_cvss31("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N")
    err = cvss_pr_alignment_error(xss_inflated, "backend", "user")
    assert err is not None
    assert "PR:L" in err
    assert cvss_pr_alignment_error(xss_inflated, "frontend") is None

    aligned = parse_cvss31("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N")
    assert cvss_pr_alignment_error(aligned, "backend", "user") is None

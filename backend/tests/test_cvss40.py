from __future__ import annotations

import pytest

from app.cvss31 import parse_cvss31, stamp_advisory_cvss31
from app.cvss40 import Cvss40Error, parse_cvss40


@pytest.mark.parametrize(
    "vector,score,severity",
    [
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.3, "critical"),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N", 8.7, "high"),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 8.6, "high"),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N", 7.1, "high"),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N", 5.3, "medium"),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", 0.0, "low"),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:N", 9.9, "critical"),
    ],
)
def test_known_cvss40_vectors(vector, score, severity):
    result = parse_cvss40(vector)
    assert result.score == score
    assert result.severity == severity
    assert result.vector == vector


def test_accepts_shuffled_metrics_and_canonicalizes():
    result = parse_cvss40("CVSS:4.0/SA:N/SI:N/SC:N/VA:N/VI:N/VC:H/UI:N/PR:N/AT:N/AC:L/AV:N")
    assert result.vector == "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
    assert result.score == 8.7


def test_invalid_prefix_and_version():
    with pytest.raises(Cvss40Error, match="CVSS:4.0") as exc:
        parse_cvss40("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert "3.1" in str(exc.value)


def test_missing_metric_names_the_field():
    with pytest.raises(Cvss40Error) as exc:
        parse_cvss40("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N")
    text = str(exc.value)
    assert "缺少必填度量" in text
    assert "SA（" in text


def test_invalid_ui_explains_passive_active():
    with pytest.raises(Cvss40Error) as exc:
        parse_cvss40("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:R/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N")
    text = str(exc.value)
    assert "UI" in text
    assert "P=Passive" in text


def test_unknown_metric_rejected():
    with pytest.raises(Cvss40Error, match="未知度量") as exc:
        parse_cvss40("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A")
    assert "E:A" in str(exc.value)


def test_empty_vector():
    with pytest.raises(Cvss40Error, match="缺少评分向量"):
        parse_cvss40("  ")


def test_stamp_advisory_keeps_both_cvss_lines():
    src = (
        "## Severity / CWE\n\n"
        "- **Severity:** Low\n"
        "- **CVSS 3.1:** (pending)\n"
        "- **CVSS 4.0:** (pending)\n"
        "- **CWE:** CWE-89\n"
    )
    cvss31 = parse_cvss31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
    cvss40 = parse_cvss40("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N")
    out = stamp_advisory_cvss31(src, cvss31, cvss40)
    assert "**CVSS 3.1:** 7.5 High" in out
    assert cvss31.vector in out
    assert "**CVSS 4.0:** 8.7 High" in out
    assert cvss40.vector in out
    assert "**Severity:** High" in out
    assert out.count("**CVSS") == 2

from __future__ import annotations

from app.services.semgrep_scan import language_configs
from app.services.sink_filter import (
    CANDIDATE_LIMIT,
    FilterContext,
    merge_findings,
    protected_from_drop,
    select_candidates,
)


def _finding(
    *,
    path: str,
    line: int,
    check_id: str,
    severity: str = "WARNING",
    confidence: str = "MEDIUM",
    category: str = "security",
    message: str = "",
    lines: str = "sink();",
) -> dict:
    return {
        "check_id": check_id,
        "path": path,
        "start": {"line": line},
        "end": {"line": line},
        "extra": {
            "severity": severity,
            "message": message or check_id,
            "lines": lines,
            "metadata": {"category": category, "confidence": confidence},
        },
    }


def test_language_configs_add_java_pack():
    configs = language_configs([".java", ".md"])
    assert configs[:2] == ["p/security-audit", "p/owasp-top-ten"]
    assert "p/java" in configs


def test_merge_dedupes_same_file_line_and_sorts_by_score_not_input_order():
    ctx = FilterContext()
    merged = merge_findings(
        [
            _finding(
                path="src/low/A.java",
                line=10,
                check_id="info.rule",
                severity="INFO",
                confidence="LOW",
                message="style nit",
            ),
            _finding(
                path="src/high/B.java",
                line=3,
                check_id="java.lang.security.audit.sql-injection",
                severity="ERROR",
                confidence="HIGH",
                message="SQL injection",
            ),
            _finding(
                path="src/high/B.java",
                line=3,
                check_id="java.lang.security.audit.sqli",
                severity="WARNING",
                confidence="MEDIUM",
                message="SQL injection",
            ),
        ],
        ctx,
    )
    assert [row["file_path"] for row in merged] == ["high/B.java", "low/A.java"]
    assert merged[0]["check_ids"] == [
        "java.lang.security.audit.sql-injection",
        "java.lang.security.audit.sqli",
    ]
    assert merged[0]["severity"] == "ERROR"
    assert merged[0]["code_score"] > merged[1]["code_score"]


def test_drop_skipped_tests_non_security_and_bounty_xss():
    ctx = FilterContext(
        skipped_paths={"app/Skip.java"},
        bounty=True,
    )
    merged = merge_findings(
        [
            _finding(path="app/Skip.java", line=1, check_id="java.lang.security.audit.command-injection"),
            _finding(path="src/tests/FooTest.java", line=2, check_id="java.lang.security.audit.command-injection"),
            _finding(
                path="app/Ok.java",
                line=3,
                check_id="java.correctness.foo",
                category="correctness",
                severity="ERROR",
            ),
            _finding(
                path="app/Xss.java",
                line=4,
                check_id="javascript.express.security.audit.xss.reflected",
                message="reflected xss",
            ),
            _finding(
                path="app/Exec.java",
                line=5,
                check_id="java.lang.security.audit.command-injection",
                severity="ERROR",
                message="command injection",
            ),
        ],
        ctx,
    )
    assert [row["file_path"] for row in merged] == ["app/Exec.java"]


def test_select_candidates_uses_scored_order_not_raw_slice():
    ctx = FilterContext()
    raw = [
        _finding(path=f"app/f{i}.java", line=1, check_id="info.rule", severity="INFO", confidence="LOW")
        for i in range(5)
    ]
    raw.append(
        _finding(
            path="app/rce.java",
            line=9,
            check_id="java.lang.security.audit.command-injection",
            severity="ERROR",
            confidence="HIGH",
            message="command injection",
        )
    )
    merged = merge_findings(raw, ctx)
    top = select_candidates(merged, limit=1)
    assert top[0]["file_path"] == "app/rce.java"
    assert CANDIDATE_LIMIT == 200


def test_protected_from_drop_requires_high_sev_conf_and_weight_or_source():
    ctx = FilterContext(file_weights={"app/A.java": 80}, has_source={"app/B.java"})
    assert protected_from_drop(severity="ERROR", confidence="HIGH", path="app/A.java", ctx=ctx)
    assert protected_from_drop(severity="HIGH", confidence="HIGH", path="app/B.java", ctx=ctx)
    assert not protected_from_drop(severity="ERROR", confidence="MEDIUM", path="app/A.java", ctx=ctx)
    assert not protected_from_drop(severity="WARNING", confidence="HIGH", path="app/A.java", ctx=ctx)
    assert not protected_from_drop(severity="ERROR", confidence="HIGH", path="app/C.java", ctx=ctx)


def test_drop_noise_rules_vendor_paths_and_root_scripts():
    ctx = FilterContext(bounty=True)
    merged = merge_findings(
        [
            _finding(
                path="app/AliPayController.java",
                line=1,
                check_id="java.spring.security.unrestricted-request-mapping.unrestricted-request-mapping",
            ),
            _finding(
                path="app/EncryptUtils.java",
                line=2,
                check_id="java.lang.security.audit.crypto.des-is-deprecated.des-is-deprecated",
                severity="WARNING",
                confidence="HIGH",
            ),
            _finding(
                path="check_env.py",
                line=3,
                check_id="python.lang.security.audit.subprocess-shell-true.subprocess-shell-true",
                severity="ERROR",
                message="command injection",
            ),
            _finding(
                path="app/src/main/resources/static/vendor/Foo.js",
                line=4,
                check_id="java.spring.security.injection.tainted-file-path.tainted-file-path",
                severity="ERROR",
                confidence="HIGH",
                message="path traversal",
            ),
            _finding(
                path="app/DynamicDBUtil.java",
                line=5,
                check_id="java.spring.security.audit.spring-sqli.spring-sqli",
                severity="WARNING",
                message="SQL injection",
            ),
        ],
        ctx,
    )
    assert [row["file_path"] for row in merged] == ["app/DynamicDBUtil.java"]
    assert merged[0]["mapped_vuln_type"] == "sqli"


def test_score_typed_sink_outranks_weighted_other():
    ctx = FilterContext(file_weights={"app/Heavy.java": 100}, has_source={"app/Heavy.java"})
    merged = merge_findings(
        [
            _finding(
                path="app/Heavy.java",
                line=1,
                check_id="java.style.something",
                severity="WARNING",
                message="style",
            ),
            _finding(
                path="app/Util.java",
                line=2,
                check_id="java.spring.security.audit.spring-sqli.spring-sqli",
                severity="WARNING",
                message="SQL injection",
            ),
        ],
        ctx,
    )
    assert merged[0]["file_path"] == "app/Util.java"
    assert merged[0]["code_score"] > merged[1]["code_score"]


def test_snippet_backfills_from_source_when_requires_login(tmp_path):
    java = tmp_path / "app" / "A.java"
    java.parent.mkdir()
    java.write_text("class A {\n  void f() {\n    Runtime.getRuntime().exec(cmd);\n  }\n}\n", encoding="utf-8")
    merged = merge_findings(
        [
            _finding(
                path="app/A.java",
                line=3,
                check_id="java.lang.security.audit.command-injection",
                severity="ERROR",
                message="command injection",
                lines="requires login",
            )
        ],
        FilterContext(),
        src_root=tmp_path,
    )
    assert "exec" in merged[0]["snippet"]
    assert "requires login" not in merged[0]["snippet"]

from __future__ import annotations

from app.services.runcode_feedback import (
    FAILURE_COMPILE,
    FAILURE_INVALID,
    FAILURE_MISSING,
    FAILURE_SANDBOX,
    annotate_run_code_result,
    note_runcode_result,
)


def test_note_runcode_result_parks_after_consecutive_failures():
    state: dict = {}
    fail = {"ok": False, "failure_class": FAILURE_MISSING, "error": "缺包"}
    assert note_runcode_result(state, fail, threshold=3) is False
    assert note_runcode_result(state, fail, threshold=3) is False
    assert note_runcode_result(state, fail, threshold=3) is True
    assert state["runcode_fail_streak"] == 3
    assert note_runcode_result(state, {"ok": True}, threshold=3) is False
    assert state["runcode_fail_streak"] == 0


def test_annotate_java_missing_package():
    raw = {
        "ok": False,
        "error": "退出码 1",
        "stdout": "",
        "stderr": "Main.java:3: error: package javax.servlet.http does not exist\n",
        "exit_code": 1,
    }
    out = annotate_run_code_result(raw, language="java", code="class Main {}")
    assert out["failure_class"] == FAILURE_MISSING
    assert "javax.servlet.http" in out["missing"]
    assert "mock" in (out.get("hint") or "")


def test_annotate_java_release_compile_hint():
    raw = {
        "ok": False,
        "error": "退出码 1",
        "stdout": "",
        "stderr": "Main.java:2: error: illegal start of type\n    var x = 1;\n",
        "exit_code": 1,
    }
    out = annotate_run_code_result(raw, language="java", code="class Main { var x = 1; }")
    assert out["failure_class"] == FAILURE_COMPILE
    assert "java-release" in (out.get("hint") or "")
    assert out.get("java_release") == 8


def test_annotate_canned_output():
    from app.services.harness_output import HARNESS_OUTPUT_ERROR

    out = annotate_run_code_result(
        {"ok": False, "error": HARNESS_OUTPUT_ERROR, "stdout": "", "stderr": "", "exit_code": -1},
        language="python",
        code='print("SUCCESS")',
    )
    assert out["failure_class"] == FAILURE_INVALID


def test_annotate_js_comma_msgs():
    from app.services.harness_output import HARNESS_JS_MSGS_ERROR

    out = annotate_run_code_result(
        {"ok": False, "error": HARNESS_JS_MSGS_ERROR, "stdout": "", "stderr": "", "exit_code": -1},
        language="javascript",
        code='const MSGS = { step: ("Step:", "步骤:") };',
    )
    assert out["failure_class"] == FAILURE_INVALID
    assert "js_comma_msgs" in (out.get("signals") or [])
    assert "[en, zh]" in (out.get("hint") or "")
    assert "逗号运算符" in (out.get("hint") or "")


def test_note_runcode_result_does_not_park_unsupported_language():
    from app.services.runcode_feedback import FAILURE_UNSUPPORTED

    state: dict = {}
    fail = {"ok": False, "failure_class": FAILURE_UNSUPPORTED, "error": "没有 rustc"}
    assert note_runcode_result(state, fail, threshold=3) is False
    assert note_runcode_result(state, fail, threshold=3) is False
    assert note_runcode_result(state, fail, threshold=3) is False
    assert state.get("runcode_fail_streak") in (0, None) or state.get("runcode_fail_streak") == 0


def test_annotate_rustc_missing_is_unsupported():
    from app.services.runcode_feedback import FAILURE_UNSUPPORTED

    out = annotate_run_code_result(
        {
            "ok": False,
            "error": "退出码 2",
            "stdout": "rustc path: <none>\nERROR: rustc not available in sandbox; cannot run the target-language harness\n",
            "stderr": "",
            "exit_code": 2,
        },
        language="bash",
        code="command -v rustc || exit 2",
    )
    assert out["failure_class"] == FAILURE_UNSUPPORTED
    assert "static_only" in (out.get("hint") or "")


def test_annotate_java_unicode_escape_hint():
    out = annotate_run_code_result(
        {
            "ok": False,
            "error": "退出码 1",
            "stdout": "",
            "stderr": "Harness.java:8: error: illegal unicode escape\n// labels as \\uXXXX\n",
            "exit_code": 1,
        },
        language="java",
        code="// java-release: 8\npublic class Harness {}",
    )
    assert out["failure_class"] == FAILURE_COMPILE
    assert "unicode" in (out.get("hint") or "").lower() or "UTF-8" in (out.get("hint") or "")
    assert "var/record" not in (out.get("hint") or "")


def test_annotate_java_filename_mismatch_hint():
    out = annotate_run_code_result(
        {
            "ok": False,
            "error": "退出码 1",
            "stdout": "",
            "stderr": "handling.java:23: error: class Harness is public, should be declared in a file named Harness.java\n",
            "exit_code": 1,
        },
        language="java",
        code="public class Harness {}",
    )
    assert out["failure_class"] == FAILURE_COMPILE
    assert "public class" in (out.get("hint") or "")
    assert "var/record" not in (out.get("hint") or "")


def test_annotate_crlf_bash_hint():
    out = annotate_run_code_result(
        {
            "ok": False,
            "error": "退出码 2",
            "stdout": "",
            "stderr": "run.sh: line 7: set: -\r: invalid option\nrun.sh: line 24: syntax error near unexpected token `fi'\n",
            "exit_code": 2,
        },
        language="bash",
        code="set -u\nfi\n",
    )
    assert "crlf" in (out.get("signals") or []) or "CRLF" in (out.get("hint") or "")
    assert "\\r" in (out.get("hint") or "") or "CRLF" in (out.get("hint") or "")


def test_annotate_c_missing_header():
    out = annotate_run_code_result(
        {
            "ok": False,
            "error": "退出码 1",
            "stdout": "",
            "stderr": "run.c:1:10: fatal error: openssl/ssl.h: No such file or directory\n",
            "exit_code": 1,
        },
        language="c",
        code='#include <openssl/ssl.h>\nint main(void) { return 0; }\n',
    )
    assert out["failure_class"] == FAILURE_MISSING
    assert "openssl/ssl.h" in out["missing"]
    assert "glibc" in (out.get("hint") or "") or "gcc" in (out.get("hint") or "")


def test_annotate_c_compile_hint():
    out = annotate_run_code_result(
        {
            "ok": False,
            "error": "退出码 1",
            "stdout": "",
            "stderr": "run.c:3:1: error: expected ';' before '}' token\n",
            "exit_code": 1,
        },
        language="c",
        code="int main(void) { return 0 }\n",
    )
    assert out["failure_class"] == FAILURE_COMPILE
    assert "gcc" in (out.get("hint") or "")


def test_annotate_docker_unavailable():
    out = annotate_run_code_result(
        {
            "ok": False,
            "error": "Docker 不可用，局部验证无法启动沙箱。 请确认本机 Docker 正在运行。",
            "stdout": "",
            "stderr": "",
            "exit_code": -1,
        },
        language="python",
        code="print(1)",
    )
    assert out["failure_class"] == FAILURE_SANDBOX
    assert "误报" in (out.get("hint") or "")

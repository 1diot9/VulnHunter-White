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

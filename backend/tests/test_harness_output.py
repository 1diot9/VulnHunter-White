from __future__ import annotations

from pathlib import Path

from app.services.harness_output import HARNESS_OUTPUT_ERROR, harness_output_block_reason

_DEMO = Path(__file__).resolve().parents[2] / "data" / "projects" / "11" / "vulns"


def test_rejects_canned_success_label():
    assert harness_output_block_reason('print("VULNERABILITY CONFIRMED")\n') == HARNESS_OUTPUT_ERROR
    assert harness_output_block_reason("print('SUCCESS')\n") == HARNESS_OUTPUT_ERROR
    assert harness_output_block_reason("print(1)\n") == HARNESS_OUTPUT_ERROR


def test_rejects_hardcoded_success_field():
    assert (
        harness_output_block_reason("print({'success': True, 'type': 'rce'})\n")
        == HARNESS_OUTPUT_ERROR
    )
    dumped = """
import json
print(json.dumps({"success": True, "vulnerable": True}))
"""
    assert harness_output_block_reason(dumped) == HARNESS_OUTPUT_ERROR


def test_rejects_fabricated_command_echo():
    assert (
        harness_output_block_reason('print("uid=0(root) gid=0(root) groups=0(root)")\n')
        == HARNESS_OUTPUT_ERROR
    )


def test_rejects_running_sink_but_printing_only_label():
    code = """
def sink(q):
    return ["alice", "admin"]

rows = sink("' OR 1=1 --")
print("VULNERABILITY CONFIRMED")
"""
    assert harness_output_block_reason(code) == HARNESS_OUTPUT_ERROR


def test_allows_runtime_evidence_plus_label():
    code = """
def sink(q):
    return [{"id": 1, "name": q, "role": "admin"}]

rows = sink("' OR 1=1 --")
print(rows)
print(f"leaked={rows[0]['name']}")
print("VULNERABILITY CONFIRMED")
"""
    assert harness_output_block_reason(code) is None


def test_allows_derived_verdict_when_evidence_printed():
    code = """
def ping_host(host):
    return "MEMO-PING 127.0.0.1\\nuid=1000(user)"

out = ping_host(";id")
print(out)
ok = "uid=" in out
print(f"confirmed={ok}")
"""
    assert harness_output_block_reason(code) is None


def test_allows_bash_toolchain_probe_without_interpolation():
    probe = """#!/bin/bash
which rustc 2>/dev/null && rustc --version 2>/dev/null
echo "---done---"
"""
    assert harness_output_block_reason(probe, language="bash") is None
    rustc_check = """#!/bin/bash
echo "Checking for rustc..."
which rustc 2>&1 || echo "rustc: not found"
"""
    assert harness_output_block_reason(rustc_check, language="bash") is None


def test_rejects_bash_canned_success():
    assert (
        harness_output_block_reason('echo "VULNERABILITY CONFIRMED"\n', language="bash")
        == HARNESS_OUTPUT_ERROR
    )
    assert harness_output_block_reason("echo SUCCESS\n", language="bash") == HARNESS_OUTPUT_ERROR


def test_rejects_js_python_tuple_msgs():
    from app.services.harness_output import HARNESS_JS_MSGS_ERROR

    broken = """
const MSGS = {
  step: ("Step:", "步骤:"),
  result: ("Result:", "结果:"),
};
const zh = process.argv.includes("--zh");
function msg(key) {
  const [en, zh_s] = MSGS[key];
  return zh ? zh_s : en;
}
function sink(input) { return input; }
const output = sink("payload");
console.log(msg("step"), output);
"""
    assert harness_output_block_reason(broken, language="javascript") == HARNESS_JS_MSGS_ERROR
    assert harness_output_block_reason(broken, language="js") == HARNESS_JS_MSGS_ERROR
    assert harness_output_block_reason(broken, language="node") == HARNESS_JS_MSGS_ERROR
    # Python tuples are valid; do not apply the JS gate.
    py_ok = """
def sink(q):
    return [{"id": 1, "name": q}]
MSGS = {"step": ("Step:", "步骤:")}
rows = sink("x")
print(rows)
"""
    assert harness_output_block_reason(py_ok, language="python") is None


def test_allows_js_array_msgs():
    ok = """
const MSGS = {
  step: ["Step:", "步骤:"],
  result: ["Result:", "结果:"],
};
const zh = process.argv.includes("--zh");
function msg(key) {
  const pair = MSGS[key];
  return zh ? pair[1] : pair[0];
}
function sink(input) { return input; }
const output = sink("payload");
console.log(msg("step"), output);
"""
    assert harness_output_block_reason(ok, language="javascript") is None
    # Two-string function args are not Python-tuple MSGS values.
    call = """
function sink(input) { return input; }
const output = sink("payload");
console.log("result", output);
"""
    assert harness_output_block_reason(call, language="javascript") is None


def test_rejects_js_canned_and_allows_variable():
    assert (
        harness_output_block_reason(
            'console.log("VULNERABILITY CONFIRMED");',
            language="javascript",
        )
        == HARNESS_OUTPUT_ERROR
    )
    assert (
        harness_output_block_reason(
            'function sink(input, extra) { return input; }\nconsole.log("CONFIRMED");',
            language="javascript",
        )
        == HARNESS_OUTPUT_ERROR
    )
    assert (
        harness_output_block_reason(
            'System.out.println("Result: " + output);',
            language="java",
        )
        is None
    )


def test_empty_code_is_skipped():
    assert harness_output_block_reason("") is None
    assert harness_output_block_reason("   \n") is None


def test_demo_harnesses_still_pass():
    if not _DEMO.is_dir():
        return
    found = list(_DEMO.glob("*/harness.py"))
    assert found, "expected showcase harness.py files"
    for path in found:
        text = path.read_text(encoding="utf-8")
        assert harness_output_block_reason(text) is None, path

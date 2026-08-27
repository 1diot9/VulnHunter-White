"""Local (harness) verification mode, ConfirmVuln evidence, sandbox RunCode."""

from __future__ import annotations

from app.dynamic_verify import (
    VERIFY_MODE_HARNESS,
    VERIFY_MODE_LAB,
    VERIFY_MODE_OFF,
    coerce_evidence_level,
    project_verify_mode,
    resolve_verify_mode,
)
from app.models import Project, Vuln
from app.services.poc_script import harness_path
from app.services.paths import vuln_dir
from app.services.report import harness_vuln_code_gap
from app.services.sandbox_exec import execute_harness, prepare_run
from app.services.verifier import enqueue_frontend_vuln, internet_test_block_reason_for_vuln
from app.tools import ROLE_ACL, registry

SEVERITY_FACTORS = {
    "impact": "sensitive_data_or_privilege",
    "exploit_complexity": "single_request",
    "defense_status": "none",
    "submission_tier": "cve_candidate",
    "submission_reason": "未认证可达且可造成敏感数据/权限影响，有 CVE 价值",
}


def _ctx(project_id: int, role: str, **kwargs):
    from app.tools import ToolContext

    return ToolContext(project_id=project_id, role=role, phase=role, **kwargs)


def _set_verify_mode(project_id: int, mode: str) -> None:
    from app.models import SessionLocal

    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        assert proj is not None
        proj.dynamic_verify_mode = mode
        proj.dynamic_verify_enabled = mode != VERIFY_MODE_OFF
        db.commit()


def _write_harness_vuln_code(project_id: int, vuln_id: int, file_path: str, code: str) -> None:
    path = vuln_dir(project_id, vuln_id) / "report.md"
    body = path.read_text(encoding="utf-8") if path.is_file() else "# t\n\n## 漏洞技术细节\n\n"
    section = (
        f"\n### 漏洞代码\n\n"
        f"- 完整路径：`{file_path}`\n\n"
        f"```java\n{code.rstrip()}\n```\n"
    )
    if "### 漏洞代码" in body:
        return
    if "### 完整 PoC 描述" in body:
        body = body.replace("### 完整 PoC 描述", section + "\n### 完整 PoC 描述", 1)
    elif "## 漏洞技术细节" in body:
        body = body.replace("## 漏洞技术细节", "## 漏洞技术细节\n" + section, 1)
    else:
        body = body.rstrip() + "\n\n## 漏洞技术细节\n" + section
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")


def test_harness_vuln_code_gap_requires_path_and_fence():
    assert harness_vuln_code_gap("") is not None
    assert harness_vuln_code_gap("## 漏洞技术细节\n") is not None
    bare = "### 漏洞代码\n\n- 完整路径：`Foo`\n\n```java\nint x = 1;\n```\n"
    assert harness_vuln_code_gap(bare, file_path="app/Foo.java") is not None
    ok = (
        "### 漏洞代码\n\n"
        "- 完整路径：`app/Main.java:12`\n\n"
        "```java\nString q = \"SELECT \" + id;\n```\n"
    )
    assert harness_vuln_code_gap(ok, file_path="app/Main.java") is None
    src_prefix = (
        "### 漏洞代码\n\n"
        "- 完整路径：`src/app/Main.java`\n\n"
        "```java\nString q = \"SELECT \" + id;\n```\n"
    )
    assert harness_vuln_code_gap(src_prefix, file_path="app/Main.java") is None
    no_code = "### 漏洞代码\n\n- 完整路径：`app/Main.java`\n\n说明一下即可\n"
    assert harness_vuln_code_gap(no_code, file_path="app/Main.java") is not None


def test_resolve_verify_mode_legacy_boolean():
    assert resolve_verify_mode() == VERIFY_MODE_OFF
    assert resolve_verify_mode(enabled=True) == VERIFY_MODE_LAB
    assert resolve_verify_mode(mode="harness") == VERIFY_MODE_HARNESS
    assert resolve_verify_mode(mode="局部验证") == VERIFY_MODE_HARNESS
    assert resolve_verify_mode(enabled=True, current_mode="harness") == VERIFY_MODE_HARNESS
    assert resolve_verify_mode(enabled=False, current_mode="harness") == VERIFY_MODE_OFF
    assert resolve_verify_mode(manual_lab=True) == VERIFY_MODE_LAB
    assert resolve_verify_mode(enabled=False, manual_lab=True) == VERIFY_MODE_LAB
    assert resolve_verify_mode(mode="harness", manual_lab=True) == VERIFY_MODE_HARNESS
    assert resolve_verify_mode(mode="off", manual_lab=True) == VERIFY_MODE_OFF


def test_static_after_review_timeouts_threshold():
    from app.dynamic_verify import review_timeouts_exhausted, static_after_review_timeouts

    assert static_after_review_timeouts(0) is False
    assert static_after_review_timeouts(1) is True
    assert static_after_review_timeouts(2) is True
    assert review_timeouts_exhausted(0) is False
    assert review_timeouts_exhausted(1) is False
    assert review_timeouts_exhausted(2) is True
    assert review_timeouts_exhausted(3) is True


def test_confirm_coerces_static_after_timeout_streak(tmp_env, project):
    _set_verify_mode(project, VERIFY_MODE_LAB)
    out = registry.dispatch(
        _ctx(project, "worker"),
        "SubmitVuln",
        {
            "title": "SQL 注入",
            "vuln_type": "sqli",
            "cwe": "CWE-89",
            "file_path": "a.java",
            "line_no": 1,
            "source_sink": "a",
            "auth_premise": "none",
            "http_request": "GET /",
            "poc_code": "print(1)\n",
            "expected_evidence": "x",
            "config_premise": "default",
        },
    )
    from app.models import SessionLocal

    with SessionLocal() as db:
        vuln = db.get(Vuln, out["vuln_id"])
        assert vuln is not None
        vuln.review_timeout_streak = 1
        db.commit()
    conf = registry.dispatch(
        _ctx(project, "reviewer"),
        "ConfirmVuln",
        {
            "vuln_id": out["vuln_id"],
            "evidence_level": "dynamic",
            "attack_surface": "frontend",
            **SEVERITY_FACTORS,
        },
    )
    assert conf["ok"] is True
    assert conf["evidence_level"] == "static_only"
    assert conf["status"] == "static_only"


_LAB_POC_OK = """
import argparse
p = argparse.ArgumentParser()
p.add_argument("-u", "--url", required=True)
p.add_argument("--proxy", default="")
args = p.parse_args()
print("hit", args.url)
raise SystemExit(0)
"""

_LAB_POC_FAIL = """
import argparse
p = argparse.ArgumentParser()
p.add_argument("-u", "--url", required=True)
p.add_argument("--proxy", default="")
args = p.parse_args()
print("miss", args.url)
raise SystemExit(2)
"""


def _submit_sqli(project: int, poc_code: str) -> int:
    out = registry.dispatch(
        _ctx(project, "worker"),
        "SubmitVuln",
        {
            "title": "SQL 注入",
            "vuln_type": "sqli",
            "cwe": "CWE-89",
            "file_path": "a.java",
            "line_no": 1,
            "source_sink": "a",
            "auth_premise": "none",
            "http_request": "GET /",
            "poc_code": poc_code,
            "expected_evidence": "x",
            "config_premise": "default",
        },
    )
    assert out["ok"] is True, out
    return int(out["vuln_id"])


def test_confirm_lab_without_target_is_static_only(tmp_env, project):
    _set_verify_mode(project, VERIFY_MODE_LAB)
    vuln_id = _submit_sqli(project, _LAB_POC_OK)
    conf = registry.dispatch(
        _ctx(project, "reviewer"),
        "ConfirmVuln",
        {
            "vuln_id": vuln_id,
            "evidence_level": "dynamic",
            "attack_surface": "frontend",
            **SEVERITY_FACTORS,
        },
    )
    assert conf["ok"] is True, conf
    assert conf["evidence_level"] == "static_only"
    assert "poc_run" not in conf


def test_confirm_lab_rejects_failed_poc(tmp_env, project):
    from app.models import SessionLocal
    from app.services.lab import save_env
    from app.services.poc_script import read_poc_code

    _set_verify_mode(project, VERIFY_MODE_LAB)
    save_env(
        project,
        {"accepted": True, "status": "running", "target_url": "http://127.0.0.1:18080"},
    )
    vuln_id = _submit_sqli(project, _LAB_POC_OK)
    conf = registry.dispatch(
        _ctx(project, "reviewer"),
        "ConfirmVuln",
        {
            "vuln_id": vuln_id,
            "evidence_level": "dynamic",
            "attack_surface": "frontend",
            "poc_code": _LAB_POC_FAIL,
            **SEVERITY_FACTORS,
        },
    )
    assert conf["ok"] is False
    assert "退出码" in conf["error"] or "未打出冲击" in conf["error"]
    assert conf.get("exit_code") == 2
    saved = read_poc_code(project, vuln_id) or ""
    assert "hit" in saved
    assert "miss" not in saved
    with SessionLocal() as db:
        vuln = db.get(Vuln, vuln_id)
        assert vuln is not None
        assert vuln.status == "pending_review"


def test_confirm_lab_upgrades_static_only_after_poc_success(tmp_env, project):
    from app.services.lab import save_env

    _set_verify_mode(project, VERIFY_MODE_LAB)
    save_env(
        project,
        {"accepted": True, "status": "running", "target_url": "http://127.0.0.1:18080"},
    )
    vuln_id = _submit_sqli(project, _LAB_POC_OK)
    conf = registry.dispatch(
        _ctx(project, "reviewer"),
        "ConfirmVuln",
        {
            "vuln_id": vuln_id,
            "evidence_level": "static_only",
            "attack_surface": "frontend",
            **SEVERITY_FACTORS,
        },
    )
    assert conf["ok"] is True, conf
    assert conf["evidence_level"] == "dynamic"
    assert conf["status"] == "confirmed"
    assert conf["poc_run"]["exit_code"] == 0


def test_force_static_hides_and_blocks_dynamic_tools(tmp_env, project):
    from app.models import SessionLocal
    from app.tools import native_shell_tool

    _set_verify_mode(project, VERIFY_MODE_LAB)
    with SessionLocal() as db:
        v = Vuln(
            project_id=project,
            title="t",
            vuln_type="sqli",
            status="pending_review",
            review_timeout_streak=1,
        )
        db.add(v)
        db.commit()
        vid = v.id
    names = {
        t["function"]["name"]
        for t in registry.openai_tools_for_role("reviewer", project_id=project, vuln_id=vid)
    }
    assert native_shell_tool() not in names
    assert "CollectLabFingerprints" not in names
    assert "RunCode" not in names
    assert "ConfirmVuln" in names
    assert "RequestLabRebuild" in names
    blocked = registry.dispatch(
        _ctx(project, "reviewer", vuln_id=vid),
        native_shell_tool(),
        {"command": "echo hi"},
    )
    assert blocked["ok"] is False
    assert "仅允许静态审核" in blocked["error"]
    assert coerce_evidence_level("dynamic", mode="off") == "static_only"
    assert coerce_evidence_level("harness", mode="lab") == "static_only"
    assert coerce_evidence_level("dynamic", mode="harness") == "static_only"
    assert coerce_evidence_level("harness", mode="harness") == "harness"
    assert coerce_evidence_level(None, mode="harness") == "harness"
    assert coerce_evidence_level("局部验证", mode="harness") == "harness"


def test_bring_up_failed_forces_static_tools_and_confirm(tmp_env, project):
    from app.models import SessionLocal
    from app.services.lab import mark_lab_bring_up_failed, save_env
    from app.tools import native_shell_tool

    _set_verify_mode(project, VERIFY_MODE_LAB)
    save_env(
        project,
        {
            "accepted": True,
            "status": "running",
            "target_url": "http://127.0.0.1:18080",
            "lab_ever_ready": True,
        },
    )
    mark_lab_bring_up_failed(project, reason="start failed", via="test")
    with SessionLocal() as db:
        v = Vuln(
            project_id=project,
            title="t",
            vuln_type="sqli",
            status="pending_review",
            review_timeout_streak=0,
            poc_code=_LAB_POC_OK,
        )
        db.add(v)
        db.commit()
        vid = v.id
    names = {
        t["function"]["name"]
        for t in registry.openai_tools_for_role("reviewer", project_id=project, vuln_id=vid)
    }
    assert native_shell_tool() not in names
    conf = registry.dispatch(
        _ctx(project, "reviewer", vuln_id=vid),
        "ConfirmVuln",
        {
            "vuln_id": vid,
            "evidence_level": "static_only",
            "attack_surface": "frontend",
            **SEVERITY_FACTORS,
        },
    )
    assert conf["ok"] is True, conf
    assert conf["evidence_level"] == "static_only"
    assert conf["status"] == "static_only"
    assert "poc_run" not in conf


def test_project_verify_mode_legacy_enabled_is_lab(tmp_env, project):
    from app.models import SessionLocal

    with SessionLocal() as db:
        proj = db.get(Project, project)
        proj.dynamic_verify_enabled = True
        proj.dynamic_verify_mode = "off"
        db.commit()
        db.refresh(proj)
        assert project_verify_mode(proj) == VERIFY_MODE_LAB


GOOD_HARNESS = """
def sink(name):
    return [{"id": 1, "name": name, "role": "admin"}]

rows = sink("' OR 1=1 --")
print(rows)
print(f"row_count={len(rows)} leaked_role={rows[0]['role']}")
"""


def test_confirm_harness_when_mode_harness(tmp_env, project):
    _set_verify_mode(project, VERIFY_MODE_HARNESS)
    payload = {
        "title": "登录处 SQL 注入",
        "vuln_type": "sqli",
        "cwe": "CWE-89",
        "file_path": "app/Main.java",
        "line_no": 1,
        "source_sink": "login -> query",
        "auth_premise": "未授权",
        "http_request": "GET /login?id=1 HTTP/1.1\nHost: x\n",
        "poc_code": "print('poc')\n",
        "expected_evidence": "error based",
        "config_premise": "default",
    }
    out = registry.dispatch(_ctx(project, "worker"), "SubmitVuln", payload)
    vuln_id = out["vuln_id"]
    blocked = registry.dispatch(
        _ctx(project, "reviewer"),
        "ConfirmVuln",
        {
            "vuln_id": vuln_id,
            "evidence_level": "harness",
            "attack_surface": "frontend",
            "harness_code": "print('harness')\n",
            **SEVERITY_FACTORS,
        },
    )
    assert blocked["ok"] is False
    assert "漏洞代码" in blocked["error"]
    _write_harness_vuln_code(
        project,
        vuln_id,
        "app/Main.java",
        'String q = "SELECT * FROM users WHERE id=" + id;',
    )
    conf = registry.dispatch(
        _ctx(project, "reviewer"),
        "ConfirmVuln",
        {
            "vuln_id": vuln_id,
            "evidence_level": "harness",
            "attack_surface": "frontend",
            "harness_code": GOOD_HARNESS,
            **SEVERITY_FACTORS,
        },
    )
    assert conf["ok"] is True
    assert conf["evidence_level"] == "harness"
    assert conf["status"] == "confirmed"
    assert harness_path(project, vuln_id).read_text(encoding="utf-8") == GOOD_HARNESS
    from app.models import SessionLocal

    with SessionLocal() as db:
        proj = db.get(Project, project)
        proj.verifier_enabled = True
        db.commit()
        vuln = db.get(Vuln, vuln_id)
        assert internet_test_block_reason_for_vuln(vuln) is not None
        queued = enqueue_frontend_vuln(project, vuln_id)
        assert queued["queued"] is False
        assert queued["skipped"] is True


def test_confirm_rejects_canned_harness_output(tmp_env, project):
    from app.services.harness_output import HARNESS_OUTPUT_ERROR

    _set_verify_mode(project, VERIFY_MODE_HARNESS)
    out = registry.dispatch(
        _ctx(project, "worker"),
        "SubmitVuln",
        {
            "title": "登录处 SQL 注入",
            "vuln_type": "sqli",
            "cwe": "CWE-89",
            "file_path": "app/Main.java",
            "line_no": 1,
            "source_sink": "login -> query",
            "auth_premise": "未授权",
            "http_request": "GET /login?id=1 HTTP/1.1\nHost: x\n",
            "poc_code": "print('poc')\n",
            "expected_evidence": "error based",
            "config_premise": "default",
        },
    )
    vuln_id = out["vuln_id"]
    _write_harness_vuln_code(
        project,
        vuln_id,
        "app/Main.java",
        'String q = "SELECT * FROM users WHERE id=" + id;',
    )
    canned = registry.dispatch(
        _ctx(project, "reviewer"),
        "ConfirmVuln",
        {
            "vuln_id": vuln_id,
            "evidence_level": "harness",
            "attack_surface": "frontend",
            "harness_code": 'print("VULNERABILITY CONFIRMED")\n',
            **SEVERITY_FACTORS,
        },
    )
    assert canned["ok"] is False
    assert canned["error"] == HARNESS_OUTPUT_ERROR


def test_run_code_rejects_canned_harness_output(tmp_env, project):
    from app.services.harness_output import HARNESS_OUTPUT_ERROR

    _set_verify_mode(project, VERIFY_MODE_HARNESS)
    out = registry.dispatch(
        _ctx(project, "reviewer", vuln_id=1),
        "RunCode",
        {"code": 'print("SUCCESS")\nprint({"success": True})\n', "language": "python"},
    )
    assert out["ok"] is False
    assert out["error"] == HARNESS_OUTPUT_ERROR


def test_confirm_coerces_dynamic_in_harness_mode(tmp_env, project):
    _set_verify_mode(project, VERIFY_MODE_HARNESS)
    out = registry.dispatch(
        _ctx(project, "worker"),
        "SubmitVuln",
        {
            "title": "SQL 注入",
            "vuln_type": "sqli",
            "cwe": "CWE-89",
            "file_path": "a.java",
            "line_no": 1,
            "source_sink": "a",
            "auth_premise": "none",
            "http_request": "GET /",
            "poc_code": "print(1)\n",
            "expected_evidence": "x",
            "config_premise": "default",
        },
    )
    conf = registry.dispatch(
        _ctx(project, "reviewer"),
        "ConfirmVuln",
        {
            "vuln_id": out["vuln_id"],
            "evidence_level": "dynamic",
            "attack_surface": "frontend",
            **SEVERITY_FACTORS,
        },
    )
    assert conf["ok"] is True
    assert conf["evidence_level"] == "static_only"


def test_run_code_hidden_unless_harness(tmp_env, project):
    names = {t["function"]["name"] for t in registry.openai_tools_for_role("reviewer")}
    assert "RunCode" not in names
    assert "RunCode" in ROLE_ACL["reviewer"]
    names_off = {t["function"]["name"] for t in registry.openai_tools_for_role("reviewer", project_id=project)}
    assert "RunCode" not in names_off
    _set_verify_mode(project, VERIFY_MODE_HARNESS)
    names_on = {t["function"]["name"] for t in registry.openai_tools_for_role("reviewer", project_id=project)}
    assert "RunCode" in names_on


def test_run_code_without_docker_does_not_look_like_false_positive(tmp_env, project, monkeypatch):
    _set_verify_mode(project, VERIFY_MODE_HARNESS)
    monkeypatch.setattr(
        "app.services.sandbox_exec.sandbox_diagnosis",
        lambda: {
            "available": False,
            "image": "vulnhunter/sandbox:latest",
            "image_present": False,
            "error": "Docker unavailable",
            "network_mode": "none",
        },
    )
    out = registry.dispatch(
        _ctx(project, "reviewer", vuln_id=1),
        "RunCode",
        {"code": GOOD_HARNESS, "language": "python"},
    )
    assert out["ok"] is False
    assert "误报" in (out.get("error") or "") or "误报" in (out.get("hint") or "")


def test_prepare_run_java_release_comment():
    _, default_cmd = prepare_run("java", "public class Demo { public static void main(String[] a) {} }")
    assert "--release 8" in default_cmd
    _, j11 = prepare_run(
        "java",
        "// java-release: 11\npublic class Demo { public static void main(String[] a) {} }",
    )
    assert "javac --release 11 Demo.java" in j11
    _, j17 = prepare_run(
        "java",
        "/* java-release: 17 */\npublic class Demo { public static void main(String[] a) {} }",
    )
    assert "javac --release 17 Demo.java" in j17
    _, invalid = prepare_run(
        "java",
        "// java-release: 21\npublic class Demo { public static void main(String[] a) {} }",
    )
    assert "javac --release 8 Demo.java" in invalid


def test_prepare_run_languages():
    name, cmd = prepare_run("python", "print(1)")
    assert name == "run.py"
    assert "python3" in cmd
    jname, jcmd = prepare_run("java", "public class Demo { public static void main(String[] a) {} }")
    assert jname == "Demo.java"
    assert "javac --release 8 Demo.java" in jcmd
    gname, gcmd = prepare_run("go", "package main\nfunc main() {}")
    assert gname == "main.go"
    assert "/tmp/harness" in gcmd
    assert "go build" in gcmd


def test_execute_harness_tmpfs_allows_exec_for_compiled_go(tmp_env, monkeypatch):
    captured: dict = {}

    class FakeContainer:
        def wait(self, timeout=None):  # noqa: ARG002, ANN001
            return {"StatusCode": 0}

        def logs(self, stdout=True, stderr=False):  # noqa: ARG002, ANN001
            return b"ok"

        def remove(self, force=False):  # noqa: ARG002, ANN001
            return None

    class FakeContainers:
        def run(self, **kwargs):
            captured.update(kwargs)
            return FakeContainer()

    class FakeClient:
        containers = FakeContainers()

    monkeypatch.setattr(
        "app.services.sandbox_exec.sandbox_diagnosis",
        lambda: {
            "available": True,
            "image": "vulnhunter/sandbox:latest",
            "image_present": True,
            "error": "",
            "network_mode": "none",
        },
    )
    monkeypatch.setattr("app.services.sandbox_exec._connect", lambda: (FakeClient(), ""))
    result = execute_harness("package main\nfunc main() {}", language="go")
    assert result["ok"] is True
    tmpfs = captured["tmpfs"]
    for mount in ("/tmp", "/home/sandbox"):
        opts = {part.strip() for part in tmpfs[mount].split(",") if part.strip()}
        assert "exec" in opts, tmpfs[mount]
        assert "noexec" not in opts
    env = captured["environment"]
    assert env["TMPDIR"] == "/tmp"
    assert env["GOTMPDIR"] == "/tmp"
    assert env["GOCACHE"].startswith("/tmp/")
    assert env["CGO_ENABLED"] == "0"
    assert captured["command"][:2] == ["sh", "-c"]
    assert "/tmp/harness" in captured["command"][2]


def test_execute_harness_without_docker(monkeypatch):
    monkeypatch.setattr(
        "app.services.sandbox_exec.sandbox_diagnosis",
        lambda: {
            "available": False,
            "image": "vulnhunter/sandbox:latest",
            "image_present": False,
            "error": "Docker unavailable",
            "network_mode": "none",
        },
    )
    result = execute_harness("print(1)", language="python")
    assert result["ok"] is False
    assert "Docker" in result["error"]


def test_confirm_lab_preserves_prior_harness_when_no_target(tmp_env, project):
    from app.models import SessionLocal

    _set_verify_mode(project, VERIFY_MODE_LAB)
    vuln_id = _submit_sqli(project, _LAB_POC_OK)
    _write_harness_vuln_code(
        project,
        vuln_id,
        "a.java",
        'String q = "SELECT * FROM t WHERE id=" + id;',
    )
    with SessionLocal() as db:
        vuln = db.get(Vuln, vuln_id)
        assert vuln is not None
        vuln.status = "confirmed"
        vuln.evidence_level = "harness"
        db.commit()
    conf = registry.dispatch(
        _ctx(project, "reviewer"),
        "ConfirmVuln",
        {
            "vuln_id": vuln_id,
            "evidence_level": "dynamic",
            "attack_surface": "frontend",
            **SEVERITY_FACTORS,
        },
    )
    assert conf["ok"] is True, conf
    assert conf["evidence_level"] == "harness"
    assert conf["status"] == "confirmed"
    with SessionLocal() as db:
        vuln = db.get(Vuln, vuln_id)
        assert vuln is not None
        assert vuln.evidence_level == "harness"
        assert vuln.status == "confirmed"


def test_can_append_dynamic_verify_harness_only_in_lab_mode(tmp_env, project):
    from app.models import SessionLocal
    from app.services.pipeline import can_append_dynamic_verify

    with SessionLocal() as db:
        vuln = Vuln(
            project_id=project,
            title="h",
            vuln_type="sqli",
            status="confirmed",
            evidence_level="harness",
        )
        db.add(vuln)
        db.commit()
        db.refresh(vuln)
        assert can_append_dynamic_verify(vuln, VERIFY_MODE_HARNESS) is False
        assert can_append_dynamic_verify(vuln, VERIFY_MODE_LAB) is True
        assert can_append_dynamic_verify(vuln, VERIFY_MODE_OFF) is False
        vuln.evidence_level = "dynamic"
        assert can_append_dynamic_verify(vuln, VERIFY_MODE_LAB) is False
        vuln.status = "static_only"
        vuln.evidence_level = "static_only"
        assert can_append_dynamic_verify(vuln, VERIFY_MODE_HARNESS) is True
        assert can_append_dynamic_verify(vuln, VERIFY_MODE_LAB) is True


def test_ensure_reviewer_skips_lab_when_harness(tmp_env, project, monkeypatch):
    from app.services import pipeline

    _set_verify_mode(project, VERIFY_MODE_HARNESS)
    started: list[int] = []

    class FakeThread:
        def __init__(self, *args, **kwargs):  # noqa: ANN002, ARG002
            self._alive = False
            self.name = kwargs.get("name") or ""

        def is_alive(self) -> bool:
            return self._alive

        def start(self) -> None:
            self._alive = True
            started.append(project)

    monkeypatch.setattr(pipeline.threading, "Thread", FakeThread)
    pipeline.reset_runtime_state()
    pipeline._ensure_reviewer(project, pipeline._cancel_event(project))
    assert started == []
    assert pipeline._next_reviewer_step(project, pending=1) == "review"

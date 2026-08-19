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


def test_coerce_evidence_level_by_mode():
    assert coerce_evidence_level("dynamic", mode="off") == "static_only"
    assert coerce_evidence_level("harness", mode="lab") == "static_only"
    assert coerce_evidence_level("dynamic", mode="harness") == "static_only"
    assert coerce_evidence_level("harness", mode="harness") == "harness"
    assert coerce_evidence_level(None, mode="harness") == "harness"
    assert coerce_evidence_level("局部验证", mode="harness") == "harness"


def test_project_verify_mode_legacy_enabled_is_lab(tmp_env, project):
    from app.models import SessionLocal

    with SessionLocal() as db:
        proj = db.get(Project, project)
        proj.dynamic_verify_enabled = True
        proj.dynamic_verify_mode = "off"
        db.commit()
        db.refresh(proj)
        assert project_verify_mode(proj) == VERIFY_MODE_LAB


def test_confirm_harness_when_mode_harness(tmp_env, project):
    _set_verify_mode(project, VERIFY_MODE_HARNESS)
    payload = {
        "title": "SQLI in login",
        "vuln_type": "sqli",
        "cwe": "CWE-89",
        "file_path": "app/Main.java",
        "line_no": 1,
        "source_sink": "login -> query",
        "auth_premise": "未授权",
        "http_request": "GET /login?id=1 HTTP/1.1\nHost: x\n",
        "poc_code": "print('poc')\n",
        "expected_evidence": "error based",
    }
    out = registry.dispatch(_ctx(project, "worker"), "SubmitVuln", payload)
    vuln_id = out["vuln_id"]
    conf = registry.dispatch(
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
    assert conf["ok"] is True
    assert conf["evidence_level"] == "harness"
    assert conf["status"] == "confirmed"
    assert harness_path(project, vuln_id).read_text(encoding="utf-8") == "print('harness')\n"
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


def test_confirm_coerces_dynamic_in_harness_mode(tmp_env, project):
    _set_verify_mode(project, VERIFY_MODE_HARNESS)
    out = registry.dispatch(
        _ctx(project, "worker"),
        "SubmitVuln",
        {
            "title": "SQLI",
            "vuln_type": "sqli",
            "cwe": "CWE-89",
            "file_path": "a.java",
            "line_no": 1,
            "source_sink": "a",
            "auth_premise": "none",
            "http_request": "GET /",
            "poc_code": "print(1)\n",
            "expected_evidence": "x",
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
        {"code": "print(1)", "language": "python"},
    )
    assert out["ok"] is False
    assert "误报" in (out.get("error") or "") or "误报" in (out.get("hint") or "")


def test_prepare_run_languages():
    name, cmd = prepare_run("python", "print(1)")
    assert name == "run.py"
    assert "python3" in cmd
    jname, jcmd = prepare_run("java", "public class Demo { public static void main(String[] a) {} }")
    assert jname == "Demo.java"
    assert "javac Demo.java" in jcmd


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

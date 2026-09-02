from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

from app.code_intelligence.cli import extract_bundle, release_target
from app.code_intelligence.query import callers, find_symbol, trace
from app.code_intelligence.service import run_build, source_fingerprint, status_payload
from app.services import pipeline
from app.services.paths import src_dir
from app.tools import ROLE_ACL, ToolContext, native_shell_tool, registry
from app.tools.sandbox import SandboxError, block_dangerous_shell


def _ctx(project_id: int, role: str) -> ToolContext:
    return ToolContext(project_id=project_id, role=role, phase=role)


def test_code_intel_tools_on_mining_and_reviewer_acl(tmp_env):
    for role in ("worker", "fast_worker", "bypass_worker", "unconstrained_worker", "reviewer"):
        for name in ("FindSymbol", "FindCallers", "FindCallees", "TraceCalls"):
            assert name in ROLE_ACL[role]
    for role in ("recon", "fix", "verifier", "sink_triage", "reviewer_lab"):
        assert "FindSymbol" not in ROLE_ACL[role]
    names = {t["function"]["name"] for t in registry.openai_tools_for_role("fast_worker")}
    assert names == set(ROLE_ACL["fast_worker"])
    native = native_shell_tool()
    worker_names = {t["function"]["name"] for t in registry.openai_tools_for_role("worker")}
    expected = {n for n in ROLE_ACL["worker"] if n not in {"Bash", "PowerShell"} or n == native}
    assert worker_names == expected


def test_find_symbol_unavailable_without_index(tmp_env, project):
    out = find_symbol(project, "UserService")
    assert out["ok"] is False
    assert out.get("unavailable") is True
    dispatched = registry.dispatch(_ctx(project, "worker"), "FindSymbol", {"query": "UserService"})
    assert dispatched["ok"] is False
    assert "Grep" in dispatched["error"]


def test_build_degrades_without_cli(tmp_env, project, monkeypatch):
    monkeypatch.setattr("app.code_intelligence.service.ensure_codegraph", lambda log=None: None)
    status = run_build(project)
    assert status == "degraded"
    payload = status_payload(project)
    assert payload["done"] is True
    assert payload["status"] == "degraded"


def _stub_codegraph_cli(monkeypatch, src: Path, captured: list[list[str]]) -> None:
    monkeypatch.setattr("app.code_intelligence.service.ensure_codegraph", lambda log=None: Path("fake-codegraph"))
    monkeypatch.setattr("app.code_intelligence.service.cli_version", lambda binary=None: "1.6.0")

    def fake_stream(args, **kwargs):  # noqa: ARG001
        captured.append(list(args))
        db = src / ".codegraph" / "codegraph.db"
        db.parent.mkdir(parents=True, exist_ok=True)
        db.write_bytes(b"stub")
        return 0

    monkeypatch.setattr("app.code_intelligence.service.stream_codegraph", fake_stream)


def test_build_inits_when_codegraph_dir_exists_without_db(tmp_env, project, monkeypatch):
    src = src_dir(project)
    (src / ".codegraph").mkdir(parents=True, exist_ok=True)
    (src / ".codegraph" / ".gitignore").write_text("*\n", encoding="utf-8")
    captured: list[list[str]] = []
    _stub_codegraph_cli(monkeypatch, src, captured)
    status = run_build(project)
    assert status == "ready"
    assert captured == [["init", "--yes"]]


def test_build_inits_on_empty_src(tmp_env, project, monkeypatch):
    src = src_dir(project)
    captured: list[list[str]] = []
    _stub_codegraph_cli(monkeypatch, src, captured)
    status = run_build(project)
    assert status == "ready"
    assert captured == [["init", "--yes"]]


def test_rebuild_inits_when_not_initialized(tmp_env, project, monkeypatch):
    src = src_dir(project)
    (src / ".codegraph").mkdir(parents=True, exist_ok=True)
    captured: list[list[str]] = []
    _stub_codegraph_cli(monkeypatch, src, captured)
    status = run_build(project, force=True)
    assert status == "ready"
    assert captured == [["init", "--yes"]]


def test_rebuild_indexes_when_db_exists(tmp_env, project, monkeypatch):
    src = src_dir(project)
    db_dir = src / ".codegraph"
    db_dir.mkdir(parents=True, exist_ok=True)
    (db_dir / "codegraph.db").write_bytes(b"old")
    captured: list[list[str]] = []
    _stub_codegraph_cli(monkeypatch, src, captured)
    status = run_build(project, force=True)
    assert status == "ready"
    assert captured == [["index", "--force"]]


def test_source_fingerprint_changes_with_file(tmp_env, project):
    src = src_dir(project)
    (src / "a.java").write_text("class A {}\n", encoding="utf-8")
    first = source_fingerprint(project)
    (src / "a.java").write_text("class A { void x() {} }\n", encoding="utf-8")
    second = source_fingerprint(project)
    assert first != second


def test_shell_blocks_codegraph(tmp_env, project):
    try:
        block_dangerous_shell("codegraph query Foo", project)
        raise AssertionError("expected SandboxError")
    except SandboxError as exc:
        assert "FindSymbol" in str(exc)


def test_extract_bundle_flattens_zip(tmp_path):
    target = release_target()
    archive = tmp_path / "cg.zip"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(f"codegraph-{target}/bin/codegraph.cmd", "@echo off\r\n")
        zf.writestr(f"codegraph-{target}/bin/codegraph", "#!/bin/sh\n")
    archive.write_bytes(buf.getvalue())
    dest = tmp_path / "current"
    extract_bundle(archive, dest, target)
    assert (dest / "bin" / "codegraph.cmd").is_file() or (dest / "bin" / "codegraph").is_file()
    assert not (dest / f"codegraph-{target}").exists()


def test_mining_prereqs_need_recon_and_code_intel(tmp_env, project):
    models = tmp_env["models"]
    Session = tmp_env["Session"]
    assert pipeline.mining_prereqs_met(project) is False
    with Session() as db:
        proj = db.get(models.Project, project)
        proj.recon_done = True
        proj.code_intel_done = False
        db.commit()
    assert pipeline.mining_prereqs_met(project) is False
    with Session() as db:
        proj = db.get(models.Project, project)
        proj.code_intel_done = True
        proj.code_intel_status = "degraded"
        db.commit()
    assert pipeline.mining_prereqs_met(project) is True


def test_find_symbol_compacts_cli_json(tmp_env, project, monkeypatch):
    monkeypatch.setattr("app.code_intelligence.query.index_ready", lambda pid: True)
    monkeypatch.setattr("app.code_intelligence.query.find_codegraph", lambda: Path("fake-codegraph"))

    class Proc:
        returncode = 0
        stdout = json.dumps(
            [
                {"name": "Foo.bar", "file": "src/Foo.java", "line": 12, "kind": "method"},
                {"name": "Foo.baz", "path": "src/Foo.java", "startLine": 40},
            ]
        )
        stderr = ""

    monkeypatch.setattr("app.code_intelligence.query.run_codegraph", lambda *a, **k: Proc())
    out = find_symbol(project, "Foo")
    assert out["ok"] is True
    assert out["count"] == 2
    assert out["items"][0]["name"] == "Foo.bar"
    assert out["items"][0]["file"] == "src/Foo.java"
    assert out["items"][0]["line"] == 12
    callers_out = callers(project, "Foo.bar")
    assert callers_out["ok"] is True
    assert "callers" in callers_out


def test_trace_compacts_explore_json(tmp_env, project, monkeypatch):
    monkeypatch.setattr("app.code_intelligence.query.index_ready", lambda pid: True)
    monkeypatch.setattr("app.code_intelligence.query.find_codegraph", lambda: Path("fake-codegraph"))

    class Proc:
        returncode = 0
        stdout = json.dumps(
            {
                "paths": [
                    [
                        {"name": "AdminController.run", "file": "Admin.java", "line": 10},
                        {"name": "CommandService.exec", "file": "Cmd.java", "line": 3},
                    ]
                ]
            }
        )
        stderr = ""

    monkeypatch.setattr("app.code_intelligence.query.run_codegraph", lambda *a, **k: Proc())
    out = trace(project, "AdminController.run", "Runtime.exec")
    assert out["ok"] is True
    assert out["paths"]
    assert out["paths"][0][0]["name"] == "AdminController.run"


def test_rebuild_api_starts_thread(tmp_env, project, monkeypatch):
    from app.main import app
    from fastapi.testclient import TestClient

    started: list[tuple[int, bool]] = []
    monkeypatch.setattr(
        pipeline,
        "_start_code_intel_thread",
        lambda pid, force=False: started.append((pid, force)),
    )
    with TestClient(app) as client:
        rebuilt = client.post(f"/api/projects/{project}/code-intelligence/rebuild")
        assert rebuilt.status_code == 200
    assert started == [(project, True)]


def test_conversation_rejected_for_code_intel(tmp_env, project):
    from app.main import app
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        r = client.post(
            f"/api/projects/{project}/conversation",
            json={"log_phase": "code-intel", "action": "new", "message": ""},
        )
        assert r.status_code == 400


def test_project_payload_includes_code_intel(tmp_env, project):
    from app.main import app
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        r = client.get(f"/api/projects/{project}")
        assert r.status_code == 200
        body = r.json()
        assert body["code_intel_done"] is False
        assert body["code_intel_status"] == "pending"

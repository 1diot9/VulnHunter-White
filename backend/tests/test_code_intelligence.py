from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

from app.code_intelligence.cli import extract_bundle, release_target
from app.code_intelligence.query import callers, find_symbol, trace
from app.code_intelligence.service import mark_code_intel, run_build, source_fingerprint, status_payload, write_metadata
from app.services import pipeline
from app.services.paths import src_dir
from app.tools import ROLE_ACL, ToolContext, native_shell_tool, registry
from app.tools.sandbox import SandboxError, block_dangerous_shell


def _ctx(project_id: int, role: str) -> ToolContext:
    return ToolContext(project_id=project_id, role=role, phase=role)


def _request_codegraph(project_id: int) -> None:
    write_metadata(project_id, {"requested_backends": ["codegraph"], "backends": {"codegraph": {"status": "pending"}}})


def test_code_intel_tools_on_mining_and_reviewer_acl(tmp_env):
    for role in ("worker", "fast_worker", "bypass_worker", "unconstrained_worker", "reviewer"):
        for name in ("FindSymbol", "FindCallers", "FindCallees", "TraceCalls"):
            assert name in ROLE_ACL[role]
    assert "MarkCodeIntel" in ROLE_ACL["recon"]
    assert "MarkCodeIntel" not in ROLE_ACL["worker"]
    for role in ("fix", "verifier", "sink_triage", "reviewer_lab"):
        assert "FindSymbol" not in ROLE_ACL[role]
    names = {t["function"]["name"] for t in registry.openai_tools_for_role("fast_worker")}
    assert names == set(ROLE_ACL["fast_worker"])
    native = native_shell_tool()
    worker_names = {t["function"]["name"] for t in registry.openai_tools_for_role("worker")}
    expected = {n for n in ROLE_ACL["worker"] if n not in {"Bash", "PowerShell"} or n == native}
    assert worker_names == expected
    recon_names = {t["function"]["name"] for t in registry.openai_tools_for_role("recon")}
    assert "MarkCodeIntel" in recon_names
    assert "FindSymbol" not in recon_names


def test_find_symbol_unavailable_without_index(tmp_env, project):
    out = find_symbol(project, "UserService")
    assert out["ok"] is False
    assert out.get("unavailable") is True
    dispatched = registry.dispatch(_ctx(project, "worker"), "FindSymbol", {"query": "UserService"})
    assert dispatched["ok"] is False
    assert "Grep" in dispatched["error"]


def test_build_waits_without_mark_code_intel(tmp_env, project, monkeypatch):
    monkeypatch.setattr("app.code_intelligence.service.ensure_codegraph", lambda log=None: Path("fake-codegraph"))
    status = run_build(project)
    assert status == "pending"
    payload = status_payload(project)
    assert payload["done"] is False
    assert payload["status"] == "pending"


def test_build_degrades_without_cli(tmp_env, project, monkeypatch):
    _request_codegraph(project)
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
    _request_codegraph(project)
    src = src_dir(project)
    (src / ".codegraph").mkdir(parents=True, exist_ok=True)
    (src / ".codegraph" / ".gitignore").write_text("*\n", encoding="utf-8")
    captured: list[list[str]] = []
    _stub_codegraph_cli(monkeypatch, src, captured)
    status = run_build(project)
    assert status == "ready"
    assert captured == [["init", "--yes"]]


def test_build_inits_on_empty_src(tmp_env, project, monkeypatch):
    _request_codegraph(project)
    src = src_dir(project)
    captured: list[list[str]] = []
    _stub_codegraph_cli(monkeypatch, src, captured)
    status = run_build(project)
    assert status == "ready"
    assert captured == [["init", "--yes"]]


def test_rebuild_inits_when_not_initialized(tmp_env, project, monkeypatch):
    _request_codegraph(project)
    src = src_dir(project)
    (src / ".codegraph").mkdir(parents=True, exist_ok=True)
    captured: list[list[str]] = []
    _stub_codegraph_cli(monkeypatch, src, captured)
    status = run_build(project, force=True)
    assert status == "ready"
    assert captured == [["init", "--yes"]]


def test_rebuild_indexes_when_db_exists(tmp_env, project, monkeypatch):
    _request_codegraph(project)
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


def test_mining_prereqs_skip_code_intel_when_disabled(tmp_env, project):
    models = tmp_env["models"]
    Session = tmp_env["Session"]
    assert pipeline.mining_prereqs_met(project) is False
    with Session() as db:
        proj = db.get(models.Project, project)
        proj.recon_done = True
        proj.code_intel_enabled = False
        proj.code_intel_done = False
        db.commit()
    assert pipeline.mining_prereqs_met(project) is True


def test_mining_prereqs_need_recon_and_code_intel(tmp_env, project):
    models = tmp_env["models"]
    Session = tmp_env["Session"]
    assert pipeline.mining_prereqs_met(project) is False
    with Session() as db:
        proj = db.get(models.Project, project)
        proj.recon_done = True
        proj.code_intel_enabled = True
        proj.code_intel_done = False
        db.commit()
    assert pipeline.mining_prereqs_met(project) is False
    with Session() as db:
        proj = db.get(models.Project, project)
        proj.code_intel_done = True
        proj.code_intel_status = "degraded"
        db.commit()
    assert pipeline.mining_prereqs_met(project) is True


def test_code_intel_blocks_mining_until_build_settles(tmp_env, project):
    models = tmp_env["models"]
    Session = tmp_env["Session"]
    assert pipeline._code_intel_blocks_mining(project) is False
    with Session() as db:
        proj = db.get(models.Project, project)
        proj.recon_done = True
        proj.code_intel_enabled = True
        proj.code_intel_done = False
        db.commit()
    assert pipeline.mining_prereqs_met(project) is False
    assert pipeline._code_intel_blocks_mining(project) is True
    with Session() as db:
        proj = db.get(models.Project, project)
        proj.code_intel_done = True
        proj.code_intel_status = "ready"
        db.commit()
    assert pipeline._code_intel_blocks_mining(project) is False
    assert pipeline.mining_prereqs_met(project) is True


def test_find_symbol_compacts_cli_json(tmp_env, project, monkeypatch):
    _request_codegraph(project)
    src = src_dir(project)
    (src / ".codegraph").mkdir(parents=True, exist_ok=True)
    (src / ".codegraph" / "codegraph.db").write_bytes(b"stub")
    with tmp_env["Session"]() as db:
        proj = db.get(tmp_env["models"].Project, project)
        proj.code_intel_enabled = True
        proj.code_intel_status = "ready"
        proj.code_intel_done = True
        db.commit()
    monkeypatch.setattr("app.code_intelligence.query_codegraph.find_codegraph", lambda: Path("fake-codegraph"))

    class Proc:
        returncode = 0
        stdout = json.dumps(
            [
                {"name": "Foo.bar", "file": "src/Foo.java", "line": 12, "kind": "method"},
                {"name": "Foo.baz", "path": "src/Foo.java", "startLine": 40},
            ]
        )
        stderr = ""

    monkeypatch.setattr("app.code_intelligence.query_codegraph.run_codegraph", lambda *a, **k: Proc())
    out = find_symbol(project, "Foo")
    assert out["ok"] is True
    assert out["count"] == 2
    assert out["items"][0]["name"] == "Foo.bar"
    assert out["items"][0]["file"] == "src/Foo.java"
    assert out["items"][0]["line"] == 12
    assert out["items"][0].get("backend") == "codegraph"
    callers_out = callers(project, "Foo.bar")
    assert callers_out["ok"] is True
    assert "callers" in callers_out


def test_trace_compacts_explore_json(tmp_env, project, monkeypatch):
    _request_codegraph(project)
    src = src_dir(project)
    (src / ".codegraph").mkdir(parents=True, exist_ok=True)
    (src / ".codegraph" / "codegraph.db").write_bytes(b"stub")
    with tmp_env["Session"]() as db:
        proj = db.get(tmp_env["models"].Project, project)
        proj.code_intel_enabled = True
        proj.code_intel_status = "ready"
        proj.code_intel_done = True
        db.commit()
    monkeypatch.setattr("app.code_intelligence.query_codegraph.find_codegraph", lambda: Path("fake-codegraph"))

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

    monkeypatch.setattr("app.code_intelligence.query_codegraph.run_codegraph", lambda *a, **k: Proc())
    out = trace(project, "AdminController.run", "Runtime.exec")
    assert out["ok"] is True
    assert out["paths"]
    assert out["paths"][0][0]["name"] == "AdminController.run"


def test_rebuild_rejected_when_disabled(tmp_env, project):
    from app.main import app
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        rebuilt = client.post(f"/api/projects/{project}/code-intelligence/rebuild")
        assert rebuilt.status_code == 400
        assert "未开启" in rebuilt.json()["detail"]


def test_rebuild_api_starts_thread(tmp_env, project, monkeypatch):
    from app.main import app
    from fastapi.testclient import TestClient

    models = tmp_env["models"]
    Session = tmp_env["Session"]
    with Session() as db:
        proj = db.get(models.Project, project)
        proj.code_intel_enabled = True
        db.commit()
    write_metadata(project, {"requested_backends": ["codegraph"]})

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
        assert body["code_intel_enabled"] is False


def test_parse_help_commands_skips_wrapped_descriptions():
    from app.code_intelligence.cli import parse_help_commands

    text = """
Usage: codegraph [options] [command]

Commands:
  init [options] [path]          Initialize CodeGraph in a project directory and
                                 build the initial index
  daemon|daemons                 Manage running CodeGraph background daemons
  help [command]                 display help for command
"""
    names = parse_help_commands(text)
    assert "init" in names
    assert "daemon" in names
    assert "daemons" in names
    assert "help" in names
    assert "build" not in names
    assert "ui" not in names


def _mark_code_intel_ready(tmp_env, project_id: int) -> None:
    models = tmp_env["models"]
    Session = tmp_env["Session"]
    with Session() as db:
        proj = db.get(models.Project, project_id)
        proj.code_intel_status = "ready"
        proj.code_intel_done = True
        proj.code_intel_enabled = True
        db.commit()
    write_metadata(project_id, {"requested_backends": ["codegraph"], "backends": {"codegraph": {"status": "ready"}}})
    db_dir = src_dir(project_id) / ".codegraph"
    db_dir.mkdir(parents=True, exist_ok=True)
    (db_dir / "codegraph.db").write_bytes(b"stub")


def test_request_ui_uses_builtin_when_cli_lacks_ui(tmp_env, project, monkeypatch):
    from app.code_intelligence.service import request_ui

    _mark_code_intel_ready(tmp_env, project)
    monkeypatch.setattr("app.code_intelligence.service.find_codegraph", lambda: Path("fake-codegraph"))
    monkeypatch.setattr("app.code_intelligence.service.ui_subcommand", lambda binary=None: None)
    out = request_ui(project)
    assert out["ok"] is True
    assert out["builtin"] is True


def test_open_ui_api_returns_builtin(tmp_env, project, monkeypatch):
    from app.main import app
    from fastapi.testclient import TestClient

    _mark_code_intel_ready(tmp_env, project)
    monkeypatch.setattr("app.code_intelligence.service.find_codegraph", lambda: Path("fake-codegraph"))
    monkeypatch.setattr("app.code_intelligence.service.ui_subcommand", lambda binary=None: None)
    with TestClient(app) as client:
        r = client.post(f"/api/projects/{project}/code-intelligence/ui")
        assert r.status_code == 200
        body = r.json()
        assert body["ok"] is True
        assert body["builtin"] is True


def test_symbols_api_uses_query(tmp_env, project, monkeypatch):
    from app.main import app
    from fastapi.testclient import TestClient

    _mark_code_intel_ready(tmp_env, project)
    monkeypatch.setattr(
        "app.code_intelligence.query.find_symbol",
        lambda pid, q, **k: {"ok": True, "query": q, "items": [{"name": "Main.login"}], "count": 1},
    )
    with TestClient(app) as client:
        r = client.get(f"/api/projects/{project}/code-intelligence/symbols", params={"q": "login"})
        assert r.status_code == 200
        body = r.json()
        assert body["ok"] is True
        assert body["items"][0]["name"] == "Main.login"


def test_create_code_intel_defaults_off(tmp_env, monkeypatch):
    from app.main import app
    from fastapi.testclient import TestClient

    monkeypatch.setattr("app.api.projects.start_ingest_and_audit", lambda *a, **k: None)
    with TestClient(app) as client:
        created = client.post(
            "/api/projects",
            json={"source_type": "github", "source_url": "https://github.com/owner/demo"},
        )
        assert created.status_code == 200
        body = created.json()
        assert body["code_intel_enabled"] is False
        assert body["code_intel_status"] == "skipped"
        on = client.post(
            "/api/projects",
            json={
                "source_type": "github",
                "source_url": "https://github.com/owner/with-ci",
                "code_intel_enabled": True,
            },
        )
        assert on.status_code == 200
        assert on.json()["code_intel_enabled"] is True
        assert on.json()["code_intel_status"] == "pending"


def test_patch_code_intel_only_when_paused(tmp_env, project, monkeypatch):
    from app.main import app
    from fastapi.testclient import TestClient

    monkeypatch.setattr(pipeline, "_start_code_intel_thread", lambda *a, **k: None)
    models = tmp_env["models"]
    Session = tmp_env["Session"]
    with TestClient(app) as client:
        denied = client.patch(f"/api/projects/{project}", json={"code_intel_enabled": True})
        assert denied.status_code == 400
        with Session() as db:
            proj = db.get(models.Project, project)
            proj.status = "paused"
            db.commit()
        enabled = client.patch(f"/api/projects/{project}", json={"code_intel_enabled": True})
        assert enabled.status_code == 200
        assert enabled.json()["code_intel_enabled"] is True
        assert enabled.json()["code_intel_status"] == "pending"


def test_disable_code_intel_purges_index(tmp_env, project):
    from app.main import app
    from fastapi.testclient import TestClient
    from app.code_intelligence.service import jars_index_dir

    models = tmp_env["models"]
    Session = tmp_env["Session"]
    db_dir = src_dir(project) / ".codegraph"
    db_dir.mkdir(parents=True, exist_ok=True)
    (db_dir / "codegraph.db").write_bytes(b"stub")
    jars = jars_index_dir(project) / "abc123"
    jars.mkdir(parents=True, exist_ok=True)
    (jars / "jar-analyzer.db").write_bytes(b"stub")
    write_metadata(project, {"requested_backends": ["codegraph", "jar_analyzer"]})
    with Session() as db:
        proj = db.get(models.Project, project)
        proj.status = "paused"
        proj.code_intel_enabled = True
        proj.code_intel_status = "ready"
        proj.code_intel_done = True
        db.commit()
    with TestClient(app) as client:
        off = client.patch(f"/api/projects/{project}", json={"code_intel_enabled": False})
        assert off.status_code == 200
        assert off.json()["code_intel_enabled"] is False
        assert off.json()["code_intel_status"] == "skipped"
    assert not (db_dir / "codegraph.db").exists()
    assert not (jars / "jar-analyzer.db").exists()


def test_mark_code_intel_tool_recon_only(tmp_env, project, monkeypatch):
    models = tmp_env["models"]
    Session = tmp_env["Session"]
    with Session() as db:
        proj = db.get(models.Project, project)
        proj.code_intel_enabled = True
        proj.code_intel_status = "pending"
        db.commit()
    monkeypatch.setattr(pipeline, "request_code_intel_after_choice", lambda *a, **k: None)
    bad = registry.dispatch(_ctx(project, "worker"), "MarkCodeIntel", {"codegraph": True})
    assert bad["ok"] is False
    ok = registry.dispatch(
        _ctx(project, "recon"),
        "MarkCodeIntel",
        {"codegraph": True, "jar_analyzer": False},
    )
    assert ok["ok"] is True
    assert "codegraph" in ok["backends"]
    from app.code_intelligence.service import requested_backends

    assert requested_backends(project) == ["codegraph"]


def test_jar_analyzer_none_degrades_but_codegraph_ready(tmp_env, project, monkeypatch):
    from app.services.decompile_java import _write_business_jars_doc

    write_metadata(
        project,
        {
            "requested_backends": ["codegraph", "jar_analyzer"],
            "backends": {
                "codegraph": {"status": "pending"},
                "jar_analyzer": {"status": "pending"},
            },
        },
    )
    _write_business_jars_doc(project, paths=[], complete=True, none=True, note="none")
    src = src_dir(project)
    captured: list[list[str]] = []
    _stub_codegraph_cli(monkeypatch, src, captured)
    status = run_build(project)
    assert status == "ready"
    from app.code_intelligence.service import read_metadata

    meta = read_metadata(project)
    backends = meta.get("backends") or {}
    assert backends.get("codegraph", {}).get("status") == "ready"
    assert backends.get("jar_analyzer", {}).get("status") == "degraded"
    payload = status_payload(project)
    assert payload["done"] is True


def test_jar_analyzer_callers_sql(tmp_env, project):
    import sqlite3

    from app.code_intelligence.backends import jar_analyzer as ja

    write_metadata(project, {"requested_backends": ["jar_analyzer"]})
    with tmp_env["Session"]() as db:
        proj = db.get(tmp_env["models"].Project, project)
        proj.code_intel_enabled = True
        proj.code_intel_status = "ready"
        proj.code_intel_done = True
        db.commit()
    digest = "a" * 64
    out_dir = ja.artifact_dir(project, digest)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "meta.json").write_text(
        json.dumps({"source": "src/app.jar"}),
        encoding="utf-8",
    )
    db_path = out_dir / "jar-analyzer.db"
    conn = sqlite3.connect(db_path)
    conn.executescript(
        """
        CREATE TABLE class_table (class_name TEXT);
        CREATE TABLE method_table (class_name TEXT, method_name TEXT, line_number INTEGER);
        CREATE TABLE method_call_table (
            caller_class_name TEXT, caller_method_name TEXT,
            callee_class_name TEXT, callee_method_name TEXT
        );
        INSERT INTO class_table VALUES ('com/example/AdminController');
        INSERT INTO method_table VALUES ('com/example/AdminController', 'run', 10);
        INSERT INTO method_call_table VALUES (
            'com/example/AdminController', 'run',
            'java/lang/Runtime', 'exec'
        );
        """
    )
    conn.commit()
    conn.close()
    out = callers(project, "Runtime.exec")
    assert out["ok"] is True
    assert out["count"] >= 1
    assert any("AdminController" in (x.get("name") or "") for x in out["callers"])
    assert out.get("backend") == "jar_analyzer" or any(
        x.get("backend") == "jar_analyzer" for x in out["callers"]
    )


def test_shell_blocks_jar_analyzer(tmp_env, project):
    try:
        block_dangerous_shell("java -jar jar-analyzer-engine.jar --jar app.jar", project)
        raise AssertionError("expected SandboxError")
    except SandboxError as exc:
        assert "FindSymbol" in str(exc)


def test_recon_map_ready_needs_mark_code_intel(tmp_env, project, monkeypatch):
    from app.tools.phase_recon import recon_map_ready
    from app.services.paths import docs_dir

    monkeypatch.setattr(pipeline, "request_code_intel_after_choice", lambda *a, **k: None)
    docs = docs_dir(project)
    docs.mkdir(parents=True, exist_ok=True)
    (docs / "code-map.md").write_text("# map\n", encoding="utf-8")
    (docs / "auth.md").write_text("# auth\n", encoding="utf-8")
    with tmp_env["Session"]() as db:
        proj = db.get(tmp_env["models"].Project, project)
        proj.code_intel_enabled = True
        db.commit()
    assert recon_map_ready(project) is False
    out = mark_code_intel(project, codegraph=True, jar_analyzer=False)
    assert out["ok"] is True
    from app.code_intelligence.service import code_intel_choice_ready

    assert code_intel_choice_ready(project) is True
    assert recon_map_ready(project) is True

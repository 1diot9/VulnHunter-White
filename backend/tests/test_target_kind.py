from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.target_kind import (
    TARGET_KIND_LIBRARY,
    TARGET_KIND_MIXED,
    TARGET_KIND_WEB,
    create_verify_defaults,
    initial_hint,
    is_component_target,
    normalize_target_kind,
    parse_target_kind,
    target_kind_label,
)


def test_normalize_and_parse_target_kind():
    assert normalize_target_kind(None) == TARGET_KIND_WEB
    assert normalize_target_kind("组件库") == TARGET_KIND_LIBRARY
    assert normalize_target_kind("混合") == TARGET_KIND_MIXED
    assert parse_target_kind("library") == TARGET_KIND_LIBRARY
    with pytest.raises(ValueError):
        parse_target_kind("desktop")
    assert target_kind_label("library") == "组件库"
    assert is_component_target("mixed")
    assert not is_component_target("web")
    assert "公开 API" in initial_hint("library")
    assert create_verify_defaults("library")["dynamic_verify_mode"] == "harness"
    assert create_verify_defaults("web")["dynamic_verify_mode"] == "off"


def test_create_library_defaults_harness(tmp_env, monkeypatch):
    from app.main import app

    monkeypatch.setattr("app.api.projects.start_ingest_and_audit", lambda *a, **k: None)
    with TestClient(app) as client:
        created = client.post(
            "/api/projects",
            json={
                "source_type": "github",
                "source_url": "https://github.com/owner/lib",
                "target_kind": "library",
            },
        )
        assert created.status_code == 200
        body = created.json()
        assert body["target_kind"] == "library"
        assert body["dynamic_verify_mode"] == "harness"
        assert body["dynamic_verify_enabled"] is True
        assert body["verifier_enabled"] is False


def test_create_library_respects_explicit_verify(tmp_env, monkeypatch):
    from app.main import app

    monkeypatch.setattr("app.api.projects.start_ingest_and_audit", lambda *a, **k: None)
    with TestClient(app) as client:
        created = client.post(
            "/api/projects",
            json={
                "source_type": "github",
                "source_url": "https://github.com/owner/lib2",
                "target_kind": "library",
                "dynamic_verify_mode": "off",
                "verifier_enabled": True,
            },
        )
        assert created.status_code == 200
        body = created.json()
        assert body["target_kind"] == "library"
        assert body["dynamic_verify_mode"] == "off"
        assert body["verifier_enabled"] is True


def test_patch_target_kind_only_when_paused(tmp_env, monkeypatch, project):
    from app.main import app
    from app.models import Project, SessionLocal

    monkeypatch.setattr("app.api.projects.start_audit", lambda *a, **k: None)
    with SessionLocal() as db:
        p = db.get(Project, project)
        p.status = "auditing"
        db.commit()
    with TestClient(app) as client:
        denied = client.patch(f"/api/projects/{project}", json={"target_kind": "library"})
        assert denied.status_code == 400
        with SessionLocal() as db:
            p = db.get(Project, project)
            p.status = "paused"
            db.commit()
        ok = client.patch(f"/api/projects/{project}", json={"target_kind": "mixed"})
        assert ok.status_code == 200
        assert ok.json()["target_kind"] == "mixed"


def test_phase_system_prompt_includes_target_kind(tmp_env, project):
    from app.models import Project, SessionLocal
    from app.services import pipeline

    with SessionLocal() as db:
        p = db.get(Project, project)
        p.target_kind = "library"
        db.commit()
    overlay = pipeline._phase_system_prompt(project, "worker.md")
    assert "组件库" in overlay
    assert "公开 API" in overlay
    vars_ = pipeline._agent_prompt_vars(project)
    assert vars_["target_kind"] == "library"
    assert vars_["target_kind_label"] == "组件库"


def test_mixed_demo_path_demotion():
    from app.services.sink_filter import FilterContext, drop_reason, is_mixed_demo_path, score_sink

    assert is_mixed_demo_path("demo/App.java")
    assert is_mixed_demo_path("samples/Hello.java")
    assert not is_mixed_demo_path("core/Parser.java")
    ctx = FilterContext(demote_mixed_demo=True)
    assert drop_reason(path="examples/Demo.java", extra={}, ctx=ctx, vuln_type="rce") == "mixed_demo"
    score = score_sink(severity="ERROR", confidence="HIGH", path="demo/X.java", ctx=ctx, vuln_type="rce")
    base = score_sink(
        severity="ERROR",
        confidence="HIGH",
        path="core/X.java",
        ctx=FilterContext(demote_mixed_demo=True),
        vuln_type="rce",
    )
    assert score < base

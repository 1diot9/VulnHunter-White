"""Project max_token_usage budget: create/patch, auto-pause, resume gate."""

from __future__ import annotations

import io
import zipfile

import pytest
from fastapi.testclient import TestClient

from app.services.token_budget import (
    MAX_TOKEN_USAGE_CAP,
    maybe_pause_for_token_budget,
    parse_max_token_usage,
    token_budget_block_reason,
    token_budget_status,
)


def test_parse_max_token_usage():
    assert parse_max_token_usage(None) == 0
    assert parse_max_token_usage("") == 0
    assert parse_max_token_usage("  ") == 0
    assert parse_max_token_usage(0) == 0
    assert parse_max_token_usage("1000000") == 1_000_000
    assert parse_max_token_usage(1_000_000) == 1_000_000
    with pytest.raises(ValueError):
        parse_max_token_usage(-1)
    with pytest.raises(ValueError):
        parse_max_token_usage("nope")
    with pytest.raises(ValueError):
        parse_max_token_usage(True)
    with pytest.raises(ValueError):
        parse_max_token_usage(MAX_TOKEN_USAGE_CAP + 1)


def test_create_github_max_token_usage(tmp_env, monkeypatch):
    from app.main import app

    monkeypatch.setattr("app.api.projects.start_ingest_and_audit", lambda *a, **k: None)
    with TestClient(app) as client:
        created = client.post(
            "/api/projects",
            json={
                "source_type": "github",
                "source_url": "https://github.com/owner/budget",
                "max_token_usage": 1_000_000,
            },
        )
        assert created.status_code == 200
        assert created.json()["max_token_usage"] == 1_000_000
        pid = created.json()["id"]
        shown = client.get(f"/api/projects/{pid}").json()
        assert shown["max_token_usage"] == 1_000_000
        cleared = client.patch(f"/api/projects/{pid}", json={"max_token_usage": 0})
        assert cleared.status_code == 200
        assert cleared.json()["max_token_usage"] == 0
        raised = client.patch(f"/api/projects/{pid}", json={"max_token_usage": 5_000_000})
        assert raised.status_code == 200
        assert raised.json()["max_token_usage"] == 5_000_000
        bad = client.post(
            "/api/projects",
            json={
                "source_type": "github",
                "source_url": "https://github.com/owner/neg",
                "max_token_usage": -1,
            },
        )
        assert bad.status_code == 422


def test_create_zip_max_token_usage(tmp_env, monkeypatch):
    from app.main import app

    monkeypatch.setattr("app.api.projects.start_ingest_and_audit", lambda *a, **k: None)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("a.txt", "x")
    raw = buf.getvalue()
    with TestClient(app) as client:
        created = client.post(
            "/api/projects/upload",
            files={"file": ("src.zip", raw, "application/zip")},
            data={"max_token_usage": "2000000"},
        )
        assert created.status_code == 200
        assert created.json()["max_token_usage"] == 2_000_000


def test_token_budget_auto_pause_and_resume_gate(tmp_env, project, monkeypatch):
    from app.main import app
    from app.models import Project, SessionLocal, TokenUsage
    from app.services import pipeline

    monkeypatch.setattr(pipeline, "start_audit", lambda pid: None)
    with SessionLocal() as db:
        p = db.get(Project, project)
        p.max_token_usage = 1000
        p.status = "auditing"
        db.add(
            TokenUsage(
                project_id=project,
                phase="worker",
                role="worker",
                tokens_input=800,
                tokens_output=200,
                tokens_cached=50,
                tokens_total=1000,
            )
        )
        db.commit()

    over, used, limit = token_budget_status(project)
    assert over is True
    assert used == 1000
    assert limit == 1000
    assert maybe_pause_for_token_budget(project) is True
    with SessionLocal() as db:
        p = db.get(Project, project)
        assert p.status == "paused"
    assert pipeline.get_phase_states(project)["project_paused"] is True
    reason = token_budget_block_reason(project)
    assert reason is not None
    assert "Token 上限" in reason

    with TestClient(app) as client:
        blocked = client.post(f"/api/projects/{project}/resume")
        assert blocked.status_code == 400
        assert "Token 上限" in blocked.json()["detail"]
        raised = client.patch(f"/api/projects/{project}", json={"max_token_usage": 2000})
        assert raised.status_code == 200
        assert raised.json()["max_token_usage"] == 2000
        resumed = client.post(f"/api/projects/{project}/resume")
        assert resumed.status_code == 200
        assert resumed.json()["ok"] is True

    with SessionLocal() as db:
        p = db.get(Project, project)
        assert p.status != "paused"


def test_token_budget_unlimited_does_not_pause(tmp_env, project):
    from app.models import SessionLocal, TokenUsage

    with SessionLocal() as db:
        db.add(
            TokenUsage(
                project_id=project,
                phase="recon",
                role="recon",
                tokens_input=9_000,
                tokens_output=1_000,
                tokens_cached=0,
                tokens_total=10_000,
            )
        )
        db.commit()
    over, used, limit = token_budget_status(project)
    assert over is False
    assert used == 10_000
    assert limit == 0
    assert maybe_pause_for_token_budget(project) is False
    assert token_budget_block_reason(project) is None


def test_lowering_cap_pauses_running_project(tmp_env, project, monkeypatch):
    from app.main import app
    from app.models import Project, SessionLocal, TokenUsage
    from app.services import pipeline

    monkeypatch.setattr(pipeline, "start_audit", lambda pid: None)
    with SessionLocal() as db:
        p = db.get(Project, project)
        p.status = "auditing"
        db.add(
            TokenUsage(
                project_id=project,
                phase="worker",
                role="worker",
                tokens_input=500,
                tokens_output=100,
                tokens_cached=0,
                tokens_total=600,
            )
        )
        db.commit()
    with TestClient(app) as client:
        out = client.patch(f"/api/projects/{project}", json={"max_token_usage": 600})
        assert out.status_code == 200
        assert out.json()["status"] == "paused"
        assert out.json()["max_token_usage"] == 600

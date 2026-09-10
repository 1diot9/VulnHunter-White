"""API gates for Docker Desktop runtime (no auto lab build)."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app
from app.services import runtime


def test_create_lab_without_manual_rejected_in_docker(tmp_env, monkeypatch):
    monkeypatch.setenv("VULNHUNTER_RUNTIME", "docker")
    runtime.reset_runtime_cache()
    with TestClient(app) as client:
        r = client.post(
            "/api/projects",
            json={
                "source_url": "https://github.com/example/demo",
                "name": "docker-lab-reject",
                "dynamic_verify_mode": "lab",
                "manual_lab": False,
                "manual_lab_prompt": "",
                "heuristic_enabled": True,
            },
        )
        assert r.status_code == 400
        detail = r.json()["detail"]
        assert "人工靶场" in detail or "自动搭建" in detail


def test_create_manual_lab_ok_in_docker(tmp_env, monkeypatch):
    monkeypatch.setenv("VULNHUNTER_RUNTIME", "docker")
    runtime.reset_runtime_cache()
    monkeypatch.setattr("app.api.projects.start_ingest_and_audit", lambda *a, **k: None)
    with TestClient(app) as client:
        r = client.post(
            "/api/projects",
            json={
                "source_url": "https://github.com/example/demo2",
                "name": "docker-manual-lab",
                "dynamic_verify_mode": "lab",
                "manual_lab": True,
                "manual_lab_prompt": "http://127.0.0.1:18080 admin/admin",
                "heuristic_enabled": True,
            },
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["dynamic_verify_mode"] == "lab"
        assert body["manual_lab"] is True


def test_health_runtime_fields(tmp_env, monkeypatch):
    monkeypatch.setenv("VULNHUNTER_RUNTIME", "docker")
    runtime.reset_runtime_cache()
    with TestClient(app) as client:
        r = client.get("/api/health")
        assert r.status_code == 200
        body = r.json()
        assert body["ok"] is True
        assert body["runtime"] == "docker"
        assert body["docker_lab_build_enabled"] is False

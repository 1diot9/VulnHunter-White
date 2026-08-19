from __future__ import annotations

import json

import httpx
import pytest
from fastapi.testclient import TestClient


def _patch_http(monkeypatch, handler):
    import app.services.llm_probe as llm_probe

    def fake_client(timeout=30.0):
        return httpx.Client(transport=httpx.MockTransport(handler), timeout=timeout)

    monkeypatch.setattr(llm_probe, "chat_http_client", fake_client)


def test_list_models_success(tmp_env, monkeypatch):
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["auth"] = request.headers.get("authorization", "")
        return httpx.Response(
            200,
            json={"data": [{"id": "gpt-4o"}, {"id": "gpt-4o-mini"}, {"id": "gpt-4o"}]},
        )

    _patch_http(monkeypatch, handler)
    from app.main import app

    with TestClient(app) as client:
        r = client.post(
            "/api/settings/llm/models",
            json={"base_url": "https://api.example.com/v1", "api_key": "sk-live"},
        )
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["models"] == ["gpt-4o", "gpt-4o-mini"]
    assert body["count"] == 2
    assert seen["url"].endswith("/v1/models")
    assert seen["auth"] == "Bearer sk-live"


def test_list_models_uses_saved_key(tmp_env, monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers.get("authorization") == "Bearer sk-saved"
        return httpx.Response(200, json={"models": ["local-a", "local-b"]})

    _patch_http(monkeypatch, handler)
    from app.main import app

    with TestClient(app) as client:
        saved = client.put(
            "/api/settings",
            json={"default_base_url": "https://saved.example/v1", "default_api_key": "sk-saved"},
        )
        assert saved.status_code == 200
        r = client.post("/api/settings/llm/models", json={})
    assert r.status_code == 200
    assert r.json()["ok"] is True
    assert r.json()["models"] == ["local-a", "local-b"]


def test_list_models_401(tmp_env, monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, text="invalid api key")

    _patch_http(monkeypatch, handler)
    from app.main import app

    with TestClient(app) as client:
        r = client.post(
            "/api/settings/llm/models",
            json={"base_url": "https://api.example.com/v1", "api_key": "bad"},
        )
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is False
    assert "401" in body["error"]


def test_connectivity_success(tmp_env, monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        assert payload["model"] == "gpt-test"
        assert request.url.path.endswith("/chat/completions")
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": "pong"}}]},
        )

    _patch_http(monkeypatch, handler)
    from app.main import app

    with TestClient(app) as client:
        r = client.post(
            "/api/settings/llm/test",
            json={
                "base_url": "https://api.example.com/v1",
                "api_key": "sk-live",
                "model": "gpt-test",
            },
        )
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["model"] == "gpt-test"
    assert body["reply"] == "pong"
    assert body["latency_ms"] is not None


def test_connectivity_requires_model_and_key(tmp_env, monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("should not call provider")

    _patch_http(monkeypatch, handler)
    from app.main import app

    with TestClient(app) as client:
        missing_model = client.post(
            "/api/settings/llm/test",
            json={"base_url": "https://api.example.com/v1", "api_key": "sk-live"},
        )
        missing_key = client.post(
            "/api/settings/llm/test",
            json={"base_url": "https://api.example.com/v1", "model": "gpt-test"},
        )
    assert missing_model.json()["ok"] is False
    assert "模型" in missing_model.json()["error"]
    assert missing_key.json()["ok"] is False
    assert "API Key" in missing_key.json()["error"]


def test_connectivity_anthropic_messages(tmp_env, monkeypatch):
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["x_api_key"] = request.headers.get("x-api-key", "")
        seen["version"] = request.headers.get("anthropic-version", "")
        seen["payload"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "type": "message",
                "role": "assistant",
                "content": [{"type": "text", "text": "pong"}],
                "stop_reason": "end_turn",
            },
        )

    _patch_http(monkeypatch, handler)
    from app.main import app

    with TestClient(app) as client:
        r = client.post(
            "/api/settings/llm/test",
            json={
                "base_url": "https://api.anthropic.com/v1",
                "api_key": "sk-ant",
                "model": "claude-test",
                "wire_api": "anthropic",
            },
        )
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["reply"] == "pong"
    assert str(seen["url"]).endswith("/messages")
    assert seen["x_api_key"] == "sk-ant"
    assert seen["version"] == "2023-06-01"
    payload = seen["payload"]
    assert isinstance(payload, dict)
    assert payload["max_tokens"] == 16
    assert payload["messages"][0]["role"] == "user"
    assert "stream" not in payload


def test_list_models_anthropic_headers(tmp_env, monkeypatch):
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers.get("authorization", "")
        seen["x_api_key"] = request.headers.get("x-api-key", "")
        seen["version"] = request.headers.get("anthropic-version", "")
        return httpx.Response(200, json={"data": [{"id": "claude-sonnet-4-20250514"}]})

    _patch_http(monkeypatch, handler)
    from app.main import app

    with TestClient(app) as client:
        r = client.post(
            "/api/settings/llm/models",
            json={
                "base_url": "https://api.anthropic.com/v1",
                "api_key": "sk-ant",
                "wire_api": "anthropic",
            },
        )
    assert r.status_code == 200
    assert r.json()["models"] == ["claude-sonnet-4-20250514"]
    assert seen["x_api_key"] == "sk-ant"
    assert seen["auth"] == "Bearer sk-ant"
    assert seen["version"] == "2023-06-01"


def test_merge_providers_accepts_anthropic(tmp_env):
    from app.schemas import LlmProviderIn
    from app.services.llm_settings import merge_providers_update

    merged = merge_providers_update(
        [],
        [
            LlmProviderIn(
                id="default",
                name="Claude",
                base_url="https://api.anthropic.com/v1",
                wire_api="messages",
                env_key="",
                api_key="sk-ant",
            )
        ],
    )
    assert merged[0]["wire_api"] == "anthropic"
    assert merged[0]["env_key"] == "ANTHROPIC_API_KEY"


def test_merge_providers_rejects_unknown_wire():
    from app.schemas import LlmProviderIn
    from app.services.llm_settings import merge_providers_update

    with pytest.raises(ValueError, match="wire_api"):
        merge_providers_update(
            [],
            [LlmProviderIn(id="x", name="x", base_url="https://x", wire_api="grpc")],
        )


def test_resolve_llm_anthropic_provider(tmp_env):
    from app.models import AppSettings, SessionLocal
    from app.services.llm_settings import resolve_llm

    with SessionLocal() as db:
        row = db.query(AppSettings).first()
        row.llm_providers = json.dumps(
            [
                {
                    "id": "claude",
                    "name": "Claude",
                    "base_url": "https://api.anthropic.com/v1",
                    "wire_api": "anthropic",
                    "env_key": "ANTHROPIC_API_KEY",
                    "api_key": "sk-ant",
                }
            ]
        )
        row.llm_roles = json.dumps(
            {"worker": {"provider_id": "claude", "model": "claude-test", "reasoning_effort": ""}}
        )
        db.commit()

    llm = resolve_llm("worker")
    assert llm.wire_api == "anthropic"
    assert llm.base_url == "https://api.anthropic.com/v1"
    assert llm.model == "claude-test"
    assert llm.api_key == "sk-ant"


def test_llm_role_for_recon_sub_sessions():
    from app.services.llm_settings import llm_role_for_agent

    assert llm_role_for_agent("recon") == "recon"
    assert llm_role_for_agent("recon-old-vuln") == "recon"
    assert llm_role_for_agent("recon_old_vuln") == "recon"
    assert llm_role_for_agent("recon-old-vuln-ghsa") == "recon"
    assert llm_role_for_agent("recon_old_vuln_ghsa") == "recon"
    assert llm_role_for_agent("recon_source_ext") == "recon"
    assert llm_role_for_agent("recon-source-ext") == "recon"
    assert llm_role_for_agent("recon_mark") == "recon"
    assert llm_role_for_agent("recon-mark") == "recon"
    assert llm_role_for_agent("fix") == "worker"
    assert llm_role_for_agent("reviewer") == "reviewer"
    assert llm_role_for_agent("reviewer_lab") == "reviewer"
    assert llm_role_for_agent("reviewer-lab") == "reviewer"
    assert llm_role_for_agent("verifier") == "verifier"
    assert llm_role_for_agent("fast_worker") == "worker"
    assert llm_role_for_agent("sink_triage") == "worker"
    assert llm_role_for_agent("bypass_worker") == "worker"


def test_resolve_llm_uses_project_model(tmp_env, project):
    from app.models import AppSettings, Project, SessionLocal
    from app.services.llm_settings import resolve_llm

    with SessionLocal() as db:
        row = db.query(AppSettings).first()
        row.default_model = "global-model"
        row.default_base_url = "https://api.example.com/v1"
        row.default_api_key = "sk-test"
        row.llm_roles = (
            '{"worker": {"provider_id": "", "model": "role-model", "reasoning_effort": ""}}'
        )
        proj = db.get(Project, project)
        proj.llm_model = "project-model"
        db.commit()

    global_llm = resolve_llm("worker")
    assert global_llm.model == "role-model"
    project_llm = resolve_llm("worker", project_id=project)
    assert project_llm.model == "project-model"
    assert project_llm.source.endswith("+project")

    with SessionLocal() as db:
        proj = db.get(Project, project)
        proj.llm_model = None
        db.commit()
    fallback = resolve_llm("worker", project_id=project)
    assert fallback.model == "role-model"
    assert "+project" not in fallback.source

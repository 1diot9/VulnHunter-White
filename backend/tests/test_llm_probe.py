from __future__ import annotations

import json

import httpx
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


def test_llm_role_for_recon_sub_sessions():
    from app.services.llm_settings import llm_role_for_agent

    assert llm_role_for_agent("recon") == "recon"
    assert llm_role_for_agent("recon-old-vuln") == "recon"
    assert llm_role_for_agent("recon_old_vuln") == "recon"
    assert llm_role_for_agent("recon_source_ext") == "recon"
    assert llm_role_for_agent("recon-source-ext") == "recon"
    assert llm_role_for_agent("recon_mark") == "recon"
    assert llm_role_for_agent("recon-mark") == "recon"
    assert llm_role_for_agent("fix") == "worker"
    assert llm_role_for_agent("reviewer") == "reviewer"
    assert llm_role_for_agent("reviewer_lab") == "reviewer"
    assert llm_role_for_agent("reviewer-lab") == "reviewer"
    assert llm_role_for_agent("verifier") == "verifier"

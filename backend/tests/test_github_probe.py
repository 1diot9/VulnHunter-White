from __future__ import annotations

import json

import httpx
from fastapi.testclient import TestClient


def _patch_http(monkeypatch, handler, seen=None):
    import app.services.github_probe as github_probe

    def fake_client(timeout=15.0, proxy=None):
        if seen is not None:
            seen["proxy"] = proxy
            seen["timeout"] = timeout
        return httpx.Client(transport=httpx.MockTransport(handler), timeout=timeout)

    monkeypatch.setattr(github_probe, "probe_http_client", fake_client)


def test_github_connectivity_anonymous(tmp_env, monkeypatch):
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["auth"] = request.headers.get("authorization")
        return httpx.Response(
            200,
            json={"resources": {"core": {"limit": 60, "remaining": 58, "used": 2}}},
        )

    _patch_http(monkeypatch, handler, seen)
    from app.main import app

    with TestClient(app) as client:
        r = client.post("/api/settings/github/test", json={"http_proxy": ""})
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["authenticated"] is False
    assert body["login"] == ""
    assert body["rate_limit"] == 60
    assert body["rate_remaining"] == 58
    assert body["latency_ms"] is not None
    assert seen["url"].endswith("/rate_limit")
    assert seen["auth"] is None
    assert seen["proxy"] is None


def test_github_connectivity_with_form_pat(tmp_env, monkeypatch):
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["auth"] = request.headers.get("authorization")
        return httpx.Response(
            200,
            headers={"X-RateLimit-Limit": "5000", "X-RateLimit-Remaining": "4997"},
            json={"login": "octocat", "email": "octocat@github.com", "id": 1},
        )

    _patch_http(monkeypatch, handler, seen)
    from app.main import app

    with TestClient(app) as client:
        r = client.post(
            "/api/settings/github/test",
            json={"github_pat": "ghp_live-token", "http_proxy": "http://127.0.0.1:10808"},
        )
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["authenticated"] is True
    assert body["login"] == "octocat"
    assert body["rate_limit"] == 5000
    assert body["rate_remaining"] == 4997
    dumped = json.dumps(body)
    assert "ghp_live-token" not in dumped
    assert "octocat@github.com" not in dumped
    assert seen["url"].endswith("/user")
    assert seen["auth"] == "Bearer ghp_live-token"
    assert seen["proxy"] == "http://127.0.0.1:10808"


def test_github_connectivity_uses_saved_pat(tmp_env, monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers.get("authorization") == "Bearer ghp_saved"
        return httpx.Response(200, json={"login": "saved-user"})

    _patch_http(monkeypatch, handler)
    from app.main import app

    with TestClient(app) as client:
        saved = client.put("/api/settings", json={"github_pat": "ghp_saved"})
        assert saved.status_code == 200
        assert saved.json()["github_pat_set"] is True
        assert "ghp_saved" not in json.dumps(saved.json())
        r = client.post("/api/settings/github/test", json={})
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["login"] == "saved-user"
    assert "ghp_saved" not in json.dumps(body)


def test_github_connectivity_invalid_pat(tmp_env, monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"message": "Bad credentials"})

    _patch_http(monkeypatch, handler)
    from app.main import app

    with TestClient(app) as client:
        r = client.post("/api/settings/github/test", json={"github_pat": "bad"})
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is False
    assert body["authenticated"] is True
    assert "PAT" in body["error"]


def test_github_connectivity_connect_error(tmp_env, monkeypatch):
    import app.services.github_probe as github_probe

    def fake_client(timeout=15.0, proxy=None):
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(github_probe, "probe_http_client", fake_client)
    from app.main import app

    with TestClient(app) as client:
        r = client.post("/api/settings/github/test", json={})
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is False
    assert "无法连接" in body["error"]

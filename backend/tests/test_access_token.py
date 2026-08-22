from __future__ import annotations

from fastapi.testclient import TestClient

from app.services.access_token import hash_token


def test_auth_status_open_when_unset(tmp_env):
    from app.main import app

    with TestClient(app) as client:
        status = client.get("/api/auth/status")
        assert status.status_code == 200
        assert status.json()["required"] is False
        login = client.post("/api/auth/login", json={"token": ""})
        assert login.status_code == 200
        assert login.json()["ok"] is True
        assert login.json()["required"] is False
        assert client.get("/api/settings").status_code == 200


def test_env_token_gates_api(tmp_env, monkeypatch):
    monkeypatch.setattr("app.config.settings.access_token", "env-secret")
    from app.main import app

    with TestClient(app) as client:
        assert client.get("/api/health").json()["ok"] is True
        assert client.get("/api/auth/status").json()["required"] is True
        denied = client.get("/api/settings")
        assert denied.status_code == 401
        assert denied.json()["detail"] == "需要访问令牌"

        wrong = client.get("/api/settings", headers={"Authorization": "Bearer nope"})
        assert wrong.status_code == 401
        assert wrong.json()["detail"] == "访问令牌无效"

        ok = client.get("/api/settings", headers={"Authorization": "Bearer env-secret"})
        assert ok.status_code == 200
        assert ok.json()["access_token_set"] is True

        header = client.get("/api/settings", headers={"X-VulnHunter-Token": "env-secret"})
        assert header.status_code == 200

        query = client.get("/api/settings", params={"access_token": "env-secret"})
        assert query.status_code == 200

        docs = client.get("/docs")
        assert docs.status_code == 401

        bad_login = client.post("/api/auth/login", json={"token": "nope"})
        assert bad_login.status_code == 401
        good_login = client.post("/api/auth/login", json={"token": "env-secret"})
        assert good_login.status_code == 200
        assert good_login.json()["required"] is True


def test_settings_override_env_and_require_current(tmp_env, monkeypatch):
    monkeypatch.setattr("app.config.settings.access_token", "from-env")
    Session = tmp_env["Session"]
    models = tmp_env["models"]
    with Session() as db:
        row = db.query(models.AppSettings).first()
        assert row is not None
        row.access_token_hash = hash_token("from-db")
        db.commit()

    from app.main import app

    with TestClient(app) as client:
        env_hdr = {"Authorization": "Bearer from-env"}
        db_hdr = {"Authorization": "Bearer from-db"}
        assert client.get("/api/settings", headers=env_hdr).status_code == 401
        assert client.get("/api/settings", headers=db_hdr).status_code == 200

        wrong_current = client.post(
            "/api/settings/access-token",
            json={"current_token": "from-env", "new_token": "newer1"},
            headers=db_hdr,
        )
        assert wrong_current.status_code == 403
        assert "当前令牌" in wrong_current.json()["detail"]

        too_short = client.post(
            "/api/settings/access-token",
            json={"current_token": "from-db", "new_token": "ab"},
            headers=db_hdr,
        )
        assert too_short.status_code == 400

        updated = client.post(
            "/api/settings/access-token",
            json={"current_token": "from-db", "new_token": "newer1"},
            headers=db_hdr,
        )
        assert updated.status_code == 200
        assert updated.json()["access_token_set"] is True
        assert client.get("/api/settings", headers=db_hdr).status_code == 401
        new_hdr = {"Authorization": "Bearer newer1"}
        assert client.get("/api/settings", headers=new_hdr).status_code == 200

        cleared = client.post(
            "/api/settings/access-token",
            json={"current_token": "newer1", "new_token": ""},
            headers=new_hdr,
        )
        assert cleared.status_code == 200
        # DB override gone → env token is active again
        assert client.get("/api/settings", headers=new_hdr).status_code == 401
        assert client.get("/api/settings", headers=env_hdr).status_code == 200


def test_first_set_access_token_without_current(tmp_env):
    from app.main import app

    with TestClient(app) as client:
        created = client.post(
            "/api/settings/access-token",
            json={"current_token": "", "new_token": "first-token"},
        )
        assert created.status_code == 200
        assert created.json()["access_token_set"] is True
        assert client.get("/api/settings").status_code == 401
        assert client.get(
            "/api/settings",
            headers={"Authorization": "Bearer first-token"},
        ).status_code == 200

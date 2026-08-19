from __future__ import annotations

from fastapi.testclient import TestClient

from app.models import Project
from app.services import pipeline


def test_custom_audit_mode_crud_and_project_snapshot(tmp_env, monkeypatch, project):
    from app.main import app

    SessionLocal = tmp_env["Session"]
    monkeypatch.setattr("app.api.projects.start_ingest_and_audit", lambda *a, **k: None)
    with TestClient(app) as client:
        builtin = client.get("/api/settings/builtin-audit-modes")
        assert builtin.status_code == 200
        bodies = {row["id"]: row["body"] for row in builtin.json()}
        assert "赏金模式" in bodies["bounty"]
        assert "全量模式" in bodies["full"]

        empty = client.post(
            "/api/settings/custom-audit-modes",
            json={"name": "空", "body": "   "},
        )
        assert empty.status_code == 400

        created = client.post(
            "/api/settings/custom-audit-modes",
            json={"name": "只挖注入", "body": "只收 SQL 注入与命令注入。"},
        )
        assert created.status_code == 200
        preset = created.json()
        assert preset["name"] == "只挖注入"
        preset_id = preset["id"]

        listed = client.get("/api/settings/custom-audit-modes")
        assert listed.status_code == 200
        assert any(row["id"] == preset_id for row in listed.json())

        denied = client.post(
            "/api/projects",
            json={
                "source_type": "github",
                "source_url": "https://github.com/owner/custom-empty",
                "audit_mode": "custom",
            },
        )
        assert denied.status_code == 400

        ok = client.post(
            "/api/projects",
            json={
                "source_type": "github",
                "source_url": "https://github.com/owner/custom-ok",
                "audit_mode": "custom",
                "custom_audit_mode_id": preset_id,
            },
        )
        assert ok.status_code == 200
        body = ok.json()
        assert body["audit_mode"] == "custom"
        assert body["custom_audit_mode_id"] == preset_id
        assert body["custom_audit_mode_name"] == "只挖注入"
        assert "只收 SQL 注入" in body["custom_audit_prompt"]
        pid = body["id"]

        patched_lib = client.patch(
            f"/api/settings/custom-audit-modes/{preset_id}",
            json={"body": "库已改成只收 XSS。"},
        )
        assert patched_lib.status_code == 200
        still = client.get(f"/api/projects/{pid}")
        assert still.status_code == 200
        assert "只收 SQL 注入" in still.json()["custom_audit_prompt"]
        assert "XSS" not in still.json()["custom_audit_prompt"]

        blocked_del = client.delete(f"/api/settings/custom-audit-modes/{preset_id}")
        assert blocked_del.status_code == 400

        with SessionLocal() as db:
            p = db.get(Project, project)
            assert p is not None
            p.status = "paused"
            db.commit()

        switched = client.patch(
            f"/api/projects/{project}",
            json={"audit_mode": "custom", "custom_audit_mode_id": preset_id},
        )
        assert switched.status_code == 200
        snap = switched.json()
        assert snap["audit_mode"] == "custom"
        assert "库已改成只收 XSS" in snap["custom_audit_prompt"]

        overlay = pipeline._phase_system_prompt(project, "worker.md")
        assert "自定义模式「只挖注入」" in overlay
        assert "库已改成只收 XSS" in overlay
        assert "什么算漏洞" in overlay

        vars_ = pipeline._audit_mode_vars(project)
        assert vars_["audit_mode"] == "custom"
        assert "只挖注入" in vars_["audit_mode_label"]
        assert "硬闸门" in vars_["audit_mode_hint"]

        back = client.patch(f"/api/projects/{project}", json={"audit_mode": "bounty"})
        assert back.status_code == 200
        assert back.json()["audit_mode"] == "bounty"
        assert back.json()["custom_audit_mode_id"] is None
        assert back.json()["custom_audit_prompt"] == ""

        freed = client.delete(f"/api/settings/custom-audit-modes/{preset_id}")
        # still referenced by pid project
        assert freed.status_code == 400

        with SessionLocal() as db:
            p = db.get(Project, pid)
            assert p is not None
            p.status = "paused"
            db.commit()
        clear = client.patch(f"/api/projects/{pid}", json={"audit_mode": "full"})
        assert clear.status_code == 200
        deleted = client.delete(f"/api/settings/custom-audit-modes/{preset_id}")
        assert deleted.status_code == 200
        assert deleted.json()["ok"] is True

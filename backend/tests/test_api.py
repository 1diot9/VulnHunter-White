from __future__ import annotations

from fastapi.testclient import TestClient


def test_health_and_settings(tmp_env):
    from app.main import app

    with TestClient(app) as client:
        assert client.get("/api/health").json()["ok"] is True
        s = client.get("/api/settings")
        assert s.status_code == 200
        body = s.json()
        assert "llm_providers" in body
        assert "worker_concurrency" not in body
        assert "fix_concurrency" not in body
        assert "llm_thread_limit" in body
        assert body["llm_thread_limit"] == 6
        assert body["http_proxy"] == ""
        assert body["chat_proxy"] == ""
        assert "cli_tools_dir" in body

        upd = client.put(
            "/api/settings",
            json={
                "llm_thread_limit": 8,
                "default_model": "gpt-test",
                "http_proxy": "http://127.0.0.1:19999",
                "chat_proxy": "http://127.0.0.1:19998",
            },
        )
        assert upd.status_code == 200
        assert upd.json()["llm_thread_limit"] == 8
        assert upd.json()["default_model"] == "gpt-test"
        from app.services.llm_thread import llm_thread_limiter

        assert llm_thread_limiter.current_limit() == 8
        assert upd.json()["http_proxy"] == "http://127.0.0.1:19999"
        assert upd.json()["chat_proxy"] == "http://127.0.0.1:19998"
        usage = client.get("/api/settings/llm-threads")
        assert usage.status_code == 200
        assert usage.json()["limit"] == 8
        assert usage.json()["used"] == 0
        assert usage.json()["waiting"] == 0
        cleared = client.put("/api/settings", json={"http_proxy": "", "chat_proxy": ""})
        assert cleared.json()["http_proxy"] == ""
        assert cleared.json()["chat_proxy"] == ""


def test_llm_thread_usage_api(tmp_env):
    import threading
    import time

    from app.main import app
    from app.services.llm_thread import llm_thread_limiter

    llm_thread_limiter.reset()
    cancel = threading.Event()
    t: threading.Thread | None = None
    try:
        llm_thread_limiter.set_limit_override(1)
        assert llm_thread_limiter.acquire() is True

        queued = threading.Event()

        def waiter() -> None:
            queued.set()
            llm_thread_limiter.acquire(cancel)

        t = threading.Thread(target=waiter)
        t.start()
        assert queued.wait(timeout=3)
        deadline = time.time() + 2
        while time.time() < deadline:
            if llm_thread_limiter.snapshot()[2] >= 1:
                break
            time.sleep(0.02)
        else:
            raise AssertionError("waiter did not queue")

        with TestClient(app) as client:
            body = client.get("/api/settings/llm-threads").json()
            assert body["used"] == 1
            assert body["limit"] == 1
            assert body["waiting"] >= 1
    finally:
        cancel.set()
        if t is not None:
            t.join(timeout=3)
        llm_thread_limiter.release()
        llm_thread_limiter.reset()


def test_purge_live_logs_api(tmp_env, project):
    import os
    import time

    from app.main import app
    from app.services.live_log import live_log
    from app.services.paths import logs_dir

    live_log.reset_runtime_state()
    live_log.agent(project, "old", phase="worker", role="worker")
    live_log.agent(project, "recent", phase="recon", role="recon")
    old_path = logs_dir(project) / "live-events" / "worker" / "round-1.jsonl"
    recent = logs_dir(project) / "live-events" / "recon" / "round-1.jsonl"
    os.utime(old_path, (time.time() - 10 * 86400, time.time() - 10 * 86400))

    with TestClient(app) as client:
        bad = client.post("/api/settings/logs/purge", json={"older_than_days": -1})
        assert bad.status_code == 422
        r = client.post("/api/settings/logs/purge", json={"older_than_days": 7})
        assert r.status_code == 200
        body = r.json()
        assert body["ok"] is True
        assert body["files"] == 1
        assert body["projects"] == 1
        assert body["older_than_days"] == 7
        assert body["bytes"] > 0
        empty = client.post("/api/settings/logs/purge", json={"older_than_days": 7})
        assert empty.json()["files"] == 0
    assert not old_path.exists()
    assert recent.exists()


def test_project_events_tail_and_before(tmp_env, project, monkeypatch, tmp_path):
    from app.main import app
    from app.services.live_log import live_log

    path = tmp_path / "live.events.jsonl"
    monkeypatch.setattr("app.services.live_log.live_events_path", lambda _pid: path)
    for i in range(6):
        live_log.agent(project, f"e{i}", phase="worker", role="worker")
    live_log.agent(project, "fix-1", phase="fix", role="fix")
    live_log.agent(project, "fast-1", phase="fast-worker", role="fast_worker")

    with TestClient(app) as client:
        tail = client.get(f"/api/projects/{project}/events?tail=true&limit=3&phase=worker")
        assert tail.status_code == 200
        body = tail.json()
        assert [e["text"] for e in body["events"]] == ["e5", "fix-1", "fast-1"]
        assert body["has_older"] is True
        older = client.get(
            f"/api/projects/{project}/events?before={body['oldest']}&limit=3&phase=worker"
        )
        assert [e["text"] for e in older.json()["events"]] == ["e2", "e3", "e4"]
        mine = client.get(f"/api/projects/{project}/events?tail=true&limit=10&phase=mine")
        assert [e["text"] for e in mine.json()["events"]] == ["e0", "e1", "e2", "e3", "e4", "e5"]
        fast = client.get(f"/api/projects/{project}/events?tail=true&limit=10&phase=fast")
        assert [e["text"] for e in fast.json()["events"]] == ["fast-1"]
        fix = client.get(f"/api/projects/{project}/events?tail=true&limit=10&phase=fix")
        assert [e["text"] for e in fix.json()["events"]] == ["fix-1"]


def test_project_events_session_pages(tmp_env, project, monkeypatch, tmp_path):
    from app.main import app
    from app.services.live_log import live_log

    path = tmp_path / "live.events.jsonl"
    monkeypatch.setattr("app.services.live_log.live_events_path", lambda _pid: path)
    live_log.reset_runtime_state()
    live_log.agent(project, "round-1", phase="worker", role="worker")
    live_log.begin_session(project, "worker")
    live_log.system(project, "挖掘阶段新跑，新开对话", phase="worker", session_start=True)
    live_log.agent(project, "round-2", phase="worker", role="worker")

    with TestClient(app) as client:
        latest = client.get(f"/api/projects/{project}/events?tail=true&limit=10&phase=worker")
        body = latest.json()
        assert body["session"] == 2
        assert body["session_count"] == 2
        assert [e["text"] for e in body["events"]] == ["挖掘阶段新跑，新开对话", "round-2"]
        hist = client.get(f"/api/projects/{project}/events?tail=true&limit=10&phase=worker&session=1")
        assert [e["text"] for e in hist.json()["events"]] == ["round-1"]


def test_project_events_subphase_session_pages(tmp_env, project, monkeypatch, tmp_path):
    from app.main import app
    from app.services.live_log import live_log

    path = tmp_path / "live.events.jsonl"
    monkeypatch.setattr("app.services.live_log.live_events_path", lambda _pid: path)
    live_log.reset_runtime_state()
    live_log.agent(project, "map-1", phase="recon", role="recon")
    live_log.agent(project, "mark-1", phase="recon-mark", role="recon_mark")
    live_log.begin_session(project, "recon-mark")
    live_log.system(project, "侦察新开对话（盖章）", phase="recon-mark", session_start=True)
    live_log.agent(project, "mark-2", phase="recon-mark", role="recon_mark")

    with TestClient(app) as client:
        mapped = client.get(f"/api/projects/{project}/events?tail=true&limit=10&phase=recon-map")
        assert mapped.json()["session_count"] == 1
        assert [e["text"] for e in mapped.json()["events"]] == ["map-1"]
        mark = client.get(f"/api/projects/{project}/events?tail=true&limit=10&phase=recon-mark")
        body = mark.json()
        assert body["session"] == 2
        assert body["session_count"] == 2
        assert [e["text"] for e in body["events"]] == ["侦察新开对话（盖章）", "mark-2"]
        mark_first = client.get(
            f"/api/projects/{project}/events?tail=true&limit=10&phase=recon-mark&session=1"
        )
        assert [e["text"] for e in mark_first.json()["events"]] == ["mark-1"]


def test_projects_list_empty(tmp_env):
    from app.main import app

    with TestClient(app) as client:
        r = client.get("/api/projects")
        assert r.status_code == 200
        assert r.json() == []


def test_create_github_audit_mode_defaults_bounty(tmp_env, monkeypatch):
    from app.main import app

    monkeypatch.setattr("app.api.projects.start_ingest_and_audit", lambda *a, **k: None)
    with TestClient(app) as client:
        created = client.post(
            "/api/projects",
            json={"source_type": "github", "source_url": "https://github.com/owner/demo"},
        )
        assert created.status_code == 200
        assert created.json()["audit_mode"] == "bounty"
        assert created.json()["manual_lab"] is False
        assert created.json()["manual_lab_prompt"] == ""
        assert created.json()["verifier_enabled"] is False
        assert created.json()["dynamic_verify_enabled"] is False
        assert created.json()["llm_model"] == ""
        assert created.json()["worker_hint"] == ""
        full = client.post(
            "/api/projects",
            json={
                "source_type": "github",
                "source_url": "https://github.com/owner/full",
                "audit_mode": "full",
            },
        )
        assert full.status_code == 200
        assert full.json()["audit_mode"] == "full"
        bad = client.post(
            "/api/projects",
            json={
                "source_type": "github",
                "source_url": "https://github.com/owner/bad",
                "audit_mode": "nope",
            },
        )
        assert bad.status_code == 422


def test_create_zip_audit_mode_and_invalid(tmp_env, monkeypatch):
    import io
    import zipfile

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
            data={"audit_mode": "full"},
        )
        assert created.status_code == 200
        assert created.json()["audit_mode"] == "full"
        assert created.json()["heuristic_lite"] is False
        lite = client.post(
            "/api/projects/upload",
            files={"file": ("src.zip", raw, "application/zip")},
            data={"heuristic_lite": "true"},
        )
        assert lite.status_code == 200
        assert lite.json()["heuristic_lite"] is True
        assert lite.json()["heuristic_enabled"] is True
        bad = client.post(
            "/api/projects/upload",
            files={"file": ("src.zip", raw, "application/zip")},
            data={"audit_mode": "nope"},
        )
        assert bad.status_code == 400


def test_patch_audit_mode_only_when_paused_or_completed(tmp_env, project):
    from app.main import app
    from app.models import Project, SessionLocal

    with TestClient(app) as client:
        denied = client.patch(f"/api/projects/{project}", json={"audit_mode": "full"})
        assert denied.status_code == 400
        assert "暂停或完成" in denied.json()["detail"]
        with SessionLocal() as db:
            p = db.get(Project, project)
            p.status = "paused"
            db.commit()
        ok = client.patch(f"/api/projects/{project}", json={"audit_mode": "full"})
        assert ok.status_code == 200
        assert ok.json()["audit_mode"] == "full"
        assert ok.json()["status"] == "paused"
        with SessionLocal() as db:
            p = db.get(Project, project)
            p.status = "completed"
            p.audit_mode = "full"
            db.commit()
        done = client.patch(f"/api/projects/{project}", json={"audit_mode": "bounty"})
        assert done.status_code == 200
        assert done.json()["audit_mode"] == "bounty"
        assert done.json()["status"] == "completed"


def test_create_and_patch_manual_lab_prompt_while_running(tmp_env, monkeypatch):
    from app.main import app
    from app.models import Project, SessionLocal

    monkeypatch.setattr("app.api.projects.start_ingest_and_audit", lambda *a, **k: None)
    with TestClient(app) as client:
        created = client.post(
            "/api/projects",
            json={
                "source_type": "github",
                "source_url": "https://github.com/owner/lab",
                "manual_lab": True,
                "manual_lab_prompt": "  http://127.0.0.1:8080 admin/admin  ",
            },
        )
        assert created.status_code == 200
        body = created.json()
        assert body["manual_lab"] is True
        assert body["manual_lab_prompt"] == "http://127.0.0.1:8080 admin/admin"
        pid = body["id"]
        with SessionLocal() as db:
            p = db.get(Project, pid)
            assert p.status != "paused"
        empty = client.patch(f"/api/projects/{pid}", json={})
        assert empty.status_code == 400
        updated = client.patch(
            f"/api/projects/{pid}",
            json={"manual_lab_prompt": "http://10.0.0.8:9000 user/pass"},
        )
        assert updated.status_code == 200
        assert updated.json()["manual_lab"] is True
        assert updated.json()["manual_lab_prompt"] == "http://10.0.0.8:9000 user/pass"
        assert updated.json()["audit_mode"] == "bounty"


def test_create_zip_manual_lab(tmp_env, monkeypatch):
    import io
    import zipfile

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
            data={
                "audit_mode": "bounty",
                "manual_lab": "true",
                "manual_lab_prompt": "http://127.0.0.1:18080",
            },
        )
        assert created.status_code == 200
        assert created.json()["manual_lab"] is True
        assert created.json()["manual_lab_prompt"] == "http://127.0.0.1:18080"


def test_create_and_patch_dynamic_verify_enabled(tmp_env, monkeypatch):
    from app.main import app

    monkeypatch.setattr("app.api.projects.start_ingest_and_audit", lambda *a, **k: None)
    monkeypatch.setattr("app.api.projects.start_audit", lambda *a, **k: None)
    with TestClient(app) as client:
        created = client.post(
            "/api/projects",
            json={"source_type": "github", "source_url": "https://github.com/owner/demo"},
        )
        assert created.status_code == 200
        assert created.json()["dynamic_verify_enabled"] is False
        assert created.json()["dynamic_verify_mode"] == "off"
        pid = created.json()["id"]
        enabled = client.patch(f"/api/projects/{pid}", json={"dynamic_verify_enabled": True})
        assert enabled.status_code == 200
        assert enabled.json()["dynamic_verify_enabled"] is True
        assert enabled.json()["dynamic_verify_mode"] == "lab"
        harness = client.patch(f"/api/projects/{pid}", json={"dynamic_verify_mode": "harness"})
        assert harness.status_code == 200
        assert harness.json()["dynamic_verify_mode"] == "harness"
        assert harness.json()["dynamic_verify_enabled"] is True
        disabled = client.patch(f"/api/projects/{pid}", json={"dynamic_verify_mode": "off"})
        assert disabled.status_code == 200
        assert disabled.json()["dynamic_verify_enabled"] is False
        assert disabled.json()["dynamic_verify_mode"] == "off"
        on = client.post(
            "/api/projects",
            json={
                "source_type": "github",
                "source_url": "https://github.com/owner/dyn",
                "dynamic_verify_enabled": True,
            },
        )
        assert on.status_code == 200
        assert on.json()["dynamic_verify_enabled"] is True
        assert on.json()["dynamic_verify_mode"] == "lab"
        local = client.post(
            "/api/projects",
            json={
                "source_type": "github",
                "source_url": "https://github.com/owner/harness",
                "dynamic_verify_mode": "harness",
            },
        )
        assert local.status_code == 200
        assert local.json()["dynamic_verify_mode"] == "harness"
        assert local.json()["dynamic_verify_enabled"] is True


def test_project_llm_model_create_patch_and_clear(tmp_env, monkeypatch):
    from app.main import app

    monkeypatch.setattr("app.api.projects.start_ingest_and_audit", lambda *a, **k: None)
    monkeypatch.setattr("app.api.projects.start_audit", lambda *a, **k: None)
    with TestClient(app) as client:
        created = client.post(
            "/api/projects",
            json={
                "source_type": "github",
                "source_url": "https://github.com/owner/model",
                "llm_model": "  project-model  ",
            },
        )
        assert created.status_code == 200
        assert created.json()["llm_model"] == "project-model"
        pid = created.json()["id"]
        cleared = client.patch(f"/api/projects/{pid}", json={"llm_model": "  "})
        assert cleared.status_code == 200
        assert cleared.json()["llm_model"] == ""
        updated = client.patch(f"/api/projects/{pid}", json={"llm_model": "other-model"})
        assert updated.status_code == 200
        assert updated.json()["llm_model"] == "other-model"


def test_create_zip_llm_model(tmp_env, monkeypatch):
    import io
    import zipfile

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
            data={"llm_model": " zip-model "},
        )
        assert created.status_code == 200
        assert created.json()["llm_model"] == "zip-model"


def test_project_worker_hint_create_patch_and_clear(tmp_env, monkeypatch):
    from app.main import app
    from app.models import Project, SessionLocal

    monkeypatch.setattr("app.api.projects.start_ingest_and_audit", lambda *a, **k: None)
    monkeypatch.setattr("app.api.projects.start_audit", lambda *a, **k: None)
    with TestClient(app) as client:
        created = client.post(
            "/api/projects",
            json={
                "source_type": "github",
                "source_url": "https://github.com/owner/hint",
                "worker_hint": "  重点看导出接口  ",
            },
        )
        assert created.status_code == 200
        assert created.json()["worker_hint"] == "重点看导出接口"
        pid = created.json()["id"]
        with SessionLocal() as db:
            p = db.get(Project, pid)
            assert p.status != "paused"
        updated = client.patch(
            f"/api/projects/{pid}",
            json={"worker_hint": "忽略演示账号\n鉴权以 JWT 为准"},
        )
        assert updated.status_code == 200
        assert updated.json()["worker_hint"] == "忽略演示账号\n鉴权以 JWT 为准"
        cleared = client.patch(f"/api/projects/{pid}", json={"worker_hint": "  "})
        assert cleared.status_code == 200
        assert cleared.json()["worker_hint"] == ""
        too_long = client.patch(f"/api/projects/{pid}", json={"worker_hint": "x" * 20001})
        assert too_long.status_code == 422


def test_create_zip_worker_hint(tmp_env, monkeypatch):
    import io
    import zipfile

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
            data={"worker_hint": "  zip 提示  "},
        )
        assert created.status_code == 200
        assert created.json()["worker_hint"] == "zip 提示"


def test_project_file_progress_counts(tmp_env, project):
    from app.main import app
    from app.models import FileWeight, PhaseRun, SessionLocal

    with SessionLocal() as db:
        db.add_all(
            [
                FileWeight(project_id=project, path="a.java", weight=None, skipped=False, audited=False),
                FileWeight(project_id=project, path="b.java", weight=0, skipped=True, audited=True),
                FileWeight(project_id=project, path="c.java", weight=50, skipped=False, audited=False),
                FileWeight(project_id=project, path="d.java", weight=100, skipped=False, audited=True),
                PhaseRun(project_id=project, phase="worker", role="worker"),
                PhaseRun(project_id=project, phase="worker", role="worker"),
                PhaseRun(project_id=project, phase="fix", role="fix"),
            ]
        )
        db.commit()

    with TestClient(app) as client:
        body = client.get(f"/api/projects/{project}").json()
        assert body["audit_mode"] == "bounty"
        assert body["lab_setup_done"] is False
        assert body["manual_lab"] is False
        assert body["manual_lab_prompt"] == ""
        assert body["verifier_enabled"] is False
        assert body["dynamic_verify_enabled"] is False
        assert body["files_total"] == 4
        assert body["files_weighted"] == 2
        assert body["files_skipped"] == 1
        assert body["files_audited"] == 1
        assert body["files_weight100"] == 1
        assert body["files_weight100_audited"] == 1
        assert body["heuristic_lite"] is False
        assert body["worker_rounds"] == 2
        assert body["weight_exts"] == [{"ext": ".java", "agent_added": False, "files": 4}]
        subs = body["recon_subphases"]
        assert [s["id"] for s in subs] == ["map", "source_ext", "old_vulns", "mark"]
        assert all("label" in s and "done" in s for s in subs)
        subs = body["recon_subphases"]
        assert [s["id"] for s in subs] == ["map", "source_ext", "old_vulns", "mark"]
        assert all("label" in s and "done" in s for s in subs)


def test_project_weight_exts_marks_agent_added(tmp_env, project):
    from app.main import app
    from app.models import FileWeight, SessionLocal

    with SessionLocal() as db:
        db.add_all(
            [
                FileWeight(project_id=project, path="app/Main.java", weight=80, skipped=False),
                FileWeight(project_id=project, path="app/util.py", weight=40, skipped=False),
                FileWeight(project_id=project, path="app/job.ftl", weight=None, skipped=False),
                FileWeight(project_id=project, path="app/mapper.xml", weight=None, skipped=False),
                FileWeight(project_id=project, path="tests/job.ftl", weight=0, skipped=True),
            ]
        )
        db.commit()

    with TestClient(app) as client:
        body = client.get(f"/api/projects/{project}").json()
        assert body["weight_exts"] == [
            {"ext": ".java", "agent_added": False, "files": 1},
            {"ext": ".py", "agent_added": False, "files": 1},
            {"ext": ".ftl", "agent_added": True, "files": 2},
            {"ext": ".xml", "agent_added": True, "files": 1},
        ]
        listed = client.get("/api/projects").json()
        row = next(p for p in listed if p["id"] == project)
        assert row["weight_exts"] == body["weight_exts"]


def test_project_token_usage_counts(tmp_env, project):
    from app.main import app
    from app.models import SessionLocal, TokenUsage

    with SessionLocal() as db:
        db.add_all(
            [
                TokenUsage(
                    project_id=project,
                    phase="recon",
                    role="recon",
                    tokens_input=1000,
                    tokens_output=200,
                    tokens_cached=400,
                    tokens_total=1200,
                ),
                TokenUsage(
                    project_id=project,
                    phase="worker",
                    role="worker",
                    tokens_input=500,
                    tokens_output=100,
                    tokens_cached=50,
                    tokens_total=600,
                ),
            ]
        )
        db.commit()

    with TestClient(app) as client:
        body = client.get(f"/api/projects/{project}").json()
        assert body["tokens_input"] == 1500
        assert body["tokens_output"] == 300
        assert body["tokens_cached"] == 450
        assert body["tokens_total"] == 1800


def test_vulns_list_and_download(tmp_env, project):
    from app.main import app
    from app.tools import ToolContext, registry

    payload = {
        "title": "RCE demo",
        "vuln_type": "rce",
        "cwe": "CWE-78",
        "file_path": "app/Main.java",
        "line_no": 10,
        "source_sink": "a->b",
        "auth_premise": "none",
        "http_request": "POST /x HTTP/1.1\n",
        "poc_code": "print('x')\n",
        "expected_evidence": "shell",
        "config_premise": "default",
    }
    out = registry.dispatch(
        ToolContext(project_id=project, role="worker", phase="worker"),
        "SubmitVuln",
        payload,
    )
    assert out.get("ok") is True, out
    vid = out["vuln_id"]

    with TestClient(app) as client:
        lst = client.get(f"/api/vulns?project_id={project}")
        assert lst.status_code == 200
        hit = next(v for v in lst.json() if v["id"] == vid)
        assert hit["project_name"] == "demo"
        assert hit["mining_path"] == "heuristic"
        assert hit["config_premise"] == "default"
        detail = client.get(f"/api/vulns/{vid}")
        assert detail.status_code == 200
        body = detail.json()
        assert body["title"] == "RCE demo"
        assert body["project_name"] == "demo"
        assert body["mining_path"] == "heuristic"
        assert body["config_premise"] == "default"
        assert body["created_at"]
        assert body["attack_surface"] is None
        assert body["required_account"] is None
        assert body["submission_tier"] is None
        assert body["submission_reason"] is None
        assert body["root_cause_key"] is None
        assert body["tracking_status"] == "none"
        assert "**产出时间**：" in (body.get("report_md") or "")
        assert "GitHub Security Advisory" in (body.get("advisory_md") or "")
        assert "## Title" in (body.get("advisory_md") or "")
        dl = client.post("/api/vulns/download", json={"ids": [vid]})
        assert dl.status_code == 200
        assert dl.headers["content-type"].startswith("application/zip")
        assert len(dl.content) > 20
        import io
        import zipfile

        names = zipfile.ZipFile(io.BytesIO(dl.content)).namelist()
        assert f"vuln-{vid}/report.md" in names
        assert f"vuln-{vid}/advisory.md" in names
        one = client.get(f"/api/vulns/{vid}/download")
        assert one.status_code == 200
        assert one.headers["content-type"].startswith("text/markdown")
        disposition = one.headers["content-disposition"]
        assert "attachment" in disposition
        assert f'filename="vuln-{vid}.md"' in disposition
        assert f"vuln-{vid}-RCE%20demo.md" in disposition
        assert "**产出时间**：" in one.text
        advisory = client.get(f"/api/vulns/{vid}/download?kind=advisory")
        assert advisory.status_code == 200
        assert "GitHub Security Advisory" in advisory.text
        assert f'filename="vuln-{vid}-advisory.md"' in advisory.headers["content-disposition"]
        assert client.get(f"/api/vulns/{vid}/download?kind=nope").status_code == 400
        assert client.get("/api/vulns/999999/download").status_code == 404


def test_download_single_vuln_report_missing_file(tmp_env, project):
    from app.main import app
    from app.api.vulns import _report_download_filename
    from app.models import SessionLocal, Vuln

    assert _report_download_filename(3, 'a/b:c*?"<>|') == "vuln-3-a_b_c.md"
    assert _report_download_filename(3, "  ..  ") == "vuln-3.md"

    with SessionLocal() as db:
        v = Vuln(project_id=project, title="No report", vuln_type="xss", severity="low", status="pending_review")
        db.add(v)
        db.commit()
        vid = v.id

    with TestClient(app) as client:
        missing = client.get(f"/api/vulns/{vid}/download")
        assert missing.status_code == 404
        assert "报告不存在" in missing.text


def test_vuln_tracking_status_mark_and_filter(tmp_env, project):
    from app.main import app
    from app.models import SessionLocal, Vuln

    with SessionLocal() as db:
        a = Vuln(project_id=project, title="A", vuln_type="idor", severity="high", status="confirmed")
        b = Vuln(project_id=project, title="B", vuln_type="xss", severity="low", status="confirmed")
        c = Vuln(project_id=project, title="C", vuln_type="ssrf", severity="medium", status="static_only")
        db.add_all([a, b, c])
        db.commit()
        db.refresh(a)
        db.refresh(b)
        db.refresh(c)
        aid, bid, cid = a.id, b.id, c.id

    with TestClient(app) as client:
        marked = client.patch(f"/api/vulns/{aid}", json={"tracking_status": "submitted"})
        assert marked.status_code == 200
        assert marked.json()["tracking_status"] == "submitted"
        assert marked.json()["status"] == "confirmed"

        ignored = client.patch(f"/api/vulns/{bid}", json={"tracking_status": "ignored"})
        assert ignored.status_code == 200
        assert ignored.json()["tracking_status"] == "ignored"

        submitted = client.get(f"/api/vulns?project_id={project}&tracking_status=submitted").json()
        assert [v["id"] for v in submitted] == [aid]
        ignored_rows = client.get(f"/api/vulns?project_id={project}&tracking_status=ignored").json()
        assert [v["id"] for v in ignored_rows] == [bid]
        unmarked = client.get(f"/api/vulns?project_id={project}&tracking_status=none").json()
        assert [v["id"] for v in unmarked] == [cid]

        batch = client.post(
            "/api/vulns/mark",
            json={"ids": [aid, cid, 999999], "tracking_status": "ignored"},
        )
        assert batch.status_code == 200
        assert {v["id"]: v["tracking_status"] for v in batch.json()} == {
            aid: "ignored",
            cid: "ignored",
        }

        cleared = client.patch(f"/api/vulns/{aid}", json={"tracking_status": "none"})
        assert cleared.status_code == 200
        assert cleared.json()["tracking_status"] == "none"

        missing = client.patch("/api/vulns/999999", json={"tracking_status": "submitted"})
        assert missing.status_code == 404
        bad = client.patch(f"/api/vulns/{aid}", json={"tracking_status": "nope"})
        assert bad.status_code == 422
        bad_filter = client.get(f"/api/vulns?project_id={project}&tracking_status=nope")
        assert bad_filter.status_code == 400
        empty_batch = client.post("/api/vulns/mark", json={"ids": [], "tracking_status": "submitted"})
        assert empty_batch.status_code == 422


def test_vuln_followups_continue_archived_reviewer_context(tmp_env, project, monkeypatch):
    from app.agent.checkpoint import LoopCheckpoint, checkpoint_exists, save_checkpoint
    from app.main import app
    from app.models import PhaseRun, SessionLocal, Vuln
    from app.services import pipeline
    from app.services.paths import vuln_dir

    with SessionLocal() as db:
        vuln = Vuln(
            project_id=project,
            title="IDOR demo",
            vuln_type="idor",
            severity="high",
            status="confirmed",
        )
        db.add(vuln)
        db.commit()
        db.refresh(vuln)
        vuln.report_path = f"vulns/{vuln.id}/report.md"
        run = PhaseRun(project_id=project, phase="reviewer", role="reviewer", vuln_id=vuln.id)
        db.add(run)
        db.commit()
        db.refresh(run)
        vid = vuln.id
        run_id = run.id

    (vuln_dir(project, vid) / "report.md").write_text("# IDOR demo\n\nReviewer 已确认。\n", encoding="utf-8")
    save_checkpoint(
        LoopCheckpoint(
            project_id=project,
            phase_run_id=run_id,
            role="reviewer",
            phase="reviewer",
            system_prompt="Reviewer system",
            user_prompt="请审核漏洞",
            messages=[
                {"role": "system", "content": "Reviewer system"},
                {"role": "user", "content": "请审核漏洞"},
                {"role": "assistant", "content": "Reviewer 原始判断：可越权读取订单。"},
            ],
            state={"review_done": True},
            vuln_id=vid,
        )
    )

    seen: dict[str, object] = {}

    def fake_llm(project_id: int, messages: list[dict[str, str]]) -> str:
        seen["project_id"] = project_id
        seen["messages"] = messages
        return "追问答复：应重点说明对象归属校验缺失。"

    monkeypatch.setattr("app.services.vuln_followup._call_reviewer_llm", fake_llm)
    pipeline._finish_phase_run(run_id, "completed")
    assert not checkpoint_exists(project, run_id)
    assert (vuln_dir(project, vid) / f"reviewer-context-{run_id}.json").is_file()

    with TestClient(app) as client:
        initial = client.get(f"/api/vulns/{vid}/follow-ups")
        assert initial.status_code == 200
        assert initial.json()["reviewer_context_available"] is True
        assert initial.json()["reviewer_phase_run_id"] == run_id
        assert initial.json()["messages"] == []

        asked = client.post(f"/api/vulns/{vid}/follow-ups", json={"question": "根因是什么？"})
        assert asked.status_code == 200
        body = asked.json()
        assert [m["role"] for m in body["messages"]] == ["user", "assistant"]
        assert body["messages"][1]["content"].startswith("追问答复")

        messages = seen["messages"]
        assert isinstance(messages, list)
        context = messages[1]["content"]
        assert "Reviewer 轮次上下文" in context
        assert "Reviewer 原始判断" in context
        assert "IDOR demo" in context
        assert "已有追问记录" not in context

        persisted = client.get(f"/api/vulns/{vid}/follow-ups").json()
        assert len(persisted["messages"]) == 2

        asked2 = client.post(f"/api/vulns/{vid}/follow-ups", json={"question": "刚才说的校验具体缺在哪？"})
        assert asked2.status_code == 200
        assert [m["role"] for m in asked2.json()["messages"]] == ["user", "assistant", "user", "assistant"]

        followup_messages = seen["messages"]
        assert isinstance(followup_messages, list)
        followup_context = followup_messages[1]["content"]
        joined = "\n".join(str(m.get("content") or "") for m in followup_messages)
        assert "已有追问记录" in followup_context
        assert "根因是什么？" in joined
        assert "追问答复：应重点说明对象归属校验缺失。" in joined
        assert "刚才说的校验具体缺在哪？" in joined
        assert followup_messages[-1]["role"] == "user"
        assert followup_messages[-1]["content"] == "刚才说的校验具体缺在哪？"


def test_dynamic_verify_continues_archived_reviewer_round(tmp_env, project, monkeypatch):
    from app.agent.checkpoint import LoopCheckpoint, load_checkpoint, save_checkpoint
    from app.main import app
    from app.models import PhaseRun, Project, SessionLocal, Vuln
    from app.services import pipeline
    from app.services.paths import vuln_dir

    monkeypatch.setattr(pipeline, "start_audit", lambda pid: None)
    monkeypatch.setattr(pipeline, "_ensure_reviewer", lambda pid, cancel: None)

    with SessionLocal() as db:
        vuln = Vuln(
            project_id=project,
            title="Static SQLI",
            vuln_type="sqli",
            severity="high",
            status="static_only",
            evidence_level="static_only",
        )
        db.add(vuln)
        db.commit()
        db.refresh(vuln)
        run = PhaseRun(project_id=project, phase="reviewer", role="reviewer", vuln_id=vuln.id)
        db.add(run)
        db.commit()
        db.refresh(run)
        vid = vuln.id
        run_id = run.id

    (vuln_dir(project, vid) / "report.md").write_text("# Static SQLI\n\n静态已确认。\n", encoding="utf-8")
    save_checkpoint(
        LoopCheckpoint(
            project_id=project,
            phase_run_id=run_id,
            role="reviewer",
            phase="reviewer",
            system_prompt="仅静态 Reviewer",
            user_prompt="请审核漏洞",
            messages=[
                {"role": "system", "content": "仅静态 Reviewer"},
                {"role": "user", "content": "请审核漏洞"},
                {"role": "assistant", "content": "静态结论：默认可利用。"},
            ],
            state={"review_done": True, "review_verdict": "static_only"},
            vuln_id=vid,
        )
    )
    pipeline._finish_phase_run(run_id, "completed")

    with TestClient(app) as client:
        off = client.get(f"/api/vulns/{vid}")
        assert off.status_code == 200
        assert off.json()["can_dynamic_verify"] is False
        blocked = client.post(f"/api/vulns/{vid}/dynamic-verify")
        assert blocked.status_code == 400
        assert "靶场动态或局部验证" in blocked.json()["detail"]

        with SessionLocal() as db:
            proj = db.get(Project, project)
            proj.dynamic_verify_enabled = True
            proj.status = "completed"
            db.commit()

        ready = client.get(f"/api/vulns/{vid}")
        assert ready.json()["can_dynamic_verify"] is True
        assert ready.json()["dynamic_verify_queued"] is False

        queued = client.post(f"/api/vulns/{vid}/dynamic-verify")
        assert queued.status_code == 200
        body = queued.json()
        assert body["ok"] is True
        assert body["vuln_id"] == vid
        new_run = body["phase_run_id"]
        assert new_run != run_id

        cp = load_checkpoint(project, new_run)
        assert cp is not None
        assert cp.vuln_id == vid
        assert cp.state["dynamic_followup"] is True
        assert cp.state["review_done"] is False
        assert any("静态结论：默认可利用" in str(m.get("content") or "") for m in cp.messages)

        with SessionLocal() as db:
            proj = db.get(Project, project)
            assert proj.status == "reviewing"
            assert proj.phase == "reviewer"

        again = client.post(f"/api/vulns/{vid}/dynamic-verify")
        assert again.status_code == 409
        detail = client.get(f"/api/vulns/{vid}")
        assert detail.json()["dynamic_verify_queued"] is True
        assert detail.json()["can_dynamic_verify"] is True


def test_vulns_list_filters_attack_surface_and_score(tmp_env, project):
    from app.main import app
    from app.models import SessionLocal, Vuln
    from app.services.paths import vuln_dir

    with SessionLocal() as db:
        front = Vuln(
            project_id=project,
            title="Frontend SQLI",
            vuln_type="sqli",
            severity="high",
            severity_score=4,
            status="confirmed",
            attack_surface="frontend",
            submission_tier="cve_candidate",
            submission_reason="未认证 SQLI",
        )
        back = Vuln(
            project_id=project,
            title="Backend IDOR",
            vuln_type="idor",
            severity="medium",
            severity_score=2,
            status="confirmed",
            attack_surface="backend",
            required_account="user",
            submission_tier="low_impact",
            submission_reason="低权限 IDOR，低危害难利用",
            root_cause_key="idor:UserController",
        )
        legacy = Vuln(
            project_id=project,
            title="Legacy Report Score",
            vuln_type="xss",
            severity="low",
            status="confirmed",
            attack_surface="frontend",
        )
        hard = Vuln(
            project_id=project,
            title="CORS hardening",
            vuln_type="other",
            severity="low",
            severity_score=0,
            status="confirmed",
            attack_surface="frontend",
            submission_tier="hardening",
            submission_reason="CORS 低危害难利用",
        )
        db.add_all([front, back, legacy, hard])
        db.commit()
        db.refresh(front)
        db.refresh(back)
        db.refresh(legacy)
        db.refresh(hard)
        legacy.report_path = f"vulns/{legacy.id}/report.md"
        db.commit()
        front_id = front.id
        back_id = back.id
        legacy_id = legacy.id
        hard_id = hard.id

    (vuln_dir(project, legacy_id) / "report.md").write_text(
        "## 审核标注\n- 校准得分：-1\n",
        encoding="utf-8",
    )

    with TestClient(app) as client:
        front_rows = client.get(f"/api/vulns?project_id={project}&attack_surface=frontend").json()
        front_ids = {v["id"] for v in front_rows}
        assert front_id in front_ids
        assert legacy_id in front_ids
        assert hard_id in front_ids
        assert back_id not in front_ids
        assert next(v for v in front_rows if v["id"] == front_id)["severity_score"] == 4
        assert next(v for v in front_rows if v["id"] == legacy_id)["severity_score"] == -1

        back_rows = client.get(f"/api/vulns?project_id={project}&attack_surface=backend").json()
        assert [v["id"] for v in back_rows] == [back_id]

        bad = client.get(f"/api/vulns?project_id={project}&attack_surface=internal")
        assert bad.status_code == 400

        cve_rows = client.get(f"/api/vulns?project_id={project}&submission_tier=cve_candidate").json()
        assert [v["id"] for v in cve_rows] == [front_id]
        assert cve_rows[0]["submission_reason"] == "未认证 SQLI"

        low_rows = client.get(f"/api/vulns?project_id={project}&submission_tier=low_impact").json()
        assert {v["id"] for v in low_rows} == {back_id, hard_id}
        alias_rows = client.get(f"/api/vulns?project_id={project}&submission_tier=hardening").json()
        assert {v["id"] for v in alias_rows} == {back_id, hard_id}

        untiered = client.get(f"/api/vulns?project_id={project}&submission_tier=untiered").json()
        assert [v["id"] for v in untiered] == [legacy_id]

        grouped = client.get(
            f"/api/vulns?project_id={project}&root_cause_key=idor:UserController"
        ).json()
        assert [v["id"] for v in grouped] == [back_id]

        bad_tier = client.get(f"/api/vulns?project_id={project}&submission_tier=nope")
        assert bad_tier.status_code == 400


def test_phase_control_endpoints(tmp_env, project, monkeypatch):
    from app.main import app
    from app.services import pipeline
    from app.services.paths import docs_dir, old_vulns_dir
    from app.tools.phase_recon import mark_old_vuln_search_complete

    monkeypatch.setattr(pipeline, "_run_recon_map_refresh", lambda pid, cancel: True)
    monkeypatch.setattr(pipeline, "_run_recon_old_vulns", lambda pid, cancel: True)
    docs = docs_dir(project)
    (docs / "code-map.md").write_text("# 地图\n", encoding="utf-8")
    (docs / "auth.md").write_text("# 鉴权\n", encoding="utf-8")
    old = old_vulns_dir(project)
    old.mkdir(parents=True, exist_ok=True)
    mark_old_vuln_search_complete(project, note="seed")

    with TestClient(app) as client:
        body = client.get(f"/api/projects/{project}").json()
        assert "phase_states" in body
        assert "worker" in body["phase_states"]
        assert "verifier" in body["phase_states"]
        bad = client.post(f"/api/projects/{project}/recon-subphases/mark/rerun")
        assert bad.status_code == 400
        map_rerun = client.post(f"/api/projects/{project}/recon-subphases/map/rerun")
        assert map_rerun.status_code == 200
        assert map_rerun.json()["subphase"] == "map"
        t = pipeline._recon_rerun_threads.get(project)
        if t is not None:
            t.join(timeout=5)
        old_rerun = client.post(f"/api/projects/{project}/recon-subphases/old_vulns/rerun")
        assert old_rerun.status_code == 200
        assert old_rerun.json()["subphase"] == "old_vulns"
        t2 = pipeline._recon_rerun_threads.get(project)
        if t2 is not None:
            t2.join(timeout=5)
        gone = client.post(f"/api/projects/{project}/phases/worker/pause")
        assert gone.status_code == 404


def test_completed_project_can_change_mode_but_not_pause(tmp_env, project, monkeypatch):
    from app.main import app
    from app.models import Project, SessionLocal
    from app.services import pipeline

    monkeypatch.setattr(pipeline, "start_audit", lambda pid: None)
    with SessionLocal() as db:
        p = db.get(Project, project)
        p.status = "completed"
        p.phase = "done"
        db.commit()
    with TestClient(app) as client:
        mode = client.patch(f"/api/projects/{project}", json={"audit_mode": "full"})
        assert mode.status_code == 200
        assert mode.json()["audit_mode"] == "full"
        assert mode.json()["status"] == "completed"
        paused = client.post(f"/api/projects/{project}/pause")
        assert paused.status_code == 400
        assert "不可暂停" in paused.json()["detail"]
        shown = client.get(f"/api/projects/{project}").json()
        assert shown["status"] == "completed"
        assert shown["project_paused"] is False


def test_reset_progress_endpoint(tmp_env, project, monkeypatch):
    from app.main import app
    from app.models import BypassTarget, FileWeight, Project, SessionLocal, Sink, Vuln
    from app.services import pipeline
    from app.services.paths import docs_dir, workspace_dir

    monkeypatch.setattr(pipeline, "start_audit", lambda pid: None)
    docs_dir(project).mkdir(parents=True, exist_ok=True)
    (docs_dir(project) / "code-map.md").write_text("# 地图\n", encoding="utf-8")
    rounds = workspace_dir(project) / "rounds"
    rounds.mkdir(parents=True, exist_ok=True)
    (rounds / "round-2.md").write_text("旧轮次\n", encoding="utf-8")
    (rounds / "fast-round-2.md").write_text("Sink 轮次\n", encoding="utf-8")
    (rounds / "bypass-round-2.md").write_text("绕过轮次\n", encoding="utf-8")
    with SessionLocal() as db:
        db.add(FileWeight(project_id=project, path="app/Main.java", weight=80, skipped=False, audited=True))
        db.add(Vuln(project_id=project, title="保留洞", vuln_type="xss", status="confirmed"))
        db.add(Sink(project_id=project, file_path="app/Main.java", line_start=1, status="done", verdict="noise"))
        db.add(
            BypassTarget(
                project_id=project,
                file_path="docs/old-vulns/cve.md",
                title="旧洞",
                status="done",
                verdict="still_patched",
            )
        )
        p = db.get(Project, project)
        p.status = "auditing"
        p.recon_done = True
        db.commit()

    with TestClient(app) as client:
        missing = client.post("/api/projects/99999/reset-progress")
        assert missing.status_code == 404
        denied = client.post(f"/api/projects/{project}/reset-progress")
        assert denied.status_code == 400
        assert "暂停" in denied.json()["detail"]
        with SessionLocal() as db:
            p = db.get(Project, project)
            p.status = "paused"
            db.commit()
        ok = client.post(f"/api/projects/{project}/reset-progress")
        assert ok.status_code == 200
        body = ok.json()
        assert body["status"] == "paused"
        assert body["files_audited"] == 0
        assert body["vuln_confirmed"] == 1
        assert body["project_paused"] is True

    assert (docs_dir(project) / "code-map.md").is_file()
    assert not (rounds / "round-2.md").exists()
    assert (rounds / "fast-round-2.md").is_file()
    assert (rounds / "bypass-round-2.md").is_file()
    with SessionLocal() as db:
        fw = db.query(FileWeight).filter(FileWeight.project_id == project, FileWeight.path == "app/Main.java").one()
        assert fw.audited is False
        assert fw.weight == 80
        assert db.query(Vuln).filter(Vuln.project_id == project, Vuln.title == "保留洞").one().status == "confirmed"
        sink = db.query(Sink).filter(Sink.project_id == project).one()
        assert sink.status == "done"
        bypass = db.query(BypassTarget).filter(BypassTarget.project_id == project).one()
        assert bypass.status == "done"


def test_project_phase_reports(tmp_env, project):
    from app.main import app
    from app.services.paths import docs_dir, summaries_dir, workspace_dir

    docs = docs_dir(project)
    (docs / "code-map.md").write_text("# 地图\n\n入口在 Main.java。\n", encoding="utf-8")
    (docs / "auth.md").write_text("# 鉴权\n\nJWT 过滤器。\n", encoding="utf-8")
    (docs / "old-vulns" / "index.md").write_text("# 历史漏洞\n\nCVE-1\n", encoding="utf-8")
    rounds = workspace_dir(project) / "rounds"
    rounds.mkdir(parents=True, exist_ok=True)
    (rounds / "round-1.md").write_text("## 第1轮审计报告\n\n审计了 Main.java。\n", encoding="utf-8")
    summaries = summaries_dir(project)
    (summaries / "worker-round-1.md").write_text("压缩：Main.java 已审完。\n", encoding="utf-8")
    (summaries / "fix-1.md").write_text("修复上下文压缩。\n", encoding="utf-8")
    (summaries / "recon-mark-rescue-1.md").write_text("盖章超时抢救。\n", encoding="utf-8")
    (summaries / "reviewer-rescue-1.md").write_text("审核抢救摘要。\n", encoding="utf-8")
    (summaries / "ignored.txt").write_text("nope", encoding="utf-8")

    with TestClient(app) as client:
        missing = client.get("/api/projects/99999/reports")
        assert missing.status_code == 404
        body = client.get(f"/api/projects/{project}/reports").json()
        assert body["count"] == 6
        by_phase = {g["phase"]: g for g in body["phases"]}
        assert by_phase["recon"]["count"] == 4
        assert by_phase["worker"]["count"] == 1
        assert by_phase["reviewer"]["count"] == 1
        ids = {item["id"] for g in body["phases"] for item in g["reports"]}
        assert "workspace/rounds/round-1.md" in ids
        assert "docs/summaries/worker-round-1.md" not in ids
        assert "docs/summaries/fix-1.md" not in ids
        assert "docs/summaries/recon-mark-rescue-1.md" in ids
        round_item = next(i for i in by_phase["worker"]["reports"] if i["id"] == "workspace/rounds/round-1.md")
        assert round_item["kind"] == "round"
        assert round_item["title"] == "单轮挖掘方向"
        assert round_item["round"] == 1
        mark = next(i for i in by_phase["recon"]["reports"] if i["kind"] == "rescue")
        assert mark["subphase"] == "mark"
        assert mark["kind_label"] == "抢救"

        detail = client.get(
            f"/api/projects/{project}/reports/file",
            params={"path": "workspace/rounds/round-1.md"},
        )
        assert detail.status_code == 200
        assert "审计了 Main.java" in detail.json()["content"]

        traversal = client.get(
            f"/api/projects/{project}/reports/file",
            params={"path": "../secrets.md"},
        )
        assert traversal.status_code == 400
        unknown = client.get(
            f"/api/projects/{project}/reports/file",
            params={"path": "docs/summaries/ignored.txt"},
        )
        assert unknown.status_code == 400
        absent = client.get(
            f"/api/projects/{project}/reports/file",
            params={"path": "workspace/rounds/round-99.md"},
        )
        assert absent.status_code == 404


def test_project_phase_reports_are_paged(tmp_env, project):
    import os

    from app.main import app
    from app.services.paths import workspace_dir

    rounds = workspace_dir(project) / "rounds"
    rounds.mkdir(parents=True, exist_ok=True)
    base_ts = 1_700_000_000
    for n in range(1, 14):
        path = rounds / f"round-{n}.md"
        path.write_text(f"## 第{n}轮审计报告\n\n审计了第 {n} 个目标。\n", encoding="utf-8")
        os.utime(path, (base_ts + n, base_ts + n))

    with TestClient(app) as client:
        body = client.get(
            f"/api/projects/{project}/reports",
            params={"phase": "worker", "subphase": "mine"},
        ).json()
        worker = next(p for p in body["phases"] if p["phase"] == "worker")
        assert body["count"] == 13
        assert body["selected_count"] == 13
        assert worker["count"] == 13
        assert [item["round"] for item in worker["reports"]] == list(range(13, 3, -1))
        assert all(not p["reports"] for p in body["phases"] if p["phase"] != "worker")

        older = client.get(
            f"/api/projects/{project}/reports",
            params={"phase": "worker", "subphase": "mine", "offset": 10, "limit": 10},
        ).json()
        older_worker = next(p for p in older["phases"] if p["phase"] == "worker")
        assert older["selected_count"] == 13
        assert [item["round"] for item in older_worker["reports"]] == [3, 2, 1]

        bad = client.get(f"/api/projects/{project}/reports", params={"phase": "unknown"})
        assert bad.status_code == 400

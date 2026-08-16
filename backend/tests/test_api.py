from __future__ import annotations

from fastapi.testclient import TestClient


def test_health_and_settings(tmp_env):
    from app.main import app

    with TestClient(app) as client:
        assert client.get("/api/health").json()["ok"] is True
        s = client.get("/api/settings")
        assert s.status_code == 200
        body = s.json()
        assert "worker_concurrency" in body
        assert "fix_concurrency" in body
        assert "llm_providers" in body

        upd = client.put(
            "/api/settings",
            json={"worker_concurrency": 2, "fix_concurrency": 3, "default_model": "gpt-test"},
        )
        assert upd.status_code == 200
        assert upd.json()["worker_concurrency"] == 2
        assert upd.json()["fix_concurrency"] == 3
        assert upd.json()["default_model"] == "gpt-test"


def test_project_events_tail_and_before(tmp_env, project, monkeypatch, tmp_path):
    from app.main import app
    from app.services.live_log import live_log

    path = tmp_path / "live.events.jsonl"
    monkeypatch.setattr("app.services.live_log.live_events_path", lambda _pid: path)
    for i in range(6):
        live_log.agent(project, f"e{i}", phase="worker", role="worker")
    live_log.agent(project, "fix-1", phase="fix", role="fix")

    with TestClient(app) as client:
        tail = client.get(f"/api/projects/{project}/events?tail=true&limit=3&phase=worker")
        assert tail.status_code == 200
        body = tail.json()
        assert [e["text"] for e in body["events"]] == ["e4", "e5", "fix-1"]
        assert body["has_older"] is True
        older = client.get(
            f"/api/projects/{project}/events?before={body['oldest']}&limit=3&phase=worker"
        )
        assert [e["text"] for e in older.json()["events"]] == ["e1", "e2", "e3"]
        mine = client.get(f"/api/projects/{project}/events?tail=true&limit=10&phase=mine")
        assert [e["text"] for e in mine.json()["events"]] == ["e0", "e1", "e2", "e3", "e4", "e5"]
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


def test_projects_list_empty(tmp_env):
    from app.main import app

    with TestClient(app) as client:
        r = client.get("/api/projects")
        assert r.status_code == 200
        assert r.json() == []


def test_project_file_progress_counts(tmp_env, project):
    from app.main import app
    from app.models import FileWeight, SessionLocal

    with SessionLocal() as db:
        db.add_all(
            [
                FileWeight(project_id=project, path="a.java", weight=None, skipped=False, audited=False),
                FileWeight(project_id=project, path="b.java", weight=0, skipped=True, audited=False),
                FileWeight(project_id=project, path="c.java", weight=50, skipped=False, audited=False),
                FileWeight(project_id=project, path="d.java", weight=100, skipped=False, audited=True),
            ]
        )
        db.commit()

    with TestClient(app) as client:
        body = client.get(f"/api/projects/{project}").json()
        assert body["files_total"] == 4
        assert body["files_weighted"] == 2
        assert body["files_skipped"] == 1
        assert body["files_audited"] == 1
        subs = body["recon_subphases"]
        assert [s["id"] for s in subs] == ["map", "old_vulns", "mark"]
        assert all("label" in s and "done" in s for s in subs)
        subs = body["recon_subphases"]
        assert [s["id"] for s in subs] == ["map", "old_vulns", "mark"]
        assert all("label" in s and "done" in s for s in subs)


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
        detail = client.get(f"/api/vulns/{vid}")
        assert detail.status_code == 200
        body = detail.json()
        assert body["title"] == "RCE demo"
        assert body["project_name"] == "demo"
        assert body["created_at"]
        assert body["attack_surface"] is None
        assert body["required_account"] is None
        assert "**产出时间**：" in (body.get("report_md") or "")
        dl = client.post("/api/vulns/download", json={"ids": [vid]})
        assert dl.status_code == 200
        assert dl.headers["content-type"].startswith("application/zip")
        assert len(dl.content) > 20


def test_phase_control_endpoints(tmp_env, project, monkeypatch):
    from app.main import app
    from app.services import pipeline

    monkeypatch.setattr(pipeline, "start_audit", lambda pid: None)
    with TestClient(app) as client:
        body = client.get(f"/api/projects/{project}").json()
        assert "phase_states" in body
        assert "worker" in body["phase_states"]
        bad = client.post(f"/api/projects/{project}/phases/nope/pause")
        assert bad.status_code == 400
        paused = client.post(f"/api/projects/{project}/phases/worker/pause")
        assert paused.status_code == 200
        assert paused.json()["phases"]["worker"]["paused"] is True
        assert paused.json()["phases"]["recon"]["paused"] is False
        resumed = client.post(f"/api/projects/{project}/phases/worker/resume")
        assert resumed.status_code == 200
        assert resumed.json()["phases"]["worker"]["paused"] is False
        restarted = client.post(f"/api/projects/{project}/phases/recon/restart")
        assert restarted.status_code == 200
        assert restarted.json()["ok"] is True


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
    (summaries / "recon-mark-rescue-1.md").write_text("盖章超时抢救。\n", encoding="utf-8")
    (summaries / "reviewer-rescue-1.md").write_text("审核抢救摘要。\n", encoding="utf-8")
    (summaries / "ignored.txt").write_text("nope", encoding="utf-8")

    with TestClient(app) as client:
        missing = client.get("/api/projects/99999/reports")
        assert missing.status_code == 404
        body = client.get(f"/api/projects/{project}/reports").json()
        assert body["count"] == 7
        by_phase = {g["phase"]: g for g in body["phases"]}
        assert by_phase["recon"]["count"] == 4
        assert by_phase["worker"]["count"] == 2
        assert by_phase["reviewer"]["count"] == 1
        ids = {item["id"] for g in body["phases"] for item in g["reports"]}
        assert "workspace/rounds/round-1.md" in ids
        assert "docs/summaries/worker-round-1.md" in ids
        assert "docs/summaries/recon-mark-rescue-1.md" in ids
        round_item = next(i for i in by_phase["worker"]["reports"] if i["id"] == "workspace/rounds/round-1.md")
        assert round_item["kind"] == "round"
        assert round_item["title"] == "第1轮审计报告"
        assert round_item["round"] == 1
        summary_item = next(
            i for i in by_phase["worker"]["reports"] if i["id"] == "docs/summaries/worker-round-1.md"
        )
        assert summary_item["kind"] == "summary"
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

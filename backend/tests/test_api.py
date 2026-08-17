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
        bad = client.post(
            "/api/projects/upload",
            files={"file": ("src.zip", raw, "application/zip")},
            data={"audit_mode": "nope"},
        )
        assert bad.status_code == 400


def test_patch_audit_mode_only_when_paused(tmp_env, project):
    from app.main import app
    from app.models import Project, SessionLocal

    with TestClient(app) as client:
        denied = client.patch(f"/api/projects/{project}", json={"audit_mode": "full"})
        assert denied.status_code == 400
        assert "暂停" in denied.json()["detail"]
        with SessionLocal() as db:
            p = db.get(Project, project)
            p.status = "paused"
            db.commit()
        ok = client.patch(f"/api/projects/{project}", json={"audit_mode": "full"})
        assert ok.status_code == 200
        assert ok.json()["audit_mode"] == "full"
        assert ok.json()["status"] == "paused"


def test_project_file_progress_counts(tmp_env, project):
    from app.main import app
    from app.models import FileWeight, PhaseRun, SessionLocal

    with SessionLocal() as db:
        db.add_all(
            [
                FileWeight(project_id=project, path="a.java", weight=None, skipped=False, audited=False),
                FileWeight(project_id=project, path="b.java", weight=0, skipped=True, audited=False),
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
        assert body["files_total"] == 4
        assert body["files_weighted"] == 2
        assert body["files_skipped"] == 1
        assert body["files_audited"] == 1
        assert body["worker_rounds"] == 2
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
        assert body["submission_tier"] is None
        assert body["submission_reason"] is None
        assert body["root_cause_key"] is None
        assert "**产出时间**：" in (body.get("report_md") or "")
        dl = client.post("/api/vulns/download", json={"ids": [vid]})
        assert dl.status_code == 200
        assert dl.headers["content-type"].startswith("application/zip")
        assert len(dl.content) > 20


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

        persisted = client.get(f"/api/vulns/{vid}/follow-ups").json()
        assert len(persisted["messages"]) == 2


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
        assert round_item["title"] == "第1轮审计报告"
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

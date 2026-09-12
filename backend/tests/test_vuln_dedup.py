from __future__ import annotations

from fastapi.testclient import TestClient

from app.services.paths import old_vulns_dir
from app.services.pipeline import control_phase, request_vuln_dedup
from app.tools import ROLE_ACL, ToolContext, registry
from app.tools.phase_vuln_dedup import report_path, resolve_vuln_ids, save_request


def _ctx(project_id: int, role: str = "vuln_dedup", **kwargs):
    return ToolContext(project_id=project_id, role=role, phase="vuln_dedup", **kwargs)


def _submit(project_id: int, title: str = "登录处 SQL 注入", **extra):
    payload = {
        "title": title,
        "vuln_type": "sqli",
        "cwe": "CWE-89",
        "file_path": "app/Login.java",
        "line_no": 12,
        "source_sink": "GET /api/login -> query",
        "auth_premise": "未授权",
        "http_request": "GET /api/login?id=1",
        "poc_code": "print(1)",
        "expected_evidence": "error",
        "config_premise": "default",
    }
    payload.update(extra)
    out = registry.dispatch(_ctx(project_id, "worker"), "SubmitVuln", payload)
    if out.get("duplicate_soft_gate"):
        out = registry.dispatch(
            _ctx(project_id, "worker"),
            "SubmitVuln",
            {**payload, "confirm_not_duplicate": True},
        )
    assert out["ok"] is True, out
    return int(out["vuln_id"])


def test_control_phase_vuln_dedup():
    assert control_phase("vuln_dedup") == "vuln_dedup"
    assert control_phase("vuln-dedup") == "vuln_dedup"


def test_vuln_dedup_acl():
    allowed = ROLE_ACL["vuln_dedup"]
    assert "SearchOldVuln" in allowed
    assert "RecordVulnDedup" in allowed
    assert "FinishVulnDedup" in allowed
    assert "Read" in allowed
    assert "Grep" in allowed
    assert "Glob" in allowed
    assert "SubmitVuln" not in allowed
    assert "ConfirmVuln" not in allowed
    assert "MarkFalsePositive" not in allowed
    assert "WebSearch" not in allowed


def test_search_old_vuln_dedup_role_only_old(tmp_env, project):
    old = old_vulns_dir(project)
    old.mkdir(parents=True, exist_ok=True)
    (old / "hist.md").write_text(
        "---\ntitle: Hist SQLI\nsummary: old login sqli\nfix_status: patched\n---\n\n# old\n",
        encoding="utf-8",
    )
    _submit(project)
    listed = registry.dispatch(_ctx(project), "SearchOldVuln", {"query": ""})
    assert listed["ok"] is True
    kinds = {d["kind"] for d in listed["docs"]}
    titles = {d["title"] for d in listed["docs"]}
    assert kinds == {"old"}
    assert "Hist SQLI" in titles
    assert all(d["kind"] != "found" for d in listed["docs"])


def _record(ctx, vuln_id: int, **extra):
    payload = {
        "vuln_id": vuln_id,
        "verdict": "known_public",
        "source_status": "present",
        "old_title": "Hist SQLI",
        "reason": "同一 GET /api/login 入口的 SQL 注入，公开文已覆盖；src 中 sink 仍在",
    }
    payload.update(extra)
    return registry.dispatch(ctx, "RecordVulnDedup", payload)


def test_record_and_finish_vuln_dedup(tmp_env, project):
    old = old_vulns_dir(project)
    old.mkdir(parents=True, exist_ok=True)
    (old / "hist.md").write_text(
        "---\ntitle: Hist SQLI\nsummary: login sqli\n---\n\nGET /api/login\n",
        encoding="utf-8",
    )
    vuln_id = _submit(project)
    ctx = _ctx(project)
    rec = _record(ctx, vuln_id)
    assert rec["ok"] is True
    assert rec["verdict"] == "known_public"
    assert rec["source_status"] == "present"
    assert rec["marked_false_positive"] is True
    assert rec["fp_kind"] == "known_public"
    assert ctx.state.get("review_done") is not True

    from app.models import SessionLocal, Vuln

    with SessionLocal() as db:
        row = db.get(Vuln, vuln_id)
        assert row.status == "false_positive"
        assert row.fp_kind == "known_public"

    fin = registry.dispatch(ctx, "FinishVulnDedup", {"notes": "查 1 条，已公开 1 条，源码仍在"})
    assert fin["ok"] is True
    assert ctx.state.get("vuln_dedup_done") is True
    path = report_path(project)
    assert path.is_file()
    text = path.read_text(encoding="utf-8")
    assert "known_public" in text
    assert "仍存在" in text
    assert f"#{vuln_id}" in text


def test_record_requires_source_status(tmp_env, project):
    vuln_id = _submit(project)
    rec = registry.dispatch(
        _ctx(project),
        "RecordVulnDedup",
        {
            "vuln_id": vuln_id,
            "verdict": "unique",
            "reason": "没有公开文",
        },
    )
    assert rec["ok"] is False
    assert "source_status" in (rec.get("error") or "")


def test_record_source_fixed_marks_fp(tmp_env, project):
    vuln_id = _submit(project)
    rec = _record(
        _ctx(project),
        vuln_id,
        verdict="unique",
        source_status="fixed",
        old_title="",
        reason="公开文未覆盖；src 中 Login.java 的拼接查询已删除",
    )
    assert rec["ok"] is True
    assert rec["marked_false_positive"] is True
    assert rec["fp_kind"] == "source_fixed"

    from app.models import SessionLocal, Vuln

    with SessionLocal() as db:
        row = db.get(Vuln, vuln_id)
        assert row.status == "false_positive"
        assert row.fp_kind == "source_fixed"


def test_record_known_public_and_fixed_marks_fixed(tmp_env, project):
    vuln_id = _submit(project)
    rec = _record(
        _ctx(project),
        vuln_id,
        source_status="fixed",
        reason="同一 GET /api/login；当前 src 已加参数绑定，无法再注入",
    )
    assert rec["ok"] is True
    assert rec["fp_kind"] == "source_fixed"

    from app.models import SessionLocal, Vuln

    with SessionLocal() as db:
        row = db.get(Vuln, vuln_id)
        assert row.status == "false_positive"
        assert row.fp_kind == "source_fixed"


def test_record_unique_present_does_not_mark_fp(tmp_env, project):
    vuln_id = _submit(project)
    rec = _record(
        _ctx(project),
        vuln_id,
        verdict="unique",
        source_status="present",
        old_title="",
        reason="公开文未写到该参数；src 中 sink 仍在",
    )
    assert rec["ok"] is True
    assert rec["marked_false_positive"] is False

    from app.models import SessionLocal, Vuln

    with SessionLocal() as db:
        row = db.get(Vuln, vuln_id)
        assert row.status != "false_positive"


def test_format_source_note_zip(tmp_env, project):
    from app.tools.phase_vuln_dedup import format_source_note

    note = format_source_note(project, attempted_sync=False)
    assert "zip" in note
    assert "src/" in note


def test_resolve_ids_and_api(tmp_env, project, monkeypatch):
    vuln_id = _submit(project)
    assert resolve_vuln_ids(project, [vuln_id]) == [vuln_id]
    try:
        resolve_vuln_ids(project, [999999])
        assert False, "expected missing id"
    except ValueError as e:
        assert "不存在" in str(e) or "不属于" in str(e)

    kicked = {}

    def _fake_kick(pid: int) -> None:
        kicked["pid"] = pid

    monkeypatch.setattr("app.services.pipeline._kick_vuln_dedup_thread", _fake_kick)
    out = request_vuln_dedup(project, [vuln_id])
    assert out["ok"] is True
    assert out["vuln_ids"] == [vuln_id]
    assert kicked["pid"] == project

    from app.main import app

    with TestClient(app) as client:
        resp = client.post(f"/api/projects/{project}/vuln-dedup", json={"vuln_ids": [vuln_id]})
        assert resp.status_code == 200
        body = resp.json()
        assert body["ok"] is True
        assert body["count"] == 1


def test_dedup_without_old_docs_still_runs_agent(tmp_env, project, monkeypatch):
    from types import SimpleNamespace

    vuln_id = _submit(project)
    save_request(project, {"run_id": 1, "vuln_ids": [vuln_id], "consumed": False})
    captured: dict = {}

    def _boom_sync(pid: int) -> None:
        raise AssertionError("running project should not sync github")

    class FakeLoop:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def run(self):
            return SimpleNamespace(
                ok=True,
                stop_reason="completed",
                error=None,
                state={"vuln_dedup_done": True, "dedup_results": []},
            )

    monkeypatch.setattr("app.services.pipeline._maybe_sync_github_on_resume", _boom_sync)
    monkeypatch.setattr("app.services.pipeline.AgentLoop", FakeLoop)
    monkeypatch.setattr("app.services.pipeline._new_phase_run", lambda *a, **k: 1)
    monkeypatch.setattr("app.services.pipeline._start_log_session", lambda *a, **k: None)
    monkeypatch.setattr("app.services.pipeline._finish_phase_run", lambda *a, **k: None)
    from app.services.pipeline import _run_vuln_dedup_once

    _run_vuln_dedup_once(project)
    user = captured.get("user_prompt") or ""
    assert "当前源码快照" in user
    assert str(vuln_id) in user
    assert "zip" in user


def test_dedup_syncs_github_when_completed(tmp_env, project, monkeypatch):
    from types import SimpleNamespace

    from app.models import Project, SessionLocal

    vuln_id = _submit(project)
    with SessionLocal() as db:
        p = db.get(Project, project)
        p.status = "completed"
        p.source_type = "github"
        db.commit()
    save_request(project, {"run_id": 1, "vuln_ids": [vuln_id], "consumed": False})
    synced: dict = {}

    class FakeLoop:
        def __init__(self, **kwargs):
            synced["user"] = kwargs.get("user_prompt") or ""

        def run(self):
            return SimpleNamespace(
                ok=True,
                stop_reason="completed",
                error=None,
                state={"vuln_dedup_done": True, "dedup_results": []},
            )

    monkeypatch.setattr(
        "app.services.pipeline._maybe_sync_github_on_resume",
        lambda pid: synced.update(pid=pid),
    )
    monkeypatch.setattr("app.services.pipeline.AgentLoop", FakeLoop)
    monkeypatch.setattr("app.services.pipeline._new_phase_run", lambda *a, **k: 1)
    monkeypatch.setattr("app.services.pipeline._start_log_session", lambda *a, **k: None)
    monkeypatch.setattr("app.services.pipeline._finish_phase_run", lambda *a, **k: None)
    from app.services.pipeline import _run_vuln_dedup_once

    _run_vuln_dedup_once(project)
    assert synced.get("pid") == project
    assert "GitHub" in synced.get("user", "")

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


def test_record_and_finish_vuln_dedup(tmp_env, project):
    old = old_vulns_dir(project)
    old.mkdir(parents=True, exist_ok=True)
    (old / "hist.md").write_text(
        "---\ntitle: Hist SQLI\nsummary: login sqli\n---\n\nGET /api/login\n",
        encoding="utf-8",
    )
    vuln_id = _submit(project)
    ctx = _ctx(project)
    rec = registry.dispatch(
        ctx,
        "RecordVulnDedup",
        {
            "vuln_id": vuln_id,
            "verdict": "known_public",
            "old_title": "Hist SQLI",
            "reason": "同一 GET /api/login 入口的 SQL 注入，公开文已覆盖",
        },
    )
    assert rec["ok"] is True
    assert rec["verdict"] == "known_public"
    assert rec["marked_false_positive"] is True
    assert ctx.state.get("review_done") is not True

    from app.models import SessionLocal, Vuln

    with SessionLocal() as db:
        row = db.get(Vuln, vuln_id)
        assert row.status == "false_positive"
        assert row.fp_kind == "known_public"

    fin = registry.dispatch(ctx, "FinishVulnDedup", {"notes": "查 1 条，已公开 1 条"})
    assert fin["ok"] is True
    assert ctx.state.get("vuln_dedup_done") is True
    path = report_path(project)
    assert path.is_file()
    text = path.read_text(encoding="utf-8")
    assert "known_public" in text
    assert f"#{vuln_id}" in text


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


def test_dedup_without_old_docs_writes_report(tmp_env, project):
    vuln_id = _submit(project)
    save_request(project, {"run_id": 1, "vuln_ids": [vuln_id], "consumed": False})
    from app.services.pipeline import _run_vuln_dedup_once

    _run_vuln_dedup_once(project)
    path = report_path(project)
    assert path.is_file()
    assert "尚无历史漏洞" in path.read_text(encoding="utf-8") or "没有" in path.read_text(encoding="utf-8")

"""Attack-chain role, tools, gates, and project toggle."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.models import AttackChain, Project, Vuln
from app.services.paths import attack_chains_dir, old_vulns_dir
from app.services.pipeline import control_phase
from app.tools import ROLE_ACL, registry
from app.tools.phase_attack_chain import (
    attack_chain_ready,
    confirmed_vuln_count,
    is_attack_chain_done,
    mark_attack_chain_done,
)
from app.tools.phase_worker import project_complete_gates


def _ctx(project_id: int, role: str = "attack_chain", **kwargs):
    from app.tools import ToolContext

    return ToolContext(project_id=project_id, role=role, phase=role, **kwargs)


def _db():
    from app.models import SessionLocal

    return SessionLocal()


def _submit_and_confirm(project, *, title="洞 A", file_path="a.java", root_cause_key=None, **extra):
    payload = {
        "title": title,
        "vuln_type": "unauthorized_access",
        "cwe": "CWE-284",
        "file_path": file_path,
        "line_no": 1,
        "source_sink": "http -> sink",
        "auth_premise": "未授权",
        "http_request": "GET /api/x",
        "poc_code": "print('poc')",
        "expected_evidence": "200",
        "root_cause_key": root_cause_key or f"unauthorized_access:{file_path}:{title}",
    }
    payload.update(extra)
    out = registry.dispatch(_ctx(project, "worker"), "SubmitVuln", payload)
    if out.get("duplicate_soft_gate"):
        out = registry.dispatch(
            _ctx(project, "worker"),
            "SubmitVuln",
            {**payload, "confirm_not_duplicate": True},
        )
    assert out["ok"] is True, out
    vuln_id = out["vuln_id"]
    confirm = registry.dispatch(
        _ctx(project, "reviewer", vuln_id=vuln_id),
        "ConfirmVuln",
        {
            "vuln_id": vuln_id,
            "attack_surface": "frontend",
            "impact": "sensitive_data_or_privilege",
            "exploit_complexity": "single_request",
            "defense_status": "none",
            "submission_tier": "cve_candidate",
            "submission_reason": "high impact",
            "root_cause_key": payload["root_cause_key"],
        },
    )
    assert confirm["ok"] is True, confirm
    return vuln_id


def _make_mining_done(project):
    with _db() as db:
        proj = db.get(Project, project)
        proj.recon_done = True
        proj.heuristic_enabled = True
        proj.fast_enabled = False
        proj.bypass_enabled = False
        db.commit()
    from app.models import FileWeight, SessionLocal

    with SessionLocal() as db:
        db.query(FileWeight).filter(FileWeight.project_id == project).delete()
        db.commit()


def test_control_phase_attack_chain():
    assert control_phase("attack_chain") == "attack_chain"
    assert control_phase("attack-chain") == "attack_chain"


def test_attack_chain_acl():
    allowed = ROLE_ACL["attack_chain"]
    assert "SearchOldVuln" in allowed
    assert "Read" in allowed
    assert "Grep" in allowed
    assert "TodoWrite" in allowed
    assert "SubmitAttackChain" in allowed
    assert "FinishAttackChain" in allowed
    assert "Write" not in allowed
    assert "Bash" not in allowed
    assert "SubmitVuln" not in allowed
    assert "WebSearch" not in allowed


def test_search_old_vuln_attack_chain_filters_old_and_pending(tmp_env, project):
    old = old_vulns_dir(project)
    old.mkdir(parents=True, exist_ok=True)
    (old / "hist.md").write_text(
        "---\ntitle: Hist CVE\nsummary: old\n---\n\n# old body\n",
        encoding="utf-8",
    )
    pending = registry.dispatch(
        _ctx(project, "worker"),
        "SubmitVuln",
        {
            "title": "Pending Only",
            "vuln_type": "sqli",
            "cwe": "CWE-89",
            "file_path": "a.java",
            "line_no": 1,
            "source_sink": "a->b",
            "auth_premise": "none",
            "http_request": "GET /",
            "poc_code": "print(1)",
            "expected_evidence": "x",
        },
    )
    assert pending["ok"] is True
    confirmed_id = _submit_and_confirm(project, title="Confirmed Hole")

    listed = registry.dispatch(_ctx(project, "attack_chain"), "SearchOldVuln", {})
    assert listed["ok"] is True
    titles = {d["title"] for d in listed["docs"]}
    assert "Hist CVE" not in titles
    assert "Pending Only" not in titles
    assert "Confirmed Hole" in titles
    doc = next(d for d in listed["docs"] if d["vuln_id"] == confirmed_id)
    assert doc["kind"] == "found"
    assert doc["status"] in ("confirmed", "static_only")
    assert "auth_premise" in doc

    full = registry.dispatch(_ctx(project, "attack_chain"), "SearchOldVuln", {"title": f"#{confirmed_id}"})
    assert full["matched"] is True
    assert full.get("http_request")
    assert full.get("poc_code")


def test_submit_attack_chain_and_finish(tmp_env, project):
    a = _submit_and_confirm(project, title="洞 A")
    b = _submit_and_confirm(project, title="洞 B", file_path="b.java")
    ctx = _ctx(project, "attack_chain")
    bad = registry.dispatch(
        ctx,
        "SubmitAttackChain",
        {"title": "假链", "vuln_ids": [a], "steps": "只有一步"},
    )
    assert bad["ok"] is False

    pending_id = None
    with _db() as db:
        row = Vuln(
            project_id=project,
            title="未确认",
            vuln_type="unauthorized_access",
            cwe="CWE-284",
            file_path="c.java",
            line_no=1,
            source_sink="c->d",
            auth_premise="none",
            http_request="GET /",
            poc_code="print(1)",
            expected_evidence="x",
            status="pending_review",
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        pending_id = row.id
    reject = registry.dispatch(
        ctx,
        "SubmitAttackChain",
        {
            "title": "含未确认",
            "vuln_ids": [a, pending_id],
            "steps": "不能用未确认",
        },
    )
    assert reject["ok"] is False

    ok = registry.dispatch(
        ctx,
        "SubmitAttackChain",
        {
            "title": "A 到 B",
            "vuln_ids": [a, b],
            "summary": "匿名读到后台",
            "steps": "## 步骤\n1. 打洞 A\n2. 用结果打洞 B\n",
        },
    )
    assert ok["ok"] is True, ok
    assert ok["chain_id"]
    with _db() as db:
        row = db.get(AttackChain, ok["chain_id"])
        assert row is not None
        assert row.title == "A 到 B"
        assert str(a) in row.vuln_ids and str(b) in row.vuln_ids
        report = attack_chains_dir(project) / row.report_path.split("/")[-1]
        assert report.is_file()
        assert "打洞 A" in report.read_text(encoding="utf-8")
        assert (attack_chains_dir(project) / "index.md").is_file()

    done = registry.dispatch(ctx, "FinishAttackChain", {"notes": "已提交 1 条"})
    assert done["ok"] is True
    assert ctx.state.get("attack_chain_done") is True
    assert is_attack_chain_done(project) is True


def test_project_complete_gates_waits_for_attack_chain(tmp_env, project):
    a = _submit_and_confirm(project, title="洞 A")
    b = _submit_and_confirm(project, title="洞 B", file_path="b.java")
    _make_mining_done(project)
    assert confirmed_vuln_count(project) >= 2

    with _db() as db:
        proj = db.get(Project, project)
        proj.attack_chain_enabled = True
        proj.attack_chain_done = False
        db.commit()

    assert attack_chain_ready(project) is True
    assert project_complete_gates(project) is False

    mark_attack_chain_done(project, reason="测试收工")
    assert project_complete_gates(project) is True

    with _db() as db:
        proj = db.get(Project, project)
        proj.attack_chain_enabled = False
        proj.attack_chain_done = False
        db.commit()
    assert project_complete_gates(project) is True
    _ = (a, b)


def test_skip_when_fewer_than_two_confirmed(tmp_env, project):
    from app.services.pipeline import _ensure_attack_chain
    import threading

    _submit_and_confirm(project, title="仅一条")
    _make_mining_done(project)
    with _db() as db:
        proj = db.get(Project, project)
        proj.attack_chain_enabled = True
        proj.attack_chain_done = False
        db.commit()

    assert attack_chain_ready(project) is True
    assert confirmed_vuln_count(project) == 1
    cancel = threading.Event()
    _ensure_attack_chain(project, cancel)
    assert is_attack_chain_done(project) is True


def test_create_and_patch_attack_chain_enabled(tmp_env, monkeypatch):
    from app.main import app

    monkeypatch.setattr("app.api.projects.start_ingest_and_audit", lambda *a, **k: None)
    monkeypatch.setattr("app.api.projects.start_audit", lambda *a, **k: None)

    client = TestClient(app)
    created = client.post(
        "/api/projects",
        json={"source_type": "github", "source_url": "https://github.com/o/r", "name": "t"},
    )
    assert created.status_code == 200
    body = created.json()
    assert body["attack_chain_enabled"] is False
    assert body["attack_chain_done"] is False
    pid = body["id"]

    enabled = client.patch(f"/api/projects/{pid}", json={"attack_chain_enabled": True})
    assert enabled.status_code == 200
    assert enabled.json()["attack_chain_enabled"] is True

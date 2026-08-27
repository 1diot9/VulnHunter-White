"""Attack-chain role, tools, gates, and project toggle."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.models import AttackChain, FileWeight, Project, Vuln
from app.services.paths import attack_chains_dir, old_vulns_dir
from app.services.pipeline import control_phase
from app.tools import ROLE_ACL, registry
from app.tools.phase_attack_chain import (
    attack_chain_prereqs,
    attack_chain_ready,
    confirmed_vuln_count,
    is_attack_chain_done,
    mark_attack_chain_done,
    reclaim_premature_attack_chain_done,
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
        "config_premise": "default",
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
    assert "Write" in allowed
    assert "Bash" in allowed or "PowerShell" in allowed
    assert "TodoWrite" in allowed
    assert "SubmitAttackChain" in allowed
    assert "IndexAttackChain" in allowed
    assert "FinishAttackChain" in allowed
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
            "title": "仅待审核",
            "vuln_type": "sqli",
            "cwe": "CWE-89",
            "file_path": "a.java",
            "line_no": 1,
            "source_sink": "a->b",
            "auth_premise": "none",
            "http_request": "GET /",
            "poc_code": "print(1)",
            "expected_evidence": "x",
            "config_premise": "default",
        },
    )
    assert pending["ok"] is True
    confirmed_id = _submit_and_confirm(project, title="已确认漏洞")

    listed = registry.dispatch(_ctx(project, "attack_chain"), "SearchOldVuln", {})
    assert listed["ok"] is True
    titles = {d["title"] for d in listed["docs"]}
    assert "Hist CVE" not in titles
    assert "仅待审核" not in titles
    assert "已确认漏洞" in titles
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
        index = (attack_chains_dir(project) / "index.md").read_text(encoding="utf-8")
        assert "## 详文" in index
        assert "A 到 B" in index

    done = registry.dispatch(ctx, "FinishAttackChain", {"notes": "已提交 1 条"})
    assert done["ok"] is True
    assert ctx.state.get("attack_chain_done") is True
    assert is_attack_chain_done(project) is True


def test_detailed_chain_cap_and_index_brief(tmp_env, project):
    vulns = [
        _submit_and_confirm(project, title=f"洞 {i}", file_path=f"{i}.java")
        for i in range(8)
    ]
    ctx = _ctx(project, "attack_chain")
    for i in range(3):
        ok = registry.dispatch(
            ctx,
            "SubmitAttackChain",
            {
                "title": f"详文 {i}",
                "vuln_ids": [vulns[i * 2], vulns[i * 2 + 1]],
                "summary": f"摘要 {i}",
                "steps": f"## 步骤\n打 {i}\n",
            },
        )
        assert ok["ok"] is True, ok
        assert ok["kind"] == "detailed"
    fourth = registry.dispatch(
        ctx,
        "SubmitAttackChain",
        {
            "title": "第4条详文",
            "vuln_ids": [vulns[6], vulns[7]],
            "summary": "不该写详文",
            "steps": "## 步骤\n太多了\n",
        },
    )
    assert fourth["ok"] is False
    assert "最多 3 条" in str(fourth.get("error") or "")

    brief = registry.dispatch(
        ctx,
        "IndexAttackChain",
        {
            "title": "简述链",
            "vuln_ids": [vulns[6], vulns[7]],
            "summary": "危害较低，匿名可读后再打低危接口",
        },
    )
    assert brief["ok"] is True, brief
    assert brief["kind"] == "brief"
    with _db() as db:
        row = db.get(AttackChain, brief["chain_id"])
        assert row is not None
        assert not row.report_path
    chain_dir = attack_chains_dir(project)
    md_files = [p for p in chain_dir.glob("*.md") if p.name != "index.md"]
    assert len(md_files) == 3
    index = (chain_dir / "index.md").read_text(encoding="utf-8")
    assert "## 详文" in index
    assert "## 其他简述" in index
    assert "简述链" in index
    assert "第4条详文" not in index
    assert "不该写详文" not in index


def test_finish_other_chains_go_to_index(tmp_env, project):
    a = _submit_and_confirm(project, title="洞 A")
    b = _submit_and_confirm(project, title="洞 B", file_path="b.java")
    c = _submit_and_confirm(project, title="洞 C", file_path="c.java")
    d = _submit_and_confirm(project, title="洞 D", file_path="d.java")
    ctx = _ctx(project, "attack_chain")
    ok = registry.dispatch(
        ctx,
        "SubmitAttackChain",
        {
            "title": "主链",
            "vuln_ids": [a, b],
            "summary": "最强",
            "steps": "## 步骤\n1\n",
        },
    )
    assert ok["ok"] is True, ok
    done = registry.dispatch(
        ctx,
        "FinishAttackChain",
        {
            "notes": "1 详文 + 1 简述",
            "other_chains": [
                {
                    "title": "次链",
                    "vuln_ids": [c, d],
                    "summary": "同入口但后续危害更小",
                }
            ],
        },
    )
    assert done["ok"] is True, done
    assert done["detailed_count"] == 1
    assert done["brief_count"] == 1
    index = (attack_chains_dir(project) / "index.md").read_text(encoding="utf-8")
    assert "主链" in index
    assert "次链" in index
    md_files = [p for p in attack_chains_dir(project).glob("*.md") if p.name != "index.md"]
    assert len(md_files) == 1


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


def _leave_mining_open(project):
    with _db() as db:
        proj = db.get(Project, project)
        proj.recon_done = True
        proj.heuristic_enabled = True
        proj.heuristic_lite = False
        proj.fast_enabled = False
        proj.bypass_enabled = False
        proj.attack_chain_enabled = True
        proj.attack_chain_done = False
        db.add(
            FileWeight(
                project_id=project,
                path="still-open.java",
                weight=50,
                skipped=False,
                audited=False,
            )
        )
        db.commit()


def test_ensure_attack_chain_waits_until_mining_complete(tmp_env, project):
    import threading

    from app.services import pipeline

    _submit_and_confirm(project, title="洞 A")
    _submit_and_confirm(project, title="洞 B", file_path="b.java")
    _leave_mining_open(project)
    pipeline._force_new_run.add((project, "attack_chain"))

    assert attack_chain_prereqs(project) is False
    assert attack_chain_ready(project) is False
    pipeline._ensure_attack_chain(project, threading.Event())
    assert is_attack_chain_done(project) is False
    t = pipeline._attack_chain_threads.get(project)
    assert t is None or not t.is_alive()

    pipeline._run_attack_chain_once(project)
    assert is_attack_chain_done(project) is False


def test_reclaim_premature_attack_chain_done(tmp_env, project):
    _leave_mining_open(project)
    mark_attack_chain_done(project, reason="误提前收工")
    assert is_attack_chain_done(project) is True
    assert reclaim_premature_attack_chain_done(project) is True
    assert is_attack_chain_done(project) is False

    _make_mining_done(project)
    with _db() as db:
        proj = db.get(Project, project)
        proj.attack_chain_enabled = True
        proj.attack_chain_done = True
        db.commit()
    assert attack_chain_prereqs(project) is True
    assert reclaim_premature_attack_chain_done(project) is False
    assert is_attack_chain_done(project) is True


def test_phase_report_reads_attack_chain_doc(tmp_env, project):
    from app.services.phase_reports import read_phase_report, reports_by_phase

    a = _submit_and_confirm(project, title="洞 A")
    b = _submit_and_confirm(project, title="洞 B", file_path="b.java")
    ctx = _ctx(project, "attack_chain")
    ok = registry.dispatch(
        ctx,
        "SubmitAttackChain",
        {
            "title": "匿名读到后台",
            "vuln_ids": [a, b],
            "summary": "先读配置再打后台",
            "steps": "## 步骤\n1. 打洞 A\n2. 用结果打洞 B\n",
        },
    )
    assert ok["ok"] is True, ok
    grouped = reports_by_phase(project)
    chain = next(p for p in grouped["phases"] if p["phase"] == "attack_chain")
    ids = {item["id"] for item in chain["reports"]}
    assert ok["path"] in ids
    assert "docs/attack-chains/index.md" in ids
    detail = read_phase_report(project, ok["path"])
    assert "打洞 A" in detail["content"]
    assert detail["title"] == "匿名读到后台"
    assert detail["phase"] == "attack_chain"


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


_CHAIN_SCRIPT_OK = """
import argparse
p = argparse.ArgumentParser()
p.add_argument("-u", "--url", required=True)
p.add_argument("--proxy", default="")
args = p.parse_args()
print("chain-ok", args.url)
raise SystemExit(0)
"""

_CHAIN_SCRIPT_FAIL = """
import argparse
p = argparse.ArgumentParser()
p.add_argument("-u", "--url", required=True)
p.add_argument("--proxy", default="")
args = p.parse_args()
print("chain-miss", args.url)
raise SystemExit(2)
"""


def _lab_up(project, url: str = "http://127.0.0.1:18080"):
    from app.services.lab import save_env

    save_env(
        project,
        {
            "accepted": True,
            "status": "running",
            "target_url": url,
            "lab_ever_ready": True,
            "container_name": f"test-{project}",
        },
    )


def test_submit_static_without_lab_needs_no_script(tmp_env, project):
    a = _submit_and_confirm(project, title="洞 A")
    b = _submit_and_confirm(project, title="洞 B", file_path="b.java")
    ctx = _ctx(project, "attack_chain")
    ok = registry.dispatch(
        ctx,
        "SubmitAttackChain",
        {
            "title": "静态链",
            "vuln_ids": [a, b],
            "summary": "无靶场",
            "steps": "## 步骤\n静态\n",
        },
    )
    assert ok["ok"] is True, ok
    assert ok["verify_status"] == "static"
    assert not ok.get("script_path")


def test_lab_noninteractive_requires_chain_script(tmp_env, project):
    _lab_up(project)
    a = _submit_and_confirm(project, title="洞 A", vuln_type="sqli")
    b = _submit_and_confirm(project, title="洞 B", file_path="b.java", vuln_type="rce")
    ctx = _ctx(project, "attack_chain")
    missing = registry.dispatch(
        ctx,
        "SubmitAttackChain",
        {
            "title": "缺脚本",
            "vuln_ids": [a, b],
            "summary": "应拒绝",
            "steps": "## 步骤\n无脚本\n",
        },
    )
    assert missing["ok"] is False
    assert "chain_script" in str(missing.get("error") or "")


def test_lab_verifies_chain_script_and_lands_py(tmp_env, project):
    _lab_up(project)
    a = _submit_and_confirm(project, title="洞 A", vuln_type="sqli")
    b = _submit_and_confirm(project, title="洞 B", file_path="b.java", vuln_type="rce")
    ctx = _ctx(project, "attack_chain")
    ok = registry.dispatch(
        ctx,
        "SubmitAttackChain",
        {
            "title": "已验证链",
            "vuln_ids": [a, b],
            "summary": "SQLi 到 RCE",
            "steps": "## 步骤\n1\n2\n",
            "chain_script": _CHAIN_SCRIPT_OK,
        },
    )
    assert ok["ok"] is True, ok
    assert ok["verify_status"] == "verified"
    assert ok.get("script_path", "").endswith(".py")
    script = attack_chains_dir(project) / ok["script_path"].split("/")[-1]
    assert script.is_file()
    assert "chain-ok" in script.read_text(encoding="utf-8")
    with _db() as db:
        row = db.get(AttackChain, ok["chain_id"])
        assert row is not None
        assert row.verify_status == "verified"
        assert row.script_path == ok["script_path"]
    index = (attack_chains_dir(project) / "index.md").read_text(encoding="utf-8")
    assert "已动态验证" in index


def test_lab_rejects_failing_chain_script(tmp_env, project):
    _lab_up(project)
    a = _submit_and_confirm(project, title="洞 A", vuln_type="info_disclosure")
    b = _submit_and_confirm(project, title="洞 B", file_path="b.java", vuln_type="auth_bypass")
    ctx = _ctx(project, "attack_chain")
    bad = registry.dispatch(
        ctx,
        "SubmitAttackChain",
        {
            "title": "失败链",
            "vuln_ids": [a, b],
            "summary": "应失败",
            "steps": "## 步骤\n失败\n",
            "chain_script": _CHAIN_SCRIPT_FAIL,
        },
    )
    assert bad["ok"] is False
    assert bad.get("exit_code") == 2
    assert not list(attack_chains_dir(project).glob("*.md"))


def test_interactive_xss_skips_dynamic_verify(tmp_env, project):
    _lab_up(project)
    a = _submit_and_confirm(project, title="存储 XSS", vuln_type="stored_xss")
    b = _submit_and_confirm(project, title="后台 RCE", file_path="b.java", vuln_type="rce")
    ctx = _ctx(project, "attack_chain")
    ok = registry.dispatch(
        ctx,
        "SubmitAttackChain",
        {
            "title": "XSS 链",
            "vuln_ids": [a, b],
            "summary": "需 admin 打开页面",
            "steps": "## 步骤\n需受害者交互\n",
        },
    )
    assert ok["ok"] is True, ok
    assert ok["verify_status"] == "skipped_interaction"
    assert ok.get("skipped_interaction") is True
    assert not ok.get("script_path")


def test_needs_interaction_flag_skips_even_without_xss_type(tmp_env, project):
    _lab_up(project)
    a = _submit_and_confirm(project, title="洞 A", vuln_type="info_disclosure")
    b = _submit_and_confirm(project, title="洞 B", file_path="b.java", vuln_type="rce")
    ctx = _ctx(project, "attack_chain")
    ok = registry.dispatch(
        ctx,
        "SubmitAttackChain",
        {
            "title": "声明交互",
            "vuln_ids": [a, b],
            "summary": "Agent 声明需交互",
            "steps": "## 步骤\n需扫码\n",
            "needs_interaction": True,
        },
    )
    assert ok["ok"] is True, ok
    assert ok["verify_status"] == "skipped_interaction"

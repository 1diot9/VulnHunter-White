from __future__ import annotations

from app.services.paths import old_vulns_dir
from app.tools import ToolContext, registry


def _ctx(project_id: int, role: str = "worker", vuln_id: int | None = None) -> ToolContext:
    return ToolContext(project_id=project_id, role=role, phase=role, vuln_id=vuln_id)


def _submit(project_id: int, title: str = "SQLI in login", ctx: ToolContext | None = None, **extra):
    payload = {
        "title": title,
        "vuln_type": "sqli",
        "cwe": "CWE-89",
        "file_path": "app/Main.java",
        "line_no": 1,
        "source_sink": "login -> query",
        "auth_premise": "未授权",
        "config_premise": "default",
        "http_request": "GET /login?id=1 HTTP/1.1\nHost: x\n",
        "poc_code": "print('poc')\n",
        "expected_evidence": "error based",
        "intended_behavior": False,
    }
    payload.update(extra)
    tool_ctx = ctx or _ctx(project_id)
    out = registry.dispatch(tool_ctx, "SubmitVuln", payload)
    if out.get("duplicate_soft_gate"):
        out = registry.dispatch(tool_ctx, "SubmitVuln", {**payload, "confirm_not_duplicate": True})
    return out


def test_search_old_vuln_list_and_expand(tmp_env, project):
    old = old_vulns_dir(project)
    old.mkdir(parents=True, exist_ok=True)
    (old / "demo.md").write_text(
        "---\ntitle: Demo CVE\nsummary: short summary\nfix_status: unpatched\n---\n\n# body detail\n",
        encoding="utf-8",
    )
    ctx = _ctx(project)
    listed = registry.dispatch(ctx, "SearchOldVuln", {"query": "demo"})
    assert listed["ok"] is True
    assert listed["count"] >= 1
    assert listed["docs"][0]["title"] == "Demo CVE"
    assert listed["docs"][0]["kind"] == "old"
    assert listed["docs"][0]["kind_label"] == "侦察旧漏洞"
    assert listed["docs"][0]["fix_status"] == "unpatched"
    assert listed["docs"][0]["fix_status_label"] == "未修复"
    assert "body" not in listed["docs"][0]

    full = registry.dispatch(ctx, "SearchOldVuln", {"title": "Demo CVE"})
    assert full["ok"] is True
    assert full["kind"] == "old"
    assert "body detail" in full["content"]

    miss = registry.dispatch(ctx, "SearchOldVuln", {"title": "Demo CVE extra words that do not exist"})
    assert miss["ok"] is True
    assert miss.get("matched") is False
    assert any(s["title"] == "Demo CVE" and s["kind"] == "old" for s in miss.get("suggestions") or [])


def test_search_old_vuln_includes_submitted(tmp_env, project):
    old = old_vulns_dir(project)
    old.mkdir(parents=True, exist_ok=True)
    (old / "demo.md").write_text(
        "---\ntitle: Demo CVE\nsummary: historical sqli\n---\n\n# old body\n",
        encoding="utf-8",
    )
    out = _submit(project, title="SQLI in login")
    assert out["ok"] is True
    vuln_id = out["vuln_id"]

    listed = registry.dispatch(_ctx(project), "SearchOldVuln", {"query": "sqli"})
    kinds = {d["title"]: d["kind"] for d in listed["docs"]}
    assert kinds["Demo CVE"] == "old"
    assert kinds["SQLI in login"] == "found"
    found = next(d for d in listed["docs"] if d["kind"] == "found")
    assert found["kind_label"] == "本项目已提交"
    assert found["vuln_id"] == vuln_id
    assert found["status"] == "pending_review"
    assert found["file_path"] == "app/Main.java"
    assert "root_cause_key" in found
    assert "submission_tier" in found
    assert "content" not in found

    full = registry.dispatch(_ctx(project), "SearchOldVuln", {"title": "SQLI in login"})
    assert full["matched"] is True
    assert full["kind"] == "found"
    assert full["vuln_id"] == vuln_id
    assert "login -> query" in full["content"]

    by_id = registry.dispatch(_ctx(project), "SearchOldVuln", {"title": str(vuln_id)})
    assert by_id["matched"] is True
    assert by_id["vuln_id"] == vuln_id


def test_search_old_vuln_stays_in_project(tmp_env, project):
    _submit(project, title="project-one-only")
    models = tmp_env["models"]
    Session = tmp_env["Session"]
    with Session() as db:
        other = models.Project(name="other", source_type="zip", status="recon", phase="recon")
        db.add(other)
        db.commit()
        db.refresh(other)
        other_id = other.id
    from app.services.paths import ensure_project_dirs

    ensure_project_dirs(other_id)
    _submit(other_id, title="project-two-only")

    listed = registry.dispatch(_ctx(project), "SearchOldVuln", {"query": ""})
    titles = {d["title"] for d in listed["docs"]}
    assert "project-one-only" in titles
    assert "project-two-only" not in titles


def test_search_old_vuln_excludes_current_review_vuln(tmp_env, project):
    worker = _ctx(project)
    first = _submit(project, title="first submitted", ctx=worker)
    second = _submit(project, title="second submitted", ctx=worker)
    listed = registry.dispatch(
        _ctx(project, role="reviewer", vuln_id=second["vuln_id"]),
        "SearchOldVuln",
        {"query": ""},
    )
    titles = {d["title"] for d in listed["docs"]}
    assert "first submitted" in titles
    assert "second submitted" not in titles
    assert first["vuln_id"] != second["vuln_id"]

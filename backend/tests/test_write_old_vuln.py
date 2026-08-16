from __future__ import annotations

from app.services.paths import old_vulns_dir
from app.tools import ToolContext, registry


def _ctx(project_id: int, role: str = "recon_old_vuln") -> ToolContext:
    return ToolContext(project_id=project_id, role=role, phase=role)


def test_write_old_vuln_creates_doc_and_index(tmp_env, project):
    out = registry.dispatch(
        _ctx(project),
        "WriteOldVuln",
        {
            "title": "Demo CVE",
            "summary": "short summary",
            "content": "## 漏洞点\nlogin 注入\n",
            "cve": "CVE-2024-0001",
            "cwe": "CWE-89",
        },
    )
    assert out["ok"] is True, out
    assert out["created"] is True
    assert out["indexed"] == 1
    old = old_vulns_dir(project)
    written = old / "CVE-2024-0001.md"
    assert written.exists()
    text = written.read_text(encoding="utf-8")
    assert "title: Demo CVE" in text
    assert "login 注入" in text
    index = (old / "index.md").read_text(encoding="utf-8")
    assert "Demo CVE" in index
    assert "CVE-2024-0001.md" in index


def test_write_old_vuln_incremental_second_doc(tmp_env, project):
    registry.dispatch(
        _ctx(project),
        "WriteOldVuln",
        {"title": "First", "summary": "a", "content": "body-a", "cve": "CVE-1"},
    )
    out = registry.dispatch(
        _ctx(project),
        "WriteOldVuln",
        {"title": "Second", "summary": "b", "content": "body-b", "cve": "CVE-2"},
    )
    assert out["ok"] is True
    assert out["indexed"] == 2
    listed = registry.dispatch(_ctx(project, "worker"), "SearchOldVuln", {"query": ""})
    titles = {d["title"] for d in listed["docs"]}
    assert titles == {"First", "Second"}


def test_write_old_vuln_overwrite_same_title(tmp_env, project):
    registry.dispatch(
        _ctx(project),
        "WriteOldVuln",
        {"title": "Same", "summary": "old", "content": "v1", "cve": "CVE-9"},
    )
    out = registry.dispatch(
        _ctx(project),
        "WriteOldVuln",
        {"title": "Same", "summary": "new", "content": "v2 patched", "cve": "CVE-9"},
    )
    assert out["created"] is False
    assert out["indexed"] == 1
    text = (old_vulns_dir(project) / "CVE-9.md").read_text(encoding="utf-8")
    assert "v2 patched" in text
    assert "summary: new" in text


def test_write_old_vuln_no_findings(tmp_env, project):
    out = registry.dispatch(
        _ctx(project),
        "WriteOldVuln",
        {"no_findings": True, "note": "GHSA 无命中"},
    )
    assert out["ok"] is True
    assert out["indexed"] == 0
    index = (old_vulns_dir(project) / "index.md").read_text(encoding="utf-8")
    assert "GHSA 无命中" in index


def test_write_old_vuln_acl_recon_old_vuln_only(tmp_env, project):
    denied_worker = registry.dispatch(
        _ctx(project, "worker"),
        "WriteOldVuln",
        {"title": "x", "summary": "y", "content": "z"},
    )
    assert denied_worker["ok"] is False
    assert "无权" in denied_worker["error"]
    denied_map = registry.dispatch(
        _ctx(project, "recon"),
        "WriteOldVuln",
        {"title": "x", "summary": "y", "content": "z"},
    )
    assert denied_map["ok"] is False
    assert "无权" in denied_map["error"]


def test_write_tool_cannot_write_old_vulns(tmp_env, project):
    out = registry.dispatch(
        _ctx(project, "recon"),
        "Write",
        {"path": "docs/old-vulns/sneak.md", "content": "nope"},
    )
    assert out["ok"] is False
    assert "WriteOldVuln" in out["error"]
    assert not (old_vulns_dir(project) / "sneak.md").exists()

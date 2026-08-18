from __future__ import annotations

from app.services.paths import old_vuln_crawl_spec_path, old_vulns_dir
from app.tools import ToolContext, registry
from app.tools.phase_recon import recon_old_vuln_llm_ready, recon_old_vulns_ready


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
    assert out["done"] is False
    assert recon_old_vuln_llm_ready(project) is False
    assert recon_old_vulns_ready(project) is False
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


def test_write_old_vuln_no_findings_ends_llm_pass_only(tmp_env, project):
    out = registry.dispatch(
        _ctx(project),
        "WriteOldVuln",
        {"no_findings": True, "note": "WebSearch 无命中", "keyword": "demo"},
    )
    assert out["ok"] is True
    assert out["indexed"] == 0
    assert out["done"] is True
    assert recon_old_vuln_llm_ready(project) is True
    assert recon_old_vulns_ready(project) is False
    index = (old_vulns_dir(project) / "index.md").read_text(encoding="utf-8")
    assert "WebSearch 无命中" in index
    assert "llm_complete: true" in index
    assert "\ncomplete: false\n" in index
    spec = old_vuln_crawl_spec_path(project).read_text(encoding="utf-8")
    assert "demo" in spec


def test_write_old_vuln_acl_recon_old_vuln_roles(tmp_env, project):
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
    allowed_ghsa = registry.dispatch(
        _ctx(project, "recon_old_vuln_ghsa"),
        "WriteOldVuln",
        {"title": "ghsa", "summary": "s", "content": "body", "cve": "CVE-8"},
    )
    assert allowed_ghsa["ok"] is True


def test_write_tool_cannot_write_old_vulns(tmp_env, project):
    out = registry.dispatch(
        _ctx(project, "recon"),
        "Write",
        {"path": "docs/old-vulns/sneak.md", "content": "nope"},
    )
    assert out["ok"] is False
    assert "WriteOldVuln" in out["error"]
    assert not (old_vulns_dir(project) / "sneak.md").exists()


def test_write_old_vuln_done_after_entries_ends_llm_pass(tmp_env, project):
    registry.dispatch(
        _ctx(project),
        "WriteOldVuln",
        {"title": "First", "summary": "a", "content": "body-a", "cve": "CVE-1"},
    )
    assert recon_old_vulns_ready(project) is False
    out = registry.dispatch(_ctx(project), "WriteOldVuln", {"done": True, "keyword": "demo"})
    assert out["ok"] is True
    assert out["done"] is True
    assert out["indexed"] == 1
    assert recon_old_vuln_llm_ready(project) is True
    assert recon_old_vulns_ready(project) is False
    index = (old_vulns_dir(project) / "index.md").read_text(encoding="utf-8")
    assert "First" in index
    assert "llm_complete: true" in index


def test_write_old_vuln_done_appends_skip_note(tmp_env, project):
    registry.dispatch(
        _ctx(project),
        "WriteOldVuln",
        {"title": "App CVE", "summary": "own", "content": "call site Foo.bar", "cve": "CVE-1"},
    )
    out = registry.dispatch(
        _ctx(project),
        "WriteOldVuln",
        {"done": True, "note": "已跳过已修复的 Spring/Tomcat 传递依赖 CVE，未单独建档"},
    )
    assert out["ok"] is True
    assert out["done"] is True
    index = (old_vulns_dir(project) / "index.md").read_text(encoding="utf-8")
    assert "App CVE" in index
    assert "检索说明" in index
    assert "Spring/Tomcat" in index
    assert "llm_complete: true" in index


def test_write_old_vuln_last_entry_can_declare_done(tmp_env, project):
    out = registry.dispatch(
        _ctx(project),
        "WriteOldVuln",
        {
            "title": "Only",
            "summary": "s",
            "content": "body",
            "cve": "CVE-9",
            "done": True,
            "note": "已跳过未使用的 Undertow CVE",
        },
    )
    assert out["ok"] is True
    assert out["done"] is True
    assert recon_old_vuln_llm_ready(project) is True
    assert recon_old_vulns_ready(project) is False
    index = (old_vulns_dir(project) / "index.md").read_text(encoding="utf-8")
    assert "Only" in index
    assert "Undertow" in index


def test_write_old_vuln_no_findings_after_entries_keeps_docs(tmp_env, project):
    registry.dispatch(
        _ctx(project),
        "WriteOldVuln",
        {"title": "Kept", "summary": "s", "content": "body", "cve": "CVE-3"},
    )
    out = registry.dispatch(_ctx(project), "WriteOldVuln", {"no_findings": True})
    assert out["ok"] is True
    assert out["indexed"] == 1
    assert recon_old_vuln_llm_ready(project) is True
    index = (old_vulns_dir(project) / "index.md").read_text(encoding="utf-8")
    assert "Kept" in index
    assert "未发现需单独建档" not in index


def test_write_old_vuln_ghsa_pass_completes_phase(tmp_env, project):
    registry.dispatch(
        _ctx(project),
        "WriteOldVuln",
        {"title": "LLM", "summary": "a", "content": "body", "cve": "CVE-1", "done": True},
    )
    assert recon_old_vuln_llm_ready(project) is True
    assert recon_old_vulns_ready(project) is False
    out = registry.dispatch(
        _ctx(project, "recon_old_vuln_ghsa"),
        "WriteOldVuln",
        {
            "title": "GHSA extra",
            "summary": "from crawler",
            "content": "call site Bar.baz",
            "cve": "CVE-2",
            "done": True,
            "note": "已核验爬虫候选",
        },
    )
    assert out["ok"] is True
    assert recon_old_vulns_ready(project) is True
    index = (old_vulns_dir(project) / "index.md").read_text(encoding="utf-8")
    assert "\ncomplete: true\n" in index
    assert "LLM" in index
    assert "GHSA extra" in index
    assert "已核验爬虫候选" in index

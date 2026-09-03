from __future__ import annotations

from app.services.paths import docs_dir, old_vulns_dir, src_dir
from app.services.source_baseline import (
    BASELINE_ACKNOWLEDGED,
    BASELINE_STALE,
    FP_KIND_KNOWN_CVE_PATCHED,
    acknowledge_source_baseline,
    build_source_baseline_report,
    known_patched_cve_submit_block_reason,
    run_source_baseline_check,
    source_baseline_blocks_mining,
    version_compare,
)
from app.tools import registry


def _ctx(project_id: int, role: str, **kwargs):
    from app.tools import ToolContext

    return ToolContext(project_id=project_id, role=role, phase=role, **kwargs)


def _seed_cloudreve_like_baseline(project: int) -> None:
    src = src_dir(project)
    (src / "application/constants").mkdir(parents=True, exist_ok=True)
    (src / "application/constants/constants.go").write_text(
        'var BackendVersion = "4.14.0"\n',
        encoding="utf-8",
    )
    old = old_vulns_dir(project)
    old.mkdir(parents=True, exist_ok=True)
    (old / "index.md").write_text("---\ncomplete: true\n---\n", encoding="utf-8")
    (old / "CVE-2026-54563.md").write_text(
        "---\n"
        "title: WebDAV scope escape\n"
        "summary: patched upstream\n"
        "cve: CVE-2026-54563\n"
        "fix_status: patched\n"
        "affected_version: < 4.16.0\n"
        "source: ghsa\n"
        "---\n\nbody\n",
        encoding="utf-8",
    )


def test_version_compare_orders_semver():
    assert version_compare("4.14.0", "4.16.0") < 0
    assert version_compare("4.16.1", "4.16.0") > 0


def test_build_source_baseline_report_detects_stale_snapshot(tmp_env, project):
    _seed_cloudreve_like_baseline(project)
    report = build_source_baseline_report(project)
    assert report.status == BASELINE_STALE
    assert report.source_version == "4.14.0"
    assert any(i.cve == "CVE-2026-54563" for i in report.issues)


def test_run_source_baseline_check_blocks_mining_until_acknowledged(tmp_env, project):
    from app.models import Project, SessionLocal

    _seed_cloudreve_like_baseline(project)
    report = run_source_baseline_check(project)
    assert report.status == BASELINE_STALE
    assert source_baseline_blocks_mining(project) is True
    assert (docs_dir(project) / "source-baseline.json").is_file()
    acknowledge_source_baseline(project)
    with SessionLocal() as db:
        proj = db.get(Project, project)
        assert proj.source_baseline_status == BASELINE_ACKNOWLEDGED
    assert source_baseline_blocks_mining(project) is False


def test_submit_vuln_blocks_known_patched_cve_on_bypass(tmp_env, project):
    from app.models import Project, SessionLocal

    _seed_cloudreve_like_baseline(project)
    run_source_baseline_check(project)
    acknowledge_source_baseline(project)
    with SessionLocal() as db:
        proj = db.get(Project, project)
        proj.recon_done = True
        db.commit()
    ctx = _ctx(project, "bypass_worker")
    ctx.state["mining_path"] = "bypass"
    out = registry.dispatch(
        ctx,
        "SubmitVuln",
        {
            "title": "Cloudreve WebDAV 路径穿越（CVE-2026-54563）",
            "vuln_type": "path_traversal",
            "cwe": "CWE-22",
            "file_path": "src/pkg/webdav/webdav.go",
            "line_no": 41,
            "source_sink": "stripPrefix",
            "auth_premise": "user",
            "http_request": "PUT /dav/../x",
            "poc_code": "#!/usr/bin/env python3\nimport argparse\n"
            "p=argparse.ArgumentParser()\n"
            "p.add_argument('-u','--url',required=True)\n"
            "p.add_argument('--proxy',default='')\n"
            "p.parse_args()\n",
            "expected_evidence": "escape",
            "config_premise": "default",
            "root_cause_key": "path_traversal:stripPrefix",
            "report_md": "## 摘要\n\nCVE-2026-54563\n\n## 漏洞描述\n\nx\n\n## 漏洞危害\n\nx\n\n"
            "## 漏洞厂商全称\n\nCloudreve\n\n## 已知受影响产品及版本\n\n<4.16.0\n\n"
            "## 互联网资产证明\n\n### 精准测绘语法\n\n#### FOFA\n\n```\ntitle=\"x\"\n```\n\n"
            "## 漏洞技术细节\n\n### 补丁绕过简析\n\nx\n\n### Source → Sink\n\nx\n\n"
            "### 漏洞代码\n\n```go\nx\n```\n\n### 完整 PoC 描述\n\nx\n\n"
            "### 触发条件\n\nx\n\n## 同根因受影响点\n\nx\n\n## 复现证明\n\nx\n\n## 修复方案\n\nx\n",
        },
    )
    assert out["ok"] is False
    assert "still_patched" in out["error"]


def test_confirm_vuln_auto_false_positive_for_known_patched_cve(tmp_env, project):
    from app.models import Project, SessionLocal, Vuln

    _seed_cloudreve_like_baseline(project)
    run_source_baseline_check(project)
    acknowledge_source_baseline(project)
    with SessionLocal() as db:
        proj = db.get(Project, project)
        proj.recon_done = True
        vuln = Vuln(
            project_id=project,
            title="Cloudreve WebDAV CVE-2026-54563",
            vuln_type="path_traversal",
            severity="high",
            cwe="CWE-22",
            file_path="src/pkg/webdav/webdav.go",
            line_no=41,
            status="pending",
            mining_path="bypass",
        )
        db.add(vuln)
        db.commit()
        vid = vuln.id
    ctx = _ctx(project, "reviewer", vuln_id=vid)
    out = registry.dispatch(
        ctx,
        "ConfirmVuln",
        {
            "vuln_id": vid,
            "attack_surface": "backend",
            "required_account": "user",
        },
    )
    assert out["ok"] is True
    assert out["status"] == "false_positive"
    with SessionLocal() as db:
        row = db.get(Vuln, vid)
        assert row.status == "false_positive"
        assert row.fp_kind == FP_KIND_KNOWN_CVE_PATCHED

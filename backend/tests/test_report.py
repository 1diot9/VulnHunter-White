from __future__ import annotations

from datetime import datetime, timezone

from app.services.report import format_produced_at, stamp_produced_at, write_report_md
from app.services.paths import vuln_dir
from app.tools import ToolContext, registry


def test_stamp_after_h1():
    dt = datetime(2026, 8, 16, 1, 17, 0, tzinfo=timezone.utc)
    out = stamp_produced_at("# Title\n\n## 描述\nbody\n", dt)
    assert out.startswith("# Title\n\n**产出时间**：2026-08-16 09:17:00\n\n")
    assert "## 描述" in out


def test_stamp_prepends_when_no_h1():
    dt = datetime(2026, 8, 16, 1, 17, 0, tzinfo=timezone.utc)
    out = stamp_produced_at("## 漏洞概述\nbody\n", dt)
    assert out.startswith("**产出时间**：2026-08-16 09:17:00\n\n## 漏洞概述")


def test_stamp_replaces_existing_line():
    dt = datetime(2026, 8, 16, 1, 17, 0, tzinfo=timezone.utc)
    src = "# Title\n\n**产出时间**：2020-01-01 00:00:00\n\nbody\n"
    out = stamp_produced_at(src, dt)
    assert out.count("**产出时间**") == 1
    assert "2026-08-16 09:17:00" in out
    assert "2020-01-01" not in out
    assert "**产出时间**：2026-08-16 09:17:00\n\nbody\n" in out


def test_format_naive_utc():
    dt = datetime(2026, 8, 16, 1, 17, 0)
    assert format_produced_at(dt) == "2026-08-16 09:17:00"


def test_submit_vuln_stamps_custom_report(tmp_env, project):
    payload = {
        "title": "custom report",
        "vuln_type": "sqli",
        "cwe": "CWE-89",
        "file_path": "app/Main.java",
        "line_no": 1,
        "source_sink": "a->b",
        "auth_premise": "未授权",
        "http_request": "GET / HTTP/1.1\n",
        "poc_code": "print(1)\n",
        "expected_evidence": "ok",
        "report_md": "# custom report\n\n## 漏洞描述\nhello\n",
    }
    out = registry.dispatch(
        ToolContext(project_id=project, role="worker", phase="worker"),
        "SubmitVuln",
        payload,
    )
    assert out["ok"] is True
    report = (vuln_dir(project, out["vuln_id"]) / "report.md").read_text(encoding="utf-8")
    assert report.startswith("# custom report\n\n**产出时间**：")
    assert "## 漏洞描述" in report


def test_finish_fix_keeps_original_produced_at(tmp_env, project):
    payload = {
        "title": "needs fix",
        "vuln_type": "sqli",
        "cwe": "CWE-89",
        "file_path": "app/Main.java",
        "line_no": 1,
        "source_sink": "a->b",
        "auth_premise": "未授权",
        "http_request": "GET / HTTP/1.1\n",
        "poc_code": "print(1)\n",
        "expected_evidence": "ok",
    }
    out = registry.dispatch(
        ToolContext(project_id=project, role="worker", phase="worker"),
        "SubmitVuln",
        payload,
    )
    vuln_id = out["vuln_id"]
    models = tmp_env["models"]
    Session = tmp_env["Session"]
    with Session() as db:
        v = db.get(models.Vuln, vuln_id)
        v.status = "returned"
        created = v.created_at
        db.commit()
    registry.dispatch(
        ToolContext(project_id=project, role="fix", phase="fix", vuln_id=vuln_id),
        "FinishFix",
        {"vuln_id": vuln_id, "report_md": "# needs fix\n\nupdated\n"},
    )
    report = (vuln_dir(project, vuln_id) / "report.md").read_text(encoding="utf-8")
    from app.services.report import produced_at_line

    assert produced_at_line(created) in report
    assert "updated" in report


def test_upsert_report_section_replaces_same_heading(tmp_path):
    path = tmp_path / "report.md"
    path.write_text("# t\n\nbody\n", encoding="utf-8")
    from app.services.report import upsert_report_section

    upsert_report_section(path, "## 审核标注", "- 攻击面：前台")
    first = path.read_text(encoding="utf-8")
    assert first.count("## 审核标注") == 1
    assert "- 攻击面：前台" in first
    upsert_report_section(path, "## 审核标注", "- 攻击面：后台\n- 所需账号：管理员")
    second = path.read_text(encoding="utf-8")
    assert second.count("## 审核标注") == 1
    assert "前台" not in second
    assert "- 攻击面：后台" in second
    assert "- 所需账号：管理员" in second


def test_write_report_md_creates_parent(tmp_path):
    path = tmp_path / "nested" / "report.md"
    write_report_md(path, "# t\n\nbody\n", datetime(2026, 8, 16, 1, 17, 0, tzinfo=timezone.utc))
    text = path.read_text(encoding="utf-8")
    assert "**产出时间**：2026-08-16 09:17:00" in text

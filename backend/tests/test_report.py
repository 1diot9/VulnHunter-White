from __future__ import annotations

from datetime import datetime, timezone

from app.services.report import (
    ensure_search_fingerprint_section,
    extract_asset_queries,
    format_produced_at,
    is_placeholder_query,
    replace_search_fingerprint_section,
    stamp_produced_at,
    write_report_md,
)
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
    assert "## 互联网资产证明" in report


def test_submit_vuln_writes_search_fingerprints(tmp_env, project):
    payload = {
        "title": "fingerprint report",
        "vuln_type": "sqli",
        "cwe": "CWE-89",
        "file_path": "app/Main.java",
        "line_no": 1,
        "source_sink": "a->b",
        "auth_premise": "未授权",
        "http_request": "GET / HTTP/1.1\n",
        "poc_code": "print(1)\n",
        "expected_evidence": "ok",
        "fofa_fingerprint": 'title="Demo App" && body="/static/demo.css"',
        "x_fingerprint": 'app="Demo App" && title="Demo App"',
        "fingerprint_basis": "- 标题：Demo App\n- 静态资源：/static/demo.css",
    }
    out = registry.dispatch(
        ToolContext(project_id=project, role="worker", phase="worker"),
        "SubmitVuln",
        payload,
    )
    assert out["ok"] is True
    report = (vuln_dir(project, out["vuln_id"]) / "report.md").read_text(encoding="utf-8")
    assert "## 互联网资产证明" in report
    assert "### 精准测绘语法" in report
    assert 'title="Demo App" && body="/static/demo.css"' in report
    assert 'app="Demo App" && title="Demo App"' in report
    assert "### 指纹依据" not in report
    assert "## 应用搜索指纹" not in report
    assert report.index("## 互联网资产证明") < report.index("## 漏洞技术细节")
    assert "docs/lab.md" in report


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


def test_ensure_search_fingerprint_section_inserts_before_poc():
    text = "# t\n\n## 预期证据\nok\n\n## PoC\n见 poc.py\n"
    out = ensure_search_fingerprint_section(text, fofa='title="A"', x='app="A"', basis="- 标题：A")
    assert out.index("## 互联网资产证明") < out.index("## PoC")
    assert 'title="A"' in out
    assert 'app="A"' in out
    assert "### 指纹依据" not in out


def test_ensure_search_fingerprint_section_inserts_before_tech_details():
    text = "# t\n\n## 已知受影响产品及版本\n暂未明确\n\n## 漏洞技术细节\n-\n"
    out = ensure_search_fingerprint_section(text, fofa='title="A"', x='app="A"')
    assert out.index("## 互联网资产证明") < out.index("## 漏洞技术细节")
    assert "### 精准测绘语法" in out


def test_ensure_search_fingerprint_section_keeps_legacy_heading():
    text = "# t\n\n## 应用搜索指纹\n\n### FOFA\n```text\ntitle=\"A\"\n```\n"
    out = ensure_search_fingerprint_section(text, fofa='title="B"', x='app="B"')
    assert out == text
    assert "## 互联网资产证明" not in out


def test_replace_search_fingerprint_section_updates_middle():
    text = "# t\n\n## 已知受影响产品及版本\n暂未明确\n\n## 互联网资产证明\n\n### 精准测绘语法\n\n#### FOFA\n```text\n待运行环境确认\n```\n\n#### X 情报社区\n```text\n待根据 app 确认\n```\n\n## 漏洞技术细节\nkeep-me\n"
    out = replace_search_fingerprint_section(text, fofa='title="OA"', x='app="OA"')
    assert out.index("## 互联网资产证明") < out.index("## 漏洞技术细节")
    assert 'title="OA"' in out
    assert 'app="OA"' in out
    assert "待运行环境确认" not in out
    assert "keep-me" in out
    assert "暂未明确" in out
    fofa, x = extract_asset_queries(out)
    assert fofa == 'title="OA"'
    assert x == 'app="OA"'


def test_replace_search_fingerprint_section_upgrades_legacy_heading():
    text = "# t\n\n## 应用搜索指纹\n\n#### FOFA\n```text\ntitle=\"old\"\n```\n\n## 漏洞技术细节\n-\n"
    out = replace_search_fingerprint_section(text, fofa='title="new"', x='app="new"')
    assert "## 应用搜索指纹" not in out
    assert "## 互联网资产证明" in out
    assert 'title="new"' in out
    assert "## 漏洞技术细节" in out


def test_is_placeholder_query():
    assert is_placeholder_query("")
    assert is_placeholder_query("待运行环境确认")
    assert is_placeholder_query("待根据应用标题、稳定 body/header 特征、favicon hash 等确认")
    assert not is_placeholder_query('title="XXOA办公系统" && body="Copyright"')


def test_extract_product_hints_skips_placeholders():
    from app.services.report import extract_product_hints

    text = "# SQLI in login\n\n## 漏洞厂商全称\n暂未明确\n\n## 已知受影响产品及版本\nXXOA 办公系统\n"
    assert extract_product_hints(text) == ["XXOA 办公系统"]

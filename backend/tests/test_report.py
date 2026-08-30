from __future__ import annotations

from datetime import datetime, timezone

from app.services.report import (
    CHINESE_TITLE_ERROR,
    chinese_title_block_reason,
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

_DETAILED_CVE_DESC = """ExampleCorp WidgetApp through 1.0.0 is affected by SQL injection because app/Db.java query() concatenates the id parameter into a JDBC statement without parameterization.
Attack chain: an unauthenticated GET to /api/item (source: query parameter id) reaches the sink in Db.query() and executes attacker-controlled SQL on the default deployment.
Vulnerable code in app/Db.java:
public Result query(String id) {
    return stmt.execute("SELECT * FROM items WHERE id=" + id);
}
HTTP PoC:
GET /api/item?id=1%20OR%201=1 HTTP/1.1
Host: TARGET

Impact: a remote unauthenticated attacker can read or modify database rows. Remaining control: none on the default install.
"""

_DETAILED_CVE_HTML = (
    "<p>ExampleCorp WidgetApp through 1.0.0 is affected by SQL injection because "
    "app/Db.java query() concatenates the id parameter into a JDBC statement without parameterization.</p>"
    "<p>Attack chain: an unauthenticated GET to /api/item (source: query parameter id) "
    "reaches the sink in Db.query() and executes attacker-controlled SQL on the default deployment.</p>"
    "<p>Vulnerable code in <code>app/Db.java</code>:</p>"
    "<pre>public Result query(String id) {\n"
    "    return stmt.execute(\"SELECT * FROM items WHERE id=\" + id);\n}</pre>"
    "<pre>GET /api/item?id=1%20OR%201=1 HTTP/1.1\nHost: TARGET</pre>"
    "<p>Impact: a remote unauthenticated attacker can read or modify database rows. "
    "Remaining control: none on the default install.</p>"
)

_CHAIN_POC_NO_SOURCE_DESC = """ExampleCorp WidgetApp through 1.0.0 is affected by SQL injection because Db.java query() concatenates the id parameter into a JDBC statement without parameterization.
Attack chain: an unauthenticated GET to /api/item (source: query parameter id) reaches the sink in Db.query() and executes attacker-controlled SQL on the default deployment.
HTTP PoC:
GET /api/item?id=1%20OR%201=1 HTTP/1.1
Host: TARGET

Impact: a remote unauthenticated attacker can read or modify database rows. Remaining control: none on the default install.
"""


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


def test_chinese_title_block_reason_unit():
    assert chinese_title_block_reason("登录处 SQL 注入") is None
    assert chinese_title_block_reason("XXOA 前台 SQL Injection") is None
    assert chinese_title_block_reason("SQL Injection in login") == CHINESE_TITLE_ERROR
    assert chinese_title_block_reason("RCE") == CHINESE_TITLE_ERROR
    assert (
        chinese_title_block_reason(
            "登录处 SQL 注入",
            report_md="# SQL Injection in login\n\n## 摘要\nx\n",
        )
        == CHINESE_TITLE_ERROR
    )
    assert chinese_title_block_reason(report_md='---\ntitle: "登录注入"\n---\n\n# 登录注入\n') is None
    assert chinese_title_block_reason() is None


def test_submit_vuln_rejects_english_only_title(tmp_env, project):
    payload = {
        "title": "SQL Injection in login",
        "vuln_type": "sqli",
        "cwe": "CWE-89",
        "file_path": "app/Main.java",
        "line_no": 1,
        "source_sink": "a->b",
        "auth_premise": "未授权",
        "http_request": "GET / HTTP/1.1\n",
        "poc_code": "print(1)\n",
        "expected_evidence": "ok",
        "config_premise": "default",
    }
    out = registry.dispatch(
        ToolContext(project_id=project, role="worker", phase="worker"),
        "SubmitVuln",
        payload,
    )
    assert out["ok"] is False
    assert "中文" in out["error"]


def test_submit_vuln_rejects_english_report_h1(tmp_env, project):
    payload = {
        "title": "登录处 SQL 注入",
        "vuln_type": "sqli",
        "cwe": "CWE-89",
        "file_path": "app/Main.java",
        "line_no": 1,
        "source_sink": "a->b",
        "auth_premise": "未授权",
        "http_request": "GET / HTTP/1.1\n",
        "poc_code": "print(1)\n",
        "expected_evidence": "ok",
        "config_premise": "default",
        "report_md": "# SQL Injection in login\n\n## 摘要\nx\n",
    }
    out = registry.dispatch(
        ToolContext(project_id=project, role="worker", phase="worker"),
        "SubmitVuln",
        payload,
    )
    assert out["ok"] is False
    assert "中文" in out["error"]


def test_submit_vuln_stamps_custom_report(tmp_env, project):
    payload = {
        "title": "自定义报告",
        "vuln_type": "sqli",
        "cwe": "CWE-89",
        "file_path": "app/Main.java",
        "line_no": 1,
        "source_sink": "a->b",
        "auth_premise": "未授权",
        "http_request": "GET / HTTP/1.1\n",
        "poc_code": "print(1)\n",
        "expected_evidence": "ok",
        "config_premise": "default",
        "report_md": "# 自定义报告\n\n## 漏洞描述\nhello\n",
    }
    out = registry.dispatch(
        ToolContext(project_id=project, role="worker", phase="worker"),
        "SubmitVuln",
        payload,
    )
    assert out["ok"] is True
    report = (vuln_dir(project, out["vuln_id"]) / "report.md").read_text(encoding="utf-8")
    assert report.startswith("# 自定义报告\n\n**产出时间**：")
    assert "## 漏洞描述" in report
    assert "## 互联网资产证明" in report
    advisory = (vuln_dir(project, out["vuln_id"]) / "advisory.md").read_text(encoding="utf-8")
    assert advisory.startswith("# GitHub Security Advisory")
    assert "## Title" in advisory
    assert "### Summary" in advisory
    assert "### Vulnerable code" in advisory
    assert "**产出时间**" not in advisory


def test_submit_vuln_writes_search_fingerprints(tmp_env, project):
    payload = {
        "title": "指纹报告",
        "vuln_type": "sqli",
        "cwe": "CWE-89",
        "file_path": "app/Main.java",
        "line_no": 1,
        "source_sink": "a->b",
        "auth_premise": "未授权",
        "http_request": "GET / HTTP/1.1\n",
        "poc_code": "print(1)\n",
        "expected_evidence": "ok",
        "config_premise": "default",
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
        "title": "待修复",
        "vuln_type": "sqli",
        "cwe": "CWE-89",
        "file_path": "app/Main.java",
        "line_no": 1,
        "source_sink": "a->b",
        "auth_premise": "未授权",
        "http_request": "GET / HTTP/1.1\n",
        "poc_code": "print(1)\n",
        "expected_evidence": "ok",
        "config_premise": "default",
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
        {"vuln_id": vuln_id, "report_md": "# 待修复\n\nupdated\n"},
    )
    report = (vuln_dir(project, vuln_id) / "report.md").read_text(encoding="utf-8")
    from app.services.report import produced_at_line

    assert produced_at_line(created) in report
    assert "updated" in report


def test_submit_and_confirm_write_custom_advisory(tmp_env, project):
    payload = {
        "title": "预算绕过",
        "vuln_type": "idor",
        "cwe": "CWE-863",
        "file_path": "app/Keys.java",
        "line_no": 12,
        "source_sink": "update -> budget",
        "auth_premise": "internal_user",
        "http_request": "POST /key/update HTTP/1.1\n",
        "poc_code": "print(1)\n",
        "expected_evidence": "200",
        "config_premise": "default",
        "advisory_md": "# GitHub Security Advisory\n\n## Title\n\n```\ncustom advisory title\n```\n",
    }
    out = registry.dispatch(
        ToolContext(project_id=project, role="worker", phase="worker"),
        "SubmitVuln",
        payload,
    )
    assert out["ok"] is True
    path = vuln_dir(project, out["vuln_id"]) / "advisory.md"
    assert "custom advisory title" in path.read_text(encoding="utf-8")
    confirmed = registry.dispatch(
        ToolContext(project_id=project, role="reviewer", phase="reviewer", vuln_id=out["vuln_id"]),
        "ConfirmVuln",
        {
            "vuln_id": out["vuln_id"],
            "attack_surface": "frontend",
            "evidence_level": "static_only",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "submission_tier": "cve_candidate",
            "submission_reason": "has cve value",
            "advisory_md": "# GitHub Security Advisory\n\n## Title\n\n```\nreviewed title\n```\n",
        },
    )
    assert confirmed["ok"] is True
    assert "reviewed title" in path.read_text(encoding="utf-8")


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


def test_write_advisory_md_no_produced_at(tmp_path):
    from app.services.report import write_advisory_md

    path = tmp_path / "advisory.md"
    write_advisory_md(path, "# GitHub Security Advisory\n\n## Title\n")
    text = path.read_text(encoding="utf-8")
    assert text == "# GitHub Security Advisory\n\n## Title\n"
    assert "**产出时间**" not in text


def test_default_advisory_md_includes_cvss_fields():
    from app.services.report import default_advisory_md

    text = default_advisory_md({"title": "demo", "cwe": "CWE-89", "file_path": "app/Db.java"})
    assert "**CVSS 3.1:**" in text
    assert "### Vulnerable code" in text
    assert "app/Db.java" in text


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


def test_missing_report_headings_bypass_requires_patch_section():
    from app.services.report import missing_report_headings

    minimal = "\n".join(
        [
            "## 摘要",
            "## 漏洞描述",
            "## 漏洞危害",
            "## 漏洞厂商全称",
            "## 已知受影响产品及版本",
            "## 互联网资产证明",
            "## 漏洞技术细节",
            "### Source → Sink",
            "## 同根因受影响点",
            "## 复现证明",
            "## 修复方案",
            "## 备注",
        ]
    )
    assert missing_report_headings(minimal, bypass=False) == []
    assert "### 补丁绕过简析" in missing_report_headings(minimal, bypass=True)
    with_patch = minimal.replace(
        "## 漏洞技术细节",
        "## 漏洞技术细节\n\n### 补丁绕过简析\nok",
        1,
    )
    assert missing_report_headings(with_patch, bypass=True) == []


def test_harness_vuln_code_gap_unit():
    from app.services.report import harness_vuln_code_gap

    assert "漏洞代码" in (harness_vuln_code_gap("# t\n") or "")
    good = (
        "## 漏洞技术细节\n\n### 漏洞代码\n\n"
        "- 完整路径：`src/app/Db.java:3`\n\n"
        "```java\nreturn jdbc.query(sql);\n```\n\n### 完整 PoC 描述\nx\n"
    )
    assert harness_vuln_code_gap(good, file_path="app/Db.java") is None


def test_cve_record_initialize_and_fill(tmp_env, project):
    import json

    from app.services.cve_record import (
        CVE_FIELD_PLACEHOLDER,
        cve_record_path,
        cve_record_status,
        read_cve_record,
        set_cve_field,
    )
    from app.tools import ToolContext, registry

    payload = {
        "title": "SQL 注入演示",
        "vuln_type": "sqli",
        "cwe": "CWE-89",
        "file_path": "app/Db.java",
        "line_no": 3,
        "source_sink": "id -> query",
        "auth_premise": "none",
        "http_request": "GET /x HTTP/1.1\n",
        "poc_code": "print(1)\n",
        "expected_evidence": "500",
        "config_premise": "default",
        "report_md": "# SQL 注入演示\n\n## 摘要\nx\n## 漏洞描述\nx\n## 漏洞危害\nx\n## 漏洞厂商全称\nx\n## 已知受影响产品及版本\nx\n## 互联网资产证明\nx\n## 漏洞技术细节\nx\n## 同根因受影响点\nx\n## 复现证明\nx\n## 修复方案\nx\n## 备注\nx\n",
    }
    out = registry.dispatch(
        ToolContext(project_id=project, role="worker", phase="worker"),
        "SubmitVuln",
        payload,
    )
    assert out["ok"] is True
    vid = out["vuln_id"]
    path = cve_record_path(project, vid)
    assert path.is_file()
    record = read_cve_record(project, vid)
    assert record is not None
    assert record["cveMetadata"]["cveId"] == CVE_FIELD_PLACEHOLDER
    status = cve_record_status(project, vid)
    assert status["all_required_filled"] is False
    assert status["required_pending"]

    read_out = registry.dispatch(
        ToolContext(project_id=project, role="reviewer", phase="reviewer", vuln_id=vid),
        "ReadCveRecord",
        {},
    )
    assert read_out["ok"] is True
    assert read_out["placeholder"] == CVE_FIELD_PLACEHOLDER
    assert any(f["needs_fill"] for f in read_out["fields"])
    assert "英文详述" in read_out["message"]

    thin = registry.dispatch(
        ToolContext(project_id=project, role="reviewer", phase="reviewer", vuln_id=vid),
        "SetCveRecordField",
        {
            "path": "containers.cna.descriptions[0].value",
            "value": "Example product is affected by SQL injection.",
        },
    )
    assert thin["ok"] is True
    assert thin["needs_fill"] is True
    assert thin["quality_issues"]

    set_out = registry.dispatch(
        ToolContext(project_id=project, role="reviewer", phase="reviewer", vuln_id=vid),
        "SetCveRecordField",
        {
            "path": "containers.cna.descriptions[0].value",
            "value": _DETAILED_CVE_DESC,
        },
    )
    assert set_out["ok"] is True
    assert set_out["needs_fill"] is False
    assert "SQL injection" in json.loads(path.read_text(encoding="utf-8"))["containers"]["cna"]["descriptions"][0]["value"]

    set_cve_field(
        project,
        vid,
        "containers.cna.problemTypes[0].descriptions[0].description",
        "SQL Injection",
    )
    set_cve_field(project, vid, "containers.cna.affected[0].versions[0].version", "<=1.0.0")
    set_cve_field(project, vid, "containers.cna.affected[0].vendor", "ExampleCorp")
    set_cve_field(project, vid, "containers.cna.affected[0].product", "WidgetApp")
    set_cve_field(
        project,
        vid,
        "containers.cna.descriptions[0].supportingMedia[0].value",
        _DETAILED_CVE_HTML,
    )
    set_cve_field(project, vid, "containers.cna.references[0].url", "https://example.com/advisory")
    status = cve_record_status(project, vid)
    assert status["all_required_filled"] is True

    bad = registry.dispatch(
        ToolContext(project_id=project, role="reviewer", phase="reviewer", vuln_id=vid),
        "SetCveRecordField",
        {"path": "dataType", "value": "HACKED"},
    )
    assert bad["ok"] is False


def test_set_cve_record_field_cvss_vector_computes_score(tmp_env, project):
    import json

    from app.services.cve_record import cve_record_path
    from app.tools import ToolContext, registry

    out = registry.dispatch(
        ToolContext(project_id=project, role="worker", phase="worker"),
        "SubmitVuln",
        {
            "title": "SQL 注入演示",
            "vuln_type": "sqli",
            "cwe": "CWE-89",
            "file_path": "app/Db.java",
            "line_no": 3,
            "source_sink": "id -> query",
            "auth_premise": "none",
            "http_request": "GET /x HTTP/1.1\n",
            "poc_code": "print(1)\n",
            "expected_evidence": "500",
            "config_premise": "default",
        },
    )
    vid = out["vuln_id"]
    ctx = ToolContext(project_id=project, role="reviewer", phase="reviewer", vuln_id=vid)
    vector_path = "containers.cna.metrics[0].cvssV3_1.vectorString"

    score_write = registry.dispatch(
        ctx,
        "SetCveRecordField",
        {"path": "containers.cna.metrics[0].cvssV3_1.baseScore", "value": 9.8},
    )
    assert score_write["ok"] is False
    assert "不要手填" in score_write["error"]

    v30 = registry.dispatch(
        ctx,
        "SetCveRecordField",
        {
            "path": "containers.cna.metrics[0].cvssV3_0.vectorString",
            "value": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        },
    )
    assert v30["ok"] is False
    assert "CVSS 3.1" in v30["error"]

    invalid = registry.dispatch(
        ctx,
        "SetCveRecordField",
        {"path": vector_path, "value": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H"},
    )
    assert invalid["ok"] is False
    assert "缺少必填度量" in invalid["error"]
    assert "A（" in invalid["error"]

    ok = registry.dispatch(
        ctx,
        "SetCveRecordField",
        {
            "path": vector_path,
            "value": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        },
    )
    assert ok["ok"] is True
    assert ok["severity_score"] == 7.5
    assert ok["cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    metric = json.loads(cve_record_path(project, vid).read_text(encoding="utf-8"))[
        "containers"
    ]["cna"]["metrics"][0]["cvssV3_1"]
    assert metric["baseScore"] == 7.5
    assert metric["baseSeverity"] == "HIGH"
    assert metric["vectorString"] == ok["cvss_vector"]


def test_cve_record_initialize_standalone(tmp_env, project):
    from app.services.cve_record import CVE_FIELD_PLACEHOLDER, initialize_cve_record

    record = initialize_cve_record(project, 999)
    assert record["containers"]["cna"]["descriptions"][0]["value"] == CVE_FIELD_PLACEHOLDER


def test_cve_description_detail_issues():
    from app.services.cve_record import description_detail_issues

    assert description_detail_issues("Example product is affected by SQL injection.")
    assert not description_detail_issues(_DETAILED_CVE_DESC)
    html_plain = description_detail_issues(_DETAILED_CVE_DESC, html=True)
    assert any("pre" in item for item in html_plain)
    assert not description_detail_issues(_DETAILED_CVE_HTML, html=True)

    missing_code = description_detail_issues(_CHAIN_POC_NO_SOURCE_DESC)
    assert any("路径" in item or "源码" in item for item in missing_code)

    html_http_only = (
        "<p>ExampleCorp WidgetApp through 1.0.0 is affected by SQL injection because "
        "app/Db.java query() concatenates the id parameter into a JDBC statement without parameterization.</p>"
        "<p>Attack chain: an unauthenticated GET to /api/item (source: query parameter id) "
        "reaches the sink in Db.query() and executes attacker-controlled SQL on the default deployment.</p>"
        "<p>Vulnerable code is in app/Db.java query() which concatenates id into SQL.</p>"
        "<pre>GET /api/item?id=1%20OR%201=1 HTTP/1.1\nHost: TARGET</pre>"
        "<p>Impact: a remote unauthenticated attacker can read or modify database rows. "
        "Remaining control: none on the default install.</p>"
    )
    html_missing = description_detail_issues(html_http_only, html=True)
    assert any("源码" in item or "pre" in item for item in html_missing)

    lib_desc = """ExampleCorp WidgetLib through 2.1.0 is affected by path traversal because src/parser/Parser.java parse() concatenates the caller-supplied name into a filesystem path.
Attack chain: a public API call Parser.parse(name) (source: name argument) reaches the sink FileInputStream without normalizing against the intended base directory.
Vulnerable code in src/parser/Parser.java:
public InputStream parse(String name) {
    return new FileInputStream(baseDir + name);
}
PoC via public API / harness: invoke Parser.parse("../secrets/key.pem") from a trusted caller on a default install.
Impact: a local caller can read files outside the intended directory. Remaining control: none if the library is used as documented.
"""
    assert not description_detail_issues(lib_desc)


def test_fit_cve_value_truncates_plain_description():
    from app.services.cve_record import CVE_VALUE_MAX_LEN, fit_cve_value

    long_text = "A" * (CVE_VALUE_MAX_LEN + 500)
    fitted, truncated = fit_cve_value(long_text)
    assert truncated is True
    assert len(fitted) <= CVE_VALUE_MAX_LEN


def test_parse_advisory_affected_table_and_free_text():
    from app.services.cve_record import parse_advisory_affected

    table = """## Affected products

| Field | Value |
| --- | --- |
| Ecosystem | `pip` |
| Package name | memoboard |
| Affected versions | 0.5.0 |
"""
    parsed = parse_advisory_affected(table)
    assert parsed["packageName"] == "memoboard"
    assert parsed["collectionURL"] == "https://pypi.python.org"
    assert parsed["version"] == "0.5.0"

    free = "## Affected products\n\nLibreNMS latest version (as of August 2026)\n"
    parsed_free = parse_advisory_affected(free)
    assert parsed_free["vendor"] == "LibreNMS"
    assert parsed_free["product"] == "LibreNMS"


def test_set_cve_record_field_truncates_long_plain_description(tmp_env, project):
    import json

    from app.services.cve_record import CVE_VALUE_MAX_LEN, cve_record_path, set_cve_field

    from app.tools import ToolContext, registry

    out = registry.dispatch(
        ToolContext(project_id=project, role="worker", phase="worker"),
        "SubmitVuln",
        {
            "title": "SQL 注入演示",
            "vuln_type": "sqli",
            "cwe": "CWE-89",
            "file_path": "app/Db.java",
            "line_no": 3,
            "source_sink": "id -> query",
            "auth_premise": "none",
            "http_request": "GET /x HTTP/1.1\n",
            "poc_code": "print(1)\n",
            "expected_evidence": "500",
            "config_premise": "default",
        },
    )
    vid = out["vuln_id"]
    long_desc = ("ExampleCorp WidgetApp through 1.0.0 is affected by SQL injection because "
                 "app/Db.java query() concatenates the id parameter. Attack chain: GET /api/item. "
                 "Vulnerable code in app/Db.java:\npublic Result query(String id) { return stmt.execute(\"SELECT * FROM items WHERE id=\" + id); }\n"
                 "HTTP PoC:\nGET /api/item?id=1 HTTP/1.1\nHost: TARGET\n"
                 "Impact: remote SQL injection.\n") + ("X" * (CVE_VALUE_MAX_LEN + 200))
    result = set_cve_field(
        project,
        vid,
        "containers.cna.descriptions[0].value",
        long_desc,
    )
    assert result["ok"] is True
    assert "截断" in (result.get("message") or "")
    stored = json.loads(cve_record_path(project, vid).read_text(encoding="utf-8"))
    assert len(stored["containers"]["cna"]["descriptions"][0]["value"]) <= CVE_VALUE_MAX_LEN


def test_initialize_cve_record_seeds_affected_from_advisory(tmp_env, project):
    from app.services.cve_record import affected_identity_ok, initialize_cve_record
    from app.services.paths import vuln_dir
    from app.services.report import write_advisory_md

    vid = 999
    vdir = vuln_dir(project, vid)
    write_advisory_md(
        vdir / "advisory.md",
        (
            "## Title\nDemo\n\n## Affected products\n\n"
            "| Field | Value |\n| --- | --- |\n| Ecosystem | `npm` |\n"
            "| Package name | demo-lib |\n| Affected versions | <=1.0.0 |\n"
        ),
    )
    record = initialize_cve_record(project, vid)
    assert affected_identity_ok(record)
    affected = record["containers"]["cna"]["affected"][0]
    assert affected["packageName"] == "demo-lib"
    assert affected["collectionURL"] == "https://registry.npmjs.org"
    assert affected["versions"][0]["version"] == "<=1.0.0"

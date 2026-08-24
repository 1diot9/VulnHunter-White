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

_DETAILED_CVE_DESC = """ExampleCorp WidgetApp through 1.0.0 is affected by SQL injection because Db.java query() concatenates the id parameter into a JDBC statement without parameterization.
Attack chain: an unauthenticated GET to /api/item (source: query parameter id) reaches the sink in Db.query() and executes attacker-controlled SQL on the default deployment.
HTTP PoC:
GET /api/item?id=1%20OR%201=1 HTTP/1.1
Host: TARGET

Impact: a remote unauthenticated attacker can read or modify database rows. Remaining control: none on the default install.
"""

_DETAILED_CVE_HTML = (
    "<p>ExampleCorp WidgetApp through 1.0.0 is affected by SQL injection because "
    "Db.java query() concatenates the id parameter into a JDBC statement without parameterization.</p>"
    "<p>Attack chain: an unauthenticated GET to /api/item (source: query parameter id) "
    "reaches the sink in Db.query() and executes attacker-controlled SQL on the default deployment.</p>"
    "<pre>GET /api/item?id=1%20OR%201=1 HTTP/1.1\nHost: TARGET</pre>"
    "<p>Impact: a remote unauthenticated attacker can read or modify database rows. "
    "Remaining control: none on the default install.</p>"
)


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
        "config_premise": "default",
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
    advisory = (vuln_dir(project, out["vuln_id"]) / "advisory.md").read_text(encoding="utf-8")
    assert advisory.startswith("# GitHub Security Advisory")
    assert "## Title" in advisory
    assert "### Summary" in advisory
    assert "**产出时间**" not in advisory


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
        {"vuln_id": vuln_id, "report_md": "# needs fix\n\nupdated\n"},
    )
    report = (vuln_dir(project, vuln_id) / "report.md").read_text(encoding="utf-8")
    from app.services.report import produced_at_line

    assert produced_at_line(created) in report
    assert "updated" in report


def test_submit_and_confirm_write_custom_advisory(tmp_env, project):
    payload = {
        "title": "budget bypass",
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
            "impact": "sensitive_data_or_privilege",
            "exploit_complexity": "single_request",
            "defense_status": "none",
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

    text = default_advisory_md({"title": "demo", "cwe": "CWE-89"})
    assert "**CVSS 3.1:**" in text
    assert "**CVSS 4.0:**" in text


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
        "title": "sqli demo",
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
        "report_md": "# sqli\n\n## 摘要\nx\n## 漏洞描述\nx\n## 漏洞危害\nx\n## 漏洞厂商全称\nx\n## 已知受影响产品及版本\nx\n## 互联网资产证明\nx\n## 漏洞技术细节\nx\n## 同根因受影响点\nx\n## 复现证明\nx\n## 修复方案\nx\n## 备注\nx\n",
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

    lib_desc = """ExampleCorp WidgetLib through 2.1.0 is affected by path traversal because Parser.parse() concatenates the caller-supplied name into a filesystem path.
Attack chain: a public API call Parser.parse(name) (source: name argument) reaches the sink FileInputStream without normalizing against the intended base directory.
PoC via public API / harness: invoke Parser.parse("../secrets/key.pem") from a trusted caller on a default install.
Impact: a local caller can read files outside the intended directory. Remaining control: none if the library is used as documented.
"""
    assert not description_detail_issues(lib_desc)

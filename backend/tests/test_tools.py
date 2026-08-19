from __future__ import annotations

import json
import os
import time

from app.services.ingest import build_file_index
from app.services.paths import docs_dir, old_vulns_dir, src_dir, vuln_dir, workspace_dir
from app.tools import ROLE_ACL, SHELL_TOOLS, ToolContext, ToolSpec, native_shell_tool, registry
from app.tools.common import todo_relpath


def _ctx(project_id: int, role: str, **kwargs) -> ToolContext:
    return ToolContext(project_id=project_id, role=role, phase=role, **kwargs)


SEVERITY_FACTORS = {
    "impact": "sensitive_data_or_privilege",
    "exploit_complexity": "single_request",
    "defense_status": "none",
    "submission_tier": "cve_candidate",
    "submission_reason": "未认证可达且可造成敏感数据/权限影响，有 CVE 价值",
}


def _set_audit_mode(project_id: int, mode: str) -> None:
    from app.models import Project, SessionLocal

    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        assert proj is not None
        proj.audit_mode = mode
        db.commit()


def test_acl_blocks_worker_from_mark_weight(tmp_env, project):
    build_file_index(project)
    out = registry.dispatch(_ctx(project, "worker"), "MarkWeight", {"path": "app/Main.java", "weight": 10})
    assert out["ok"] is False
    assert "无权" in out["error"]


def test_mark_source_sets_weight_100(tmp_env, project):
    build_file_index(project)
    out = registry.dispatch(
        _ctx(project, "recon"),
        "MarkSource",
        {"file": "app/Main.java", "method": "login"},
    )
    assert out["ok"] is True
    models = tmp_env["models"]
    Session = tmp_env["Session"]
    with Session() as db:
        fw = (
            db.query(models.FileWeight)
            .filter(models.FileWeight.project_id == project, models.FileWeight.path == "app/Main.java")
            .first()
        )
        assert fw is not None
        assert fw.weight == 100
        assert fw.has_source is True
        srcs = db.query(models.Source).filter(models.Source.project_id == project).all()
        assert any(s.method_name == "login" for s in srcs)


def test_recon_gates_requires_docs_and_weights(tmp_env, project):
    from app.tools.phase_recon import (
        apply_recon_done,
        recon_docs_ready,
        recon_gates_met,
        recon_gates_status,
        recon_old_vulns_ready,
    )

    build_file_index(project)
    status = recon_gates_status(project)
    assert status["ok"] is False
    assert status["errors"]

    docs = docs_dir(project)
    (docs / "code-map.md").write_text("# map\n", encoding="utf-8")
    (docs / "auth.md").write_text("# auth\n", encoding="utf-8")
    old = old_vulns_dir(project)
    old.mkdir(parents=True, exist_ok=True)
    (old / "index.md").write_text("# index\n", encoding="utf-8")
    assert recon_docs_ready(project) is False
    assert recon_old_vulns_ready(project) is False
    status = recon_gates_status(project)
    assert any("爬虫落盘尚未结束" in e for e in status["errors"])
    by_id = {s["id"]: s["done"] for s in status["subphases"]}
    assert by_id["old_vulns"] is False
    assert by_id["source_ext"] is False
    (old / "index.md").write_text(
        "---\ntitle: 历史漏洞索引\nsummary: test\ncomplete: true\n---\n\n# index\n",
        encoding="utf-8",
    )
    assert recon_docs_ready(project) is True
    assert recon_old_vulns_ready(project) is True
    assert [s["id"] for s in recon_gates_status(project)["subphases"]] == [
        "map",
        "source_ext",
        "old_vulns",
        "mark",
    ]
    assert [s["done"] for s in recon_gates_status(project)["subphases"]] == [True, False, True, False]

    models = tmp_env["models"]
    Session = tmp_env["Session"]
    with Session() as db:
        for fw in db.query(models.FileWeight).filter(models.FileWeight.project_id == project).all():
            if fw.weight is None and not fw.skipped:
                registry.dispatch(
                    _ctx(project, "recon_mark"),
                    "MarkWeight",
                    {"path": fw.path, "weight": 50},
                )

    assert recon_gates_met(project) is False
    none = registry.dispatch(_ctx(project, "recon_source_ext"), "AddSourceExt", {"none": True})
    assert none["ok"] is True
    assert recon_gates_met(project) is True
    assert apply_recon_done(project) is True
    with Session() as db:
        p = db.get(models.Project, project)
        assert p.recon_done is True


def test_submit_vuln_requires_fields(tmp_env, project):
    out = registry.dispatch(_ctx(project, "worker"), "SubmitVuln", {"title": "x"})
    assert out["ok"] is False
    assert "缺少必填" in out["error"]


def test_submit_vuln_rejects_hardcoded_http_poc(tmp_env, project):
    out = registry.dispatch(
        _ctx(project, "worker"),
        "SubmitVuln",
        {
            "title": "RCE",
            "vuln_type": "rce",
            "cwe": "CWE-78",
            "file_path": "app/Main.java",
            "line_no": 1,
            "source_sink": "q -> exec",
            "auth_premise": "未授权",
            "http_request": "GET /x HTTP/1.1\nHost: x\n",
            "poc_code": "import requests\nprint(requests.get('http://127.0.0.1:18080/x').text)\n",
            "expected_evidence": "id",
        },
    )
    assert out["ok"] is False
    assert "-u/--url" in out["error"]


def test_confirm_vuln_can_rewrite_parameterized_poc(tmp_env, project):
    from app.services.poc_script import read_poc_code
    from app.services.paths import vuln_dir

    payload = {
        "title": "RCE in ping",
        "vuln_type": "rce",
        "cwe": "CWE-78",
        "file_path": "app/Main.java",
        "line_no": 1,
        "source_sink": "ping -> exec",
        "auth_premise": "未授权",
        "http_request": "GET /ping?cmd=id HTTP/1.1\nHost: x\n",
        "poc_code": "print('poc')\n",
        "expected_evidence": "uid=",
    }
    out = registry.dispatch(_ctx(project, "worker"), "SubmitVuln", payload)
    assert out["ok"] is True
    vuln_id = out["vuln_id"]
    rewritten = (
        "import argparse\n"
        "p = argparse.ArgumentParser()\n"
        "p.add_argument('-u', '--url', required=True)\n"
        "p.add_argument('-c', '--cmd', default='id')\n"
        "print(p.parse_args())\n"
    )
    conf = registry.dispatch(
        _ctx(project, "reviewer"),
        "ConfirmVuln",
        {
            "vuln_id": vuln_id,
            "evidence_level": "static_only",
            "attack_surface": "frontend",
            "poc_code": rewritten,
            **SEVERITY_FACTORS,
        },
    )
    assert conf["ok"] is True
    models = tmp_env["models"]
    Session = tmp_env["Session"]
    with Session() as db:
        row = db.get(models.Vuln, vuln_id)
        assert row.poc_code == rewritten
    assert "--cmd" in (vuln_dir(project, vuln_id) / "poc.py").read_text(encoding="utf-8")
    assert "--cmd" in (read_poc_code(project, vuln_id) or "")


def test_submit_and_confirm_flow(tmp_env, project):
    payload = {
        "title": "SQLI in login",
        "vuln_type": "sqli",
        "cwe": "CWE-89",
        "file_path": "app/Main.java",
        "line_no": 1,
        "source_sink": "login -> query",
        "auth_premise": "未授权",
        "http_request": "GET /login?id=1 HTTP/1.1\nHost: x\n",
        "poc_code": "print('poc')\n",
        "expected_evidence": "error based",
        "intended_behavior": False,
    }
    out = registry.dispatch(_ctx(project, "worker"), "SubmitVuln", payload)
    assert out["ok"] is True
    vuln_id = out["vuln_id"]
    models = tmp_env["models"]
    Session = tmp_env["Session"]
    with Session() as db:
        submitted = db.get(models.Vuln, vuln_id)
        assert submitted.severity == "pending"

    conf = registry.dispatch(
        _ctx(project, "reviewer"),
        "ConfirmVuln",
        {
            "vuln_id": vuln_id,
            "evidence_level": "static_only",
            "attack_surface": "frontend",
            **SEVERITY_FACTORS,
        },
    )
    assert conf["ok"] is True
    assert conf["status"] == "static_only"
    assert conf["attack_surface"] == "frontend"
    assert conf["attack_surface_label"] == "前台"
    assert conf["required_account"] is None
    assert conf["severity"] == "high"
    assert conf["severity_score"] == 3
    assert conf["submission_tier"] == "cve_candidate"
    assert conf["submission_tier_label"] == "有 CVE 价值"
    assert "CVE" in conf["submission_reason"]

    models = tmp_env["models"]
    Session = tmp_env["Session"]
    with Session() as db:
        v = db.get(models.Vuln, vuln_id)
        assert v.status == "static_only"
        assert v.evidence_level == "static_only"
        assert v.attack_surface == "frontend"
        assert v.required_account is None
        assert v.severity == "high"
        assert v.severity_score == 3
        assert v.submission_tier == "cve_candidate"
        assert v.submission_reason
    report = (vuln_dir(project, vuln_id) / "report.md").read_text(encoding="utf-8")
    assert "**产出时间**：" in report
    assert report.index("**产出时间**：") < report.index("## 摘要")
    assert "## 漏洞描述" in report
    assert "## 互联网资产证明" in report
    assert "### 触发条件" in report
    assert "docs/lab.md" in report
    assert "## 审核标注" in report
    assert "- 攻击面：前台" in report
    assert "- 严重度：高危（high）" in report
    assert "- 校准得分：3" in report
    assert "- 价值分层：有 CVE 价值（cve_candidate）" in report
    assert "- 分层理由：" in report
    assert "原始类型映射" not in report
    assert "所需账号" not in report


def test_confirm_requires_attack_surface(tmp_env, project):
    payload = {
        "title": "SQLI in login",
        "vuln_type": "sqli",
        "cwe": "CWE-89",
        "file_path": "app/Main.java",
        "line_no": 1,
        "source_sink": "login -> query",
        "auth_premise": "未授权",
        "http_request": "GET /login?id=1 HTTP/1.1\nHost: x\n",
        "poc_code": "print('poc')\n",
        "expected_evidence": "error based",
    }
    out = registry.dispatch(_ctx(project, "worker"), "SubmitVuln", payload)
    vuln_id = out["vuln_id"]
    ctx = _ctx(project, "reviewer")
    conf = registry.dispatch(ctx, "ConfirmVuln", {"vuln_id": vuln_id})
    assert conf["ok"] is False
    assert "attack_surface" in conf["error"]
    assert ctx.state.get("review_done") is not True
    models = tmp_env["models"]
    Session = tmp_env["Session"]
    with Session() as db:
        v = db.get(models.Vuln, vuln_id)
        assert v.status == "pending_review"
        assert v.attack_surface is None


def test_confirm_requires_severity_factors(tmp_env, project):
    payload = {
        "title": "SSRF",
        "vuln_type": "ssrf",
        "cwe": "CWE-918",
        "file_path": "app/Main.java",
        "line_no": 1,
        "source_sink": "url -> requests.get",
        "auth_premise": "未授权",
        "http_request": "GET /fetch?url=http://127.0.0.1 HTTP/1.1\n",
        "poc_code": "print(1)\n",
        "expected_evidence": "internal response",
    }
    out = registry.dispatch(_ctx(project, "worker"), "SubmitVuln", payload)
    vuln_id = out["vuln_id"]
    conf = registry.dispatch(
        _ctx(project, "reviewer"),
        "ConfirmVuln",
        {"vuln_id": vuln_id, "attack_surface": "frontend"},
    )
    assert conf["ok"] is False
    assert "impact" in conf["error"]


def test_confirm_requires_submission_tier(tmp_env, project):
    payload = {
        "title": "SSRF",
        "vuln_type": "ssrf",
        "cwe": "CWE-918",
        "file_path": "app/Main.java",
        "line_no": 1,
        "source_sink": "url -> requests.get",
        "auth_premise": "未授权",
        "http_request": "GET /fetch?url=http://127.0.0.1 HTTP/1.1\n",
        "poc_code": "print(1)\n",
        "expected_evidence": "internal response",
    }
    out = registry.dispatch(_ctx(project, "worker"), "SubmitVuln", payload)
    vuln_id = out["vuln_id"]
    conf = registry.dispatch(
        _ctx(project, "reviewer"),
        "ConfirmVuln",
        {
            "vuln_id": vuln_id,
            "attack_surface": "frontend",
            "impact": "sensitive_data_or_privilege",
            "exploit_complexity": "single_request",
            "defense_status": "none",
        },
    )
    assert conf["ok"] is False
    assert "submission_tier" in conf["error"]


def test_confirm_rejects_needs_more_evidence_tier(tmp_env, project):
    payload = {
        "title": "SQLi",
        "vuln_type": "sqli",
        "cwe": "CWE-89",
        "file_path": "app/Main.java",
        "line_no": 1,
        "source_sink": "login -> query",
        "auth_premise": "未授权",
        "http_request": "GET /login?id=1 HTTP/1.1\nHost: x\n",
        "poc_code": "print('poc')\n",
        "expected_evidence": "error based",
    }
    out = registry.dispatch(_ctx(project, "worker"), "SubmitVuln", payload)
    conf = registry.dispatch(
        _ctx(project, "reviewer"),
        "ConfirmVuln",
        {
            "vuln_id": out["vuln_id"],
            "evidence_level": "static_only",
            "attack_surface": "frontend",
            "impact": "rce_or_full_data",
            "exploit_complexity": "single_request",
            "defense_status": "none",
            "submission_tier": "证据不足",
            "submission_reason": "环境没打出来",
        },
    )
    assert conf["ok"] is False
    assert "submission_tier" in conf["error"]


def test_confirm_low_impact_and_duplicate_tiers(tmp_env, project):
    _set_audit_mode(project, "full")
    worker = _ctx(project, "worker")
    payload = {
        "title": "CORS",
        "vuln_type": "other",
        "cwe": "CWE-942",
        "file_path": "app/Main.java",
        "line_no": 1,
        "source_sink": "Origin -> ACAO",
        "auth_premise": "未授权",
        "http_request": "GET / HTTP/1.1\n",
        "poc_code": "print(1)\n",
        "expected_evidence": "reflected origin",
    }
    out = registry.dispatch(worker, "SubmitVuln", payload)
    vuln_id = out["vuln_id"]
    hard = registry.dispatch(
        _ctx(project, "reviewer"),
        "ConfirmVuln",
        {
            "vuln_id": vuln_id,
            "attack_surface": "frontend",
            "impact": "limited_info",
            "exploit_complexity": "single_request",
            "defense_status": "none",
            "submission_tier": "低危害难利用",
            "submission_reason": "CORS 配置问题，默认按低危害难利用处理",
        },
    )
    assert hard["ok"] is True
    assert hard["submission_tier"] == "low_impact"

    payload2 = dict(payload)
    payload2["title"] = "CORS again"
    warn2 = registry.dispatch(worker, "SubmitVuln", payload2)
    assert warn2.get("duplicate_soft_gate") is True
    out2 = registry.dispatch(worker, "SubmitVuln", {**payload2, "confirm_not_duplicate": True})
    assert out2["ok"] is True

    reviewer2 = _ctx(project, "reviewer", vuln_id=out2["vuln_id"])
    dup = registry.dispatch(
        reviewer2,
        "ConfirmVuln",
        {
            "vuln_id": out2["vuln_id"],
            "attack_surface": "frontend",
            "impact": "limited_info",
            "exploit_complexity": "single_request",
            "defense_status": "none",
            "submission_tier": "duplicate_grouped",
            "submission_reason": "与已确认 CORS 同根因",
        },
    )
    assert dup["ok"] is False
    assert "root_cause_key" in dup["error"]

    # Soft-gate first (sibling #vuln_id), then ack with correct root key.
    soft = registry.dispatch(
        reviewer2,
        "ConfirmVuln",
        {
            "vuln_id": out2["vuln_id"],
            "attack_surface": "frontend",
            "impact": "limited_info",
            "exploit_complexity": "single_request",
            "defense_status": "none",
            "submission_tier": "duplicate_grouped",
            "submission_reason": "与已确认 CORS 同根因",
            "root_cause_key": "cors:JwtFilter",
        },
    )
    assert soft.get("duplicate_soft_gate") is True
    dup_ok = registry.dispatch(
        reviewer2,
        "ConfirmVuln",
        {
            "vuln_id": out2["vuln_id"],
            "attack_surface": "frontend",
            "impact": "limited_info",
            "exploit_complexity": "single_request",
            "defense_status": "none",
            "submission_tier": "duplicate_grouped",
            "submission_reason": "与已确认 CORS 同根因",
            "root_cause_key": "cors:JwtFilter",
            "confirm_not_duplicate": True,
        },
    )
    assert dup_ok["ok"] is True
    assert dup_ok["submission_tier"] == "duplicate_grouped"
    assert dup_ok["root_cause_key"] == "cors:JwtFilter"
    report = (vuln_dir(project, out2["vuln_id"]) / "report.md").read_text(encoding="utf-8")
    assert "- 根因合并键：cors:JwtFilter" in report
    models = tmp_env["models"]
    Session = tmp_env["Session"]
    with Session() as db:
        parent = db.get(models.Vuln, vuln_id)
        assert parent is not None
        assert parent.root_cause_key == "cors:JwtFilter"

    payload3 = dict(payload)
    payload3["title"] = "CORS third"
    warn3 = registry.dispatch(worker, "SubmitVuln", payload3)
    assert warn3.get("duplicate_soft_gate") is True
    out3 = registry.dispatch(worker, "SubmitVuln", {**payload3, "confirm_not_duplicate": True})
    assert out3["ok"] is True
    reviewer3 = _ctx(project, "reviewer", vuln_id=out3["vuln_id"])
    soft3 = registry.dispatch(
        reviewer3,
        "ConfirmVuln",
        {
            "vuln_id": out3["vuln_id"],
            "attack_surface": "frontend",
            "impact": "limited_info",
            "exploit_complexity": "single_request",
            "defense_status": "none",
            "submission_tier": "duplicate_grouped",
            "submission_reason": "与已确认 CORS 同根因",
            "root_cause_key": "cors:JwtFilter:again",
        },
    )
    # Soft gate or key mismatch both fail; after ack, key mismatch still blocks.
    if soft3.get("duplicate_soft_gate"):
        dup_new_key = registry.dispatch(
            reviewer3,
            "ConfirmVuln",
            {
                "vuln_id": out3["vuln_id"],
                "attack_surface": "frontend",
                "impact": "limited_info",
                "exploit_complexity": "single_request",
                "defense_status": "none",
                "submission_tier": "duplicate_grouped",
                "submission_reason": "与已确认 CORS 同根因",
                "root_cause_key": "cors:JwtFilter:again",
                "confirm_not_duplicate": True,
            },
        )
    else:
        dup_new_key = soft3
    assert dup_new_key["ok"] is False
    assert "cors:JwtFilter" in dup_new_key["error"]
    assert "不要另写新键" in dup_new_key["error"]


def test_confirm_defaults_static_only_when_dynamic_off(tmp_env, project):
    payload = {
        "title": "SQLI in login",
        "vuln_type": "sqli",
        "cwe": "CWE-89",
        "file_path": "app/Main.java",
        "line_no": 1,
        "source_sink": "login -> query",
        "auth_premise": "未授权",
        "http_request": "GET /login?id=1 HTTP/1.1\nHost: x\n",
        "poc_code": "print('poc')\n",
        "expected_evidence": "error based",
    }
    out = registry.dispatch(_ctx(project, "worker"), "SubmitVuln", payload)
    vuln_id = out["vuln_id"]
    coerced = registry.dispatch(
        _ctx(project, "reviewer"),
        "ConfirmVuln",
        {
            "vuln_id": vuln_id,
            "evidence_level": "dynamic",
            "attack_surface": "frontend",
            **SEVERITY_FACTORS,
        },
    )
    assert coerced["ok"] is True
    assert coerced["evidence_level"] == "static_only"
    assert coerced["status"] == "static_only"


def test_confirm_keeps_dynamic_when_enabled(tmp_env, project):
    from app.models import Project, SessionLocal

    with SessionLocal() as db:
        proj = db.get(Project, project)
        proj.dynamic_verify_enabled = True
        db.commit()
    payload = {
        "title": "SQLI in login",
        "vuln_type": "sqli",
        "cwe": "CWE-89",
        "file_path": "app/Main.java",
        "line_no": 1,
        "source_sink": "login -> query",
        "auth_premise": "未授权",
        "http_request": "GET /login?id=1 HTTP/1.1\nHost: x\n",
        "poc_code": "print('poc')\n",
        "expected_evidence": "error based",
    }
    out = registry.dispatch(_ctx(project, "worker"), "SubmitVuln", payload)
    vuln_id = out["vuln_id"]
    conf = registry.dispatch(
        _ctx(project, "reviewer"),
        "ConfirmVuln",
        {
            "vuln_id": vuln_id,
            "evidence_level": "dynamic",
            "attack_surface": "frontend",
            **SEVERITY_FACTORS,
        },
    )
    assert conf["ok"] is True
    assert conf["evidence_level"] == "dynamic"
    assert conf["status"] == "confirmed"


def test_collect_lab_fingerprints_allows_static_only(tmp_env, project, monkeypatch):
    from app.services.lab import save_env

    payload = {
        "title": "SQLI in login",
        "vuln_type": "sqli",
        "cwe": "CWE-89",
        "file_path": "app/Main.java",
        "line_no": 1,
        "source_sink": "login -> query",
        "auth_premise": "未授权",
        "http_request": "GET /login?id=1 HTTP/1.1\nHost: x\n",
        "poc_code": "print('poc')\n",
        "expected_evidence": "error based",
    }
    out = registry.dispatch(_ctx(project, "worker"), "SubmitVuln", payload)
    vuln_id = out["vuln_id"]
    conf = registry.dispatch(
        _ctx(project, "reviewer"),
        "ConfirmVuln",
        {
            "vuln_id": vuln_id,
            "evidence_level": "static_only",
            "attack_surface": "frontend",
            **SEVERITY_FACTORS,
        },
    )
    assert conf["status"] == "static_only"
    save_env(
        project,
        {"accepted": True, "status": "running", "target_url": "http://127.0.0.1:18080"},
    )

    def fake_fetch(url: str, *, timeout: float = 8.0):
        html = b"<html><head><title>DemoCMS</title></head><body>ok</body></html>"
        return 200, {"content-type": "text/html"}, html, url

    monkeypatch.setattr("app.services.asset_proof.fetch_bytes", fake_fetch)
    applied = registry.dispatch(
        ToolContext(project_id=project, role="reviewer", phase="reviewer", vuln_id=vuln_id),
        "CollectLabFingerprints",
        {"apply": True},
    )
    assert applied["ok"] is True, applied
    assert applied["applied"] is True


def test_bounty_mode_rejects_xss_submit_and_low_impact_confirm(tmp_env, project):
    xss = registry.dispatch(
        _ctx(project, "worker"),
        "SubmitVuln",
        {
            "title": "Reflected XSS",
            "vuln_type": "反射XSS",
            "cwe": "CWE-79",
            "file_path": "app/Main.java",
            "line_no": 1,
            "source_sink": "q -> HTML",
            "auth_premise": "未授权",
            "http_request": "GET /?q=<script> HTTP/1.1\n",
            "poc_code": "print(1)\n",
            "expected_evidence": "script echoed",
        },
    )
    assert xss["ok"] is False
    assert "赏金模式" in xss["error"]

    payload = {
        "title": "CORS",
        "vuln_type": "other",
        "cwe": "CWE-942",
        "file_path": "app/Main.java",
        "line_no": 1,
        "source_sink": "Origin -> ACAO",
        "auth_premise": "未授权",
        "http_request": "GET / HTTP/1.1\n",
        "poc_code": "print(1)\n",
        "expected_evidence": "reflected origin",
    }
    out = registry.dispatch(_ctx(project, "worker"), "SubmitVuln", payload)
    assert out["ok"] is True
    hard = registry.dispatch(
        _ctx(project, "reviewer"),
        "ConfirmVuln",
        {
            "vuln_id": out["vuln_id"],
            "attack_surface": "frontend",
            "impact": "limited_info",
            "exploit_complexity": "single_request",
            "defense_status": "none",
            "submission_tier": "hardening",
            "submission_reason": "CORS 配置问题",
        },
    )
    assert hard["ok"] is False
    assert "赏金模式" in hard["error"]
    assert "低危害" in hard["error"]


def test_bounty_mode_allows_stored_xss_and_source_hardcoded_secret(tmp_env, project):
    stored = registry.dispatch(
        _ctx(project, "worker"),
        "SubmitVuln",
        {
            "title": "Comment stored XSS",
            "vuln_type": "xss",
            "cwe": "CWE-79",
            "file_path": "app/Comment.java",
            "line_no": 12,
            "source_sink": "comment -> 存储型XSS HTML",
            "auth_premise": "登录用户",
            "http_request": "POST /comment HTTP/1.1\n",
            "poc_code": "print(1)\n",
            "expected_evidence": "script persists",
        },
    )
    assert stored["ok"] is True
    models = tmp_env["models"]
    Session = tmp_env["Session"]
    with Session() as db:
        row = db.get(models.Vuln, stored["vuln_id"])
        assert row.vuln_type == "stored_xss"
    confirmed = registry.dispatch(
        _ctx(project, "reviewer"),
        "ConfirmVuln",
        {
            "vuln_id": stored["vuln_id"],
            "attack_surface": "backend",
            "required_account": "user",
            **SEVERITY_FACTORS,
            "submission_reason": "存储型 XSS 可在其他用户浏览器执行",
            "root_cause_key": "stored_xss:Comment",
        },
    )
    assert confirmed["ok"] is True

    secret = registry.dispatch(
        _ctx(project, "worker"),
        "SubmitVuln",
        {
            "title": "Hardcoded JWT secret",
            "vuln_type": "hardcoded_secret",
            "cwe": "CWE-798",
            "file_path": "app/JwtHelper.java",
            "line_no": 8,
            "source_sink": "SECRET constant -> JWT sign",
            "auth_premise": "未授权",
            "http_request": "GET / HTTP/1.1\n",
            "poc_code": "print(1)\n",
            "expected_evidence": "forged token accepted",
        },
    )
    assert secret["ok"] is True

    config_secret = registry.dispatch(
        _ctx(project, "worker"),
        "SubmitVuln",
        {
            "title": "Default password in yml",
            "vuln_type": "hardcoded_secret",
            "cwe": "CWE-798",
            "file_path": "src/main/resources/application.yml",
            "line_no": 4,
            "source_sink": "spring.datasource.password",
            "auth_premise": "未授权",
            "http_request": "GET / HTTP/1.1\n",
            "poc_code": "print(1)\n",
            "expected_evidence": "default password",
        },
    )
    assert config_secret["ok"] is False
    assert "赏金模式" in config_secret["error"]
    assert "配置文件" in config_secret["error"]


def test_full_mode_allows_xss_submit(tmp_env, project):
    _set_audit_mode(project, "full")
    out = registry.dispatch(
        _ctx(project, "worker"),
        "SubmitVuln",
        {
            "title": "Reflected XSS",
            "vuln_type": "xss",
            "cwe": "CWE-79",
            "file_path": "app/Main.java",
            "line_no": 1,
            "source_sink": "q -> HTML",
            "auth_premise": "未授权",
            "http_request": "GET /?q=<script> HTTP/1.1\n",
            "poc_code": "print(1)\n",
            "expected_evidence": "script echoed",
        },
    )
    assert out["ok"] is True
    assert out["status"] == "pending_review"


def test_confirm_backend_requires_account(tmp_env, project):
    payload = {
        "title": "SQLI in login",
        "vuln_type": "sqli",
        "cwe": "CWE-89",
        "file_path": "app/Main.java",
        "line_no": 1,
        "source_sink": "login -> query",
        "auth_premise": "管理员",
        "http_request": "GET /admin HTTP/1.1\nHost: x\n",
        "poc_code": "print('poc')\n",
        "expected_evidence": "error based",
    }
    out = registry.dispatch(_ctx(project, "worker"), "SubmitVuln", payload)
    vuln_id = out["vuln_id"]
    missing = registry.dispatch(
        _ctx(project, "reviewer"),
        "ConfirmVuln",
        {"vuln_id": vuln_id, "attack_surface": "backend"},
    )
    assert missing["ok"] is False
    assert "required_account" in missing["error"]

    conf = registry.dispatch(
        _ctx(project, "reviewer"),
        "ConfirmVuln",
        {
            "vuln_id": vuln_id,
            "attack_surface": "后台",
            "required_account": "管理员",
            "impact": "rce_or_full_data",
            "exploit_complexity": "single_request",
            "defense_status": "none",
            "submission_tier": "cve_candidate",
            "submission_reason": "管理员可达但可完整控制，仍有 CVE 价值",
        },
    )
    assert conf["ok"] is True
    assert conf["attack_surface"] == "backend"
    assert conf["required_account"] == "admin"
    assert conf["required_account_label"] == "管理员"
    assert conf["severity"] == "high"
    models = tmp_env["models"]
    Session = tmp_env["Session"]
    with Session() as db:
        v = db.get(models.Vuln, vuln_id)
        assert v.attack_surface == "backend"
        assert v.required_account == "admin"
        assert v.severity == "high"
    report = (vuln_dir(project, vuln_id) / "report.md").read_text(encoding="utf-8")
    assert "- 攻击面：后台" in report
    assert "- 所需账号：管理员" in report


def test_confirm_backend_user_account(tmp_env, project):
    payload = {
        "title": "IDOR",
        "vuln_type": "privilege_escalation",
        "cwe": "CWE-639",
        "file_path": "app/Main.java",
        "line_no": 1,
        "source_sink": "id -> query",
        "auth_premise": "登录后",
        "http_request": "GET /user/1 HTTP/1.1\n",
        "poc_code": "print(1)\n",
        "expected_evidence": "other user data",
    }
    out = registry.dispatch(_ctx(project, "worker"), "SubmitVuln", payload)
    vuln_id = out["vuln_id"]
    conf = registry.dispatch(
        _ctx(project, "reviewer"),
        "ConfirmVuln",
        {
            "vuln_id": vuln_id,
            "attack_surface": "backend",
            "required_account": "普通权限",
            **SEVERITY_FACTORS,
        },
    )
    assert conf["ok"] is True
    assert conf["required_account"] == "user"
    assert conf["required_account_label"] == "普通权限"
    assert conf["severity"] == "medium"
    assert conf["severity_score"] == 2
    report = (vuln_dir(project, vuln_id) / "report.md").read_text(encoding="utf-8")
    assert "- 所需账号：普通权限" in report


def test_confirm_frontend_ignores_account(tmp_env, project):
    payload = {
        "title": "SQLi",
        "vuln_type": "sqli",
        "cwe": "CWE-89",
        "file_path": "app/Main.java",
        "line_no": 1,
        "source_sink": "a->b",
        "auth_premise": "未授权",
        "http_request": "GET / HTTP/1.1\n",
        "poc_code": "print(1)\n",
        "expected_evidence": "error based",
    }
    out = registry.dispatch(_ctx(project, "worker"), "SubmitVuln", payload)
    vuln_id = out["vuln_id"]
    conf = registry.dispatch(
        _ctx(project, "reviewer"),
        "ConfirmVuln",
        {
            "vuln_id": vuln_id,
            "attack_surface": "前台漏洞",
            "required_account": "admin",
            **SEVERITY_FACTORS,
        },
    )
    assert conf["ok"] is True
    assert conf["attack_surface"] == "frontend"
    assert conf["required_account"] is None
    models = tmp_env["models"]
    Session = tmp_env["Session"]
    with Session() as db:
        v = db.get(models.Vuln, vuln_id)
        assert v.required_account is None


def test_return_to_worker_false_positive(tmp_env, project):
    payload = {
        "title": "intended",
        "vuln_type": "info_disclosure",
        "cwe": "CWE-200",
        "file_path": "app/Main.java",
        "line_no": 2,
        "source_sink": "a->b",
        "auth_premise": "登录后",
        "http_request": "GET / HTTP/1.1\n",
        "poc_code": "print(1)\n",
        "expected_evidence": "ok",
        "intended_behavior": True,
    }
    out = registry.dispatch(_ctx(project, "worker"), "SubmitVuln", payload)
    vuln_id = out["vuln_id"]
    ret = registry.dispatch(
        _ctx(project, "reviewer"),
        "ReturnToWorker",
        {"vuln_id": vuln_id, "reason": "已知业务能力", "false_positive": True},
    )
    assert ret["status"] == "false_positive"
    report = (vuln_dir(project, vuln_id) / "report.md").read_text(encoding="utf-8")
    assert report.rstrip().endswith("已知业务能力")
    assert "## 误报判定" in report
    assert report.index("## 误报判定") > report.index("# intended")


def test_return_to_worker_keeps_report_when_not_fp(tmp_env, project):
    payload = {
        "title": "needs fix",
        "vuln_type": "sqli",
        "cwe": "CWE-89",
        "file_path": "app/Main.java",
        "line_no": 1,
        "source_sink": "login -> query",
        "auth_premise": "未授权",
        "http_request": "GET /login?id=1 HTTP/1.1\nHost: x\n",
        "poc_code": "print('poc')\n",
        "expected_evidence": "error based",
        "intended_behavior": False,
    }
    out = registry.dispatch(_ctx(project, "worker"), "SubmitVuln", payload)
    vuln_id = out["vuln_id"]
    before = (vuln_dir(project, vuln_id) / "report.md").read_text(encoding="utf-8")
    ret = registry.dispatch(
        _ctx(project, "reviewer"),
        "ReturnToWorker",
        {"vuln_id": vuln_id, "reason": "PoC 证据不足，请补全"},
    )
    assert ret["status"] == "returned"
    after = (vuln_dir(project, vuln_id) / "report.md").read_text(encoding="utf-8")
    assert after == before
    assert "## 误报判定" not in after


def test_return_to_worker_max_rejects_appends_reason(tmp_env, project):
    payload = {
        "title": "flaky",
        "vuln_type": "sqli",
        "cwe": "CWE-89",
        "file_path": "app/Main.java",
        "line_no": 1,
        "source_sink": "a->b",
        "auth_premise": "未授权",
        "http_request": "GET / HTTP/1.1\n",
        "poc_code": "print(1)\n",
        "expected_evidence": "ok",
        "intended_behavior": False,
    }
    out = registry.dispatch(_ctx(project, "worker"), "SubmitVuln", payload)
    vuln_id = out["vuln_id"]
    models = tmp_env["models"]
    Session = tmp_env["Session"]
    with Session() as db:
        v = db.get(models.Vuln, vuln_id)
        v.review_rounds = 2
        db.commit()
    ret = registry.dispatch(
        _ctx(project, "reviewer"),
        "ReturnToWorker",
        {"vuln_id": vuln_id, "reason": "仍无法复现"},
    )
    assert ret["status"] == "false_positive"
    report = (vuln_dir(project, vuln_id) / "report.md").read_text(encoding="utf-8")
    assert "## 误报判定" in report
    assert "超过最大打回次数" in report
    assert "仍无法复现" in report


def test_todo_write_isolated_by_phase(tmp_env, project):
    recon = ToolContext(project_id=project, role="recon", phase="recon")
    worker_a = ToolContext(
        project_id=project, role="worker", phase="worker", worker_id="worker-1-abc"
    )
    worker_b = ToolContext(
        project_id=project, role="worker", phase="worker", worker_id="worker-2-def"
    )
    reviewer = ToolContext(project_id=project, role="reviewer", phase="reviewer", vuln_id=9)
    verifier = ToolContext(project_id=project, role="verifier", phase="verifier", vuln_id=9)
    fixer = ToolContext(project_id=project, role="fix", phase="fix", vuln_id=9)

    r_recon = registry.dispatch(
        recon, "TodoWrite", {"todos": [{"id": "1", "content": "recon-task", "status": "pending"}]}
    )
    r_wa = registry.dispatch(
        worker_a, "TodoWrite", {"todos": [{"id": "1", "content": "worker-a", "status": "in_progress"}]}
    )
    r_wb = registry.dispatch(
        worker_b, "TodoWrite", {"todos": [{"id": "1", "content": "worker-b", "status": "pending"}]}
    )
    r_rev = registry.dispatch(
        reviewer, "TodoWrite", {"todos": [{"id": "1", "content": "review", "status": "pending"}]}
    )
    r_ver = registry.dispatch(
        verifier, "TodoWrite", {"todos": [{"id": "1", "content": "verify", "status": "pending"}]}
    )
    r_fix = registry.dispatch(
        fixer, "TodoWrite", {"todos": [{"id": "1", "content": "fix", "status": "pending"}]}
    )

    assert r_recon["path"] == "workspace/todos-recon.json"
    assert r_wa["path"] == "workspace/todos-worker-worker-1-abc.json"
    assert r_wb["path"] == "workspace/todos-worker-worker-2-def.json"
    assert r_rev["path"] == "workspace/todos-reviewer-9.json"
    assert r_ver["path"] == "workspace/todos-verifier-9.json"
    assert r_fix["path"] == "workspace/todos-fix-9.json"

    ws = workspace_dir(project)
    recon_todos = json.loads((ws / "todos-recon.json").read_text(encoding="utf-8"))
    wa_todos = json.loads((ws / "todos-worker-worker-1-abc.json").read_text(encoding="utf-8"))
    wb_todos = json.loads((ws / "todos-worker-worker-2-def.json").read_text(encoding="utf-8"))
    rev_todos = json.loads((ws / "todos-reviewer-9.json").read_text(encoding="utf-8"))
    ver_todos = json.loads((ws / "todos-verifier-9.json").read_text(encoding="utf-8"))
    fix_todos = json.loads((ws / "todos-fix-9.json").read_text(encoding="utf-8"))
    assert recon_todos[0]["content"] == "recon-task"
    assert wa_todos[0]["content"] == "worker-a"
    assert wb_todos[0]["content"] == "worker-b"
    assert rev_todos[0]["content"] == "review"
    assert ver_todos[0]["content"] == "verify"
    assert fix_todos[0]["content"] == "fix"
    assert not (ws / "todos.json").exists()
    assert todo_relpath(recon) != todo_relpath(worker_a)


def test_openai_tools_for_role_contains_expected(tmp_env, project):
    recon_names = {t["function"]["name"] for t in registry.openai_tools_for_role("recon")}
    assert "FinishRecon" not in recon_names
    assert "WriteOldVuln" not in recon_names
    assert "SearchGHSA" not in recon_names
    assert "WebSearch" not in recon_names
    assert "MarkSource" in recon_names
    assert "AddSourceExt" not in recon_names
    assert "SubmitVuln" not in recon_names
    assert "MarkWeight" not in recon_names
    old_names = {t["function"]["name"] for t in registry.openai_tools_for_role("recon_old_vuln")}
    assert "WriteOldVuln" in old_names
    assert "Grep" not in old_names
    assert "Glob" not in old_names
    assert "SearchGHSA" not in old_names
    assert "SearchGitHubIssues" not in old_names
    assert "WebSearch" not in old_names
    denied_ghsa = registry.dispatch(_ctx(project, "recon_old_vuln"), "SearchGHSA", {"query": "halo"})
    assert denied_ghsa["ok"] is False
    assert "无权" in denied_ghsa["error"]
    denied_issues = registry.dispatch(_ctx(project, "recon_old_vuln"), "SearchGitHubIssues", {"query": "RCE"})
    assert denied_issues["ok"] is False
    assert "无权" in denied_issues["error"]
    denied_web = registry.dispatch(_ctx(project, "recon_old_vuln"), "WebSearch", {"query": "halo cve"})
    assert denied_web["ok"] is False
    assert "无权" in denied_web["error"]
    assert "MarkSource" not in old_names
    assert "AddSourceExt" not in old_names
    assert "Write" not in old_names
    ghsa_names = {t["function"]["name"] for t in registry.openai_tools_for_role("recon_old_vuln_ghsa")}
    assert "WriteOldVuln" in ghsa_names
    assert "Grep" not in ghsa_names
    assert "Glob" not in ghsa_names
    assert "SearchGHSA" in ghsa_names
    assert "SearchGitHubIssues" in ghsa_names
    assert "WebSearch" in ghsa_names
    ext_names = {t["function"]["name"] for t in registry.openai_tools_for_role("recon_source_ext")}
    assert "AddSourceExt" in ext_names
    assert "Read" in ext_names
    assert "MarkWeight" not in ext_names
    mark_names = {t["function"]["name"] for t in registry.openai_tools_for_role("recon_mark")}
    assert mark_names == {"MarkSource", "MarkWeight", "MarkSkip"}
    mark_tools = {
        t["function"]["name"]: t["function"]["description"]
        for t in registry.openai_tools_for_role("recon_mark")
    }
    assert "WebSocket" in mark_tools["MarkSource"]
    assert "不要只标 HTTP" in mark_tools["MarkSource"]
    assert "70–90" in mark_tools["MarkWeight"]
    worker_names = {t["function"]["name"] for t in registry.openai_tools_for_role("worker")}
    assert "FinishAudit" not in worker_names
    assert "FinishRound" in worker_names
    assert "AppendAffectedLocations" in worker_names
    assert "AddSourceExt" not in worker_names
    assert ROLE_ACL["worker"].isdisjoint({"FinishRecon", "FinishAudit", "ConfirmVuln", "WriteOldVuln"})
    assert "FinishSink" not in ROLE_ACL["worker"]
    assert "FinishSinkTriage" not in ROLE_ACL["worker"]
    assert "FinishBypass" not in ROLE_ACL["worker"]
    reviewer_names = {t["function"]["name"] for t in registry.openai_tools_for_role("reviewer")}
    assert "MergeIntoVuln" in reviewer_names
    assert "ConfirmVuln" in reviewer_names
    assert "CollectLabFingerprints" in reviewer_names
    assert "FinishLab" not in reviewer_names
    lab_names = {t["function"]["name"] for t in registry.openai_tools_for_role("reviewer_lab")}
    assert "FinishLab" in lab_names
    assert "Write" in lab_names
    assert "ConfirmVuln" not in lab_names
    assert "CollectLabFingerprints" not in lab_names
    assert "ReturnToWorker" not in lab_names
    verifier_names = {t["function"]["name"] for t in registry.openai_tools_for_role("verifier")}
    assert "FofaSearch" in verifier_names
    assert "FinishVerifier" in verifier_names
    assert "ConfirmVuln" not in verifier_names
    injected_shells = recon_names & SHELL_TOOLS
    assert injected_shells == {native_shell_tool()}


def test_native_shell_tool_matches_host():
    name = native_shell_tool()
    assert name in SHELL_TOOLS
    if os.name == "nt":
        assert name == "PowerShell"
    else:
        assert name == "Bash"


def test_openai_tools_injects_only_one_shell(monkeypatch):
    monkeypatch.setattr("app.tools.native_shell_tool", lambda: "PowerShell")
    names = {t["function"]["name"] for t in registry.openai_tools_for_role("recon")}
    assert "PowerShell" in names
    assert "Bash" not in names
    monkeypatch.setattr("app.tools.native_shell_tool", lambda: "Bash")
    names = {t["function"]["name"] for t in registry.openai_tools_for_role("worker")}
    assert "Bash" in names
    assert "PowerShell" not in names


def test_websearch_empty_or_non_json_is_ok(monkeypatch, project):
    class FakeResp:
        status_code = 200
        text = ""
        content = b""

        def raise_for_status(self) -> None:
            return None

        def json(self):
            raise ValueError("Expecting value: line 1 column 1 (char 0)")

    class FakeClient:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def get(self, *args, **kwargs):
            return FakeResp()

    monkeypatch.setattr("app.services.fingerprint_search.http_client", lambda timeout=20.0: FakeClient())
    out = registry.dispatch(_ctx(project, "recon_old_vuln_ghsa"), "WebSearch", {"query": "halo cve"})
    assert out["ok"] is True
    assert out.get("results") == []
    note = out.get("note") or ""
    assert "不可用" in note or "空" in note or "非 JSON" in note or note == ""


def test_dispatch_rejects_non_native_shell(monkeypatch, project):
    monkeypatch.setattr("app.tools.native_shell_tool", lambda: "PowerShell")
    out = registry.dispatch(_ctx(project, "recon"), "Bash", {"command": "echo 1"})
    assert out["ok"] is False
    assert "PowerShell" in out["error"]
    monkeypatch.setattr("app.tools.native_shell_tool", lambda: "Bash")
    out = registry.dispatch(_ctx(project, "worker"), "PowerShell", {"command": "echo 1"})
    assert out["ok"] is False
    assert "Bash" in out["error"]


def test_shell_rejects_recursive_listing_immediately(tmp_env, project):
    tool = native_shell_tool()
    started = time.time()
    out = registry.dispatch(
        _ctx(project, "recon"),
        tool,
        {"command": 'Get-ChildItem -Path "src" -Directory -Recurse -Depth 4'},
    )
    assert out["ok"] is False
    assert "递归" in (out.get("error") or "")
    assert time.time() - started < 3


def test_glob_and_grep_skip_node_modules(tmp_env, project):
    globbed = registry.dispatch(_ctx(project, "recon"), "Glob", {"pattern": "**/*", "root": "src"})
    assert globbed["ok"] is True
    assert globbed["count"] >= 1
    assert all("node_modules" not in m.replace("\\", "/") for m in globbed["matches"])
    grepped = registry.dispatch(
        _ctx(project, "recon"),
        "Grep",
        {"pattern": "module\\.exports", "root": "src"},
    )
    assert grepped["ok"] is True
    assert all("node_modules" not in h["path"].replace("\\", "/") for h in grepped.get("hits") or [])


def test_shell_timeout_kills_process(tmp_env, project):
    tool = native_shell_tool()
    command = "Start-Sleep -Seconds 30" if tool == "PowerShell" else "sleep 30"
    started = time.time()
    out = registry.dispatch(_ctx(project, "recon"), tool, {"command": command, "timeout": 2})
    assert out["ok"] is False
    assert "超时" in (out.get("error") or "")
    assert time.time() - started < 15


def test_shell_dispatch_hard_timeout_returns_if_handler_hangs(monkeypatch, tmp_env, project):
    import app.tools as tools_mod

    tool = native_shell_tool()
    original = registry.get(tool)
    assert original is not None

    def hung_handler(ctx, args):  # noqa: ANN001
        time.sleep(5)
        return {"ok": True}

    monkeypatch.setattr(tools_mod, "_SHELL_DISPATCH_TIMEOUT_GRACE", 0)
    registry.register(
        ToolSpec(
            name=tool,
            description=original.description,
            parameters=original.parameters,
            handler=hung_handler,
        )
    )
    try:
        started = time.time()
        out = registry.dispatch(_ctx(project, "recon"), tool, {"command": "ignored", "timeout": 1})
    finally:
        registry.register(original)

    assert out["ok"] is False
    assert out.get("hard_timeout") is True
    assert "工具调用硬超时" in (out.get("error") or "")
    assert time.time() - started < 3


def test_decode_shell_bytes_utf8_and_gbk():
    from app.tools.common import decode_shell_bytes

    text = '无法将"/etc"项识别为 cmdlet'
    assert decode_shell_bytes(text.encode("utf-8")) == text
    assert decode_shell_bytes(text.encode("gbk")) == text
    assert decode_shell_bytes(b"") == ""
    assert decode_shell_bytes(b"\xef\xbb\xbfhello") == "hello"


def test_recon_docs_ready_and_mark_batch(tmp_env, project):
    from app.tools.phase_recon import (
        paths_fully_marked,
        pick_unmarked_batch,
        recon_docs_ready,
        recon_gates_met,
        recon_map_ready,
        recon_old_vulns_ready,
        recon_subphases,
    )

    build_file_index(project)
    assert recon_docs_ready(project) is False
    assert recon_map_ready(project) is False
    assert recon_old_vulns_ready(project) is False
    docs = docs_dir(project)
    (docs / "code-map.md").write_text("# map\n", encoding="utf-8")
    (docs / "auth.md").write_text("# auth\n", encoding="utf-8")
    assert recon_map_ready(project) is True
    assert recon_old_vulns_ready(project) is False
    assert recon_docs_ready(project) is False
    old = old_vulns_dir(project)
    old.mkdir(parents=True, exist_ok=True)
    (old / "index.md").write_text("# index\n", encoding="utf-8")
    assert recon_old_vulns_ready(project) is False
    (old / "index.md").write_text(
        "---\ntitle: 历史漏洞索引\nsummary: test\ncomplete: true\n---\n\n# index\n",
        encoding="utf-8",
    )
    assert recon_old_vulns_ready(project) is True
    assert recon_docs_ready(project) is True
    assert recon_gates_met(project) is False
    subs = {s["id"]: s["done"] for s in recon_subphases(project)}
    assert subs["map"] is True
    assert subs["source_ext"] is False
    assert subs["old_vulns"] is True
    assert subs["mark"] is False

    batch = pick_unmarked_batch(project, 10)
    assert batch
    assert paths_fully_marked(project, batch) is False
    out = registry.dispatch(_ctx(project, "recon_mark"), "MarkWeight", {"paths": batch, "weight": 40})
    assert out["ok"] is True
    assert paths_fully_marked(project, batch) is True


def _add_maven_source(project_id: int, rel: str = "src/main/java/im/zfile/Foo.java") -> str:
    src = src_dir(project_id)
    fp = src / rel
    fp.parent.mkdir(parents=True, exist_ok=True)
    fp.write_text("class Foo {}\n", encoding="utf-8")
    return rel.replace("\\", "/")


def test_mark_weight_keeps_maven_src_prefix(tmp_env, project):
    from app.tools.phase_recon import paths_fully_marked

    rel = _add_maven_source(project)
    build_file_index(project)
    out = registry.dispatch(_ctx(project, "recon_mark"), "MarkWeight", {"path": rel, "weight": 80})
    assert out["ok"] is True
    assert out["count"] == 1
    assert out["updated"][0]["path"] == rel
    assert out["updated"][0]["weight"] == 80
    assert paths_fully_marked(project, [rel]) is True
    models = tmp_env["models"]
    Session = tmp_env["Session"]
    with Session() as db:
        fw = (
            db.query(models.FileWeight)
            .filter(models.FileWeight.project_id == project, models.FileWeight.path == rel)
            .one()
        )
        assert fw.weight == 80


def test_mark_weight_accepts_workspace_src_prefix(tmp_env, project):
    build_file_index(project)
    out = registry.dispatch(
        _ctx(project, "recon_mark"),
        "MarkWeight",
        {"path": "src/app/Main.java", "weight": 40},
    )
    assert out["ok"] is True
    assert out["count"] == 1
    assert out["updated"][0]["path"] == "app/Main.java"


def test_mark_weight_reports_unmatched_paths(tmp_env, project):
    build_file_index(project)
    out = registry.dispatch(
        _ctx(project, "recon_mark"),
        "MarkWeight",
        {"path": "no/such.java", "weight": 10},
    )
    assert out["ok"] is False
    assert out["count"] == 0
    assert "未找到文件索引" in out["error"]
    assert out["unmatched"] == ["no/such.java"]


def test_mark_source_maven_path_and_empty_method(tmp_env, project):
    from app.tools.phase_recon import paths_fully_marked

    rel = _add_maven_source(project, "src/main/java/im/zfile/FrontIndexController.java")
    build_file_index(project)
    out = registry.dispatch(
        _ctx(project, "recon_mark"),
        "MarkSource",
        {"file": rel, "method": "", "note": "首页"},
    )
    assert out["ok"] is True
    assert out["count"] == 1
    assert out["marked"][0]["file"] == rel
    assert out["marked"][0]["method"] == "*"
    assert paths_fully_marked(project, [rel]) is True
    models = tmp_env["models"]
    Session = tmp_env["Session"]
    with Session() as db:
        fw = (
            db.query(models.FileWeight)
            .filter(models.FileWeight.project_id == project, models.FileWeight.path == rel)
            .one()
        )
        assert fw.weight == 100
        assert fw.has_source is True
        srcs = db.query(models.Source).filter(models.Source.project_id == project).all()
        assert any(s.file_path == rel and s.method_name == "*" for s in srcs)


def test_mark_skip_keeps_maven_src_prefix(tmp_env, project):
    from app.tools.phase_recon import paths_fully_marked

    rel = _add_maven_source(project)
    build_file_index(project)
    out = registry.dispatch(_ctx(project, "recon_mark"), "MarkSkip", {"paths": [rel]})
    assert out["ok"] is True
    assert out["count"] == 1
    assert out["skipped"] == [rel]
    assert paths_fully_marked(project, [rel]) is True


def test_recon_cannot_mark_weight(tmp_env, project):
    out = registry.dispatch(_ctx(project, "recon"), "MarkWeight", {"path": "app/Main.java", "weight": 10})
    assert out["ok"] is False
    assert "无权" in out["error"]


def test_recon_old_vuln_cannot_write(tmp_env, project):
    out = registry.dispatch(
        _ctx(project, "recon_old_vuln"),
        "Write",
        {"path": "docs/code-map.md", "content": "# no\n"},
    )
    assert out["ok"] is False
    assert "无权" in out["error"]


def test_recon_old_vuln_cannot_read_source(tmp_env, project):
    denied_grep = registry.dispatch(
        _ctx(project, "recon_old_vuln"),
        "Grep",
        {"pattern": "TODO", "path": "src"},
    )
    assert denied_grep["ok"] is False
    assert "无权" in denied_grep["error"]
    out = registry.dispatch(
        _ctx(project, "recon_old_vuln"),
        "Read",
        {"path": "src/app/Main.java"},
    )
    assert out["ok"] is False
    assert "禁止读源码" in (out.get("error") or "")
    docs = docs_dir(project)
    docs.mkdir(parents=True, exist_ok=True)
    (docs / "code-map.md").write_text("# map\n", encoding="utf-8")
    allowed = registry.dispatch(
        _ctx(project, "recon_old_vuln"),
        "Read",
        {"path": "docs/code-map.md"},
    )
    assert allowed["ok"] is True
    assert any("map" in str(f.get("content") or "") for f in allowed.get("files") or [])


def test_write_ready_env_json_generates_lab_doc(tmp_env, project):
    from app.services.phase_reports import reports_by_phase

    env = {
        "accepted": True,
        "runtime": "java",
        "image": "demo:latest",
        "container_name": f"vulnhunter-{project}",
        "container_port": 8080,
        "host_port": 18080,
        "jdwp_container_port": 5005,
        "jdwp_host_port": 15005,
        "target_url": "http://127.0.0.1:18080",
        "lab_state": "ready",
        "credentials": {"username": "admin", "password": "admin123"},
        "status": "running",
        "notes": "seeded test data",
    }

    out = registry.dispatch(
        _ctx(project, "reviewer"),
        "Write",
        {"path": "env/env.json", "content": json.dumps(env, ensure_ascii=False)},
    )

    assert out["ok"] is True
    assert out["lab_doc_path"] == "docs/lab.md"
    doc = (docs_dir(project) / "lab.md").read_text(encoding="utf-8")
    assert "# 动态环境搭建" in doc
    assert "http://127.0.0.1:18080" in doc
    assert "demo:latest" in doc
    assert "seeded test data" in doc
    phase_reports = reports_by_phase(project)
    reviewer_reports = next(p for p in phase_reports["phases"] if p["phase"] == "reviewer")
    assert any(item["id"] == "docs/lab.md" for item in reviewer_reports["reports"])
    assert any(item["id"] == "docs/lab.md" and item["subphase"] == "lab" for item in reviewer_reports["reports"])


def test_finish_lab_marks_setup_finished(tmp_env, project):
    from app.services.lab import lab_setup_finished, load_env

    env = {
        "accepted": True,
        "target_url": "http://127.0.0.1:18080",
        "status": "running",
    }
    registry.dispatch(
        _ctx(project, "reviewer_lab"),
        "Write",
        {"path": "env/env.json", "content": json.dumps(env, ensure_ascii=False)},
    )
    ctx = _ctx(project, "reviewer_lab")
    out = registry.dispatch(ctx, "FinishLab", {})
    assert out["ok"] is True
    assert out["setup_finished"] is True
    assert lab_setup_finished(project) is True
    assert ctx.state.get("lab_done") is True
    assert load_env(project).get("setup_finished") is True


def test_finish_lab_skip_without_running_container(tmp_env, project):
    from app.services.lab import lab_setup_finished
    from app.services.paths import docs_dir

    ctx = _ctx(project, "reviewer_lab")
    denied = registry.dispatch(ctx, "FinishLab", {})
    assert denied["ok"] is False
    out = registry.dispatch(ctx, "FinishLab", {"skipped": True, "reason": "本机无 docker"})
    assert out["ok"] is True
    assert out["skipped"] is True
    assert lab_setup_finished(project) is True
    assert (docs_dir(project) / "lab.md").is_file()


def test_recon_mark_cannot_read(tmp_env, project):
    out = registry.dispatch(_ctx(project, "recon_mark"), "Read", {"path": "app/Main.java"})
    assert out["ok"] is False
    assert "无权" in out["error"]


def test_add_source_ext_is_recon_source_ext_only(tmp_env, project):
    from app.tools.phase_recon import recon_source_ext_ready

    models = tmp_env["models"]
    Session = tmp_env["Session"]
    src = src_dir(project)
    (src / "app" / "job.ftl").write_text("<#-- view -->\n", encoding="utf-8")
    (src / "app" / "page.html").write_text("<html></html>\n", encoding="utf-8")
    build_file_index(project)

    for role in ("recon", "recon_mark", "worker", "recon_old_vuln"):
        denied = registry.dispatch(_ctx(project, role), "AddSourceExt", {"ext": ".ftl"})
        assert denied["ok"] is False
        assert "无权" in denied["error"]

    out = registry.dispatch(_ctx(project, "recon_source_ext"), "AddSourceExt", {"exts": [".ftl", ".png"]})
    assert out["ok"] is True
    assert out["exts"] == [".ftl"]
    assert out["added_count"] == 1
    assert out["done"] is False
    assert recon_source_ext_ready(project) is False
    assert "job.ftl" in out["added_sample"][0]
    assert ".png" in out["rejected"]

    with Session() as db:
        ftl = (
            db.query(models.FileWeight)
            .filter(models.FileWeight.project_id == project, models.FileWeight.path == "app/job.ftl")
            .one()
        )
        java = (
            db.query(models.FileWeight)
            .filter(models.FileWeight.project_id == project, models.FileWeight.path == "app/Main.java")
            .one()
        )
        assert ftl.weight is None
        assert ftl.skipped is False
        assert java.weight is None or java.skipped

    more = registry.dispatch(
        _ctx(project, "recon_source_ext"),
        "AddSourceExt",
        {"ext": "html", "done": True},
    )
    assert more["ok"] is True
    assert more["added_count"] == 1
    assert more["done"] is True
    assert recon_source_ext_ready(project) is True
    with Session() as db:
        html = (
            db.query(models.FileWeight)
            .filter(models.FileWeight.project_id == project, models.FileWeight.path == "app/page.html")
            .one()
        )
        assert html.weight is None
        assert html.skipped is False

    bad = registry.dispatch(_ctx(project, "recon_source_ext"), "AddSourceExt", {"exts": [".png", ".exe"]})
    assert bad["ok"] is False


def test_add_source_ext_none_concludes(tmp_env, project):
    from app.tools.phase_recon import recon_source_ext_ready

    build_file_index(project)
    assert recon_source_ext_ready(project) is False
    out = registry.dispatch(_ctx(project, "recon_source_ext"), "AddSourceExt", {"none": True})
    assert out["ok"] is True
    assert out["done"] is True
    assert recon_source_ext_ready(project) is True
    doc = (docs_dir(project) / "source-exts.md").read_text(encoding="utf-8")
    assert "complete: true" in doc


def test_read_small_file_numbered(tmp_env, project):
    out = registry.dispatch(_ctx(project, "worker"), "Read", {"path": "src/app/Main.java"})
    assert out["ok"] is True
    f = out["files"][0]
    assert f["truncated"] is False
    assert f["start_line"] == 1
    assert f["total_lines"] >= 1
    assert "content" in f
    assert f["content"].lstrip().startswith("1|")
    keys = list(f.keys())
    assert keys.index("truncated") < keys.index("content")


def test_read_pages_large_file_with_next_offset(tmp_env, project):
    from app.services.paths import src_dir

    src = src_dir(project)
    lines = [f"line-{i}" for i in range(1, 21)]
    (src / "app" / "Big.java").write_text("\n".join(lines) + "\n", encoding="utf-8")
    out = registry.dispatch(_ctx(project, "worker"), "Read", {"path": "src/app/Big.java", "limit": 5})
    assert out["ok"] is True
    f = out["files"][0]
    assert f["truncated"] is True
    assert f["start_line"] == 1
    assert f["end_line"] == 5
    assert f["total_lines"] == 20
    assert f["next_offset"] == 6
    assert "offset=6" in f["hint"]
    dumped = json.dumps(f, ensure_ascii=False)
    assert dumped.index('"hint"') < dumped.index('"content"')
    nxt = registry.dispatch(_ctx(project, "worker"), "Read", {"path": "src/app/Big.java", "offset": 6, "limit": 5})
    f2 = nxt["files"][0]
    assert f2["start_line"] == 6
    assert f2["end_line"] == 10
    assert "line-6" in f2["content"]


def test_read_text_window_negative_offset_and_cap():
    from app.tools.common import read_text_window

    text = "\n".join(f"L{i}" for i in range(1, 11)) + "\n"
    tail = read_text_window(text, offset=-2, limit=10, max_bytes=80_000)
    assert tail["truncated"] is False
    assert tail["start_line"] == 9
    assert "L9" in tail["content"]
    assert "L10" in tail["content"]
    past = read_text_window(text, offset=99, max_bytes=80_000)
    assert past["content"] == ""
    assert "末尾" in (past.get("hint") or "")
    tiny = read_text_window(text, offset=1, limit=50, max_bytes=20)
    assert tiny["truncated"] is True
    assert tiny["next_offset"] == tiny["end_line"] + 1
    assert tiny["end_line"] >= 1


def test_read_text_window_auto_pages_when_over_soft_max():
    from app.tools.common import read_text_window

    big = "\n".join(f"L{i}" for i in range(1, 201)) + "\n"
    paged = read_text_window(big, max_bytes=80_000, default_limit=40, soft_max_chars=80)
    assert paged["truncated"] is True
    assert paged["end_line"] == 40
    assert paged["next_offset"] == 41
    small = "\n".join(f"L{i}" for i in range(1, 6)) + "\n"
    whole = read_text_window(small, max_bytes=80_000, default_limit=2, soft_max_chars=10_000)
    assert whole["truncated"] is False
    assert whole["end_line"] == 5
    assert "next_offset" not in whole


def test_worker_finish_tools_decouple_file_and_round():
    tools = {
        t["function"]["name"]: t["function"]["description"]
        for t in registry.openai_tools_for_role("worker")
    }
    assert "禁止立刻 FinishRound" in tools["FinishFile"]
    assert "禁止立刻" in tools["FinishRound"]
    assert "templates/round-report.md" in tools["FinishRound"]
    assert "本轮须已 FinishFile" not in tools["FinishRound"]


def test_finish_file_non_entry_blocks_immediate_finish_round(tmp_env, project):
    from app.services.paths import src_dir
    from app.tools.phase_worker import FINISH_FILE_NON_ENTRY_MSG, FINISH_ROUND_NEED_ENTRY

    src = src_dir(project)
    (src / "app" / "Helper.java").write_text("class Helper {}\n", encoding="utf-8")
    build_file_index(project)
    ctx = ToolContext(
        project_id=project,
        role="worker",
        phase="worker",
        file_path="app/Main.java",
    )
    marked = registry.dispatch(ctx, "FinishFile", {"path": "src/app/Helper.java"})
    assert marked["ok"] is True
    assert marked["message"] == FINISH_FILE_NON_ENTRY_MSG
    assert ctx.state.get("round_finished") is not True

    blocked = registry.dispatch(ctx, "FinishRound", {"summary": "too early"})
    assert blocked["ok"] is False
    assert blocked["error"] == FINISH_ROUND_NEED_ENTRY.format(injected="app/Main.java")
    assert ctx.state.get("round_finished") is not True


def test_finish_round_after_injected_entry_is_marked(tmp_env, project):
    from app.services.paths import src_dir, workspace_dir
    from app.tools.phase_worker import FINISH_FILE_ENTRY_MSG

    src = src_dir(project)
    (src / "app" / "Helper.java").write_text("class Helper {}\n", encoding="utf-8")
    build_file_index(project)
    ctx = ToolContext(
        project_id=project,
        role="worker",
        phase="worker",
        file_path="app/Main.java",
    )
    ctx.state["round_id"] = 3
    registry.dispatch(ctx, "FinishFile", {"path": "app/Helper.java"})
    entry = registry.dispatch(ctx, "FinishFile", {"path": "app/Main.java"})
    assert entry["ok"] is True
    assert entry["message"] == FINISH_FILE_ENTRY_MSG

    done = registry.dispatch(ctx, "FinishRound", {"summary": "入口已查清"})
    assert done["ok"] is True
    assert ctx.state["round_finished"] is True
    report = workspace_dir(project) / "rounds" / "round-3.md"
    assert report.read_text(encoding="utf-8") == "入口已查清"


def test_finish_round_strips_followup_section(tmp_env, project):
    from app.services.paths import src_dir, workspace_dir
    from app.tools.phase_worker import FINISH_FILE_ENTRY_MSG

    src = src_dir(project)
    (src / "app" / "Helper.java").write_text("class Helper {}\n", encoding="utf-8")
    build_file_index(project)
    ctx = ToolContext(
        project_id=project,
        role="worker",
        phase="worker",
        file_path="app/Main.java",
    )
    ctx.state["round_id"] = 4
    registry.dispatch(ctx, "FinishFile", {"path": "app/Helper.java"})
    entry = registry.dispatch(ctx, "FinishFile", {"path": "app/Main.java"})
    assert entry["ok"] is True
    assert entry["message"] == FINISH_FILE_ENTRY_MSG

    done = registry.dispatch(
        ctx,
        "FinishRound",
        {
            "report": (
                "## 已排除\n- 旧路径 A\n\n"
                "## 建议后续方向\n- 去看 QuartzJobController\n"
            )
        },
    )
    assert done["ok"] is True
    text = (workspace_dir(project) / "rounds" / "round-4.md").read_text(encoding="utf-8")
    assert "旧路径 A" in text
    assert "去看 QuartzJobController" not in text
    assert "## 建议后续方向" not in text


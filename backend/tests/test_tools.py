from __future__ import annotations

import json
import os
import time

from app.services.ingest import build_file_index
from app.services.paths import docs_dir, old_vulns_dir, src_dir, vuln_dir, workspace_dir
from app.tools import ROLE_ACL, SHELL_TOOLS, ToolContext, ToolSpec, native_shell_tool, registry
from app.tools.common import load_todos, todo_relpath


def _ctx(project_id: int, role: str, **kwargs) -> ToolContext:
    return ToolContext(project_id=project_id, role=role, phase=role, **kwargs)


SEVERITY_FACTORS = {
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "cvss4_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    "submission_tier": "cve_candidate",
    "submission_reason": "未认证可达且可造成敏感数据/权限影响，有 CVE 价值",
}
BACKEND_USER_FACTORS = {
    **SEVERITY_FACTORS,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
    "cvss4_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
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


def test_mark_source_indexes_clojure_paths(tmp_env, project):
    from app.services.paths import src_dir

    src = src_dir(project)
    (src / "metabase").mkdir(parents=True, exist_ok=True)
    (src / "metabase" / "api.clj").write_text("(ns metabase.api)\n", encoding="utf-8")
    build_file_index(project)
    out = registry.dispatch(
        _ctx(project, "recon"),
        "MarkSource",
        {"file": "src/metabase/api.clj", "method": "POST /api/session"},
    )
    assert out["ok"] is True
    assert out["count"] == 1


def test_recon_gates_requires_docs_and_weights(tmp_env, project, monkeypatch):
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
    monkeypatch.setattr(
        "app.services.decompile_java.business_jar_coverage_pending",
        lambda pid: True,
    )
    pending_status = recon_gates_status(project)
    assert pending_status["ok"] is False
    assert any("仍在反编译" in e for e in pending_status["errors"])
    assert {s["id"]: s["done"] for s in pending_status["subphases"]}["mark"] is False
    assert recon_gates_met(project) is False
    assert apply_recon_done(project) is False
    monkeypatch.setattr(
        "app.services.decompile_java.business_jar_coverage_pending",
        lambda pid: False,
    )
    assert recon_gates_met(project) is True
    assert apply_recon_done(project) is True
    with Session() as db:
        p = db.get(models.Project, project)
        assert p.recon_done is True


def test_submit_vuln_requires_fields(tmp_env, project):
    out = registry.dispatch(_ctx(project, "worker"), "SubmitVuln", {"title": "x"})
    assert out["ok"] is False
    assert "缺少必填" in out["error"]


def test_submit_vuln_requires_config_premise(tmp_env, project):
    out = registry.dispatch(
        _ctx(project, "worker"),
        "SubmitVuln",
        {
            "title": "远程代码执行",
            "vuln_type": "rce",
            "cwe": "CWE-78",
            "file_path": "app/Main.java",
            "line_no": 1,
            "source_sink": "q -> exec",
            "auth_premise": "未授权",
            "http_request": "GET /x HTTP/1.1\nHost: x\n",
            "poc_code": (
                "import argparse\n"
                "p=argparse.ArgumentParser()\n"
                "p.add_argument('-u','--url',required=True)\n"
                "print(p.parse_args())\n"
            ),
            "expected_evidence": "id",
        },
    )
    assert out["ok"] is False
    assert "config_premise" in out["error"]


def test_submit_vuln_stores_config_premise(tmp_env, project):
    models = tmp_env["models"]
    Session = tmp_env["Session"]
    out = registry.dispatch(
        _ctx(project, "worker"),
        "SubmitVuln",
        {
            "title": "远程代码执行",
            "vuln_type": "rce",
            "cwe": "CWE-78",
            "file_path": "app/Main.java",
            "line_no": 1,
            "source_sink": "q -> exec",
            "auth_premise": "未授权",
            "config_premise": "特定配置",
            "http_request": "GET /x HTTP/1.1\nHost: x\n",
            "poc_code": (
                "import argparse\n"
                "p=argparse.ArgumentParser()\n"
                "p.add_argument('-u','--url',required=True)\n"
                "print(p.parse_args())\n"
            ),
            "expected_evidence": "id",
        },
    )
    assert out["ok"] is True
    assert out["config_premise"] == "specific"
    with Session() as db:
        vuln = db.get(models.Vuln, out["vuln_id"])
        assert vuln.config_premise == "specific"
    report = (vuln_dir(project, out["vuln_id"]) / "report.md").read_text(encoding="utf-8")
    assert "特定配置" in report


def test_confirm_vuln_can_override_config_premise(tmp_env, project):
    payload = {
        "title": "ping 接口远程代码执行",
        "vuln_type": "rce",
        "cwe": "CWE-78",
        "file_path": "app/Main.java",
        "line_no": 1,
        "source_sink": "ping -> exec",
        "auth_premise": "未授权",
        "config_premise": "default",
        "http_request": "GET /ping?cmd=id HTTP/1.1\nHost: x\n",
        "poc_code": "print('poc')\n",
        "expected_evidence": "uid=",
    }
    out = registry.dispatch(_ctx(project, "worker"), "SubmitVuln", payload)
    assert out["ok"] is True
    vuln_id = out["vuln_id"]
    confirmed = registry.dispatch(
        _ctx(project, "reviewer", vuln_id=vuln_id),
        "ConfirmVuln",
        {
            "vuln_id": vuln_id,
            "attack_surface": "frontend",
            "evidence_level": "static_only",
            "config_premise": "specific",
            **SEVERITY_FACTORS,
        },
    )
    assert confirmed["ok"] is True
    models = tmp_env["models"]
    Session = tmp_env["Session"]
    with Session() as db:
        vuln = db.get(models.Vuln, vuln_id)
        assert vuln.config_premise == "specific"
    report = (vuln_dir(project, vuln_id) / "report.md").read_text(encoding="utf-8")
    assert "配置前提：特定配置" in report


def test_submit_vuln_rejects_hardcoded_http_poc(tmp_env, project):
    out = registry.dispatch(
        _ctx(project, "worker"),
        "SubmitVuln",
        {
            "title": "远程代码执行",
            "vuln_type": "rce",
            "cwe": "CWE-78",
            "file_path": "app/Main.java",
            "line_no": 1,
            "source_sink": "q -> exec",
            "auth_premise": "未授权",
            "http_request": "GET /x HTTP/1.1\nHost: x\n",
            "poc_code": "import requests\nprint(requests.get('http://127.0.0.1:18080/x').text)\n",
            "expected_evidence": "id",
            "config_premise": "default",
        },
    )
    assert out["ok"] is False
    assert "-u/--url" in out["error"]
    assert "--proxy" in out["error"]


def test_submit_vuln_rejects_http_poc_without_proxy(tmp_env, project):
    out = registry.dispatch(
        _ctx(project, "worker"),
        "SubmitVuln",
        {
            "title": "远程代码执行",
            "vuln_type": "rce",
            "cwe": "CWE-78",
            "file_path": "app/Main.java",
            "line_no": 1,
            "source_sink": "q -> exec",
            "auth_premise": "未授权",
            "http_request": "GET /x HTTP/1.1\nHost: x\n",
            "poc_code": (
                "import argparse, urllib.request\n"
                "p=argparse.ArgumentParser()\n"
                "p.add_argument('-u','--url',required=True)\n"
                "print(urllib.request.urlopen(p.parse_args().url).read())\n"
            ),
            "expected_evidence": "id",
            "config_premise": "default",
        },
    )
    assert out["ok"] is False
    assert "--proxy" in out["error"]


def _set_target_kind(project_id: int, kind: str) -> None:
    from app.models import Project, SessionLocal

    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        assert proj is not None
        proj.target_kind = kind
        db.commit()


def _library_submit_payload(**overrides):
    body = {
        "title": "列表形态 agents 策略绕过",
        "vuln_type": "auth_bypass",
        "cwe": "CWE-284",
        "file_path": "src/pkg/core.py",
        "line_no": 980,
        "source_sink": "workflow.yaml agents list -> _check_tool_policy",
        "auth_premise": "调用方构造 recipe",
        "config_premise": "default",
        "http_request": "RecipeConfig(path=recipe_dir); _check_tool_policy(cfg)",
        "expected_evidence": "list-form agents bypass denied-tool policy",
        "root_cause_key": "auth_bypass:collect_workflow_declared_tools",
    }
    body.update(overrides)
    return body


def test_submit_library_vuln_omits_poc_file(tmp_env, project):
    from app.services.paths import vuln_dir

    _set_target_kind(project, "library")
    out = registry.dispatch(_ctx(project, "worker"), "SubmitVuln", _library_submit_payload())
    assert out["ok"] is True
    assert not (vuln_dir(project, out["vuln_id"]) / "poc.py").exists()
    report = (vuln_dir(project, out["vuln_id"]) / "report.md").read_text(encoding="utf-8")
    assert "无独立" in report or "harness.py" in report


def test_submit_library_vuln_rejects_dummy_http_cli(tmp_env, project):
    _set_target_kind(project, "library")
    out = registry.dispatch(
        _ctx(project, "worker"),
        "SubmitVuln",
        _library_submit_payload(
            poc_code=(
                "import argparse\n"
                "from pkg.api import parse\n"
                "p=argparse.ArgumentParser()\n"
                "p.add_argument('-u','--url',default='')\n"
                "p.add_argument('--proxy',default='')\n"
                "print(parse('../etc/passwd'))\n"
            ),
        ),
    )
    assert out["ok"] is False
    assert "未使用" in out["error"]


def test_submit_library_vuln_rejects_harness_copy(tmp_env, project):
    _set_target_kind(project, "library")
    out = registry.dispatch(
        _ctx(project, "worker"),
        "SubmitVuln",
        _library_submit_payload(
            poc_code=(
                "# Inlined from src/pkg/core.py; sandbox lacks yaml\n"
                "_MOCK_YAML_DATA = {}\n"
                "print('bypass')\n"
            ),
        ),
    )
    assert out["ok"] is False
    assert "harness" in out["error"]


def test_submit_library_vuln_allows_installed_package_poc(tmp_env, project):
    from app.services.paths import vuln_dir

    _set_target_kind(project, "library")
    poc = (
        "import argparse\n"
        "from pkg.api import parse\n"
        "p=argparse.ArgumentParser()\n"
        "p.add_argument('--artifact', default='target.jar')\n"
        "p.add_argument('--zh', action='store_true')\n"
        "print(parse(p.parse_args().artifact))\n"
    )
    out = registry.dispatch(
        _ctx(project, "worker"),
        "SubmitVuln",
        _library_submit_payload(poc_code=poc),
    )
    assert out["ok"] is True
    saved = (vuln_dir(project, out["vuln_id"]) / "poc.py").read_text(encoding="utf-8")
    assert "from pkg.api import parse" in saved
    assert "--url" not in saved


def test_submit_library_http_surface_still_requires_poc(tmp_env, project):
    _set_target_kind(project, "library")
    out = registry.dispatch(
        _ctx(project, "worker"),
        "SubmitVuln",
        _library_submit_payload(http_request="GET /api/x HTTP/1.1\nHost: x\n"),
    )
    assert out["ok"] is False
    assert "poc_code" in out["error"]



def test_confirm_vuln_can_rewrite_parameterized_poc(tmp_env, project):
    from app.services.poc_script import read_poc_code
    from app.services.paths import vuln_dir

    payload = {
        "title": "ping 接口远程代码执行",
        "vuln_type": "rce",
        "cwe": "CWE-78",
        "file_path": "app/Main.java",
        "line_no": 1,
        "source_sink": "ping -> exec",
        "auth_premise": "未授权",
        "http_request": "GET /ping?cmd=id HTTP/1.1\nHost: x\n",
        "poc_code": "print('poc')\n",
        "expected_evidence": "uid=",
        "config_premise": "default",
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
        "title": "登录处 SQL 注入",
        "vuln_type": "sqli",
        "cwe": "CWE-89",
        "file_path": "app/Main.java",
        "line_no": 1,
        "source_sink": "login -> query",
        "auth_premise": "未授权",
        "http_request": "GET /login?id=1 HTTP/1.1\nHost: x\n",
        "poc_code": "print('poc')\n",
        "expected_evidence": "error based",
        "config_premise": "default",
        "intended_behavior": False,
    }
    out = registry.dispatch(_ctx(project, "worker"), "SubmitVuln", payload)
    assert out["ok"] is True
    assert out["mining_path"] == "heuristic"
    vuln_id = out["vuln_id"]
    models = tmp_env["models"]
    Session = tmp_env["Session"]
    with Session() as db:
        submitted = db.get(models.Vuln, vuln_id)
        assert submitted.severity == "pending"
        assert submitted.mining_path == "heuristic"

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
    assert conf["severity_score"] == 7.5
    assert conf["cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    assert conf["cvss4_vector"] == "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
    assert conf["cvss4_score"] == 8.7
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
        assert v.cvss_score == 7.5
        assert v.cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        assert v.submission_tier == "cve_candidate"
        assert v.submission_reason
    advisory = (vuln_dir(project, vuln_id) / "advisory.md").read_text(encoding="utf-8")
    assert "**CVSS 3.1:** 7.5 High" in advisory
    assert "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" in advisory
    assert "**CVSS 4.0:** 8.7 High" in advisory
    assert "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N" in advisory
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
    assert "- CVSS 3.1：7.5" in report
    assert "- 评分向量：CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" in report
    assert "- CVSS 4.0：8.7" in report
    assert "- CVSS 4.0 向量：CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N" in report
    assert "- 价值分层：有 CVE 价值（cve_candidate）" in report
    assert "- 分层理由：" in report
    assert "原始类型映射" not in report
    assert "所需账号" not in report


def test_submit_vuln_sets_mining_path_by_role(tmp_env, project):
    def payload(title: str, file_path: str) -> dict:
        return {
            "title": title,
            "vuln_type": "rce",
            "cwe": "CWE-78",
            "file_path": file_path,
            "line_no": 1,
            "source_sink": "a -> b",
            "auth_premise": "未授权",
            "http_request": "GET /x HTTP/1.1\nHost: t\n",
            "poc_code": (
                "import argparse\n"
                "p=argparse.ArgumentParser()\n"
                "p.add_argument('-u','--url',required=True)\n"
                "print(p.parse_args())\n"
            ),
            "expected_evidence": "ok",
            "config_premise": "default",
        }

    models = tmp_env["models"]
    Session = tmp_env["Session"]

    fast = registry.dispatch(
        _ctx(project, "fast_worker"),
        "SubmitVuln",
        payload("快速扫描洞", "app/Fast.java"),
    )
    assert fast["ok"] is True
    assert fast["mining_path"] == "fast"

    bypass = registry.dispatch(
        _ctx(project, "bypass_worker"),
        "SubmitVuln",
        payload("绕过路径洞", "app/Bypass.java"),
    )
    assert bypass["ok"] is True
    assert bypass["mining_path"] == "bypass"

    unconstrained = registry.dispatch(
        _ctx(project, "unconstrained_worker"),
        "SubmitVuln",
        payload("无约束扫描洞", "app/Free.java"),
    )
    assert unconstrained["ok"] is True
    assert unconstrained["mining_path"] == "unconstrained"
    bypass_report = (vuln_dir(project, bypass["vuln_id"]) / "report.md").read_text(encoding="utf-8")
    assert "### 补丁绕过简析" in bypass_report
    tech_idx = bypass_report.index("## 漏洞技术细节")
    patch_idx = bypass_report.index("### 补丁绕过简析")
    sink_idx = bypass_report.index("### Source → Sink")
    assert tech_idx < patch_idx < sink_idx

    bad = registry.dispatch(
        _ctx(project, "bypass_worker"),
        "SubmitVuln",
        {
            **payload("绕过缺段", "app/BypassBad.java"),
            "report_md": "# 不完整报告\n\n## 漏洞描述\nonly partial\n",
        },
    )
    assert bad["ok"] is False
    assert "vuln-report-bypass.md" in bad["error"]

    with Session() as db:
        parent = db.get(models.Vuln, fast["vuln_id"])
        parent.status = "returned"
        parent.return_reason = "补证据"
        db.commit()

    fix = registry.dispatch(
        _ctx(project, "fix", vuln_id=fast["vuln_id"]),
        "SubmitVuln",
        payload("修复轮提交", "app/Fix.java"),
    )
    assert fix["ok"] is True
    assert fix["mining_path"] == "fast"

    with Session() as db:
        assert db.get(models.Vuln, fast["vuln_id"]).mining_path == "fast"
        assert db.get(models.Vuln, bypass["vuln_id"]).mining_path == "bypass"
        assert db.get(models.Vuln, fix["vuln_id"]).mining_path == "fast"


def test_confirm_requires_attack_surface(tmp_env, project):
    payload = {
        "title": "登录处 SQL 注入",
        "vuln_type": "sqli",
        "cwe": "CWE-89",
        "file_path": "app/Main.java",
        "line_no": 1,
        "source_sink": "login -> query",
        "auth_premise": "未授权",
        "http_request": "GET /login?id=1 HTTP/1.1\nHost: x\n",
        "poc_code": "print('poc')\n",
        "expected_evidence": "error based",
        "config_premise": "default",
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


def test_confirm_indirect_consumer_requires_section_and_caps_tier(tmp_env, project):
    _set_audit_mode(project, "full")
    indirect_section = (
        "### 触发条件\n\n"
        "WallFilter 本身不直接接收 HTTP 请求，须在上游业务应用中找到 SELECT 型 SQL 注入点，"
        "才能把恶意 SQL 传入 WallFilter；攻击者不能直接向 Druid 发送请求完成利用。"
    )
    payload = {
        "title": "Druid Wall 默认配置放行 INTO OUTFILE",
        "vuln_type": "sqli",
        "cwe": "CWE-89",
        "file_path": "src/wall/MySqlWallVisitor.java",
        "line_no": 174,
        "source_sink": "WallFilter -> MySQL",
        "auth_premise": "依赖上游注入",
        "http_request": "GET /api/search?q=1 HTTP/1.1\nHost: x\n",
        "poc_code": (
            "import argparse\n"
            "p=argparse.ArgumentParser()\n"
            "p.add_argument('-u','--url',required=True)\n"
            "p.add_argument('--proxy',default='')\n"
            "print(p.parse_args())\n"
        ),
        "expected_evidence": "harness 绕过 wall",
        "config_premise": "default",
    }
    out = registry.dispatch(_ctx(project, "worker"), "SubmitVuln", payload)
    assert out["ok"] is True
    vuln_id = out["vuln_id"]
    report_path = vuln_dir(project, vuln_id) / "report.md"
    report_path.write_text(
        f"# Druid Wall 绕过\n\n## 漏洞危害\n\n危害说明。\n\n{indirect_section}\n",
        encoding="utf-8",
    )
    reviewer = _ctx(project, "reviewer", vuln_id=vuln_id)

    missing_section = registry.dispatch(
        reviewer,
        "ConfirmVuln",
        {
            "vuln_id": vuln_id,
            "evidence_level": "static_only",
            "attack_surface": "backend",
            "required_account": "user",
            "exposure_mode": "indirect_consumer",
            "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:L/A:N",
            "cvss4_vector": "CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N",
            "submission_tier": "low_impact",
            "submission_reason": "须上游 SELECT 注入链",
        },
    )
    assert missing_section["ok"] is False
    assert "AV" in missing_section["error"]

    report_path = vuln_dir(project, vuln_id) / "report.md"
    report_path.write_text("# 无触发条件章节\n\n## 漏洞危害\n\n只有危害。\n", encoding="utf-8")
    no_section = registry.dispatch(
        reviewer,
        "ConfirmVuln",
        {
            "vuln_id": vuln_id,
            "evidence_level": "static_only",
            "attack_surface": "backend",
            "required_account": "user",
            "exposure_mode": "indirect_consumer",
            "cvss_vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:L/A:N",
            "cvss4_vector": "CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N",
            "submission_tier": "low_impact",
            "submission_reason": "须上游 SELECT 注入链",
        },
    )
    assert no_section["ok"] is False
    assert "触发条件" in no_section["error"]
    report_path.write_text(
        f"# Druid Wall 绕过\n\n## 漏洞危害\n\n危害说明。\n\n{indirect_section}\n",
        encoding="utf-8",
    )

    bad_tier = registry.dispatch(
        reviewer,
        "ConfirmVuln",
        {
            "vuln_id": vuln_id,
            "evidence_level": "static_only",
            "attack_surface": "backend",
            "required_account": "user",
            "exposure_mode": "indirect_consumer",
            "cvss_vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:L/A:N",
            "cvss4_vector": "CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N",
            "submission_tier": "cve_candidate",
            "submission_reason": "错误分层",
        },
    )
    assert bad_tier["ok"] is False
    assert "cve_candidate" in bad_tier["error"]

    ok = registry.dispatch(
        reviewer,
        "ConfirmVuln",
        {
            "vuln_id": vuln_id,
            "evidence_level": "static_only",
            "attack_surface": "backend",
            "required_account": "user",
            "exposure_mode": "indirect_consumer",
            "cvss_vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:L/A:N",
            "cvss4_vector": "CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N",
            "submission_tier": "low_impact",
            "submission_reason": "组件缺陷成立但须上游 SELECT 注入链，真实环境难直接利用",
        },
    )
    assert ok["ok"] is True
    assert ok["exposure_mode"] == "indirect_consumer"
    assert ok["upstream_chain_proven"] is False
    assert ok["severity_score"] < 8.1

    models = tmp_env["models"]
    Session = tmp_env["Session"]
    with Session() as db:
        v = db.get(models.Vuln, vuln_id)
        assert v.exposure_mode == "indirect_consumer"
        assert v.upstream_chain_proven is False
        assert v.submission_tier == "low_impact"


def test_confirm_requires_severity_factors(tmp_env, project):
    payload = {
        "title": "服务端请求伪造",
        "vuln_type": "ssrf",
        "cwe": "CWE-918",
        "file_path": "app/Main.java",
        "line_no": 1,
        "source_sink": "url -> requests.get",
        "auth_premise": "未授权",
        "http_request": "GET /fetch?url=http://127.0.0.1 HTTP/1.1\n",
        "poc_code": "print(1)\n",
        "expected_evidence": "internal response",
        "config_premise": "default",
    }
    out = registry.dispatch(_ctx(project, "worker"), "SubmitVuln", payload)
    vuln_id = out["vuln_id"]
    conf = registry.dispatch(
        _ctx(project, "reviewer"),
        "ConfirmVuln",
        {"vuln_id": vuln_id, "attack_surface": "frontend"},
    )
    assert conf["ok"] is False
    assert "cvss_vector" in conf["error"]


def test_confirm_rejects_invalid_cvss_vector(tmp_env, project):
    payload = {
        "title": "服务端请求伪造",
        "vuln_type": "ssrf",
        "cwe": "CWE-918",
        "file_path": "app/Main.java",
        "line_no": 1,
        "source_sink": "url -> requests.get",
        "auth_premise": "未授权",
        "http_request": "GET /fetch?url=http://127.0.0.1 HTTP/1.1\n",
        "poc_code": "print(1)\n",
        "expected_evidence": "internal response",
        "config_premise": "default",
    }
    out = registry.dispatch(_ctx(project, "worker"), "SubmitVuln", payload)
    conf = registry.dispatch(
        _ctx(project, "reviewer"),
        "ConfirmVuln",
        {
            "vuln_id": out["vuln_id"],
            "attack_surface": "frontend",
            "cvss_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "cvss4_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
            "submission_tier": "cve_candidate",
            "submission_reason": "未认证 SSRF",
        },
    )
    assert conf["ok"] is False
    assert "CVSS:3.1" in conf["error"]
    assert "3.0" in conf["error"]
    missing = registry.dispatch(
        _ctx(project, "reviewer"),
        "ConfirmVuln",
        {
            "vuln_id": out["vuln_id"],
            "attack_surface": "frontend",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",
            "cvss4_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
            "submission_tier": "cve_candidate",
            "submission_reason": "未认证 SSRF",
        },
    )
    assert missing["ok"] is False
    assert "缺少必填度量" in missing["error"]
    assert "A（" in missing["error"]


def test_confirm_requires_submission_tier(tmp_env, project):
    payload = {
        "title": "服务端请求伪造",
        "vuln_type": "ssrf",
        "cwe": "CWE-918",
        "file_path": "app/Main.java",
        "line_no": 1,
        "source_sink": "url -> requests.get",
        "auth_premise": "未授权",
        "http_request": "GET /fetch?url=http://127.0.0.1 HTTP/1.1\n",
        "poc_code": "print(1)\n",
        "expected_evidence": "internal response",
        "config_premise": "default",
    }
    out = registry.dispatch(_ctx(project, "worker"), "SubmitVuln", payload)
    vuln_id = out["vuln_id"]
    conf = registry.dispatch(
        _ctx(project, "reviewer"),
        "ConfirmVuln",
        {
            "vuln_id": vuln_id,
            "attack_surface": "frontend",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "cvss4_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
        },
    )
    assert conf["ok"] is False
    assert "submission_tier" in conf["error"]


def test_confirm_rejects_needs_more_evidence_tier(tmp_env, project):
    payload = {
        "title": "SQL 注入",
        "vuln_type": "sqli",
        "cwe": "CWE-89",
        "file_path": "app/Main.java",
        "line_no": 1,
        "source_sink": "login -> query",
        "auth_premise": "未授权",
        "http_request": "GET /login?id=1 HTTP/1.1\nHost: x\n",
        "poc_code": "print('poc')\n",
        "expected_evidence": "error based",
        "config_premise": "default",
    }
    out = registry.dispatch(_ctx(project, "worker"), "SubmitVuln", payload)
    conf = registry.dispatch(
        _ctx(project, "reviewer"),
        "ConfirmVuln",
        {
            "vuln_id": out["vuln_id"],
            "evidence_level": "static_only",
            "attack_surface": "frontend",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cvss4_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
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
        "title": "CORS 配置不当",
        "vuln_type": "other",
        "cwe": "CWE-942",
        "file_path": "app/Main.java",
        "line_no": 1,
        "source_sink": "Origin -> ACAO",
        "auth_premise": "未授权",
        "http_request": "GET / HTTP/1.1\n",
        "poc_code": "print(1)\n",
        "expected_evidence": "reflected origin",
        "config_premise": "default",
    }
    out = registry.dispatch(worker, "SubmitVuln", payload)
    vuln_id = out["vuln_id"]
    hard = registry.dispatch(
        _ctx(project, "reviewer"),
        "ConfirmVuln",
        {
            "vuln_id": vuln_id,
            "attack_surface": "frontend",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
            "cvss4_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N",
            "submission_tier": "低危害难利用",
            "submission_reason": "CORS 配置问题，默认按低危害难利用处理",
        },
    )
    assert hard["ok"] is True
    assert hard["submission_tier"] == "low_impact"

    payload2 = dict(payload)
    payload2["title"] = "再次 CORS 配置不当"
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
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
            "cvss4_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N",
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
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
            "cvss4_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N",
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
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
            "cvss4_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N",
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
    payload3["title"] = "第三条 CORS 配置不当"
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
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
            "cvss4_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N",
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
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
                "cvss4_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N",
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
        "title": "登录处 SQL 注入",
        "vuln_type": "sqli",
        "cwe": "CWE-89",
        "file_path": "app/Main.java",
        "line_no": 1,
        "source_sink": "login -> query",
        "auth_premise": "未授权",
        "http_request": "GET /login?id=1 HTTP/1.1\nHost: x\n",
        "poc_code": "print('poc')\n",
        "expected_evidence": "error based",
        "config_premise": "default",
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
    from app.services.lab import save_env

    with SessionLocal() as db:
        proj = db.get(Project, project)
        proj.dynamic_verify_enabled = True
        db.commit()
    save_env(
        project,
        {"accepted": True, "status": "running", "target_url": "http://127.0.0.1:18080"},
    )
    payload = {
        "title": "登录处 SQL 注入",
        "vuln_type": "sqli",
        "cwe": "CWE-89",
        "file_path": "app/Main.java",
        "line_no": 1,
        "source_sink": "login -> query",
        "auth_premise": "未授权",
        "http_request": "GET /login?id=1 HTTP/1.1\nHost: x\n",
        "poc_code": (
            "import argparse\n"
            "p = argparse.ArgumentParser()\n"
            "p.add_argument('-u', '--url', required=True)\n"
            "p.add_argument('--proxy', default='')\n"
            "args = p.parse_args()\n"
            "print('hit', args.url)\n"
        ),
        "expected_evidence": "error based",
        "config_premise": "default",
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
    assert conf["ok"] is True, conf
    assert conf["evidence_level"] == "dynamic"
    assert conf["status"] == "confirmed"
    assert conf["poc_run"]["exit_code"] == 0
    assert "http://127.0.0.1:18080" in conf["poc_run"]["stdout"]


def test_collect_lab_fingerprints_allows_static_only(tmp_env, project, monkeypatch):
    from app.services.lab import save_env

    payload = {
        "title": "登录处 SQL 注入",
        "vuln_type": "sqli",
        "cwe": "CWE-89",
        "file_path": "app/Main.java",
        "line_no": 1,
        "source_sink": "login -> query",
        "auth_premise": "未授权",
        "http_request": "GET /login?id=1 HTTP/1.1\nHost: x\n",
        "poc_code": "print('poc')\n",
        "expected_evidence": "error based",
        "config_premise": "default",
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
            "title": "反射型 XSS",
            "vuln_type": "反射XSS",
            "cwe": "CWE-79",
            "file_path": "app/Main.java",
            "line_no": 1,
            "source_sink": "q -> HTML",
            "auth_premise": "未授权",
            "http_request": "GET /?q=<script> HTTP/1.1\n",
            "poc_code": "print(1)\n",
            "expected_evidence": "script echoed",
            "config_premise": "default",
        },
    )
    assert xss["ok"] is False
    assert "赏金模式" in xss["error"]

    payload = {
        "title": "CORS 配置不当",
        "vuln_type": "other",
        "cwe": "CWE-942",
        "file_path": "app/Main.java",
        "line_no": 1,
        "source_sink": "Origin -> ACAO",
        "auth_premise": "未授权",
        "http_request": "GET / HTTP/1.1\n",
        "poc_code": "print(1)\n",
        "expected_evidence": "reflected origin",
        "config_premise": "default",
    }
    out = registry.dispatch(_ctx(project, "worker"), "SubmitVuln", payload)
    assert out["ok"] is True
    hard = registry.dispatch(
        _ctx(project, "reviewer"),
        "ConfirmVuln",
        {
            "vuln_id": out["vuln_id"],
            "attack_surface": "frontend",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
            "cvss4_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N",
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
            "title": "评论存储型 XSS",
            "vuln_type": "xss",
            "cwe": "CWE-79",
            "file_path": "app/Comment.java",
            "line_no": 12,
            "source_sink": "comment -> 存储型XSS HTML",
            "auth_premise": "登录用户",
            "http_request": "POST /comment HTTP/1.1\n",
            "poc_code": "print(1)\n",
            "expected_evidence": "script persists",
            "config_premise": "default",
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
            **BACKEND_USER_FACTORS,
            "submission_reason": "存储型 XSS 可在其他用户浏览器执行",
            "root_cause_key": "stored_xss:Comment",
        },
    )
    assert confirmed["ok"] is True

    csrf = registry.dispatch(
        _ctx(project, "worker"),
        "SubmitVuln",
        {
            "title": "一键 CSRF 安装插件导致远程代码执行",
            "vuln_type": "csrf",
            "cwe": "CWE-352",
            "file_path": "app/PluginController.java",
            "line_no": 40,
            "source_sink": "POST /admin/plugin/install -> Runtime.exec",
            "auth_premise": "已登录管理员打开恶意页",
            "http_request": "POST /admin/plugin/install HTTP/1.1\n",
            "poc_code": "print(1)\n",
            "expected_evidence": "auto-submit installs plugin and executes command",
            "config_premise": "default",
        },
    )
    assert csrf["ok"] is True
    with Session() as db:
        row = db.get(models.Vuln, csrf["vuln_id"])
        assert row.vuln_type == "csrf"
    csrf_low = registry.dispatch(
        _ctx(project, "reviewer"),
        "ConfirmVuln",
        {
            "vuln_id": csrf["vuln_id"],
            "attack_surface": "backend",
            "required_account": "admin",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:U/C:N/I:L/A:N",
            "cvss4_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:P/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N",
            "submission_tier": "cve_candidate",
            "submission_reason": "1-click CSRF，打开恶意页面即触发高危操作",
            "root_cause_key": "csrf:PluginController",
        },
    )
    assert csrf_low["ok"] is False
    assert "1-click CSRF" in csrf_low["error"]
    csrf_ok = registry.dispatch(
        _ctx(project, "reviewer"),
        "ConfirmVuln",
        {
            "vuln_id": csrf["vuln_id"],
            "attack_surface": "backend",
            "required_account": "admin",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
            "cvss4_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            "submission_tier": "cve_candidate",
            "submission_reason": "打开恶意页面即触发插件安装 RCE",
            "root_cause_key": "csrf:PluginController",
        },
    )
    assert csrf_ok["ok"] is True

    secret = registry.dispatch(
        _ctx(project, "worker"),
        "SubmitVuln",
        {
            "title": "硬编码 JWT 密钥",
            "vuln_type": "hardcoded_secret",
            "cwe": "CWE-798",
            "file_path": "app/JwtHelper.java",
            "line_no": 8,
            "source_sink": "SECRET constant -> JWT sign",
            "auth_premise": "未授权",
            "http_request": "GET / HTTP/1.1\n",
            "poc_code": "print(1)\n",
            "expected_evidence": "forged token accepted",
            "config_premise": "default",
        },
    )
    assert secret["ok"] is True

    config_secret = registry.dispatch(
        _ctx(project, "worker"),
        "SubmitVuln",
        {
            "title": "配置文件默认口令",
            "vuln_type": "hardcoded_secret",
            "cwe": "CWE-798",
            "file_path": "src/main/resources/application.yml",
            "line_no": 4,
            "source_sink": "spring.datasource.password",
            "auth_premise": "未授权",
            "http_request": "GET / HTTP/1.1\n",
            "poc_code": "print(1)\n",
            "expected_evidence": "default password",
            "config_premise": "default",
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
            "title": "反射型 XSS",
            "vuln_type": "xss",
            "cwe": "CWE-79",
            "file_path": "app/Main.java",
            "line_no": 1,
            "source_sink": "q -> HTML",
            "auth_premise": "未授权",
            "http_request": "GET /?q=<script> HTTP/1.1\n",
            "poc_code": "print(1)\n",
            "expected_evidence": "script echoed",
            "config_premise": "default",
        },
    )
    assert out["ok"] is True
    assert out["status"] == "pending_review"


def test_confirm_backend_requires_account(tmp_env, project):
    payload = {
        "title": "登录处 SQL 注入",
        "vuln_type": "sqli",
        "cwe": "CWE-89",
        "file_path": "app/Main.java",
        "line_no": 1,
        "source_sink": "login -> query",
        "auth_premise": "管理员",
        "http_request": "GET /admin HTTP/1.1\nHost: x\n",
        "poc_code": "print('poc')\n",
        "expected_evidence": "error based",
        "config_premise": "default",
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
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
            "cvss4_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
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
        "title": "越权访问",
        "vuln_type": "privilege_escalation",
        "cwe": "CWE-639",
        "file_path": "app/Main.java",
        "line_no": 1,
        "source_sink": "id -> query",
        "auth_premise": "登录后",
        "http_request": "GET /user/1 HTTP/1.1\n",
        "poc_code": "print(1)\n",
        "expected_evidence": "other user data",
        "config_premise": "default",
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
            **BACKEND_USER_FACTORS,
        },
    )
    assert conf["ok"] is True
    assert conf["required_account"] == "user"
    assert conf["required_account_label"] == "普通权限"
    assert conf["severity"] == "high"
    assert conf["severity_score"] == 8.1
    report = (vuln_dir(project, vuln_id) / "report.md").read_text(encoding="utf-8")
    assert "- 所需账号：普通权限" in report


def test_confirm_rejects_pr_mismatch_with_attack_surface(tmp_env, project):
    payload = {
        "title": "存储型 XSS",
        "vuln_type": "stored_xss",
        "cwe": "CWE-79",
        "file_path": "app/Comment.java",
        "line_no": 1,
        "source_sink": "comment -> html",
        "auth_premise": "登录用户",
        "http_request": "POST /comment HTTP/1.1\n",
        "poc_code": "print(1)\n",
        "expected_evidence": "script persists",
        "config_premise": "default",
    }
    out = registry.dispatch(_ctx(project, "worker"), "SubmitVuln", payload)
    backend_pr_n = registry.dispatch(
        _ctx(project, "reviewer"),
        "ConfirmVuln",
        {
            "vuln_id": out["vuln_id"],
            "attack_surface": "backend",
            "required_account": "user",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
            "cvss4_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:N/VA:N/SC:H/SI:H/SA:N",
            "submission_tier": "cve_candidate",
            "submission_reason": "存储型 XSS",
            "root_cause_key": "stored_xss:Comment",
        },
    )
    assert backend_pr_n["ok"] is False
    assert "PR" in backend_pr_n["error"]
    assert "PR:L" in backend_pr_n["error"]
    assert "PR:N" in backend_pr_n["error"]

    frontend = registry.dispatch(
        _ctx(project, "worker"),
        "SubmitVuln",
        {**payload, "title": "前台泄露", "file_path": "app/Public.java", "vuln_type": "sqli"},
    )
    frontend_pr_l = registry.dispatch(
        _ctx(project, "reviewer"),
        "ConfirmVuln",
        {
            "vuln_id": frontend["vuln_id"],
            "attack_surface": "frontend",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
            "cvss4_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
            "submission_tier": "cve_candidate",
            "submission_reason": "未认证泄露",
        },
    )
    assert frontend_pr_l["ok"] is False
    assert "PR:N" in frontend_pr_l["error"]

    admin = registry.dispatch(
        _ctx(project, "worker"),
        "SubmitVuln",
        {**payload, "title": "管理员配置 XSS", "file_path": "app/AdminConfig.java"},
    )
    admin_pr_l = registry.dispatch(
        _ctx(project, "reviewer"),
        "ConfirmVuln",
        {
            "vuln_id": admin["vuln_id"],
            "attack_surface": "backend",
            "required_account": "admin",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",
            "cvss4_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N",
            "submission_tier": "cve_candidate",
            "submission_reason": "管理员存储型 XSS",
            "root_cause_key": "stored_xss:AdminConfig",
        },
    )
    assert admin_pr_l["ok"] is False
    assert "PR:H" in admin_pr_l["error"]

    aligned = registry.dispatch(
        _ctx(project, "reviewer"),
        "ConfirmVuln",
        {
            "vuln_id": out["vuln_id"],
            "attack_surface": "backend",
            "required_account": "user",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",
            "cvss4_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N",
            "submission_tier": "cve_candidate",
            "submission_reason": "存储型 XSS",
            "root_cause_key": "stored_xss:Comment",
        },
    )
    assert aligned["ok"] is True
    rewrite = registry.dispatch(
        _ctx(project, "reviewer", vuln_id=out["vuln_id"]),
        "SetCveRecordField",
        {
            "path": "containers.cna.metrics[0].cvssV3_1.vectorString",
            "value": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
        },
    )
    assert rewrite["ok"] is False
    assert "PR:L" in rewrite["error"]


def test_confirm_frontend_ignores_account(tmp_env, project):
    payload = {
        "title": "SQL 注入",
        "vuln_type": "sqli",
        "cwe": "CWE-89",
        "file_path": "app/Main.java",
        "line_no": 1,
        "source_sink": "a->b",
        "auth_premise": "未授权",
        "http_request": "GET / HTTP/1.1\n",
        "poc_code": "print(1)\n",
        "expected_evidence": "error based",
        "config_premise": "default",
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


def test_mark_false_positive(tmp_env, project):
    payload = {
        "title": "预期行为",
        "vuln_type": "info_disclosure",
        "cwe": "CWE-200",
        "file_path": "app/Main.java",
        "line_no": 2,
        "source_sink": "a->b",
        "auth_premise": "登录后",
        "http_request": "GET / HTTP/1.1\n",
        "poc_code": "print(1)\n",
        "expected_evidence": "ok",
        "config_premise": "default",
        "intended_behavior": True,
    }
    out = registry.dispatch(_ctx(project, "worker"), "SubmitVuln", payload)
    vuln_id = out["vuln_id"]
    ret = registry.dispatch(
        _ctx(project, "reviewer"),
        "MarkFalsePositive",
        {"vuln_id": vuln_id, "reason": "已知业务能力"},
    )
    assert ret["status"] == "false_positive"
    report = (vuln_dir(project, vuln_id) / "report.md").read_text(encoding="utf-8")
    assert report.rstrip().endswith("已知业务能力")
    assert "## 误报判定" in report
    assert report.index("## 误报判定") > report.index("# 预期行为")


def test_return_to_worker_false_positive_compat(tmp_env, project):
    payload = {
        "title": "遗留误报",
        "vuln_type": "info_disclosure",
        "cwe": "CWE-200",
        "file_path": "app/Main.java",
        "line_no": 2,
        "source_sink": "a->b",
        "auth_premise": "登录后",
        "http_request": "GET / HTTP/1.1\n",
        "poc_code": "print(1)\n",
        "expected_evidence": "ok",
        "config_premise": "default",
        "intended_behavior": False,
    }
    out = registry.dispatch(_ctx(project, "worker"), "SubmitVuln", payload)
    vuln_id = out["vuln_id"]
    ret = registry.dispatch(
        _ctx(project, "reviewer"),
        "ReturnToWorker",
        {"vuln_id": vuln_id, "reason": "旧参数误报", "false_positive": True},
    )
    assert ret["status"] == "false_positive"


def test_return_to_worker_keeps_report_when_not_fp(tmp_env, project):
    payload = {
        "title": "待修复",
        "vuln_type": "sqli",
        "cwe": "CWE-89",
        "file_path": "app/Main.java",
        "line_no": 1,
        "source_sink": "login -> query",
        "auth_premise": "未授权",
        "http_request": "GET /login?id=1 HTTP/1.1\nHost: x\n",
        "poc_code": "print('poc')\n",
        "expected_evidence": "error based",
        "config_premise": "default",
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
        "title": "不稳定复现",
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
        "intended_behavior": False,
    }
    out = registry.dispatch(_ctx(project, "worker"), "SubmitVuln", payload)
    vuln_id = out["vuln_id"]
    models = tmp_env["models"]
    Session = tmp_env["Session"]
    with Session() as db:
        v = db.get(models.Vuln, vuln_id)
        v.review_rounds = 1
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
    assert load_todos(worker_a)[0]["content"] == "worker-a"
    file_only = ToolContext(project_id=project, role="worker", phase="worker", worker_id="worker-1-abc")
    assert load_todos(file_only)[0]["content"] == "worker-a"


def test_openai_tools_for_role_contains_expected(tmp_env, project):
    recon_names = {t["function"]["name"] for t in registry.openai_tools_for_role("recon")}
    assert "FinishRecon" not in recon_names
    assert "WriteOldVuln" not in recon_names
    assert "SearchGHSA" not in recon_names
    assert "WebSearch" not in recon_names
    assert "MarkSource" in recon_names
    assert "FinishReconMap" in recon_names
    assert "ListBytecode" in recon_names
    assert "DecompileJava" in recon_names
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
    assert "SearchTools" in reviewer_names
    assert "ListBytecode" in reviewer_names
    assert "DecompileJava" in reviewer_names
    assert "ConfirmVuln" in reviewer_names
    assert "MarkFalsePositive" in reviewer_names
    assert "ReturnToWorker" in reviewer_names
    assert "RequestLabRebuild" in reviewer_names
    assert "RunCode" not in reviewer_names
    assert "CollectLabFingerprints" in reviewer_names
    assert "FinishLab" not in reviewer_names
    reviewer_descs = {
        t["function"]["name"]: t["function"]["description"]
        for t in registry.openai_tools_for_role("reviewer")
    }
    assert "分析债务" in reviewer_descs["ReturnToWorker"]
    assert "MarkFalsePositive" in reviewer_descs["ReturnToWorker"]
    assert "不要用来改 PoC" in reviewer_descs["MarkFalsePositive"]
    assert "无害/受限文件操作" in reviewer_descs["ConfirmVuln"]
    assert "不可获取且不可预测" in reviewer_descs["ConfirmVuln"]
    assert "无害/受限文件操作" in reviewer_descs["MarkFalsePositive"]
    assert "不可获取且不可预测" in reviewer_descs["MarkFalsePositive"]
    worker_descs = {
        t["function"]["name"]: t["function"]["description"]
        for t in registry.openai_tools_for_role("worker")
    }
    assert "无害/受限文件操作" in worker_descs["SubmitVuln"]
    assert "不可获取且不可预测" in worker_descs["SubmitVuln"]
    lab_names = {t["function"]["name"] for t in registry.openai_tools_for_role("reviewer_lab")}
    assert "FinishLab" in lab_names
    assert "Write" in lab_names
    assert "ConfirmVuln" not in lab_names
    assert "CollectLabFingerprints" not in lab_names
    assert "ReturnToWorker" not in lab_names
    assert "RequestLabRebuild" not in lab_names
    assert "MarkFalsePositive" not in lab_names
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


def test_grep_path_glob_matches_nested_java(tmp_env, project):
    nested = registry.dispatch(
        _ctx(project, "recon"),
        "Grep",
        {"pattern": "class Main", "glob": "**/*.java", "root": "src"},
    )
    assert nested["ok"] is True
    paths = [h["path"].replace("\\", "/") for h in nested.get("hits") or []]
    assert any(p.endswith("app/Main.java") or p.endswith("Main.java") for p in paths)
    by_ext = registry.dispatch(
        _ctx(project, "recon"),
        "Grep",
        {"pattern": "class Main", "glob": "*.java", "root": "src"},
    )
    assert by_ext["ok"] is True
    assert by_ext.get("hits")
    py_only = registry.dispatch(
        _ctx(project, "recon"),
        "Grep",
        {"pattern": "class Main", "glob": "**/*.py", "root": "src"},
    )
    assert py_only["ok"] is True
    assert not py_only.get("hits")


def test_grep_default_skips_binary_extensions(tmp_env, project):
    """Default Grep (no glob) must skip .png/.jar/.gif etc. so a 1 GB / 45 k-file
    repo doesn't block the worker round for 15+ minutes per call.
    """
    from app.services.paths import src_dir

    src = src_dir(project)
    big_img = src / "app" / "logo.png"
    # 6 bytes: PNG signature. Just enough to be a non-empty file with the ext.
    big_img.write_bytes(b"\x89PNG\r\n\x1a\n")
    big_jar = src / "app" / "lib.jar"
    big_jar.write_bytes(b"PK\x03\x04fake jar payload for the binary skip test")
    (src / "app" / "Util.java").write_text(
        "class Util { void sink() { System.out.println(\"unique-marker-xyz\"); } }\n",
        encoding="utf-8",
    )

    # Without glob, default-text extension filter applies: .png/.jar skipped, .java kept.
    out = registry.dispatch(
        _ctx(project, "recon"),
        "Grep",
        {"pattern": "unique-marker-xyz", "root": "src"},
    )
    assert out["ok"] is True
    paths = [h["path"].replace("\\", "/") for h in out.get("hits") or []]
    assert any(p.endswith("app/Util.java") for p in paths)
    assert not any(p.endswith(".png") or p.endswith(".jar") for p in paths)
    stats = out.get("stats") or {}
    assert stats.get("skipped_binary", 0) >= 2

    # Caller can opt out by glob=**/* — every file is scanned.
    out_all = registry.dispatch(
        _ctx(project, "recon"),
        "Grep",
        {"pattern": "unique-marker-xyz", "root": "src", "glob": "**/*"},
    )
    assert out_all["ok"] is True
    # No text hits inside .png/.jar; stats.skipped_binary should be 0 since
    # the caller explicitly asked to scan everything.
    assert (out_all.get("stats") or {}).get("skipped_binary", 0) == 0


def test_grep_caps_total_bytes_and_reports_truncated(tmp_env, project):
    from app.services.paths import src_dir

    src = src_dir(project)
    target_dir = src / "app"
    target_dir.mkdir(parents=True, exist_ok=True)
    pad = "a" * 200 + " "
    # 200 files × ~600 bytes each ≈ 120 KB, well over a 4 KB cap.
    for i in range(200):
        (target_dir / f"F{i:03d}.java").write_text(f"// marker-{i}\n{pad}\n", encoding="utf-8")

    out = registry.dispatch(
        _ctx(project, "recon"),
        "Grep",
        {
            "pattern": "marker-",
            "root": "src",
            "max_total_bytes": 4096,
            "max_file_bytes": 1024 * 1024,
        },
    )
    assert out["ok"] is True
    assert out["truncated"] is True
    assert (out.get("stats") or {}).get("bytes_scanned", 0) <= 4096
    assert out.get("hint")


def test_grep_skips_oversized_files(tmp_env, project):
    from app.services.paths import src_dir

    src = src_dir(project)
    target = src / "app" / "Big.java"
    target.write_text("x" * (2 * 1024 * 1024) + "\nclass Big {}\n", encoding="utf-8")

    out = registry.dispatch(
        _ctx(project, "recon"),
        "Grep",
        {"pattern": "class Big", "root": "src", "max_file_bytes": 64 * 1024},
    )
    assert out["ok"] is True
    assert not out.get("hits")
    assert (out.get("stats") or {}).get("skipped_size", 0) >= 1


def test_shell_timeout_kills_process(tmp_env, project):
    tool = native_shell_tool()
    command = "Start-Sleep -Seconds 30" if tool == "PowerShell" else "sleep 30"
    started = time.time()
    out = registry.dispatch(_ctx(project, "recon"), tool, {"command": command, "timeout": 2})
    assert out["ok"] is False
    assert "超时" in (out.get("error") or "")
    assert time.time() - started < 15


def test_shell_auto_prunes_docker_build_cache(tmp_env, project, monkeypatch):
    import app.tools.common as common
    from app.services.docker_service import docker_service

    tool = native_shell_tool()
    monkeypatch.setattr(common, "_run_shell_limited", lambda *args, **kwargs: (0, "built", "", None))
    monkeypatch.setattr(common.settings, "docker_auto_prune_build_cache", True)
    monkeypatch.setattr(common.settings, "docker_auto_prune_build_cache_all", False)
    monkeypatch.setattr(common.settings, "docker_auto_prune_build_cache_keep_storage_mb", 0)
    calls = []

    def fake_prune_build_cache(*, all_unused=False, keep_storage_mb=None):
        calls.append({"all_unused": all_unused, "keep_storage_mb": keep_storage_mb})
        return {"skipped": False, "freed_bytes": 123, "freed_mb": 0.0, "errors": []}

    monkeypatch.setattr(docker_service, "prune_build_cache", fake_prune_build_cache)

    out = registry.dispatch(_ctx(project, "recon"), tool, {"command": "docker build -t demo ."})
    assert out["ok"] is True
    assert out["docker_build_cache_prune"]["freed_bytes"] == 123
    assert calls == [{"all_unused": False, "keep_storage_mb": 0}]

    normal = registry.dispatch(_ctx(project, "recon"), tool, {"command": "echo no docker"})
    assert normal["ok"] is True
    assert "docker_build_cache_prune" not in normal
    assert calls == [{"all_unused": False, "keep_storage_mb": 0}]


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


def test_normalize_weight_path_keeps_hidden_files():
    from app.tools.phase_recon import normalize_weight_path

    assert normalize_weight_path(".flattened-pom.xml") == ".flattened-pom.xml"
    assert normalize_weight_path("./.flattened-pom.xml") == ".flattened-pom.xml"
    assert normalize_weight_path("./src/main/java/Foo.java") == "src/main/java/Foo.java"
    assert normalize_weight_path("src/app/Main.java") == "src/app/Main.java"


def test_mark_skip_hidden_flattened_pom(tmp_env, project):
    from app.tools.phase_recon import paths_fully_marked

    models = tmp_env["models"]
    Session = tmp_env["Session"]
    hidden = ".flattened-pom.xml"
    with Session() as db:
        db.add(
            models.FileWeight(
                project_id=project,
                path=hidden,
                weight=None,
                skipped=False,
                audited=False,
                has_source=False,
            )
        )
        db.commit()

    out = registry.dispatch(_ctx(project, "recon_mark"), "MarkSkip", {"path": hidden})
    assert out["ok"] is True
    assert out["skipped"] == [hidden]
    assert paths_fully_marked(project, [hidden]) is True


def test_skip_non_source_weight_rows_unblocks_hidden_files(tmp_env, project):
    from app.tools.phase_recon import paths_fully_marked, skip_non_source_weight_rows

    models = tmp_env["models"]
    Session = tmp_env["Session"]
    hidden = ".flattened-pom.xml"
    with Session() as db:
        db.add(
            models.FileWeight(
                project_id=project,
                path=hidden,
                weight=None,
                skipped=False,
                audited=False,
                has_source=False,
            )
        )
        db.commit()

    assert paths_fully_marked(project, [hidden]) is False
    assert skip_non_source_weight_rows(project) == 1
    assert paths_fully_marked(project, [hidden]) is True
    assert skip_non_source_weight_rows(project) == 0


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


def test_chunk_list_splits_batch(tmp_env, project):
    """Verify _chunk_list splits large batches into smaller sub-batches."""
    from app.services.pipeline import _chunk_list

    # Empty list
    assert _chunk_list([], 75) == []

    # Exact division
    assert _chunk_list(["a", "b", "c", "d"], 2) == [["a", "b"], ["c", "d"]]

    # Remainder
    assert _chunk_list(["a", "b", "c", "d", "e"], 2) == [["a", "b"], ["c", "d"], ["e"]]

    # Single chunk
    assert _chunk_list(["a", "b"], 5) == [["a", "b"]]

    # 150 files split into 75-per-sub-batch
    paths = [f"path/to/file_{i}.java" for i in range(150)]
    chunks = _chunk_list(paths, 75)
    assert len(chunks) == 2
    assert len(chunks[0]) == 75
    assert len(chunks[1]) == 75
    assert chunks[0][0] == "path/to/file_0.java"
    assert chunks[1][74] == "path/to/file_149.java"

    # 151 files split into 75+75+1
    paths = [f"path/to/file_{i}.java" for i in range(151)]
    chunks = _chunk_list(paths, 75)
    assert len(chunks) == 3
    assert len(chunks[0]) == 75
    assert len(chunks[1]) == 75
    assert len(chunks[2]) == 1


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


def test_request_lab_rebuild_invalidates_and_ends_review(tmp_env, project):
    from app.models import Project, SessionLocal
    from app.services.lab import lab_rebuild_requested, lab_setup_finished, load_env, save_env
    from app.services.paths import docs_dir as project_docs

    with SessionLocal() as db:
        proj = db.get(Project, project)
        proj.dynamic_verify_enabled = True
        proj.dynamic_verify_mode = "lab"
        db.commit()
    save_env(
        project,
        {
            "setup_finished": True,
            "accepted": True,
            "target_url": "http://127.0.0.1:18080",
            "status": "running",
            "container_name": f"demo-{project}",
        },
    )
    ctx = _ctx(project, "reviewer")
    out = registry.dispatch(
        ctx,
        "RequestLabRebuild",
        {"reason": "/portal 返回 404，数据库容器已退出"},
    )
    assert out["ok"] is True
    assert ctx.state.get("review_done") is True
    assert ctx.state.get("review_verdict") == "lab_rebuild"
    assert lab_setup_finished(project) is False
    assert lab_rebuild_requested(project) is True
    env = load_env(project)
    assert env.get("accepted") is False
    assert env.get("last_target_url") == "http://127.0.0.1:18080"
    assert env.get("retry_user_message") == "/portal 返回 404，数据库容器已退出"
    assert (project_docs(project) / "lab.md").is_file()


def test_request_lab_rebuild_denied_when_not_lab_mode(tmp_env, project):
    out = registry.dispatch(
        _ctx(project, "reviewer"),
        "RequestLabRebuild",
        {"reason": "404"},
    )
    assert out["ok"] is False
    assert "靶场动态" in out["error"]


def test_request_lab_rebuild_denied_while_setup_in_progress(tmp_env, project):
    from app.models import Project, SessionLocal
    from app.services.lab import save_env

    with SessionLocal() as db:
        proj = db.get(Project, project)
        proj.dynamic_verify_enabled = True
        proj.dynamic_verify_mode = "lab"
        db.commit()
    save_env(project, {"setup_finished": False, "accepted": False})
    out = registry.dispatch(
        _ctx(project, "reviewer"),
        "RequestLabRebuild",
        {"reason": "假就绪"},
    )
    assert out["ok"] is False
    assert "已在进行" in out["error"]


def test_request_lab_rebuild_resets_timeout_streak(tmp_env, project):
    from app.models import Project, SessionLocal
    from app.services.lab import lab_setup_timeout_streak, save_env

    with SessionLocal() as db:
        proj = db.get(Project, project)
        proj.dynamic_verify_enabled = True
        proj.dynamic_verify_mode = "lab"
        db.commit()
    save_env(
        project,
        {
            "setup_finished": True,
            "accepted": True,
            "target_url": "http://127.0.0.1:18080",
            "status": "running",
            "lab_setup_timeout_streak": 1,
        },
    )
    out = registry.dispatch(
        _ctx(project, "reviewer"),
        "RequestLabRebuild",
        {"reason": "容器不存在"},
    )
    assert out["ok"] is True
    assert lab_setup_timeout_streak(project) == 0


def test_request_lab_rebuild_acl_blocks_lab_role(tmp_env, project):
    denied = registry.dispatch(
        _ctx(project, "reviewer_lab"),
        "RequestLabRebuild",
        {"reason": "假就绪"},
    )
    assert denied["ok"] is False
    assert "无权" in denied["error"]


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

    extra = registry.dispatch(_ctx(project, "recon_source_ext"), "AddSourceExt", {"exts": [".lua"]})
    assert extra["ok"] is True
    assert ".lua" in extra["exts"]
    assert extra["rejected"] == []

    bad = registry.dispatch(_ctx(project, "recon_source_ext"), "AddSourceExt", {"exts": [".png", ".exe"]})
    assert bad["ok"] is False
    assert "忽略" in bad["error"]


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


def test_read_schema_requires_described_path():
    tools = {t["function"]["name"]: t["function"] for t in registry.openai_tools_for_role("recon")}
    params = tools["Read"]["parameters"]
    assert "path" in params["required"]
    assert params["properties"]["path"]["description"]


def test_read_accepts_file_alias(tmp_env, project):
    out = registry.dispatch(_ctx(project, "worker"), "Read", {"file": "src/app/Main.java", "limit": 20})
    assert out["ok"] is True
    assert "content" in out["files"][0]


def test_read_missing_path_lists_received_keys(tmp_env, project):
    out = registry.dispatch(_ctx(project, "worker"), "Read", {"limit": 250, "max_bytes": 16000})
    assert out["ok"] is False
    assert "缺少 path/paths" in out["error"]
    assert "limit" in out["error"]
    assert "max_bytes" in out["error"]


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
    assert "不能当入口" in tools["FinishFile"]
    assert "无漏洞" in tools["FinishFile"]
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


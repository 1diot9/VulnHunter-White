"""Verifier role, FOFA search tool, and project toggle."""

from __future__ import annotations

import json

import httpx
from fastapi.testclient import TestClient

from app.models import Project, Vuln
from app.services.fofa import FOFA_DEFAULT_SIZE, search as fofa_search
from app.services.pipeline import control_phase
from app.services.verifier import (
    enqueue_confirmed_frontend,
    extract_fofa_query,
    format_verifier_report,
    internet_test_block_reason,
    load_project_fofa_cache,
    merge_verifier_targets,
    pending_verifier_count,
)
from app.tools import ROLE_ACL, registry
from app.tools.phase_worker import project_complete_gates


def _ctx(project_id: int, role: str, **kwargs):
    from app.tools import ToolContext

    return ToolContext(project_id=project_id, role=role, phase=role, **kwargs)


def _db():
    from app.models import SessionLocal

    return SessionLocal()


def _success_targets(*hosts: str) -> list[dict]:
    return [{"host": h, "status": "success", "note": "回显一致"} for h in hosts]


def _submit_and_confirm(
    project,
    surface="frontend",
    *,
    enable_verifier=False,
    vuln_type="unauthorized_access",
    title="前台未授权",
    http_request="GET /api/x",
    poc_code="curl http://x/api/x",
    expected_evidence="200 + data",
    root_cause_key="unauthorized_access:XController",
):
    if enable_verifier:
        with _db() as db:
            proj = db.get(Project, project)
            proj.verifier_enabled = True
            db.commit()
    payload = {
        "title": title,
        "vuln_type": vuln_type,
        "cwe": "CWE-284",
        "file_path": "a.java",
        "line_no": 1,
        "source_sink": "http -> sink",
        "auth_premise": "none",
        "http_request": http_request,
        "poc_code": poc_code,
        "expected_evidence": expected_evidence,
    }
    out = registry.dispatch(_ctx(project, "worker"), "SubmitVuln", payload)
    assert out["ok"] is True, out
    vuln_id = out["vuln_id"]
    args = {
        "vuln_id": vuln_id,
        "attack_surface": surface,
        "impact": "sensitive_data_or_privilege",
        "exploit_complexity": "single_request",
        "defense_status": "none",
        "submission_tier": "cve_candidate",
        "submission_reason": "未授权可读敏感数据",
        "root_cause_key": root_cause_key,
    }
    if surface == "backend":
        args["required_account"] = "user"
    conf = registry.dispatch(_ctx(project, "reviewer", vuln_id=vuln_id), "ConfirmVuln", args)
    assert conf["ok"] is True, conf
    return vuln_id, conf


def test_control_phase_recognizes_verifier():
    assert control_phase("verifier") == "verifier"


def test_fofa_search_default_size_and_sample(tmp_env, monkeypatch):
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["params"] = dict(request.url.params)
        return httpx.Response(
            200,
            json={
                "error": False,
                "size": 88,
                "results": [
                    ["host1.example", "1.1.1.1", "80", "Title A", "example.com", "Org", "http"],
                    ["host2.example", "1.1.1.2", "443", "Title B", "example.com", "Org", "https"],
                ],
            },
        )

    def fake_client(timeout=30.0):
        return httpx.Client(transport=httpx.MockTransport(handler), timeout=timeout)

    monkeypatch.setattr("app.services.fofa.http_client", fake_client)
    monkeypatch.setattr("app.services.fofa.resolve_fofa_key", lambda: "test-key")
    out = fofa_search('title="demo"')
    assert out["ok"] is True
    assert out["size"] == 88
    assert out["returned"] == 2
    assert seen["params"]["size"] == str(FOFA_DEFAULT_SIZE)
    assert seen["params"]["size"] == "10"
    assert seen["params"]["page"] == "1"
    assert "key" not in json.dumps(out)
    assert out["sample"][0]["host"] == "host1.example"


def test_fofa_search_clamps_size(tmp_env, monkeypatch):
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["size"] = dict(request.url.params)["size"]
        return httpx.Response(200, json={"error": False, "size": 0, "results": []})

    monkeypatch.setattr(
        "app.services.fofa.http_client",
        lambda timeout=30.0: httpx.Client(transport=httpx.MockTransport(handler), timeout=timeout),
    )
    monkeypatch.setattr("app.services.fofa.resolve_fofa_key", lambda: "k")
    fofa_search("title=x", size=999)
    assert seen["size"] == "30"


def test_fofa_search_acl_and_missing_key(tmp_env, project, monkeypatch):
    monkeypatch.setattr("app.services.fofa.resolve_fofa_key", lambda: "")
    blocked = registry.dispatch(_ctx(project, "worker"), "FofaSearch", {"query": 'title="x"'})
    assert blocked["ok"] is False
    assert "无权" in blocked["error"]
    out = registry.dispatch(_ctx(project, "verifier"), "FofaSearch", {"query": 'title="x"'})
    assert out["ok"] is False
    assert "FOFA key" in out["error"]
    names = {t["function"]["name"] for t in registry.openai_tools_for_role("verifier")}
    assert "FofaSearch" in names
    assert "FinishVerifier" in names
    assert "ConfirmVuln" not in names
    assert "FofaSearch" not in ROLE_ACL["reviewer"]


def test_confirm_frontend_queues_verifier_when_enabled(tmp_env, project):
    vuln_id, conf = _submit_and_confirm(project, enable_verifier=True)
    assert conf["verifier_queued"] is True
    with _db() as db:
        v = db.get(Vuln, vuln_id)
        assert v.verifier_status == "pending"
    assert pending_verifier_count(project) == 1


def test_confirm_frontend_does_not_queue_when_disabled(tmp_env, project):
    vuln_id, conf = _submit_and_confirm(project, enable_verifier=False)
    assert conf.get("verifier_queued") is False
    with _db() as db:
        v = db.get(Vuln, vuln_id)
        assert v.verifier_status == "none"
    assert pending_verifier_count(project) == 0


def test_confirm_backend_does_not_queue(tmp_env, project):
    vuln_id, conf = _submit_and_confirm(project, surface="backend", enable_verifier=True)
    assert conf.get("verifier_queued") is False
    with _db() as db:
        v = db.get(Vuln, vuln_id)
        assert v.attack_surface == "backend"
        assert v.verifier_status == "none"


def test_enable_later_queues_existing_frontend(tmp_env, project):
    vuln_id, _ = _submit_and_confirm(project, enable_verifier=False)
    with _db() as db:
        proj = db.get(Project, project)
        proj.verifier_enabled = True
        db.commit()
    n = enqueue_confirmed_frontend(project)
    assert n == 1
    with _db() as db:
        v = db.get(Vuln, vuln_id)
        assert v.verifier_status == "pending"


def test_internet_test_block_reason_types_and_sql_write():
    assert internet_test_block_reason(vuln_type="file_delete")
    assert internet_test_block_reason(vuln_type="dos")
    assert internet_test_block_reason(vuln_type="file_upload")
    assert not internet_test_block_reason(
        vuln_type="sqli",
        poc_code="' UNION SELECT 1,2,username,password FROM users--",
    )
    assert not internet_test_block_reason(
        vuln_type="sqli",
        poc_code="id=1 AND UPDATEXML(1,CONCAT(0x7e,user()),1)",
    )
    assert "SQL" in (internet_test_block_reason(vuln_type="sqli", poc_code="DELETE FROM users WHERE 1=1") or "")
    assert "SQL" in (
        internet_test_block_reason(vuln_type="sqli", http_request="GET /x?id=1;UPDATE users SET pass=1") or ""
    )
    assert not internet_test_block_reason(vuln_type="info_disclosure", poc_code="GET /api/user")


def test_confirm_skips_destructive_internet_types(tmp_env, project):
    vuln_id, conf = _submit_and_confirm(
        project,
        enable_verifier=True,
        vuln_type="file_delete",
        title="任意文件删除",
        root_cause_key="file_delete:XController",
    )
    assert conf["verifier_queued"] is False
    assert "文件删除" in (conf.get("verifier_skip_reason") or conf.get("message") or "")
    with _db() as db:
        v = db.get(Vuln, vuln_id)
        assert v.verifier_status == "skipped"
    assert pending_verifier_count(project) == 0


def test_confirm_skips_sql_write_but_allows_select(tmp_env, project):
    write_id, write_conf = _submit_and_confirm(
        project,
        enable_verifier=True,
        vuln_type="sqli",
        title="SQL 注入写库",
        poc_code="id=1; DELETE FROM users",
        root_cause_key="sqli:write",
    )
    assert write_conf["verifier_queued"] is False
    assert "SQL" in (write_conf.get("verifier_skip_reason") or "")
    with _db() as db:
        assert db.get(Vuln, write_id).verifier_status == "skipped"

    read_id, read_conf = _submit_and_confirm(
        project,
        enable_verifier=True,
        vuln_type="sqli",
        title="SQL 注入读库",
        poc_code="' UNION SELECT 1,2,3--",
        root_cause_key="sqli:read",
    )
    assert read_conf["verifier_queued"] is True
    with _db() as db:
        assert db.get(Vuln, read_id).verifier_status == "pending"


def test_enable_later_skips_destructive_existing(tmp_env, project):
    vuln_id, _ = _submit_and_confirm(
        project,
        enable_verifier=False,
        vuln_type="dos",
        title="接口可打满 CPU",
        root_cause_key="dos:flood",
    )
    with _db() as db:
        proj = db.get(Project, project)
        proj.verifier_enabled = True
        db.commit()
    assert enqueue_confirmed_frontend(project) == 0
    with _db() as db:
        assert db.get(Vuln, vuln_id).verifier_status == "skipped"


def test_finish_verifier_rejects_sql_write_success(tmp_env, project):
    vuln_id, _ = _submit_and_confirm(project, enable_verifier=True)
    out = registry.dispatch(
        _ctx(project, "verifier", vuln_id=vuln_id),
        "FinishVerifier",
        {
            "verdict": "success",
            "verified_url": "http://hit.example/api/x",
            "poc": "GET /x?id=1;DELETE FROM users HTTP/1.1\nHost: hit.example\n\n",
            "response": "HTTP/1.1 200 OK\n\nok",
            "notes": "不该对互联网目标做删库",
        },
    )
    assert out["ok"] is False
    assert "SQL" in out["error"]


def test_finish_verifier_success(tmp_env, project):
    vuln_id, _ = _submit_and_confirm(project, enable_verifier=True)
    poc = "GET /api/x HTTP/1.1\nHost: hit.example\n\n"
    response = "HTTP/1.1 200 OK\n\n{\"secret\":\"yes\"}"
    out = registry.dispatch(
        _ctx(project, "verifier", vuln_id=vuln_id),
        "FinishVerifier",
        {
            "vuln_id": vuln_id,
            "verdict": "success",
            "verified_url": "http://hit.example/api/x",
            "poc": poc,
            "response": response,
            "fofa_query": 'title="demo"',
            "tested_count": 3,
            "targets": _success_targets(
                "http://a.example",
                "http://b.example",
                "http://hit.example",
            ),
            "notes": "3 个目标回显与报告一致",
        },
    )
    assert out["ok"] is True
    assert out["verifier_status"] == "verified"
    with _db() as db:
        v = db.get(Vuln, vuln_id)
        assert v.verifier_status == "verified"
        assert v.verifier_verified_url == "http://hit.example/api/x"
        assert v.verifier_fofa_query == 'title="demo"'
        assert "GET /api/x" in (v.verifier_poc or "")
        assert "secret" in (v.verifier_response or "")
    from app.services.paths import vuln_dir

    report = (vuln_dir(project, vuln_id) / "report.md").read_text(encoding="utf-8")
    assert "## 互联网验证" in report
    assert "打通目标：http://hit.example/api/x" in report
    assert "### FOFA 搜索语法" in report
    assert 'title="demo"' in report
    assert "### 使用的 PoC" in report
    assert "### 实际响应" in report
    assert "GET /api/x" in report
    assert '{"secret":"yes"}' in report
    assert "### FOFA 目标" in report
    assert "成功" in report

    from app.main import app

    with TestClient(app) as client:
        detail = client.get(f"/api/vulns/{vuln_id}").json()
        assert detail["verifier_status"] == "verified"
        assert detail["verifier_verified_url"] == "http://hit.example/api/x"
        assert detail["verifier_fofa_query"] == 'title="demo"'
        assert "GET /api/x" in (detail.get("verifier_poc") or "")
        assert "secret" in (detail.get("verifier_response") or "")
        assert isinstance(detail.get("verifier_targets"), list)
        assert any(t.get("status") == "success" for t in detail["verifier_targets"])


def test_finish_verifier_success_requires_query(tmp_env, project):
    vuln_id, _ = _submit_and_confirm(project, enable_verifier=True)
    out = registry.dispatch(
        _ctx(project, "verifier", vuln_id=vuln_id),
        "FinishVerifier",
        {
            "verdict": "success",
            "verified_url": "http://hit.example/api/x",
            "poc": "GET /api/x HTTP/1.1\nHost: hit.example\n\n",
            "response": "HTTP/1.1 200 OK\n\nsecret",
            "notes": "打通了但忘了填 FOFA 语法",
        },
    )
    assert out["ok"] is False
    assert "fofa_query" in out["error"]


def test_merge_verifier_targets_keeps_untested():
    rows = merge_verifier_targets(
        fofa_sample=[
            {"host": "a.example", "ip": "1.1.1.1", "port": "80", "title": "A", "protocol": "http"},
            {"host": "b.example", "ip": "1.1.1.2", "port": "443", "title": "B", "protocol": "https"},
            {"host": "c.example", "title": "C"},
        ],
        submitted=[{"host": "a.example", "status": "fail", "note": "404"}],
        verified_url="https://b.example/login",
    )
    by_host = {r["host"]: r for r in rows}
    assert len(rows) == 3
    assert by_host["http://a.example"]["status"] == "fail"
    assert by_host["https://b.example"]["status"] == "success"
    assert by_host["c.example"]["status"] == "untested"
    md = format_verifier_report(verdict="success", targets=rows, notes="停在第二个")
    assert "| 失败 | http://a.example |" in md
    assert "| 成功 | https://b.example |" in md
    assert "| 未测 | c.example |" in md


def test_finish_verifier_lists_untested_fofa_hosts(tmp_env, project, monkeypatch):
    vuln_id, _ = _submit_and_confirm(project, enable_verifier=True)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "error": False,
                "size": 3,
                "results": [
                    ["host1.example", "1.1.1.1", "80", "Title A", "example.com", "Org", "http"],
                    ["host2.example", "1.1.1.2", "443", "Title B", "example.com", "Org", "https"],
                    ["host3.example", "1.1.1.3", "8080", "Title C", "example.com", "Org", "http"],
                    ["host4.example", "1.1.1.4", "80", "Title D", "example.com", "Org", "http"],
                    ["host5.example", "1.1.1.5", "80", "Title E", "example.com", "Org", "http"],
                ],
            },
        )

    monkeypatch.setattr(
        "app.services.fofa.http_client",
        lambda timeout=30.0: httpx.Client(transport=httpx.MockTransport(handler), timeout=timeout),
    )
    monkeypatch.setattr("app.services.fofa.resolve_fofa_key", lambda: "test-key")
    ctx = _ctx(project, "verifier", vuln_id=vuln_id)
    searched = registry.dispatch(ctx, "FofaSearch", {"query": 'title="demo"'})
    assert searched["ok"] is True
    assert len(ctx.state["fofa_targets"]) == 5
    poc = "GET /api/x HTTP/1.1\nHost: host1.example\n\n"
    response = "HTTP/1.1 200 OK\n\n{\"secret\":\"yes\"}"
    out = registry.dispatch(
        ctx,
        "FinishVerifier",
        {
            "verdict": "success",
            "verified_url": "http://host1.example/api/x",
            "poc": poc,
            "response": response,
            "targets": [
                {"host": "host1.example", "status": "success", "note": "回显一致"},
                {"host": "host2.example", "status": "success", "note": "回显一致"},
                {"host": "host3.example", "status": "success", "note": "回显一致"},
            ],
            "notes": "3 个打通即停，其余未测",
        },
    )
    assert out["ok"] is True
    statuses = {t["host"]: t["status"] for t in out["targets"]}
    assert statuses["http://host1.example"] == "success"
    assert statuses["https://host2.example"] == "success"
    assert statuses["http://host3.example"] == "success"
    assert statuses["http://host4.example"] == "untested"
    assert statuses["http://host5.example"] == "untested"
    from app.services.paths import vuln_dir

    report = (vuln_dir(project, vuln_id) / "report.md").read_text(encoding="utf-8")
    assert "### FOFA 目标" in report
    assert "| 成功 | http://host1.example |" in report
    assert "| 成功 | https://host2.example |" in report
    assert "| 成功 | http://host3.example |" in report
    assert "| 未测 | http://host4.example |" in report
    assert "| 未测 | http://host5.example |" in report
    assert "共 5（成功 3 · 失败 0 · 未测 2）" in report
    assert "### FOFA 搜索语法" in report
    assert 'title="demo"' in report

    from app.main import app

    with TestClient(app) as client:
        detail = client.get(f"/api/vulns/{vuln_id}").json()
        hosts = {t["host"]: t["status"] for t in detail["verifier_targets"]}
        assert hosts["http://host1.example"] == "success"
        assert hosts["https://host2.example"] == "success"
        assert hosts["http://host3.example"] == "success"
        assert hosts["http://host4.example"] == "untested"
        assert hosts["http://host5.example"] == "untested"
        assert detail["verifier_fofa_query"] == 'title="demo"'


def test_fofa_search_shared_across_vulns(tmp_env, project, monkeypatch):
    hits = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        hits["n"] += 1
        return httpx.Response(
            200,
            json={
                "error": False,
                "size": 2,
                "results": [
                    ["shared.example", "1.1.1.1", "80", "Shared", "example.com", "Org", "http"],
                    ["other.example", "1.1.1.2", "443", "Other", "example.com", "Org", "https"],
                    ["third.example", "1.1.1.3", "80", "Third", "example.com", "Org", "http"],
                ],
            },
        )

    monkeypatch.setattr(
        "app.services.fofa.http_client",
        lambda timeout=30.0: httpx.Client(transport=httpx.MockTransport(handler), timeout=timeout),
    )
    monkeypatch.setattr("app.services.fofa.resolve_fofa_key", lambda: "test-key")
    vuln1, _ = _submit_and_confirm(project, enable_verifier=True, root_cause_key="unauthorized_access:A")
    vuln2, _ = _submit_and_confirm(
        project,
        enable_verifier=True,
        title="另一条前台未授权",
        root_cause_key="unauthorized_access:B",
    )
    first = registry.dispatch(
        _ctx(project, "verifier", vuln_id=vuln1),
        "FofaSearch",
        {"query": 'title="demo"'},
    )
    assert first["ok"] is True
    assert first.get("cached") is False
    assert hits["n"] == 1
    cache = load_project_fofa_cache(project)
    assert cache is not None
    assert cache["query"] == 'title="demo"'
    assert len(cache["sample"]) == 3

    second_ctx = _ctx(project, "verifier", vuln_id=vuln2)
    second = registry.dispatch(second_ctx, "FofaSearch", {"query": 'title="should-not-hit-api"'})
    assert second["ok"] is True
    assert second.get("cached") is True
    assert hits["n"] == 1
    assert second["query"] == 'title="demo"'
    assert second["sample"][0]["host"] == "shared.example"

    poc = "GET /api/x HTTP/1.1\nHost: shared.example\n\n"
    response = "HTTP/1.1 200 OK\n\n{\"secret\":\"yes\"}"
    out = registry.dispatch(
        second_ctx,
        "FinishVerifier",
        {
            "verdict": "success",
            "verified_url": "http://shared.example/api/x",
            "poc": poc,
            "response": response,
            "targets": _success_targets(
                "http://shared.example",
                "https://other.example",
                "http://third.example",
            ),
            "notes": "复用项目共享 FOFA 目标，3 个打通",
        },
    )
    assert out["ok"] is True, out
    assert out["fofa_query"] == 'title="demo"'
    from app.services.paths import vuln_dir

    report = (vuln_dir(project, vuln2) / "report.md").read_text(encoding="utf-8")
    assert "### FOFA 搜索语法" in report
    assert 'title="demo"' in report
    assert "| 成功 | http://shared.example |" in report
    assert "| 成功 | https://other.example |" in report
    assert "| 成功 | http://third.example |" in report
    with _db() as db:
        assert db.get(Vuln, vuln2).verifier_fofa_query == 'title="demo"'


def test_fofa_search_empty_allows_rewrite(tmp_env, project, monkeypatch):
    queries: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        q = dict(request.url.params).get("qbase64") or ""
        queries.append(q)
        if len(queries) == 1:
            return httpx.Response(200, json={"error": False, "size": 0, "results": []})
        return httpx.Response(
            200,
            json={
                "error": False,
                "size": 1,
                "results": [["hit.example", "1.1.1.1", "80", "Hit", "example.com", "Org", "http"]],
            },
        )

    monkeypatch.setattr(
        "app.services.fofa.http_client",
        lambda timeout=30.0: httpx.Client(transport=httpx.MockTransport(handler), timeout=timeout),
    )
    monkeypatch.setattr("app.services.fofa.resolve_fofa_key", lambda: "test-key")
    vuln_id, _ = _submit_and_confirm(project, enable_verifier=True)
    ctx = _ctx(project, "verifier", vuln_id=vuln_id)
    first = registry.dispatch(ctx, "FofaSearch", {"query": 'title="too-narrow"'})
    assert first["ok"] is True
    assert first["returned"] == 0
    assert first.get("cached") is False
    cache = load_project_fofa_cache(project)
    assert cache is not None
    assert not cache.get("sample")
    assert cache.get("frozen") is not True
    same = registry.dispatch(ctx, "FofaSearch", {"query": 'title="too-narrow"'})
    assert same["ok"] is False
    assert "已经搜过" in same["error"]
    second = registry.dispatch(ctx, "FofaSearch", {"query": 'title="SharedApp"'})
    assert second["ok"] is True
    assert second["returned"] == 1
    assert second["sample"][0]["host"] == "hit.example"
    frozen = load_project_fofa_cache(project)
    assert frozen["frozen"] is True
    third = registry.dispatch(ctx, "FofaSearch", {"query": 'title="should-not-hit"'})
    assert third.get("cached") is True
    assert third["query"] == 'title="SharedApp"'


def test_finish_verifier_success_requires_three_targets(tmp_env, project):
    vuln_id, _ = _submit_and_confirm(project, enable_verifier=True)
    out = registry.dispatch(
        _ctx(project, "verifier", vuln_id=vuln_id),
        "FinishVerifier",
        {
            "verdict": "success",
            "verified_url": "http://hit.example/api/x",
            "poc": "GET /api/x HTTP/1.1\nHost: hit.example\n\n",
            "response": "HTTP/1.1 200 OK\n\nsecret",
            "fofa_query": 'title="demo"',
            "targets": [{"host": "http://hit.example", "status": "success"}],
            "notes": "只打通 1 个",
        },
    )
    assert out["ok"] is False
    assert "3 个" in out["error"]


def test_finish_verifier_fail_requires_expand_when_first_batch_short(tmp_env, project, monkeypatch):
    vuln_id, _ = _submit_and_confirm(project, enable_verifier=True)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "error": False,
                "size": 2,
                "results": [
                    ["host1.example", "1.1.1.1", "80", "A", "example.com", "Org", "http"],
                    ["host2.example", "1.1.1.2", "443", "B", "example.com", "Org", "https"],
                ],
            },
        )

    monkeypatch.setattr(
        "app.services.fofa.http_client",
        lambda timeout=30.0: httpx.Client(transport=httpx.MockTransport(handler), timeout=timeout),
    )
    monkeypatch.setattr("app.services.fofa.resolve_fofa_key", lambda: "test-key")
    ctx = _ctx(project, "verifier", vuln_id=vuln_id)
    searched = registry.dispatch(ctx, "FofaSearch", {"query": 'title="demo"'})
    assert searched["ok"] is True
    out = registry.dispatch(
        ctx,
        "FinishVerifier",
        {
            "verdict": "fail",
            "fofa_query": 'title="demo"',
            "targets": [
                {"host": "host1.example", "status": "fail", "note": "404"},
                {"host": "host2.example", "status": "fail", "note": "404"},
            ],
            "notes": "首批都失败，不该直接 fail",
        },
    )
    assert out["ok"] is False
    assert "expand" in out["error"]


def test_fofa_search_expand_appends_new_page(tmp_env, project, monkeypatch):
    pages: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        page = dict(request.url.params).get("page") or "1"
        pages.append(page)
        if page == "1":
            results = [
                ["host1.example", "1.1.1.1", "80", "A", "example.com", "Org", "http"],
                ["host2.example", "1.1.1.2", "443", "B", "example.com", "Org", "https"],
            ]
        else:
            results = [
                ["host2.example", "1.1.1.2", "443", "B-dup", "example.com", "Org", "https"],
                ["host3.example", "1.1.1.3", "80", "C", "example.com", "Org", "http"],
                ["host4.example", "1.1.1.4", "80", "D", "example.com", "Org", "http"],
            ]
        return httpx.Response(200, json={"error": False, "size": 10, "results": results})

    monkeypatch.setattr(
        "app.services.fofa.http_client",
        lambda timeout=30.0: httpx.Client(transport=httpx.MockTransport(handler), timeout=timeout),
    )
    monkeypatch.setattr("app.services.fofa.resolve_fofa_key", lambda: "test-key")
    vuln_id, _ = _submit_and_confirm(project, enable_verifier=True)
    ctx = _ctx(project, "verifier", vuln_id=vuln_id)
    first = registry.dispatch(ctx, "FofaSearch", {"query": 'title="demo"'})
    assert first["ok"] is True
    assert first.get("cached") is False
    assert pages == ["1"]
    expanded = registry.dispatch(
        ctx,
        "FofaSearch",
        {"query": 'title="demo"', "expand": True},
    )
    assert expanded["ok"] is True
    assert expanded.get("expanded") is not True
    assert expanded.get("page") == 2
    assert pages == ["1", "2"]
    hosts = [row["host"] for row in expanded["sample"]]
    assert hosts == ["host1.example", "host2.example", "host3.example", "host4.example"]
    new_hosts = [row["host"] for row in expanded.get("new_sample") or []]
    assert new_hosts == ["host3.example", "host4.example"]
    cache = load_project_fofa_cache(project)
    assert cache is not None
    assert cache.get("expanded") is not True
    assert cache.get("page") == 2
    assert len(cache["sample"]) == 4
    assert expanded.get("pages_left") == 3

    again = registry.dispatch(ctx, "FofaSearch", {"query": 'title="demo"', "expand": True})
    assert again.get("cached") is not True
    assert pages == ["1", "2", "3"]

    out = registry.dispatch(
        ctx,
        "FinishVerifier",
        {
            "verdict": "success",
            "verified_url": "http://host4.example/api/x",
            "poc": "GET /api/x HTTP/1.1\nHost: host4.example\n\n",
            "response": "HTTP/1.1 200 OK\n\nsecret",
            "targets": [
                {"host": "host1.example", "status": "success", "note": "首批命中"},
                {"host": "host2.example", "status": "fail", "note": "404"},
                {"host": "host3.example", "status": "success", "note": "补搜命中"},
                {"host": "host4.example", "status": "success", "note": "补搜命中"},
            ],
            "notes": "首批 1 个成功，补搜后再打通 2 个，凑满 3 个",
        },
    )
    assert out["ok"] is True, out
    statuses = {t["host"]: t["status"] for t in out["targets"]}
    assert statuses["http://host1.example"] == "success"
    assert statuses["https://host2.example"] == "fail"
    assert statuses["http://host3.example"] == "success"
    assert statuses["http://host4.example"] == "success"


def test_fofa_search_expand_allows_five_pages_then_fail(tmp_env, project, monkeypatch):
    pages: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        page = dict(request.url.params).get("page") or "1"
        pages.append(page)
        n = int(page)
        results = [
            [f"host{n}a.example", f"1.1.{n}.1", "80", f"A{n}", "example.com", "Org", "http"],
            [f"host{n}b.example", f"1.1.{n}.2", "80", f"B{n}", "example.com", "Org", "http"],
        ]
        return httpx.Response(200, json={"error": False, "size": 10, "results": results})

    monkeypatch.setattr(
        "app.services.fofa.http_client",
        lambda timeout=30.0: httpx.Client(transport=httpx.MockTransport(handler), timeout=timeout),
    )
    monkeypatch.setattr("app.services.fofa.resolve_fofa_key", lambda: "test-key")
    vuln_id, _ = _submit_and_confirm(project, enable_verifier=True)
    ctx = _ctx(project, "verifier", vuln_id=vuln_id)
    first = registry.dispatch(ctx, "FofaSearch", {"query": 'title="demo"'})
    assert first["ok"] is True
    assert first.get("page") == 1

    def _fail_all(note: str):
        cache = load_project_fofa_cache(project)
        targets = [
            {"host": row["host"], "status": "fail", "note": note}
            for row in (cache or {}).get("sample") or []
        ]
        return registry.dispatch(
            ctx,
            "FinishVerifier",
            {
                "verdict": "fail",
                "fofa_query": 'title="demo"',
                "targets": targets,
                "notes": note,
            },
        )

    blocked = _fail_all("第 1 轮全失败")
    assert blocked["ok"] is False
    assert "expand" in blocked["error"]

    for expected_page in (2, 3, 4):
        out = registry.dispatch(ctx, "FofaSearch", {"query": 'title="demo"', "expand": True})
        assert out["ok"] is True
        assert out.get("cached") is not True
        assert out.get("page") == expected_page
        blocked = _fail_all(f"第 {expected_page} 轮仍不足")
        assert blocked["ok"] is False
        assert "expand" in blocked["error"]

    fifth = registry.dispatch(ctx, "FofaSearch", {"query": 'title="demo"', "expand": True})
    assert fifth["ok"] is True
    assert fifth.get("page") == 5
    assert fifth.get("expanded") is True
    assert fifth.get("pages_left") == 0
    cache = load_project_fofa_cache(project)
    assert cache is not None
    assert cache.get("page") == 5
    assert cache.get("expanded") is True
    assert len(cache["sample"]) == 10

    sixth = registry.dispatch(ctx, "FofaSearch", {"query": 'title="demo"', "expand": True})
    assert sixth.get("cached") is True
    assert pages == ["1", "2", "3", "4", "5"]

    done = _fail_all("5 轮都失败")
    assert done["ok"] is True, done
    assert done["verdict"] == "fail"


def test_legacy_expanded_cache_can_still_turn_pages(tmp_env, project, monkeypatch):
    from app.services.paths import fofa_cache_path
    from app.services.verifier import save_project_fofa_cache

    save_project_fofa_cache(
        project,
        query='title="demo"',
        sample=[
            {
                "host": "host1.example",
                "ip": "1.1.1.1",
                "port": "80",
                "title": "A",
                "protocol": "http",
            }
        ],
        size=1,
        frozen=True,
        page=2,
    )
    path = fofa_cache_path(project)
    data = json.loads(path.read_text(encoding="utf-8"))
    data["expanded"] = True
    data["page"] = 2
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "error": False,
                "size": 10,
                "results": [
                    ["host3.example", "1.1.1.3", "80", "C", "example.com", "Org", "http"],
                ],
            },
        )

    monkeypatch.setattr(
        "app.services.fofa.http_client",
        lambda timeout=30.0: httpx.Client(transport=httpx.MockTransport(handler), timeout=timeout),
    )
    monkeypatch.setattr("app.services.fofa.resolve_fofa_key", lambda: "test-key")
    loaded = load_project_fofa_cache(project)
    assert loaded is not None
    assert loaded.get("page") == 2
    assert loaded.get("expanded") is not True

    vuln_id, _ = _submit_and_confirm(project, enable_verifier=True)
    ctx = _ctx(project, "verifier", vuln_id=vuln_id)
    out = registry.dispatch(ctx, "FofaSearch", {"query": 'title="demo"', "expand": True})
    assert out["ok"] is True
    assert out.get("cached") is not True
    assert out.get("page") == 3
    hosts = [row["host"] for row in out["sample"]]
    assert "host1.example" in hosts
    assert "host3.example" in hosts


def test_finish_verifier_success_requires_url(tmp_env, project):
    vuln_id, _ = _submit_and_confirm(project, enable_verifier=True)
    out = registry.dispatch(
        _ctx(project, "verifier", vuln_id=vuln_id),
        "FinishVerifier",
        {"verdict": "success", "notes": "打通了但忘了填 URL"},
    )
    assert out["ok"] is False
    assert "verified_url" in out["error"]


def test_finish_verifier_success_requires_poc_and_response(tmp_env, project):
    vuln_id, _ = _submit_and_confirm(project, enable_verifier=True)
    missing_poc = registry.dispatch(
        _ctx(project, "verifier", vuln_id=vuln_id),
        "FinishVerifier",
        {
            "verdict": "success",
            "verified_url": "http://hit.example/api/x",
            "response": "HTTP/1.1 200 OK\n\nsecret",
            "notes": "有响应但没贴 PoC",
        },
    )
    assert missing_poc["ok"] is False
    assert "poc" in missing_poc["error"]
    missing_resp = registry.dispatch(
        _ctx(project, "verifier", vuln_id=vuln_id),
        "FinishVerifier",
        {
            "verdict": "success",
            "verified_url": "http://hit.example/api/x",
            "poc": "GET /api/x HTTP/1.1\nHost: hit.example\n\n",
            "notes": "有 PoC 但没贴响应",
        },
    )
    assert missing_resp["ok"] is False
    assert "response" in missing_resp["error"]


def test_complete_gates_wait_for_verifier(tmp_env, project):
    from app.models import FileWeight

    _submit_and_confirm(project, enable_verifier=True)
    with _db() as db:
        proj = db.get(Project, project)
        proj.recon_done = True
        db.add(FileWeight(project_id=project, path="a.java", weight=50, skipped=False, audited=True))
        db.commit()
    assert project_complete_gates(project) is False
    with _db() as db:
        proj = db.get(Project, project)
        proj.verifier_enabled = False
        db.commit()
    assert project_complete_gates(project) is True


def test_extract_fofa_query_from_report():
    text = """## 互联网资产证明

#### FOFA
```text
title="XX系统" && body="stable"
```
"""
    assert extract_fofa_query(text) == 'title="XX系统" && body="stable"'


def test_create_and_patch_verifier_enabled(tmp_env, monkeypatch):
    from app.main import app

    monkeypatch.setattr("app.api.projects.start_ingest_and_audit", lambda *a, **k: None)
    monkeypatch.setattr("app.api.projects.start_audit", lambda *a, **k: None)
    with TestClient(app) as client:
        created = client.post(
            "/api/projects",
            json={"source_type": "github", "source_url": "https://github.com/owner/demo"},
        )
        assert created.status_code == 200
        assert created.json()["verifier_enabled"] is False
        assert created.json()["verifier_pending"] == 0
        pid = created.json()["id"]
        enabled = client.patch(f"/api/projects/{pid}", json={"verifier_enabled": True})
        assert enabled.status_code == 200
        assert enabled.json()["verifier_enabled"] is True
        on = client.post(
            "/api/projects",
            json={
                "source_type": "github",
                "source_url": "https://github.com/owner/v",
                "verifier_enabled": True,
            },
        )
        assert on.status_code == 200
        assert on.json()["verifier_enabled"] is True


def test_settings_fofa_key_masked(tmp_env):
    from app.main import app

    with TestClient(app) as client:
        saved = client.put("/api/settings", json={"fofa_key": "fofa-secret", "fofa_base_url": "https://fofa.info"})
        assert saved.status_code == 200
        body = saved.json()
        assert body["fofa_key_set"] is True
        assert "fofa-secret" not in json.dumps(body)
        again = client.get("/api/settings").json()
        assert again["fofa_key_set"] is True


def _patch_fofa_http(monkeypatch, handler):
    monkeypatch.setattr(
        "app.services.fofa.http_client",
        lambda timeout=15.0: httpx.Client(transport=httpx.MockTransport(handler), timeout=timeout),
    )


def test_fofa_connectivity_success(tmp_env, monkeypatch):
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["key"] = dict(request.url.params).get("key")
        return httpx.Response(
            200,
            json={
                "error": False,
                "username": "alice",
                "fcoin": 0,
                "fofa_point": 99982,
                "isvip": True,
                "email": "a@b.c",
            },
        )

    _patch_fofa_http(monkeypatch, handler)
    from app.main import app

    with TestClient(app) as client:
        r = client.post(
            "/api/settings/fofa/test",
            json={"key": "live-key", "base_url": "https://fofa.info"},
        )
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["username"] == "alice"
    assert body["fcoin"] == 99982
    assert body["isvip"] is True
    assert body["latency_ms"] is not None
    dumped = json.dumps(body)
    assert "live-key" not in dumped
    assert "a@b.c" not in dumped
    assert seen["key"] == "live-key"
    assert "/api/v1/info/my" in seen["url"]


def test_fofa_connectivity_uses_saved_key(tmp_env, monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        assert dict(request.url.params).get("key") == "saved-key"
        return httpx.Response(200, json={"error": False, "username": "bob", "fcoin": 1})

    _patch_fofa_http(monkeypatch, handler)
    from app.main import app

    with TestClient(app) as client:
        saved = client.put("/api/settings", json={"fofa_key": "saved-key"})
        assert saved.status_code == 200
        r = client.post("/api/settings/fofa/test", json={})
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["username"] == "bob"
    assert "saved-key" not in json.dumps(body)


def test_fofa_connectivity_missing_key(tmp_env, monkeypatch):
    monkeypatch.setattr("app.services.fofa.resolve_fofa_key", lambda: "")

    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("should not call FOFA")

    _patch_fofa_http(monkeypatch, handler)
    from app.main import app

    with TestClient(app) as client:
        r = client.post("/api/settings/fofa/test", json={})
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is False
    assert "FOFA Key" in body["error"]


def test_fofa_connectivity_account_error(tmp_env, monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"error": True, "errmsg": "账号无效"})

    _patch_fofa_http(monkeypatch, handler)
    from app.main import app

    with TestClient(app) as client:
        r = client.post("/api/settings/fofa/test", json={"key": "bad"})
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is False
    assert body["account_error"] is True
    assert "账号无效" in body["error"]


def test_fofa_connectivity_rejects_unknown_host(tmp_env):
    from app.main import app

    with TestClient(app) as client:
        r = client.post(
            "/api/settings/fofa/test",
            json={"key": "k", "base_url": "https://evil.example"},
        )
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is False
    assert "不被允许" in body["error"]

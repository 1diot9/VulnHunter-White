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
    internet_test_block_reason,
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
            "tested_count": 2,
            "notes": "第 2 个目标回显与报告一致",
        },
    )
    assert out["ok"] is True
    assert out["verifier_status"] == "verified"
    with _db() as db:
        v = db.get(Vuln, vuln_id)
        assert v.verifier_status == "verified"
        assert v.verifier_verified_url == "http://hit.example/api/x"
        assert "GET /api/x" in (v.verifier_poc or "")
        assert "secret" in (v.verifier_response or "")
    from app.services.paths import vuln_dir

    report = (vuln_dir(project, vuln_id) / "report.md").read_text(encoding="utf-8")
    assert "## 互联网验证" in report
    assert "打通目标：http://hit.example/api/x" in report
    assert "### 使用的 PoC" in report
    assert "### 实际响应" in report
    assert "GET /api/x" in report
    assert '{"secret":"yes"}' in report

    from app.main import app

    with TestClient(app) as client:
        detail = client.get(f"/api/vulns/{vuln_id}").json()
        assert detail["verifier_status"] == "verified"
        assert detail["verifier_verified_url"] == "http://hit.example/api/x"
        assert "GET /api/x" in (detail.get("verifier_poc") or "")
        assert "secret" in (detail.get("verifier_response") or "")


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
            json={"error": False, "username": "alice", "fcoin": 42, "isvip": True, "email": "a@b.c"},
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
    assert body["fcoin"] == 42
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

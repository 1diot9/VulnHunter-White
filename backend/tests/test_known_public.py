from __future__ import annotations

from app.services.known_public import extract_path_anchors, find_known_public_matches
from app.services.paths import old_vulns_dir
from app.tools import ToolContext, registry


def _ctx(project_id: int, role: str = "worker", **kwargs) -> ToolContext:
    return ToolContext(project_id=project_id, role=role, phase=role, **kwargs)


def _seed_custom_component_old(project: int) -> None:
    old = old_vulns_dir(project)
    old.mkdir(parents=True, exist_ok=True)
    (old / "CVE-2024-37014.md").write_text(
        "---\n"
        "title: CVE-2024-37014：Langflow /api/v1/custom_component 端点远程代码执行\n"
        "summary: 未受信用户通过 POST /api/v1/custom_component 提交 Python 导致 RCE。\n"
        "cve: CVE-2024-37014\n"
        "fix_status: patched\n"
        "type: RCE\n"
        "component: custom_component 端点\n"
        "affected_version: <=1.0.18.post2\n"
        "---\n\n"
        "Langflow 允许访问 POST /api/v1/custom_component 执行任意代码。\n",
        encoding="utf-8",
    )


def _rce_payload(**extra):
    payload = {
        "title": "Langflow AUTO_LOGIN 默认开启导致未认证远程代码执行",
        "vuln_type": "rce",
        "cwe": "CWE-306",
        "file_path": "src/backend/base/langflow/api/v1/login.py",
        "line_no": 108,
        "source_sink": "GET /api/v1/auto_login → POST /api/v1/custom_component → exec()",
        "auth_premise": "无需登录",
        "config_premise": "default",
        "http_request": (
            "GET /api/v1/auto_login HTTP/1.1\nHost: TARGET\n\n"
            "POST /api/v1/custom_component HTTP/1.1\nHost: TARGET\n"
        ),
        "poc_code": "print('poc')\n",
        "expected_evidence": "uid=",
        "root_cause_key": "rce:auto_login_exec_chain",
    }
    payload.update(extra)
    return payload


def test_extract_path_anchors_skips_auth_endpoints():
    anchors = extract_path_anchors(
        "GET /api/v1/auto_login HTTP/1.1\nPOST /api/v1/custom_component HTTP/1.1\n"
    )
    assert "custom_component" in anchors
    assert "auto_login" not in anchors
    assert "login" not in anchors


def test_find_known_public_matches_same_sink(tmp_env, project):
    _seed_custom_component_old(project)
    hits = find_known_public_matches(
        project,
        title="未认证 RCE",
        source_sink="GET /api/v1/auto_login → POST /api/v1/custom_component → exec()",
        http_request="POST /api/v1/custom_component HTTP/1.1\n",
        vuln_type="rce",
    )
    assert hits
    assert hits[0]["cve"] == "CVE-2024-37014"
    assert "custom_component" in hits[0]["matched_anchors"]


def test_find_known_public_ignores_different_vuln_type(tmp_env, project):
    _seed_custom_component_old(project)
    hits = find_known_public_matches(
        project,
        title="反射 XSS",
        source_sink="POST /api/v1/custom_component",
        http_request="POST /api/v1/custom_component HTTP/1.1\n",
        vuln_type="xss",
    )
    assert hits == []


def test_submit_vuln_soft_blocks_known_public_similar(tmp_env, project):
    _seed_custom_component_old(project)
    premature = registry.dispatch(
        _ctx(project, "unconstrained_worker"),
        "SubmitVuln",
        {**_rce_payload(), "confirm_not_known_public": True},
    )
    assert premature["ok"] is False
    assert premature.get("known_public_soft_gate") is True

    ctx = _ctx(project, "unconstrained_worker")
    first = registry.dispatch(ctx, "SubmitVuln", _rce_payload())
    assert first["ok"] is False
    assert first.get("known_public_soft_gate") is True
    assert first.get("confirm_param") == "confirm_not_known_public"
    assert any("CVE-2024-37014" in (c.get("cve") or c.get("title") or "") for c in first["candidates"])

    override = registry.dispatch(
        ctx,
        "SubmitVuln",
        {**_rce_payload(), "confirm_not_known_public": True},
    )
    assert override["ok"] is True
    assert override.get("vuln_id")


def test_confirm_vuln_soft_blocks_known_public_similar(tmp_env, project):
    from app.models import SessionLocal, Vuln

    _seed_custom_component_old(project)
    with SessionLocal() as db:
        vuln = Vuln(
            project_id=project,
            title="Langflow AUTO_LOGIN 未认证 RCE",
            vuln_type="rce",
            severity="critical",
            cwe="CWE-306",
            file_path="src/backend/api/v1/login.py",
            line_no=108,
            source_sink="GET /api/v1/auto_login → POST /api/v1/custom_component → exec()",
            http_request="POST /api/v1/custom_component HTTP/1.1\nHost: TARGET\n",
            status="pending_review",
            mining_path="unconstrained",
        )
        db.add(vuln)
        db.commit()
        vid = vuln.id
    ctx = _ctx(project, "reviewer", vuln_id=vid)
    out = registry.dispatch(ctx, "ConfirmVuln", {"vuln_id": vid})
    assert out["ok"] is False
    assert out.get("known_public_soft_gate") is True
    assert "MarkFalsePositive" in out["error"]
    fp = registry.dispatch(
        ctx,
        "MarkFalsePositive",
        {"vuln_id": vid, "reason": "与 CVE-2024-37014 同一 custom_component 入口"},
    )
    assert fp["ok"] is True
    with SessionLocal() as db:
        assert db.get(Vuln, vid).status == "false_positive"

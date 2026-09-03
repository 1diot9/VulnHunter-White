"""Soft duplicate gate for SubmitVuln / ConfirmVuln."""

from __future__ import annotations

from app.tools import ToolContext, registry

SEVERITY_FACTORS = {
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "cvss4_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    "submission_tier": "cve_candidate",
    "submission_reason": "未认证可达且可造成敏感数据/权限影响，有 CVE 价值",
    "root_cause_key": "hardcoded_secret:EncryptedString",
}


def _ctx(project_id: int, role: str, vuln_id: int | None = None) -> ToolContext:
    return ToolContext(project_id=project_id, role=role, phase=role, vuln_id=vuln_id)


def _payload(**extra):
    base = {
        "title": "硬编码 AES 密钥",
        "vuln_type": "hardcoded_secret",
        "cwe": "CWE-798",
        "file_path": "src/EncryptedString.java",
        "line_no": 16,
        "source_sink": "EncryptedString.key -> AesEncryptUtil",
        "auth_premise": "未授权",
        "config_premise": "default",
        "http_request": "GET /sys/getEncryptedString HTTP/1.1\nHost: x\n",
        "poc_code": "print('poc')\n",
        "expected_evidence": "key leaked",
        "intended_behavior": False,
        "root_cause_key": "hardcoded_secret:EncryptedString",
    }
    base.update(extra)
    return base


def test_submit_soft_gate_requires_prior_warning_then_ack(tmp_env, project):
    ctx = _ctx(project, "worker")
    first = registry.dispatch(ctx, "SubmitVuln", _payload())
    assert first["ok"] is True
    vid = first["vuln_id"]

    premature = registry.dispatch(
        _ctx(project, "worker"),
        "SubmitVuln",
        _payload(title="重复提前确认", confirm_not_duplicate=True),
    )
    assert premature["ok"] is False
    assert premature.get("duplicate_soft_gate") is True
    assert "提醒过" in premature["error"]

    warn = registry.dispatch(ctx, "SubmitVuln", _payload(title="重复提醒"))
    assert warn["ok"] is False
    assert warn.get("need_confirm_not_duplicate") is True
    assert any(c["vuln_id"] == vid for c in warn["candidates"])
    assert "same_file_type" in warn["candidates"][0]["match_reasons"]

    still = registry.dispatch(ctx, "SubmitVuln", _payload(title="重复仍提交"))
    assert still["ok"] is False
    assert still.get("duplicate_soft_gate") is True

    ok = registry.dispatch(
        ctx,
        "SubmitVuln",
        _payload(title="重复确认提交", confirm_not_duplicate=True),
    )
    assert ok["ok"] is True
    assert ok["vuln_id"] != vid


def test_submit_soft_gate_same_root_key_different_file(tmp_env, project):
    ctx = _ctx(project, "worker")
    first = registry.dispatch(
        ctx,
        "SubmitVuln",
        _payload(file_path="a/One.java", root_cause_key="idor:SysCommentController"),
    )
    assert first["ok"] is True

    warn = registry.dispatch(
        ctx,
        "SubmitVuln",
        _payload(
            title="同键不同文件",
            file_path="b/Two.java",
            vuln_type="idor",
            root_cause_key="idor:SysCommentController",
        ),
    )
    assert warn["ok"] is False
    assert "same_root_cause_key" in warn["candidates"][0]["match_reasons"]


def test_confirm_soft_gate_requires_ack(tmp_env, project):
    worker = _ctx(project, "worker")
    a = registry.dispatch(worker, "SubmitVuln", _payload(title="洞甲"))
    warn = registry.dispatch(worker, "SubmitVuln", _payload(title="洞乙"))
    assert warn["ok"] is False
    b = registry.dispatch(
        worker,
        "SubmitVuln",
        _payload(title="洞乙", confirm_not_duplicate=True),
    )
    assert b["ok"] is True

    # Confirm A alone: sibling B still pending → soft gate
    reviewer = _ctx(project, "reviewer", vuln_id=a["vuln_id"])
    conf1 = registry.dispatch(
        reviewer,
        "ConfirmVuln",
        {
            "vuln_id": a["vuln_id"],
            "evidence_level": "static_only",
            "attack_surface": "frontend",
            **SEVERITY_FACTORS,
        },
    )
    assert conf1["ok"] is False
    assert conf1.get("duplicate_soft_gate") is True
    assert any(c["vuln_id"] == b["vuln_id"] for c in conf1["candidates"])

    premature = registry.dispatch(
        _ctx(project, "reviewer", vuln_id=a["vuln_id"]),
        "ConfirmVuln",
        {
            "vuln_id": a["vuln_id"],
            "evidence_level": "static_only",
            "attack_surface": "frontend",
            "confirm_not_duplicate": True,
            **SEVERITY_FACTORS,
        },
    )
    assert premature["ok"] is False
    assert "提醒过" in premature["error"]

    conf2 = registry.dispatch(
        reviewer,
        "ConfirmVuln",
        {
            "vuln_id": a["vuln_id"],
            "evidence_level": "static_only",
            "attack_surface": "frontend",
            "confirm_not_duplicate": True,
            **SEVERITY_FACTORS,
        },
    )
    assert conf2["ok"] is True

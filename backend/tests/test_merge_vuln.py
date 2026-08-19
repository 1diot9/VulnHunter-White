"""Tests for same-root-cause submit append + reviewer merge."""

from __future__ import annotations

from app.services.paths import vuln_dir
from app.tools import ToolContext, registry


SEVERITY_FACTORS = {
    "impact": "sensitive_data_or_privilege",
    "exploit_complexity": "single_request",
    "defense_status": "none",
    "submission_tier": "cve_candidate",
    "submission_reason": "未认证可达且可造成敏感数据/权限影响，有 CVE 价值",
}


def _ctx(project_id: int, role: str, vuln_id: int | None = None) -> ToolContext:
    return ToolContext(project_id=project_id, role=role, phase=role, vuln_id=vuln_id)


def _submit(ctx: ToolContext, payload: dict) -> dict:
    """Submit, acknowledging soft duplicate gate when the test intentionally creates siblings."""
    out = registry.dispatch(ctx, "SubmitVuln", payload)
    if out.get("duplicate_soft_gate"):
        out = registry.dispatch(ctx, "SubmitVuln", {**payload, "confirm_not_duplicate": True})
    return out


def _confirm(ctx: ToolContext, args: dict) -> dict:
    out = registry.dispatch(ctx, "ConfirmVuln", args)
    if out.get("duplicate_soft_gate"):
        out = registry.dispatch(ctx, "ConfirmVuln", {**args, "confirm_not_duplicate": True})
    return out


def _submit_payload(**extra):
    payload = {
        "title": "IDOR update",
        "vuln_type": "idor",
        "cwe": "CWE-639",
        "file_path": "app/SysCommentController.java",
        "line_no": 10,
        "source_sink": "update -> mapper",
        "auth_premise": "普通用户",
        "http_request": "POST /api/comment/update HTTP/1.1\nHost: x\n",
        "poc_code": "print('poc')\n",
        "expected_evidence": "cross-user write",
        "intended_behavior": False,
        "root_cause_key": "idor:SysCommentController",
    }
    payload.update(extra)
    return payload


def test_submit_stores_root_cause_key_and_affected_section(tmp_env, project):
    out = registry.dispatch(_ctx(project, "worker"), "SubmitVuln", _submit_payload())
    assert out["ok"] is True
    assert out.get("root_cause_key") == "idor:SysCommentController"
    vuln_id = out["vuln_id"]
    models = tmp_env["models"]
    Session = tmp_env["Session"]
    with Session() as db:
        vuln = db.get(models.Vuln, vuln_id)
        assert vuln.root_cause_key == "idor:SysCommentController"
    report = (vuln_dir(project, vuln_id) / "report.md").read_text(encoding="utf-8")
    assert "## 同根因受影响点" in report

    listed = registry.dispatch(_ctx(project, "worker"), "SearchOldVuln", {"query": "idor:SysCommentController"})
    assert listed["ok"] is True
    found = [d for d in listed["docs"] if d.get("vuln_id") == vuln_id]
    assert found
    assert found[0].get("root_cause_key") == "idor:SysCommentController"


def test_append_affected_locations_pending_only(tmp_env, project):
    out = registry.dispatch(_ctx(project, "worker"), "SubmitVuln", _submit_payload())
    vuln_id = out["vuln_id"]
    appended = registry.dispatch(
        _ctx(project, "worker"),
        "AppendAffectedLocations",
        {
            "vuln_id": vuln_id,
            "locations": [
                {
                    "file_path": "app/SysCommentController.java",
                    "line_no": 42,
                    "method": "delete",
                    "note": "同根因删接口",
                }
            ],
        },
    )
    assert appended["ok"] is True
    assert appended["added"] == 1
    report = (vuln_dir(project, vuln_id) / "report.md").read_text(encoding="utf-8")
    assert "delete" in report
    assert "42" in report

    conf = registry.dispatch(
        _ctx(project, "reviewer"),
        "ConfirmVuln",
        {
            "vuln_id": vuln_id,
            "evidence_level": "static_only",
            "attack_surface": "backend",
            "required_account": "user",
            **SEVERITY_FACTORS,
            "root_cause_key": "idor:SysCommentController",
        },
    )
    assert conf["ok"] is True
    blocked = registry.dispatch(
        _ctx(project, "worker"),
        "AppendAffectedLocations",
        {
            "vuln_id": vuln_id,
            "locations": [{"file_path": "app/SysCommentController.java", "line_no": 99, "method": "list"}],
        },
    )
    assert blocked["ok"] is False
    assert "pending_review" in blocked["error"]


def test_merge_into_vuln_into_and_absorb(tmp_env, project):
    worker = _ctx(project, "worker")
    primary = _submit(worker, _submit_payload(title="IDOR primary", line_no=10))
    sibling = _submit(worker, _submit_payload(title="IDOR sibling", line_no=42))
    third = _submit(worker, _submit_payload(title="IDOR third", line_no=88))
    pid, sid, tid = primary["vuln_id"], sibling["vuln_id"], third["vuln_id"]

    absorb = registry.dispatch(
        _ctx(project, "reviewer", vuln_id=pid),
        "MergeIntoVuln",
        {"absorb": [sid], "root_cause_key": "idor:SysCommentController"},
    )
    assert absorb["ok"] is True
    assert sid in absorb["absorbed"]
    models = tmp_env["models"]
    Session = tmp_env["Session"]
    with Session() as db:
        sib = db.get(models.Vuln, sid)
        assert sib.status == "merged"
        assert sib.merged_into_id == pid
    primary_report = (vuln_dir(project, pid) / "report.md").read_text(encoding="utf-8")
    assert "42" in primary_report or "SysCommentController" in primary_report

    conf = _confirm(
        _ctx(project, "reviewer", vuln_id=pid),
        {
            "vuln_id": pid,
            "evidence_level": "static_only",
            "attack_surface": "backend",
            "required_account": "user",
            **SEVERITY_FACTORS,
            "root_cause_key": "idor:SysCommentController",
        },
    )
    assert conf["ok"] is True

    into = registry.dispatch(
        _ctx(project, "reviewer", vuln_id=tid),
        "MergeIntoVuln",
        {
            "into": pid,
            "attack_surface": "backend",
            "required_account": "user",
            "locations": [
                {
                    "file_path": "app/SysCommentController.java",
                    "line_no": 88,
                    "method": "patch",
                    "note": "第三入口",
                }
            ],
        },
    )
    assert into["ok"] is True
    assert into["status"] == "merged"
    assert into["merged_into_id"] == pid
    with Session() as db:
        child = db.get(models.Vuln, tid)
        assert child.status == "merged"
        assert child.merged_into_id == pid
    merged_report = (vuln_dir(project, pid) / "report.md").read_text(encoding="utf-8")
    assert "88" in merged_report or "patch" in merged_report

    listed = registry.dispatch(_ctx(project, "worker"), "SearchOldVuln", {"query": "IDOR third"})
    docs = [d for d in listed["docs"] if d.get("vuln_id") == tid]
    assert docs
    assert docs[0].get("merged_into_id") == pid
    assert "已并入" in (docs[0].get("summary") or "") or docs[0].get("merged_note")


def test_merge_into_vuln_gates(tmp_env, project):
    a = registry.dispatch(_ctx(project, "worker"), "SubmitVuln", _submit_payload(title="A"))
    b = registry.dispatch(
        _ctx(project, "worker"),
        "SubmitVuln",
        _submit_payload(title="B", vuln_type="ssrf", root_cause_key="ssrf:other"),
    )
    ctx = _ctx(project, "reviewer", vuln_id=a["vuln_id"])
    self_merge = registry.dispatch(ctx, "MergeIntoVuln", {"into": a["vuln_id"]})
    assert self_merge["ok"] is False
    assert "自己" in self_merge["error"]

    cross = registry.dispatch(ctx, "MergeIntoVuln", {"into": b["vuln_id"]})
    assert cross["ok"] is False
    assert "vuln_type" in cross["error"]

    registry.dispatch(
        _ctx(project, "reviewer"),
        "ReturnToWorker",
        {"vuln_id": b["vuln_id"], "reason": "误报样例", "false_positive": True},
    )
    into_fp = registry.dispatch(ctx, "MergeIntoVuln", {"into": b["vuln_id"]})
    assert into_fp["ok"] is False

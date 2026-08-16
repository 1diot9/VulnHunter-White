from __future__ import annotations

import json
import os
import time

from app.services.ingest import build_file_index
from app.services.paths import docs_dir, old_vulns_dir, vuln_dir, workspace_dir
from app.tools import ROLE_ACL, SHELL_TOOLS, ToolContext, native_shell_tool, registry
from app.tools.common import todo_relpath


def _ctx(project_id: int, role: str) -> ToolContext:
    return ToolContext(project_id=project_id, role=role, phase=role)


SEVERITY_FACTORS = {
    "impact": "sensitive_data_or_privilege",
    "exploit_complexity": "single_request",
    "defense_status": "none",
}


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
    from app.tools.phase_recon import apply_recon_done, recon_docs_ready, recon_gates_met, recon_gates_status

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
    assert recon_docs_ready(project) is True
    assert [s["done"] for s in recon_gates_status(project)["subphases"]] == [True, True, False]

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

    assert recon_gates_met(project) is True
    assert apply_recon_done(project) is True
    with Session() as db:
        p = db.get(models.Project, project)
        assert p.recon_done is True


def test_submit_vuln_requires_fields(tmp_env, project):
    out = registry.dispatch(_ctx(project, "worker"), "SubmitVuln", {"title": "x"})
    assert out["ok"] is False
    assert "缺少必填" in out["error"]


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
    assert conf["severity_score"] == 4

    models = tmp_env["models"]
    Session = tmp_env["Session"]
    with Session() as db:
        v = db.get(models.Vuln, vuln_id)
        assert v.status == "static_only"
        assert v.evidence_level == "static_only"
        assert v.attack_surface == "frontend"
        assert v.required_account is None
        assert v.severity == "high"
    report = (vuln_dir(project, vuln_id) / "report.md").read_text(encoding="utf-8")
    assert "**产出时间**：" in report
    assert report.index("**产出时间**：") < report.index("## 摘要")
    assert "## 审核标注" in report
    assert "- 攻击面：前台" in report
    assert "- 严重度：高危（high）" in report
    assert "- 校准得分：4" in report
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
    assert conf["severity"] == "high"
    report = (vuln_dir(project, vuln_id) / "report.md").read_text(encoding="utf-8")
    assert "- 所需账号：普通权限" in report


def test_confirm_frontend_ignores_account(tmp_env, project):
    payload = {
        "title": "XSS",
        "vuln_type": "xss",
        "cwe": "CWE-79",
        "file_path": "app/Main.java",
        "line_no": 1,
        "source_sink": "a->b",
        "auth_premise": "未授权",
        "http_request": "GET / HTTP/1.1\n",
        "poc_code": "print(1)\n",
        "expected_evidence": "alert",
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
    r_fix = registry.dispatch(
        fixer, "TodoWrite", {"todos": [{"id": "1", "content": "fix", "status": "pending"}]}
    )

    assert r_recon["path"] == "workspace/todos-recon.json"
    assert r_wa["path"] == "workspace/todos-worker-worker-1-abc.json"
    assert r_wb["path"] == "workspace/todos-worker-worker-2-def.json"
    assert r_rev["path"] == "workspace/todos-reviewer-9.json"
    assert r_fix["path"] == "workspace/todos-fix-9.json"

    ws = workspace_dir(project)
    recon_todos = json.loads((ws / "todos-recon.json").read_text(encoding="utf-8"))
    wa_todos = json.loads((ws / "todos-worker-worker-1-abc.json").read_text(encoding="utf-8"))
    wb_todos = json.loads((ws / "todos-worker-worker-2-def.json").read_text(encoding="utf-8"))
    rev_todos = json.loads((ws / "todos-reviewer-9.json").read_text(encoding="utf-8"))
    fix_todos = json.loads((ws / "todos-fix-9.json").read_text(encoding="utf-8"))
    assert recon_todos[0]["content"] == "recon-task"
    assert wa_todos[0]["content"] == "worker-a"
    assert wb_todos[0]["content"] == "worker-b"
    assert rev_todos[0]["content"] == "review"
    assert fix_todos[0]["content"] == "fix"
    assert not (ws / "todos.json").exists()
    assert todo_relpath(recon) != todo_relpath(worker_a)


def test_openai_tools_for_role_contains_expected():
    recon_names = {t["function"]["name"] for t in registry.openai_tools_for_role("recon")}
    assert "FinishRecon" not in recon_names
    assert "WriteOldVuln" not in recon_names
    assert "SearchGHSA" not in recon_names
    assert "WebSearch" not in recon_names
    assert "MarkSource" in recon_names
    assert "SubmitVuln" not in recon_names
    assert "MarkWeight" not in recon_names
    old_names = {t["function"]["name"] for t in registry.openai_tools_for_role("recon_old_vuln")}
    assert "WriteOldVuln" in old_names
    assert "SearchGHSA" in old_names
    assert "WebSearch" in old_names
    assert "MarkSource" not in old_names
    assert "Write" not in old_names
    mark_names = {t["function"]["name"] for t in registry.openai_tools_for_role("recon_mark")}
    assert mark_names == {"MarkSource", "MarkWeight", "MarkSkip"}
    worker_names = {t["function"]["name"] for t in registry.openai_tools_for_role("worker")}
    assert "FinishAudit" not in worker_names
    assert "FinishRound" in worker_names
    assert ROLE_ACL["worker"].isdisjoint({"FinishRecon", "FinishAudit", "ConfirmVuln", "WriteOldVuln"})
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

    monkeypatch.setattr("app.tools.common.http_client", lambda timeout=20.0: FakeClient())
    out = registry.dispatch(_ctx(project, "recon_old_vuln"), "WebSearch", {"query": "halo cve"})
    assert out["ok"] is True
    assert out.get("results") == []
    assert "空" in (out.get("note") or "")


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
    assert recon_old_vulns_ready(project) is True
    assert recon_docs_ready(project) is True
    assert recon_gates_met(project) is False
    subs = {s["id"]: s["done"] for s in recon_subphases(project)}
    assert subs["map"] is True
    assert subs["old_vulns"] is True
    assert subs["mark"] is False

    batch = pick_unmarked_batch(project, 10)
    assert batch
    assert paths_fully_marked(project, batch) is False
    out = registry.dispatch(_ctx(project, "recon_mark"), "MarkWeight", {"paths": batch, "weight": 40})
    assert out["ok"] is True
    assert paths_fully_marked(project, batch) is True


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


def test_recon_mark_cannot_read(tmp_env, project):
    out = registry.dispatch(_ctx(project, "recon_mark"), "Read", {"path": "app/Main.java"})
    assert out["ok"] is False
    assert "无权" in out["error"]


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


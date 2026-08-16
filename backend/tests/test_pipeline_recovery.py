"""Recovery, claim release, state completion, and local tool-error logging."""

from __future__ import annotations

import sqlite3
from datetime import timedelta

from sqlalchemy.exc import OperationalError

from app.agent.compression import inject_summary_block, latest_summary, write_summary
from app.config import settings
from app.services.ingest import build_file_index
from app.services.paths import docs_dir, old_vulns_dir, tool_exec_errors_path
from app.services import pipeline
from app.tools import ToolContext, registry
from app.tools.phase_recon import apply_recon_done, recon_gates_met
from app.tools.phase_worker import mining_complete, project_complete_gates
from app.models import utcnow


def _ctx(project_id: int, role: str, **kwargs) -> ToolContext:
    return ToolContext(project_id=project_id, role=role, phase=role, **kwargs)


def _mark_all_weighted(project: int) -> None:
    docs = docs_dir(project)
    (docs / "code-map.md").write_text("# map\n", encoding="utf-8")
    (docs / "auth.md").write_text("# auth\n", encoding="utf-8")
    old = old_vulns_dir(project)
    old.mkdir(parents=True, exist_ok=True)
    (old / "index.md").write_text(
        "---\ntitle: 历史漏洞索引\nsummary: test\ncomplete: true\n---\n\n# index\n",
        encoding="utf-8",
    )


def test_release_claim_allows_repick(tmp_env, project):
    build_file_index(project)
    models = tmp_env["models"]
    Session = tmp_env["Session"]
    with Session() as db:
        for fw in db.query(models.FileWeight).filter(models.FileWeight.project_id == project).all():
            fw.weight = 80
        db.commit()

    fw = pipeline._pick_next_file(project, "worker-a")
    assert fw is not None
    path = fw.path
    pipeline._release_claim_if_unfinished(project, path, "worker-a", failed=True)
    with Session() as db:
        row = (
            db.query(models.FileWeight)
            .filter(models.FileWeight.project_id == project, models.FileWeight.path == path)
            .first()
        )
        assert row.claimed_by is None
        assert row.audit_attempts == 1

    fw2 = pipeline._pick_next_file(project, "worker-b")
    assert fw2 is not None
    assert fw2.path == path


def test_role_pools_are_fixed():
    assert pipeline.RECON_POOL == 1
    assert pipeline.WORKER_MINE_POOL == 1
    assert pipeline.WORKER_FIX_POOL == 1
    assert pipeline.REVIEWER_POOL == 1
    assert pipeline._worker_concurrency(1) == 1
    assert pipeline._fix_concurrency() == 1


def test_prepare_resume_clears_claims_and_fixing(tmp_env, project):
    build_file_index(project)
    models = tmp_env["models"]
    Session = tmp_env["Session"]
    with Session() as db:
        fw = db.query(models.FileWeight).filter(models.FileWeight.project_id == project).first()
        fw.weight = 50
        fw.claimed_by = "dead-worker"
        fw.claimed_at = utcnow()
        v = models.Vuln(
            project_id=project,
            title="t",
            vuln_type="sqli",
            status="fixing",
            return_reason="x",
        )
        db.add(v)
        db.commit()

    pipeline._prepare_project_resume(project)
    with Session() as db:
        fw = db.query(models.FileWeight).filter(models.FileWeight.project_id == project).first()
        assert fw.claimed_by is None
        v = db.query(models.Vuln).filter(models.Vuln.project_id == project).first()
        assert v.status == "returned"


def test_release_stale_claims(tmp_env, project, monkeypatch):
    build_file_index(project)
    monkeypatch.setattr(settings, "claim_stale_sec", 60)
    models = tmp_env["models"]
    Session = tmp_env["Session"]
    with Session() as db:
        fw = db.query(models.FileWeight).filter(models.FileWeight.project_id == project).first()
        fw.weight = 40
        fw.claimed_by = "stale"
        fw.claimed_at = utcnow() - timedelta(seconds=120)
        db.commit()
        path = fw.path
    n = pipeline._release_stale_claims(project)
    assert n == 1
    with Session() as db:
        fw = (
            db.query(models.FileWeight)
            .filter(models.FileWeight.project_id == project, models.FileWeight.path == path)
            .first()
        )
        assert fw.claimed_by is None


def test_recon_gates_no_default_weight(tmp_env, project):
    build_file_index(project)
    _mark_all_weighted(project)
    assert recon_gates_met(project) is False
    models = tmp_env["models"]
    Session = tmp_env["Session"]
    with Session() as db:
        unmarked = (
            db.query(models.FileWeight)
            .filter(
                models.FileWeight.project_id == project,
                models.FileWeight.weight.is_(None),
                models.FileWeight.skipped.is_(False),
            )
            .count()
        )
        assert unmarked > 0


def test_mining_and_project_complete_gates(tmp_env, project):
    build_file_index(project)
    _mark_all_weighted(project)
    models = tmp_env["models"]
    Session = tmp_env["Session"]
    with Session() as db:
        for fw in db.query(models.FileWeight).filter(models.FileWeight.project_id == project).all():
            fw.weight = 50
            fw.audited = True
        proj = db.get(models.Project, project)
        proj.recon_done = True
        db.commit()

    assert mining_complete(project) is True
    assert project_complete_gates(project) is True

    out = registry.dispatch(
        _ctx(project, "worker"),
        "SubmitVuln",
        {
            "title": "late",
            "vuln_type": "sqli",
            "cwe": "CWE-89",
            "file_path": "app/Main.java",
            "line_no": 1,
            "source_sink": "a->b",
            "auth_premise": "x",
            "http_request": "GET /\n",
            "poc_code": "print(1)\n",
            "expected_evidence": "e",
        },
    )
    assert out["ok"] is False
    assert "挖掘阶段已完成" in out["error"]

    # pending_review blocks project complete but not mining complete
    with Session() as db:
        for fw in db.query(models.FileWeight).filter(models.FileWeight.project_id == project).all():
            fw.audited = False
        db.commit()
    # re-open mining by marking one unaudited then submit while mining open
    with Session() as db:
        fw = db.query(models.FileWeight).filter(models.FileWeight.project_id == project).first()
        fw.audited = False
        # leave one unaudited so mining not complete - actually we need mining open to submit
        db.commit()

    # Mark all audited again after submitting via direct DB
    with Session() as db:
        for fw in db.query(models.FileWeight).filter(models.FileWeight.project_id == project).all():
            fw.audited = True
        v = models.Vuln(
            project_id=project,
            title="pending",
            vuln_type="sqli",
            status="pending_review",
        )
        db.add(v)
        db.commit()

    assert mining_complete(project) is True
    assert project_complete_gates(project) is False

    with Session() as db:
        v = db.query(models.Vuln).filter(models.Vuln.project_id == project).first()
        v.status = "returned"
        db.commit()
    assert mining_complete(project) is False
    assert project_complete_gates(project) is False


def test_maybe_complete_project(tmp_env, project):
    build_file_index(project)
    models = tmp_env["models"]
    Session = tmp_env["Session"]
    with Session() as db:
        proj = db.get(models.Project, project)
        proj.recon_done = True
        proj.status = "auditing"
        for fw in db.query(models.FileWeight).filter(models.FileWeight.project_id == project).all():
            fw.weight = 10
            fw.audited = True
        db.commit()

    assert pipeline._maybe_complete_project(project, reviewer_busy=False, fix_busy=False) is True
    with Session() as db:
        proj = db.get(models.Project, project)
        assert proj.status == "completed"
        assert proj.phase == "done"


def test_reviewer_loop_retries_sqlite_locked_project_check(tmp_env, project, monkeypatch):
    errors: list[str] = []

    class FakeCancel:
        def __init__(self) -> None:
            self.stopped = False

        def is_set(self) -> bool:
            return self.stopped

        def wait(self, timeout: float | None = None) -> bool:
            self.stopped = True
            return True

    class LockedSession:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> bool:
            return False

        def get(self, model, project_id):
            raise OperationalError(
                "SELECT projects.id FROM projects WHERE projects.id = ?",
                (project_id,),
                sqlite3.OperationalError("database is locked"),
            )

    cancel = FakeCancel()
    monkeypatch.setattr(pipeline, "_cancel_event", lambda pid: cancel)
    monkeypatch.setattr(pipeline, "_loop_cancel", lambda pid, phase: cancel)
    monkeypatch.setattr(pipeline, "SessionLocal", lambda: LockedSession())
    monkeypatch.setattr(pipeline.live_log, "error", lambda pid, text, **kwargs: errors.append(text))

    pipeline._run_reviewer_loop(project)

    assert errors == []


def test_finish_round_then_summary_injection(tmp_env, project):
    write_summary(project, "worker-round", "已分析 Main.java 的登录流")
    block = inject_summary_block(latest_summary(project, "worker"), for_file=True)
    assert "已分析 Main.java" in block
    assert "上一轮摘要" in block


def test_summary_does_not_cross_recon_subphases(tmp_env, project):
    write_summary(project, "recon", "地图会话摘要")
    write_summary(project, "recon-old-vuln", "历史漏洞会话摘要")
    write_summary(project, "recon-mark", "盖章会话摘要")
    assert latest_summary(project, "recon") == "地图会话摘要"
    assert latest_summary(project, "recon-old-vuln") == "历史漏洞会话摘要"
    assert latest_summary(project, "recon-mark") == "盖章会话摘要"


def test_run_recon_subphases_are_serial(tmp_env, project, monkeypatch):
    order: list[str] = []
    monkeypatch.setattr(pipeline, "_maybe_mark_recon_done", lambda pid: False)
    monkeypatch.setattr(pipeline, "recon_map_ready", lambda pid: False)
    monkeypatch.setattr(pipeline, "recon_old_vulns_ready", lambda pid: False)
    monkeypatch.setattr(pipeline, "_run_recon_map", lambda pid, cancel: order.append("map") or True)
    monkeypatch.setattr(
        pipeline, "_run_recon_old_vulns", lambda pid, cancel: order.append("old") or True
    )
    monkeypatch.setattr(pipeline, "_run_recon_marking", lambda pid, cancel: order.append("mark"))
    pipeline._run_recon(project)
    assert order == ["map", "old", "mark"]


def test_run_recon_does_not_skip_ahead_when_map_fails(tmp_env, project, monkeypatch):
    order: list[str] = []
    monkeypatch.setattr(pipeline, "_maybe_mark_recon_done", lambda pid: False)
    monkeypatch.setattr(pipeline, "recon_map_ready", lambda pid: False)
    monkeypatch.setattr(pipeline, "_run_recon_map", lambda pid, cancel: order.append("map") or False)
    monkeypatch.setattr(
        pipeline, "_run_recon_old_vulns", lambda pid, cancel: order.append("old") or True
    )
    monkeypatch.setattr(pipeline, "_run_recon_marking", lambda pid, cancel: order.append("mark"))
    pipeline._run_recon(project)
    assert order == ["map"]


def test_recon_control_includes_old_vuln_phase():
    assert pipeline.CONTROL_DB_PHASES["recon"] == ("recon", "recon-old-vuln", "recon-mark")
    assert pipeline.control_phase("recon-old-vuln") == "recon"
    assert pipeline.control_phase("recon-map") == "recon"


def test_local_shell_error_writes_jsonl(tmp_env, project):
    out = registry.dispatch(
        _ctx(project, "worker"),
        "PowerShell" if __import__("os").name == "nt" else "Bash",
        {"command": "exit 7"},
    )
    assert out["ok"] is False
    assert out.get("error_class") == "local"
    path = tool_exec_errors_path(project)
    assert path.exists()
    text = path.read_text(encoding="utf-8")
    assert "exit" in text.lower() or "error" in text.lower()

    # call error should not append
    before = path.read_text(encoding="utf-8")
    denied = registry.dispatch(_ctx(project, "worker"), "FinishRecon", {})
    assert denied["ok"] is False
    after = path.read_text(encoding="utf-8")
    assert after == before


def test_sandbox_write_local_fail(tmp_env, project):
    out = registry.dispatch(
        _ctx(project, "worker"),
        "Write",
        {"path": "../outside.txt", "content": "x"},
    )
    assert out["ok"] is False
    assert out.get("error_class") == "local"
    assert tool_exec_errors_path(project).exists()


def test_missing_field_is_call_not_local(tmp_env, project):
    out = registry.dispatch(_ctx(project, "worker"), "SubmitVuln", {"title": "x"})
    assert out["ok"] is False
    # SubmitVuln doesn't set error_class call explicitly — ensure not local jsonl
    path = tool_exec_errors_path(project)
    if path.exists():
        assert "SubmitVuln" not in path.read_text(encoding="utf-8")


def test_no_finish_tools_registered():
    assert registry.get("FinishRecon") is None
    assert registry.get("FinishAudit") is None


def test_apply_recon_done_sets_flag(tmp_env, project):
    build_file_index(project)
    _mark_all_weighted(project)
    models = tmp_env["models"]
    Session = tmp_env["Session"]
    with Session() as db:
        for fw in db.query(models.FileWeight).filter(models.FileWeight.project_id == project).all():
            if fw.weight is None:
                fw.weight = 20
        db.commit()
    assert apply_recon_done(project) is True
    with Session() as db:
        assert db.get(models.Project, project).recon_done is True


def test_maybe_mark_recon_done_logs_only_on_transition(tmp_env, project, monkeypatch):
    build_file_index(project)
    _mark_all_weighted(project)
    models = tmp_env["models"]
    Session = tmp_env["Session"]
    with Session() as db:
        for fw in db.query(models.FileWeight).filter(models.FileWeight.project_id == project).all():
            if fw.weight is None:
                fw.weight = 20
        db.commit()

    logs: list[str] = []
    monkeypatch.setattr(
        pipeline.live_log,
        "system",
        lambda pid, text, **kwargs: logs.append(text),
    )
    assert pipeline._maybe_mark_recon_done(project) is True
    assert logs == ["侦察门闩已满足，系统标记 recon_done"]
    assert pipeline._maybe_mark_recon_done(project) is True
    assert logs == ["侦察门闩已满足，系统标记 recon_done"]
    assert apply_recon_done(project) is True

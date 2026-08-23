"""Recovery, claim release, state completion, and local tool-error logging."""

from __future__ import annotations

import sqlite3
from datetime import timedelta

from sqlalchemy.exc import OperationalError

from app.agent.compression import (
    inject_summary_block,
    inject_worker_prior_block,
    latest_summary,
    max_round_report_no,
    strip_followup_section,
    write_summary,
)
from app.config import settings
from app.services.ingest import build_file_index
from app.services.paths import docs_dir, old_vulns_dir, tool_exec_errors_path, workspace_dir
from app.services import pipeline
from app.tools import ToolContext, registry
from app.tools.phase_recon import apply_recon_done, recon_gates_met
from app.tools.phase_worker import mining_complete, project_complete_gates
from app.models import utcnow


def _ctx(project_id: int, role: str, **kwargs) -> ToolContext:
    return ToolContext(project_id=project_id, role=role, phase=role, **kwargs)


def _enable_dynamic_verify(project_id: int, enabled: bool = True) -> None:
    from app.models import Project, SessionLocal

    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        assert proj is not None
        proj.dynamic_verify_enabled = enabled
        proj.dynamic_verify_mode = "lab" if enabled else "off"
        db.commit()


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
    (docs / "source-exts.md").write_text(
        "---\ntitle: 额外源码扩展名\nsummary: test\ncomplete: true\nexts: []\nadded_count: 0\n---\n\n# 额外源码扩展名\n",
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
            "config_premise": "default",
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


def test_refresh_project_after_reviewer_reverts_when_queue_empty(tmp_env, project):
    build_file_index(project)
    models = tmp_env["models"]
    Session = tmp_env["Session"]
    with Session() as db:
        proj = db.get(models.Project, project)
        proj.recon_done = True
        proj.status = "reviewing"
        proj.phase = "reviewer"
        rows = db.query(models.FileWeight).filter(models.FileWeight.project_id == project).all()
        assert rows
        for i, fw in enumerate(rows):
            fw.weight = 10
            fw.skipped = False
            fw.audited = i > 0
        db.commit()

    pipeline._refresh_project_after_reviewer(project)
    with Session() as db:
        proj = db.get(models.Project, project)
        assert proj.status == "auditing"
        assert proj.phase == "worker"


def test_refresh_project_after_reviewer_completes_when_idle(tmp_env, project):
    build_file_index(project)
    models = tmp_env["models"]
    Session = tmp_env["Session"]
    with Session() as db:
        proj = db.get(models.Project, project)
        proj.recon_done = True
        proj.status = "reviewing"
        proj.phase = "reviewer"
        for fw in db.query(models.FileWeight).filter(models.FileWeight.project_id == project).all():
            fw.weight = 10
            fw.audited = True
        db.commit()

    pipeline._refresh_project_after_reviewer(project)
    with Session() as db:
        proj = db.get(models.Project, project)
        assert proj.status == "completed"
        assert proj.phase == "done"


def test_reviewer_force_new_is_not_open_work(tmp_env, project):
    pipeline._force_new_run.add((project, "reviewer"))
    assert pipeline._should_skip_checkpoint(project, "reviewer") is True
    assert pipeline._reviewer_has_review_work(project, pending=0) is False


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


def _write_recon_docs(project: int) -> None:
    docs = docs_dir(project)
    (docs / "code-map.md").write_text("# 地图\n入口在 Main.java。\n", encoding="utf-8")
    (docs / "auth.md").write_text("# 鉴权\nJWT 过滤器。\n", encoding="utf-8")


def _write_security_policy(project: int, text: str = "# Security\n不接收 CSRF。\n") -> None:
    from app.services.paths import src_dir

    (src_dir(project) / "SECURITY.md").write_text(text, encoding="utf-8")


def _write_round_report(project: int, n: int, text: str) -> None:
    rounds = workspace_dir(project) / "rounds"
    rounds.mkdir(parents=True, exist_ok=True)
    (rounds / f"round-{n}.md").write_text(text, encoding="utf-8")


def test_strip_followup_section_keeps_later_h2():
    text = (
        "## 已排除\n- 旧路径 A\n\n"
        "## 建议后续方向\n- 去看 SqlUtils\n\n"
        "## 备注\n- 保留\n"
    )
    out = strip_followup_section(text)
    assert "去看 SqlUtils" not in out
    assert "旧路径 A" in out
    assert "## 备注" in out
    assert "保留" in out
    assert "建议后续方向" not in out


def test_next_worker_round_id_does_not_reuse_existing_files(tmp_env, project):
    assert pipeline._next_worker_round_id(project) == 1
    for n in range(1, 9):
        _write_round_report(project, n, f"old-{n}")
    assert max_round_report_no(project) == 8
    # Restart / 新跑 must not overwrite round-1.md just because the live-log session is 1.
    assert pipeline._next_worker_round_id(project) == 9


def test_next_worker_round_id_restarts_after_reports_cleared(tmp_env, project):
    for n in range(1, 9):
        _write_round_report(project, n, f"old-{n}")
    for path in (workspace_dir(project) / "rounds").glob("round-*.md"):
        path.unlink()
    # reset-progress deletes reports; live-log session may still be 27.
    assert pipeline._next_worker_round_id(project) == 1


def test_bind_worker_round_id_resume_keeps_unwritten_round(tmp_env, project):
    loop = pipeline.AgentLoop(
        project_id=project,
        role="worker",
        phase="worker",
        system_prompt="s",
        user_prompt="u",
    )
    loop.state["round_id"] = 3
    n = pipeline._bind_worker_round_id(loop, project, new_round=False)
    assert n == 3
    assert loop.state["round_id"] == 3


def test_bind_worker_round_id_resume_avoids_overwrite(tmp_env, project):
    for n in range(1, 4):
        _write_round_report(project, n, f"old-{n}")
    loop = pipeline.AgentLoop(
        project_id=project,
        role="worker",
        phase="worker",
        system_prompt="s",
        user_prompt="u",
    )
    loop.state["round_id"] = 3
    n = pipeline._bind_worker_round_id(loop, project, new_round=False)
    assert n == 4
    assert loop.state["round_id"] == 4


def test_worker_prior_block_injects_security_policy(tmp_env, project):
    _write_recon_docs(project)
    _write_security_policy(project, "# Policy\n不接收 CSRF 与缺少 HttpOnly。\n")

    block = inject_worker_prior_block(project)
    assert "src/SECURITY.md" in block
    assert "不接收 CSRF" in block
    assert "项目安全策略" in block


def test_worker_prior_block_injects_security_policy_without_recon_docs(tmp_env, project):
    _write_security_policy(project, "# Policy\n仅 SECURITY.md。\n")

    block = inject_worker_prior_block(project)
    assert "src/SECURITY.md" in block
    assert "仅 SECURITY.md" in block
    assert "docs/code-map.md" not in block


def test_worker_prior_block_injects_recon_and_recent_rounds(tmp_env, project):
    _write_recon_docs(project)
    for n in range(1, 13):
        _write_round_report(project, n, f"[round={n}] 已审 LoginController。")

    block = inject_worker_prior_block(project)
    assert "docs/code-map.md" in block
    assert "入口在 Main.java" in block
    assert "docs/auth.md" in block
    assert "JWT 过滤器" in block
    assert "禁止再梳理项目结构" in block
    assert "不要重复已尝试路径" in block
    assert "### 第 3 轮 ·" in block
    assert "### 第 12 轮 ·" in block
    assert "[round=3]" in block
    assert "[round=12]" in block
    assert "[round=1]" not in block
    assert "[round=2]" not in block
    assert "### 第 1 轮 ·" not in block
    assert "### 第 2 轮 ·" not in block


def test_worker_prior_block_strips_followup_from_all_rounds(tmp_env, project):
    _write_recon_docs(project)
    _write_round_report(
        project,
        1,
        "## 已排除\n- 旧路径 A\n\n## 建议后续方向\n- 去看 SqlUtils\n",
    )
    _write_round_report(
        project,
        2,
        "## 已排除\n- SqlUtils 已排除\n\n## 建议后续方向\n- 去看 QuartzJobController\n",
    )

    block = inject_worker_prior_block(project)
    assert "旧路径 A" in block
    assert "SqlUtils 已排除" in block
    assert "去看 SqlUtils" not in block
    assert "去看 QuartzJobController" not in block
    assert "## 建议后续方向" not in block
    assert "不要按历史摘要里的建议改方向" in block


def test_worker_prior_block_falls_back_to_compression_summaries(tmp_env, project):
    _write_recon_docs(project)
    for n in range(1, 4):
        write_summary(project, "worker-round", f"压缩摘要轮 {n} 已走 /admin。")

    block = inject_worker_prior_block(project)
    assert "尚无 FinishRound 报告" in block
    assert "压缩摘要轮 1 已走 /admin" in block
    assert "压缩摘要轮 3 已走 /admin" in block


def test_prompt_with_summary_injects_prior_only_for_worker_files(tmp_env, project):
    _write_recon_docs(project)
    _write_security_policy(project, "# Policy\n不接收目录遍历。\n")
    _write_round_report(project, 1, "已否决 /debug 路径。")

    worker = pipeline._prompt_with_summary("worker", project, "本轮任务正文", for_file=True)
    assert "入口在 Main.java" in worker
    assert "JWT 过滤器" in worker
    assert "已否决 /debug 路径" in worker
    assert worker.index("侦察产物") < worker.index("本轮任务正文")

    reviewer = pipeline._prompt_with_summary("reviewer", project, "审核正文")
    assert "入口在 Main.java" not in reviewer
    assert "已否决 /debug 路径" not in reviewer
    assert "src/SECURITY.md" in reviewer
    assert "不接收目录遍历" in reviewer
    assert "审核正文" in reviewer


def test_prompt_with_summary_injects_worker_hint(tmp_env, project):
    from app.models import Project, SessionLocal

    with SessionLocal() as db:
        p = db.get(Project, project)
        p.worker_hint = "  重点看后台导出；忽略演示账号  "
        db.commit()

    worker = pipeline._prompt_with_summary("worker", project, "本轮任务正文", for_file=True)
    assert "项目人工提示" in worker
    assert "重点看后台导出；忽略演示账号" in worker
    assert worker.index("本轮任务正文") < worker.index("项目人工提示")

    fast = pipeline._prompt_with_summary("fast-worker", project, "Sink 正文")
    assert "重点看后台导出；忽略演示账号" in fast
    bypass = pipeline._prompt_with_summary("bypass-worker", project, "绕过正文")
    assert "重点看后台导出；忽略演示账号" in bypass

    reviewer = pipeline._prompt_with_summary("reviewer", project, "审核正文")
    assert "项目人工提示" not in reviewer
    assert "重点看后台导出" not in reviewer
    fix = pipeline._prompt_with_summary("fix", project, "修复正文")
    assert "项目人工提示" not in fix
    triage = pipeline._prompt_with_summary("sink-triage", project, "筛选正文")
    assert "项目人工提示" not in triage

    with SessionLocal() as db:
        p = db.get(Project, project)
        p.worker_hint = "price = ${project_id} 不要改焦点"
        db.commit()
    dollar = pipeline._prompt_with_summary("worker", project, "本轮任务正文")
    assert "price = ${project_id} 不要改焦点" in dollar

    with SessionLocal() as db:
        p = db.get(Project, project)
        p.worker_hint = ""
        db.commit()
    empty = pipeline._prompt_with_summary("worker", project, "本轮任务正文", for_file=True)
    assert "项目人工提示" not in empty


def test_worker_prior_block_truncates_oversized_docs(tmp_env, project, monkeypatch):
    from app.agent.compression import inject_worker_prior_block
    from app.config import settings

    monkeypatch.setattr(settings, "recon_doc_inject_max_chars", 20)
    monkeypatch.setattr(settings, "round_report_inject_max_chars", 10)
    docs = docs_dir(project)
    (docs / "code-map.md").write_text("M" * 80, encoding="utf-8")
    (docs / "auth.md").write_text("A" * 80, encoding="utf-8")
    _write_round_report(project, 1, "R" * 80)

    block = inject_worker_prior_block(project)
    assert "truncated" in block
    assert "M" * 80 not in block


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
    monkeypatch.setattr(pipeline, "recon_source_ext_ready", lambda pid: False)
    monkeypatch.setattr(pipeline, "recon_old_vulns_ready", lambda pid: False)
    monkeypatch.setattr(pipeline, "_run_recon_map", lambda pid, cancel: order.append("map") or True)
    monkeypatch.setattr(
        pipeline, "_run_recon_source_ext", lambda pid, cancel: order.append("ext") or True
    )
    monkeypatch.setattr(
        pipeline, "_run_recon_old_vulns", lambda pid, cancel: order.append("old") or True
    )
    monkeypatch.setattr(pipeline, "_run_recon_marking", lambda pid, cancel: order.append("mark"))
    pipeline._run_recon(project)
    assert order == ["map", "ext", "old", "mark"]


def test_run_recon_does_not_skip_ahead_when_map_fails(tmp_env, project, monkeypatch):
    order: list[str] = []
    monkeypatch.setattr(pipeline, "_maybe_mark_recon_done", lambda pid: False)
    monkeypatch.setattr(pipeline, "recon_map_ready", lambda pid: False)
    monkeypatch.setattr(pipeline, "_run_recon_map", lambda pid, cancel: order.append("map") or False)
    monkeypatch.setattr(
        pipeline, "_run_recon_source_ext", lambda pid, cancel: order.append("ext") or True
    )
    monkeypatch.setattr(
        pipeline, "_run_recon_old_vulns", lambda pid, cancel: order.append("old") or True
    )
    monkeypatch.setattr(pipeline, "_run_recon_marking", lambda pid, cancel: order.append("mark"))
    pipeline._run_recon(project)
    assert order == ["map"]


def test_recon_control_includes_old_vuln_phase():
    assert pipeline.CONTROL_DB_PHASES["recon"] == (
        "recon",
        "recon-source-ext",
        "recon-old-vuln",
        "recon-old-vuln-ghsa",
        "recon-mark",
    )
    assert pipeline.control_phase("recon-old-vuln") == "recon"
    assert pipeline.control_phase("recon-old-vuln-ghsa") == "recon"
    assert pipeline.control_phase("recon-source-ext") == "recon"
    assert pipeline.control_phase("recon-map") == "recon"
    assert pipeline.control_phase("fast-worker") == "worker"
    assert pipeline.control_phase("sink-triage") == "worker"
    assert pipeline.control_phase("fast") == "worker"
    assert pipeline.control_phase("bypass-worker") == "worker"
    assert pipeline.control_phase("bypass") == "worker"


def test_ensure_workers_waits_for_old_vulns(tmp_env, project, monkeypatch):
    build_file_index(project)
    models = tmp_env["models"]
    Session = tmp_env["Session"]
    with Session() as db:
        for fw in db.query(models.FileWeight).filter(models.FileWeight.project_id == project).all():
            if fw.skipped:
                continue
            fw.weight = 80
            fw.skipped = False
            fw.audited = False
        db.commit()

    started: list[str] = []

    class FakeThread:
        def __init__(self, *args, **kwargs):  # noqa: ANN002, ARG002
            self._alive = False
            self.name = kwargs.get("name") or ""

        def is_alive(self) -> bool:
            return self._alive

        def start(self) -> None:
            self._alive = True
            started.append(self.name)

    monkeypatch.setattr(pipeline.threading, "Thread", FakeThread)
    pipeline.reset_runtime_state()
    assert pipeline.recon_old_vulns_ready(project) is False
    out = pipeline._ensure_workers(project, [])
    assert out == []
    assert started == []

    _mark_all_weighted(project)
    assert pipeline.recon_old_vulns_ready(project) is True
    out = pipeline._ensure_workers(project, [])
    assert started
    assert all(name.startswith("vh-worker-") for name in started)
    assert len(out) == len(started)


def test_ensure_bypass_prepare_waits_for_old_vulns(tmp_env, project):
    models = tmp_env["models"]
    Session = tmp_env["Session"]
    with Session() as db:
        proj = db.get(models.Project, project)
        proj.heuristic_enabled = False
        proj.fast_enabled = False
        proj.bypass_enabled = True
        db.commit()
    assert pipeline.recon_old_vulns_ready(project) is False
    pipeline._ensure_bypass_prepare(project)
    with Session() as db:
        proj = db.get(models.Project, project)
        assert bool(proj.bypass_queue_frozen) is False

    _mark_all_weighted(project)
    pipeline._ensure_bypass_prepare(project)
    with Session() as db:
        proj = db.get(models.Project, project)
        assert bool(proj.bypass_queue_frozen) is True
        assert pipeline.recon_old_vulns_ready(project) is True


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
    monkeypatch.setattr(pipeline, "_ensure_project_fingerprints_once", lambda _pid: None)
    assert pipeline._maybe_mark_recon_done(project) is True
    assert logs == ["侦察门闩已满足，系统标记 recon_done"]
    assert pipeline._maybe_mark_recon_done(project) is True
    assert logs == ["侦察门闩已满足，系统标记 recon_done"]
    assert apply_recon_done(project) is True


def test_ensure_reviewer_skips_lab_when_dynamic_off(tmp_env, project, monkeypatch):
    started: list[int] = []

    class FakeThread:
        def __init__(self, *args, **kwargs):  # noqa: ANN002, ARG002
            self._alive = False
            self.name = kwargs.get("name") or ""

        def is_alive(self) -> bool:
            return self._alive

        def start(self) -> None:
            self._alive = True
            started.append(project)

    monkeypatch.setattr(pipeline.threading, "Thread", FakeThread)
    pipeline.reset_runtime_state()
    pipeline._ensure_reviewer(project, pipeline._cancel_event(project))
    assert started == []


def test_ensure_reviewer_starts_lab_round_without_pending_vulns(tmp_env, project, monkeypatch):
    _enable_dynamic_verify(project)
    started: list[int] = []

    class FakeThread:
        def __init__(self, *args, **kwargs):  # noqa: ANN002, ARG002
            self._alive = False
            self.name = kwargs.get("name") or ""

        def is_alive(self) -> bool:
            return self._alive

        def start(self) -> None:
            self._alive = True
            started.append(project)

    monkeypatch.setattr(pipeline.threading, "Thread", FakeThread)
    pipeline.reset_runtime_state()
    pipeline._ensure_reviewer(project, pipeline._cancel_event(project))
    assert started == [project]


def test_ensure_reviewer_skips_when_lab_done_and_no_queue(tmp_env, project, monkeypatch):
    from app.services.lab import mark_lab_setup_finished

    mark_lab_setup_finished(project, skipped=True, notes="skip", via="test")
    started: list[int] = []

    class FakeThread:
        def __init__(self, *args, **kwargs):  # noqa: ANN002, ARG002
            self.name = kwargs.get("name") or ""

        def is_alive(self) -> bool:
            return False

        def start(self) -> None:
            started.append(project)

    monkeypatch.setattr(pipeline.threading, "Thread", FakeThread)
    pipeline.reset_runtime_state()
    pipeline._ensure_reviewer(project, pipeline._cancel_event(project))
    assert started == []


def test_reviewer_once_does_not_ask_to_build_lab(tmp_env, project, monkeypatch):
    from app.agent.loop import LoopResult
    from app.services.lab import mark_lab_setup_finished

    mark_lab_setup_finished(project, skipped=True, notes="无 docker", via="test")
    models = tmp_env["models"]
    Session = tmp_env["Session"]
    with Session() as db:
        db.add(
            models.Vuln(
                project_id=project,
                title="t",
                vuln_type="sqli",
                status="pending_review",
            )
        )
        db.commit()

    captured: dict[str, object] = {}

    class FakeLoop:
        def __init__(self, **kwargs):  # noqa: ANN003
            captured["user_prompt"] = kwargs.get("user_prompt") or ""
            captured["timeout_sec"] = kwargs.get("timeout_sec")

        def run(self) -> LoopResult:
            return LoopResult(ok=True, stop_reason="stop_when", state={"review_done": True})

    monkeypatch.setattr(pipeline, "AgentLoop", FakeLoop)
    pipeline._run_reviewer_once(project)
    prompt = str(captured["user_prompt"])
    assert "搭建可复用的 Web 靶场" not in prompt
    assert "不要再搭建 Docker 靶场" in prompt
    assert "本项目仅静态验证" in prompt
    assert '"preferred": "static_only"' in prompt
    assert captured["timeout_sec"] == settings.timeout_reviewer_static


def test_reviewer_once_injects_manual_lab_prompt(tmp_env, project, monkeypatch):
    from app.agent.loop import LoopResult

    _enable_dynamic_verify(project)
    models = tmp_env["models"]
    Session = tmp_env["Session"]
    with Session() as db:
        proj = db.get(models.Project, project)
        proj.manual_lab_prompt = "http://127.0.0.1:18080 账号 admin/admin"
        db.add(
            models.Vuln(
                project_id=project,
                title="t",
                vuln_type="sqli",
                status="pending_review",
            )
        )
        db.commit()

    captured: dict[str, object] = {}

    class FakeLoop:
        def __init__(self, **kwargs):  # noqa: ANN003
            captured["user_prompt"] = kwargs.get("user_prompt") or ""

        def run(self) -> LoopResult:
            return LoopResult(ok=True, stop_reason="stop_when", state={"review_done": True})

    monkeypatch.setattr(pipeline, "AgentLoop", FakeLoop)
    pipeline._run_reviewer_once(project)
    prompt = str(captured["user_prompt"])
    assert "优先使用用户提供的人工靶场" in prompt
    assert "http://127.0.0.1:18080 账号 admin/admin" in prompt
    assert "不要搭建或复用 Docker 靶场" not in prompt


def test_reviewer_timeout_streak_forces_static_then_resets(tmp_env, project, monkeypatch):
    from app.agent.loop import LoopResult

    _enable_dynamic_verify(project)
    models = tmp_env["models"]
    Session = tmp_env["Session"]
    with Session() as db:
        proj = db.get(models.Project, project)
        proj.manual_lab_prompt = "http://127.0.0.1:18080 账号 admin/admin"
        v = models.Vuln(
            project_id=project,
            title="t",
            vuln_type="sqli",
            status="pending_review",
        )
        db.add(v)
        db.commit()
        vid = v.id

    class TimeoutLoop:
        def __init__(self, **kwargs):  # noqa: ANN003
            pass

        def run(self) -> LoopResult:
            return LoopResult(ok=False, stop_reason="timeout", timed_out=True, state={})

    monkeypatch.setattr(pipeline, "AgentLoop", TimeoutLoop)
    pipeline._run_reviewer_once(project)
    with Session() as db:
        assert db.get(models.Vuln, vid).review_timeout_streak == 1
    pipeline._run_reviewer_once(project)
    with Session() as db:
        assert db.get(models.Vuln, vid).review_timeout_streak == 2

    captured: dict[str, object] = {}

    class DoneLoop:
        def __init__(self, **kwargs):  # noqa: ANN003
            captured["user_prompt"] = kwargs.get("user_prompt") or ""
            captured["system_prompt"] = kwargs.get("system_prompt") or ""

        def run(self) -> LoopResult:
            return LoopResult(ok=True, stop_reason="stop_when", state={"review_done": True})

    monkeypatch.setattr(pipeline, "AgentLoop", DoneLoop)
    pipeline._run_reviewer_once(project)
    prompt = str(captured["user_prompt"])
    system = str(captured["system_prompt"])
    assert "已连续超时 2 轮" in prompt
    assert "本项目仅静态验证" in prompt
    assert "consecutive_review_timeouts" in prompt
    assert "优先使用用户提供的人工靶场" not in prompt
    assert "仅静态" in system
    with Session() as db:
        assert db.get(models.Vuln, vid).review_timeout_streak == 0


def test_reviewer_non_timeout_failure_does_not_increment_streak(tmp_env, project, monkeypatch):
    from app.agent.loop import LoopResult

    models = tmp_env["models"]
    Session = tmp_env["Session"]
    with Session() as db:
        v = models.Vuln(
            project_id=project,
            title="t",
            vuln_type="sqli",
            status="pending_review",
            review_timeout_streak=1,
        )
        db.add(v)
        db.commit()
        vid = v.id

    class CancelledLoop:
        def __init__(self, **kwargs):  # noqa: ANN003
            pass

        def run(self) -> LoopResult:
            return LoopResult(ok=False, stop_reason="cancelled", cancelled=True, state={})

    monkeypatch.setattr(pipeline, "AgentLoop", CancelledLoop)
    pipeline._run_reviewer_once(project)
    with Session() as db:
        assert db.get(models.Vuln, vid).review_timeout_streak == 1


def test_reviewer_lab_note_prefers_manual_then_docker(tmp_env, project, monkeypatch):
    from app.services.lab import save_env

    models = tmp_env["models"]
    Session = tmp_env["Session"]
    save_env(
        project,
        {
            "accepted": True,
            "target_url": "http://127.0.0.1:18080",
            "status": "running",
        },
    )
    monkeypatch.setattr(pipeline, "recreate_lab", lambda pid, mode="full": {"ok": True, "via": "reuse", "target_url": "http://127.0.0.1:18080"})
    monkeypatch.setattr(pipeline, "debug_ports_for_runtime", lambda env: {"mcp": None})
    _enable_dynamic_verify(project)
    with Session() as db:
        proj = db.get(models.Project, project)
        proj.manual_lab_prompt = "http://10.0.0.8:9000"
        db.commit()
    note = pipeline._reviewer_lab_note(project)
    assert note.index("http://10.0.0.8:9000") < note.index("回退到已有 Docker 靶场")
    assert "http://127.0.0.1:18080" in note

    with Session() as db:
        proj = db.get(models.Project, project)
        proj.manual_lab_prompt = ""
        db.commit()
    fallback = pipeline._reviewer_lab_note(project)
    assert "优先使用用户提供的人工靶场" not in fallback
    assert "http://127.0.0.1:18080" in fallback


def test_next_reviewer_step_reviews_when_dynamic_off(tmp_env, project):
    from app.services.lab import lab_setup_finished

    assert lab_setup_finished(project) is False
    assert pipeline._next_reviewer_step(project, pending=1) == "review"
    assert pipeline._next_reviewer_step(project, pending=0) == "review"


def test_next_reviewer_step_reviews_before_lab_when_manual_prompt(tmp_env, project):
    from app.services.lab import lab_setup_finished

    _enable_dynamic_verify(project)
    models = tmp_env["models"]
    Session = tmp_env["Session"]
    assert lab_setup_finished(project) is False
    assert pipeline._next_reviewer_step(project, pending=1) == "lab"
    with Session() as db:
        proj = db.get(models.Project, project)
        proj.manual_lab_prompt = "http://127.0.0.1:8080"
        db.commit()
    assert pipeline._next_reviewer_step(project, pending=1) == "review"
    assert pipeline._next_reviewer_step(project, pending=0) == "lab"


def test_run_reviewer_lab_does_not_skip_docker_when_manual_prompt(tmp_env, project, monkeypatch):
    from app.agent.loop import LoopResult
    from app.services.lab import lab_setup_finished

    _enable_dynamic_verify(project)
    models = tmp_env["models"]
    Session = tmp_env["Session"]
    with Session() as db:
        proj = db.get(models.Project, project)
        proj.manual_lab = True
        proj.manual_lab_prompt = "http://192.168.1.8:8080"
        db.commit()

    called = {"loop": 0}

    class FakeLoop:
        def __init__(self, **kwargs):  # noqa: ANN003, ARG002
            called["loop"] += 1

        def run(self) -> LoopResult:
            return LoopResult(ok=False, cancelled=True, stop_reason="cancelled")

    monkeypatch.setattr(pipeline, "AgentLoop", FakeLoop)
    monkeypatch.setattr(pipeline, "resolve_llm", lambda role, **kwargs: object())
    pipeline._run_reviewer_lab(project)
    assert called["loop"] == 1
    assert lab_setup_finished(project) is False


def test_run_reviewer_lab_reuses_ready_env_without_agent(tmp_env, project, monkeypatch):
    from app.services.lab import lab_setup_finished, save_env

    _enable_dynamic_verify(project)
    save_env(
        project,
        {
            "accepted": True,
            "target_url": "http://127.0.0.1:18080",
            "status": "running",
            "container_name": f"vulnhunter-{project}",
        },
    )
    monkeypatch.setattr(pipeline, "recreate_lab", lambda pid, mode="full": {"ok": True, "via": "reuse"})
    called = {"loop": 0}

    class BoomLoop:
        def __init__(self, **kwargs):  # noqa: ANN003, ARG002
            called["loop"] += 1

        def run(self):  # noqa: ANN204
            raise AssertionError("lab round should reuse env without AgentLoop")

    monkeypatch.setattr(pipeline, "AgentLoop", BoomLoop)
    pipeline._run_reviewer_lab(project)
    assert called["loop"] == 0
    assert lab_setup_finished(project) is True


def test_reviewer_once_appends_dynamic_followup_without_interrupt(tmp_env, project, monkeypatch):
    from app.agent.checkpoint import LoopCheckpoint, save_checkpoint
    from app.agent.loop import INTERRUPT_RESUME, LoopResult
    from app.services.lab import mark_lab_setup_finished

    _enable_dynamic_verify(project)
    mark_lab_setup_finished(project, skipped=True, notes="skip", via="test")
    models = tmp_env["models"]
    Session = tmp_env["Session"]
    with Session() as db:
        vuln = models.Vuln(
            project_id=project,
            title="static sqli",
            vuln_type="sqli",
            status="static_only",
            evidence_level="static_only",
        )
        db.add(vuln)
        db.commit()
        db.refresh(vuln)
        vid = vuln.id

    run_id = pipeline._new_phase_run(project, "reviewer", "reviewer", vuln_id=vid)
    save_checkpoint(
        LoopCheckpoint(
            project_id=project,
            phase_run_id=run_id,
            role="reviewer",
            phase="reviewer",
            system_prompt="旧静态 system",
            user_prompt="请审核漏洞",
            messages=[
                {"role": "system", "content": "旧静态 system"},
                {"role": "user", "content": "请审核漏洞"},
                {"role": "assistant", "content": "静态结论：可利用。"},
            ],
            state={"dynamic_followup": True, "dynamic_followup_prompted": False, "review_done": True},
            vuln_id=vid,
        )
    )
    captured: dict[str, object] = {}

    class FakeLoop:
        def __init__(self, cp, **kwargs):  # noqa: ANN003
            captured["resumed"] = kwargs.get("resumed")
            captured["messages"] = list(cp.messages)
            captured["system"] = cp.system_prompt
            self.state = dict(cp.state)

        def run(self) -> LoopResult:
            return LoopResult(ok=True, stop_reason="stop_when", state={"review_done": True})

    monkeypatch.setattr(pipeline, "_loop_from_checkpoint", lambda cp, **kwargs: FakeLoop(cp, **kwargs))
    pipeline._run_reviewer_once(project)
    assert captured["resumed"] is False
    messages = captured["messages"]
    assert isinstance(messages, list)
    last = messages[-1]
    assert last["role"] == "user"
    assert "追加动态验证" in last["content"]
    assert "静态结论：可利用" in "\n".join(str(m.get("content") or "") for m in messages)
    assert INTERRUPT_RESUME not in last["content"]
    assert "仅静态" not in str(captured["system"] or "")
    assert "动态验证阶梯" in str(captured["system"] or "")


def test_prepare_lab_for_review_returns_bringup_when_start_needs_agent(tmp_env, project, monkeypatch):
    from app.services.lab import mark_lab_setup_finished, save_env

    _enable_dynamic_verify(project)
    save_env(
        project,
        {
            "accepted": True,
            "target_url": "http://127.0.0.1:18080",
            "status": "exited",
            "container_name": f"vulnhunter-{project}",
            "image": "demo:lab",
            "lab_ever_ready": True,
        },
    )
    mark_lab_setup_finished(project, via="test")
    monkeypatch.setattr(
        pipeline,
        "recreate_lab",
        lambda pid, mode="full": {
            "ok": False,
            "error": "port busy",
            "error_class": "start_failed",
            "need_agent": True,
        },
    )
    monkeypatch.setattr(pipeline, "docker_available", lambda: True)
    assert pipeline._prepare_lab_for_review(project) == "bringup"
    assert pipeline._next_reviewer_step(project, pending=1) == "lab-bringup"


def test_prepare_lab_for_review_quick_static_without_docker_lab(tmp_env, project):
    from app.services.lab import mark_lab_setup_finished

    _enable_dynamic_verify(project)
    mark_lab_setup_finished(project, skipped=True, notes="无 docker", via="test")
    assert pipeline._prepare_lab_for_review(project) == "static"
    assert pipeline._next_reviewer_step(project, pending=1) == "review"


def test_reviewer_round_verify_force_static_after_bringup_failed(tmp_env, project):
    from app.services.lab import mark_lab_bring_up_failed

    _enable_dynamic_verify(project)
    mark_lab_bring_up_failed(project, reason="compose up failed", via="test")
    lab_note, debug_plan, system, force_static = pipeline._reviewer_round_verify(project, timeout_streak=0)
    assert force_static is True
    assert debug_plan["reason"] == "lab_bring_up_failed"
    assert "强制仅静态" in lab_note
    assert "compose up failed" in lab_note
    assert "仅静态" in system

"""Per-phase pause / 续跑 / 新跑."""

from __future__ import annotations

import pytest

from app.agent.checkpoint import LoopCheckpoint, load_checkpoint, save_checkpoint
from app.services import pipeline
from app.services.ingest import build_file_index
from app.services.live_log import event_matches_phase


def _sample_messages() -> list[dict]:
    return [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "orig-task"},
        {"role": "assistant", "content": "I was looking at login"},
    ]


def test_phase_pause_does_not_pause_other_phases(tmp_env, project, monkeypatch):
    monkeypatch.setattr(pipeline, "start_audit", lambda pid: None)
    pipeline.request_phase_pause(project, "worker")
    assert pipeline._phase_is_paused(project, "worker")
    assert not pipeline._phase_is_paused(project, "recon")
    assert not pipeline._phase_is_paused(project, "reviewer")
    assert pipeline._combined_pause(project, "worker").is_set()
    assert not pipeline._combined_pause(project, "recon").is_set()
    states = pipeline.get_phase_states(project)["phases"]
    assert states["worker"]["paused"] is True
    assert states["recon"]["paused"] is False


def test_project_pause_pauses_all_phases(tmp_env, project):
    pipeline.request_pause(project)
    assert pipeline._phase_is_paused(project, "recon")
    assert pipeline._phase_is_paused(project, "worker")
    assert pipeline._phase_is_paused(project, "reviewer")
    assert pipeline._phase_is_paused(project, "verifier")
    assert pipeline.get_phase_states(project)["project_paused"] is True


def test_completed_project_pause_keeps_completed_status(tmp_env, project):
    from app.models import Project, SessionLocal

    with SessionLocal() as db:
        p = db.get(Project, project)
        p.status = "completed"
        p.phase = "done"
        db.commit()
    pipeline.request_pause(project)
    pipeline.request_phase_pause(project, "worker")
    with SessionLocal() as db:
        p = db.get(Project, project)
        assert p.status == "completed"
    assert pipeline.get_phase_states(project)["project_paused"] is False
    assert pipeline.get_phase_states(project)["phases"]["worker"]["paused"] is False


def test_phase_resume_from_project_pause_keeps_others_paused(tmp_env, project, monkeypatch):
    monkeypatch.setattr(pipeline, "start_audit", lambda pid: None)
    pipeline.request_pause(project)
    pipeline.request_phase_resume(project, "reviewer")
    assert not pipeline._phase_is_paused(project, "reviewer")
    assert pipeline._phase_is_paused(project, "worker")
    assert pipeline._phase_is_paused(project, "recon")
    assert not pipeline._pause_event(project).is_set()


def test_phase_restart_abandons_checkpoint_and_injects_file(tmp_env, project, monkeypatch):
    monkeypatch.setattr(pipeline, "start_audit", lambda pid: None)
    build_file_index(project)
    run_id = pipeline._new_phase_run(project, "worker", "worker", file_path="app/Main.java")
    save_checkpoint(
        LoopCheckpoint(
            project_id=project,
            phase_run_id=run_id,
            role="worker",
            phase="worker",
            system_prompt="s",
            user_prompt="u",
            messages=_sample_messages(),
            file_path="app/Main.java",
        ),
        status="paused",
    )
    assert load_checkpoint(project, run_id) is not None
    pipeline.request_phase_restart(project, "worker")
    assert load_checkpoint(project, run_id) is None
    assert pipeline._should_skip_checkpoint(project, "worker")
    inject = pipeline._pending_inject.get((project, "worker")) or []
    assert any(x.get("file_path") == "app/Main.java" for x in inject)
    fw = pipeline._take_inject_file(project, "worker-new")
    assert fw is not None
    assert fw.path == "app/Main.java"


def test_phase_resume_keeps_checkpoint(tmp_env, project, monkeypatch):
    monkeypatch.setattr(pipeline, "start_audit", lambda pid: None)
    run_id = pipeline._new_phase_run(project, "recon", "recon")
    save_checkpoint(
        LoopCheckpoint(
            project_id=project,
            phase_run_id=run_id,
            role="recon",
            phase="recon",
            system_prompt="s",
            user_prompt="u",
            messages=_sample_messages(),
        ),
        status="paused",
    )
    pipeline.request_phase_pause(project, "recon")
    pipeline.request_phase_resume(project, "recon")
    assert load_checkpoint(project, run_id) is not None
    assert not pipeline._should_skip_checkpoint(project, "recon")
    cp = pipeline._adopt_resumable(project, "recon")
    assert cp is not None
    assert cp.messages[2]["content"] == "I was looking at login"
    pipeline._release_adopted(project, run_id)


def test_generation_cancel_only_old_loop(tmp_env, project):
    old = pipeline._loop_cancel(project, "worker")
    assert old.is_set() is False
    pipeline._bump_phase_generation(project, "worker")
    assert old.is_set() is True
    nxt = pipeline._loop_cancel(project, "worker")
    assert nxt.is_set() is False


def test_event_matches_mine_excludes_fix():
    assert event_matches_phase({"phase": "worker"}, "mine")
    assert not event_matches_phase({"phase": "fix"}, "mine")
    assert event_matches_phase({"phase": "fix"}, "fix")
    assert not event_matches_phase({"phase": "worker"}, "fix")
    assert event_matches_phase({"phase": "fix"}, "worker")
    assert event_matches_phase({"phase": "worker"}, "worker")


def test_worker_progress_reset_clears_audit_keeps_vulns_and_recon(tmp_env, project, monkeypatch):
    from app.models import FileWeight, Project, SessionLocal, Source, Vuln
    from app.services.ingest import build_file_index
    from app.services.paths import docs_dir, summaries_dir, workspace_dir

    monkeypatch.setattr(pipeline, "start_audit", lambda pid: None)
    build_file_index(project)
    docs = docs_dir(project)
    (docs / "code-map.md").write_text("# 地图\n入口 Main.java\n", encoding="utf-8")
    (docs / "auth.md").write_text("# 鉴权\nJWT\n", encoding="utf-8")
    rounds = workspace_dir(project) / "rounds"
    rounds.mkdir(parents=True, exist_ok=True)
    (rounds / "round-1.md").write_text("## 本轮入口\nMain.java\n", encoding="utf-8")
    summaries = summaries_dir(project)
    (summaries / "worker-round-1.md").write_text("压缩：已审完。\n", encoding="utf-8")
    (summaries / "recon-1.md").write_text("侦察摘要应保留。\n", encoding="utf-8")
    (workspace_dir(project) / "todos-worker-w1.json").write_text("[]", encoding="utf-8")

    with SessionLocal() as db:
        fw = db.query(FileWeight).filter(FileWeight.project_id == project, FileWeight.path.contains("Main.java")).first()
        assert fw is not None
        fw.audited = True
        fw.claimed_by = "worker-old"
        fw.audit_attempts = 3
        skipped = db.query(FileWeight).filter(FileWeight.project_id == project, FileWeight.skipped.is_(True)).first()
        db.add(Source(project_id=project, file_path="app/Main.java", method_name="login", note="入口"))
        db.add(
            Vuln(
                project_id=project,
                title="已确认洞",
                vuln_type="sqli",
                status="confirmed",
                file_path="app/Main.java",
            )
        )
        db.add(
            Vuln(
                project_id=project,
                title="修复中",
                vuln_type="rce",
                status="fixing",
                file_path="app/Main.java",
            )
        )
        p = db.get(Project, project)
        p.status = "completed"
        p.phase = "done"
        p.recon_done = True
        db.commit()
        skipped_path = skipped.path if skipped else None

    run_id = pipeline._new_phase_run(project, "worker", "worker", file_path="app/Main.java")
    save_checkpoint(
        LoopCheckpoint(
            project_id=project,
            phase_run_id=run_id,
            role="worker",
            phase="worker",
            system_prompt="s",
            user_prompt="u",
            messages=_sample_messages(),
            file_path="app/Main.java",
        ),
        status="paused",
    )

    states = pipeline.request_worker_progress_reset(project)
    assert states["project_paused"] is True
    assert states["phases"]["worker"]["paused"] is True
    assert load_checkpoint(project, run_id) is None
    assert not (rounds / "round-1.md").exists()
    assert not (summaries / "worker-round-1.md").exists()
    assert pipeline._next_worker_round_id(project) == 1
    assert not (workspace_dir(project) / "todos-worker-w1.json").exists()
    assert (docs / "code-map.md").is_file()
    assert (docs / "auth.md").is_file()
    assert (summaries / "recon-1.md").is_file()

    with SessionLocal() as db:
        p = db.get(Project, project)
        assert p.status == "paused"
        assert p.phase == "worker"
        assert p.recon_done is True
        files = db.query(FileWeight).filter(FileWeight.project_id == project).all()
        assert files
        assert all(not f.audited and f.claimed_by is None and int(f.audit_attempts or 0) == 0 for f in files)
        if skipped_path:
            skipped = db.query(FileWeight).filter(FileWeight.project_id == project, FileWeight.path == skipped_path).one()
            assert skipped.skipped is True
        assert db.query(Source).filter(Source.project_id == project).count() == 1
        vulns = {v.title: v.status for v in db.query(Vuln).filter(Vuln.project_id == project)}
        assert vulns["已确认洞"] == "confirmed"
        assert vulns["修复中"] == "returned"


def test_worker_progress_reset_requires_pause(tmp_env, project):
    from app.models import Project, SessionLocal

    with SessionLocal() as db:
        p = db.get(Project, project)
        p.status = "auditing"
        p.phase = "worker"
        db.commit()
    with pytest.raises(ValueError, match="暂停"):
        pipeline.request_worker_progress_reset(project)


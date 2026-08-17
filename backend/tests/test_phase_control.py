"""Per-phase pause / 续跑 / 新跑."""

from __future__ import annotations

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

"""Unified conversation continue / new / steer."""

from __future__ import annotations

import pytest

from app.agent.checkpoint import LoopCheckpoint, load_checkpoint, save_checkpoint
from app.services import pipeline
from app.services.conversation import get_conversation_state, request_conversation
from app.services.conversation_archive import (
    archive_checkpoint,
    has_archived,
    load_archived,
    normalize_log_phase,
)
from app.services.conversation_steer import (
    consume_steer_messages,
    enqueue_steer,
    register_loop,
    unregister_loop,
)
from app.agent.loop import AgentLoop


def _sample_cp(project_id: int, run_id: int) -> LoopCheckpoint:
    return LoopCheckpoint(
        project_id=project_id,
        phase_run_id=run_id,
        role="worker",
        phase="worker",
        system_prompt="sys",
        user_prompt="task",
        messages=[
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "task"},
            {"role": "assistant", "content": "working"},
        ],
        file_path="app/Main.java",
    )


def test_archive_checkpoint_on_finish(tmp_env, project):
    run_id = pipeline._new_phase_run(project, "worker", "worker", file_path="app/Main.java")
    cp = _sample_cp(project, run_id)
    save_checkpoint(cp)
    pipeline._finish_phase_run(run_id, "completed")
    assert load_checkpoint(project, run_id) is None
    assert has_archived(project, "mine")
    loaded = load_archived(project, "mine")
    assert loaded is not None
    assert loaded.messages[-1]["content"] == "working"


def test_steer_queue_roundtrip(tmp_env, project):
    enqueue_steer(project, "mine", "先看鉴权")
    assert consume_steer_messages(project, "mine") == ["先看鉴权"]
    assert consume_steer_messages(project, "mine") == []


def test_steer_requires_non_empty(tmp_env, project):
    with pytest.raises(ValueError, match="不能为空"):
        enqueue_steer(project, "mine", "   ")


def test_conversation_state_idle_with_archive(tmp_env, project):
    run_id = pipeline._new_phase_run(project, "worker", "worker")
    save_checkpoint(_sample_cp(project, run_id))
    pipeline._finish_phase_run(run_id, "completed")
    state = get_conversation_state(project, "mine")
    assert state["running"] is False
    assert state["can_continue"] is True
    assert state["can_steer"] is False


def test_conversation_continue_from_archive(tmp_env, project, monkeypatch):
    run_id = pipeline._new_phase_run(project, "worker", "worker", file_path="app/X.java")
    save_checkpoint(_sample_cp(project, run_id))
    pipeline._finish_phase_run(run_id, "completed")

    started = {"n": 0}

    def fake_start(pid):  # noqa: ANN001
        started["n"] += 1

    monkeypatch.setattr(pipeline, "start_audit", fake_start)
    out = pipeline.request_conversation_continue(project, "mine", "继续挖这个文件")
    assert out["action"] == "continue"
    assert started["n"] == 1
    resumable = [
        pr for pr in __import__("app.agent.checkpoint", fromlist=["list_resumable_runs"]).list_resumable_runs(
            project, "worker"
        )
    ]
    assert resumable
    cp = load_checkpoint(project, resumable[0].id)
    assert cp is not None
    assert any("用户接续指示" in m.get("content", "") for m in cp.messages if m.get("role") == "user")


def test_conversation_steer_when_running(tmp_env, project):
    loop = AgentLoop(
        project_id=project,
        role="worker",
        phase="worker",
        system_prompt="s",
        user_prompt="u",
    )
    register_loop(loop)
    try:
        state = get_conversation_state(project, "mine")
        assert state["running"] is True
        assert state["can_steer"] is True
        out = request_conversation(project, "mine", "steer", "优先看 SQL")
        assert out["action"] == "steer"
        pending = consume_steer_messages(project, "mine")
        assert pending == ["优先看 SQL"]
    finally:
        unregister_loop(loop)


def test_normalize_log_phase_aliases():
    assert normalize_log_phase("recon-map") == "recon-map"
    assert normalize_log_phase("worker") == "mine"
    assert normalize_log_phase("fast-worker") == "fast"


def test_recon_map_new_delegates_to_rerun(tmp_env, project, monkeypatch):
    from app.services.paths import docs_dir
    from app.tools.phase_recon import recon_map_ready

    docs = docs_dir(project)
    (docs / "code-map.md").write_text("# m\n", encoding="utf-8")
    (docs / "auth.md").write_text("# a\n", encoding="utf-8")
    assert recon_map_ready(project)

    called: list[str] = []

    def fake_rerun(pid, sub):  # noqa: ANN001
        called.append(sub)
        return {"ok": True, "subphase": sub}

    monkeypatch.setattr(pipeline, "request_recon_subphase_rerun", fake_rerun)
    pipeline.request_conversation_new(project, "recon-map", "更新入口")
    assert called == ["map"]


def test_conversation_api_endpoints(tmp_env, project):
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as client:
        state = client.get(f"/api/projects/{project}/conversation?log_phase=mine")
        assert state.status_code == 200
        body = state.json()
        assert body["log_phase"] == "mine"
        assert "can_continue" in body
        steer = client.post(
            f"/api/projects/{project}/conversation",
            json={"log_phase": "mine", "action": "steer", "message": "hi"},
        )
        assert steer.status_code == 400  # not running


def test_unconstrained_conversation_stop_start_and_rejects_new(tmp_env, project, monkeypatch):
    from fastapi.testclient import TestClient

    from app.main import app
    from app.models import Project, SessionLocal
    from app.services import pipeline
    from app.services.conversation import get_conversation_state, request_conversation

    with SessionLocal() as db:
        proj = db.get(Project, project)
        proj.recon_done = True
        proj.heuristic_enabled = False
        proj.unconstrained_enabled = True
        proj.unconstrained_done = False
        proj.status = "auditing"
        db.commit()

    state = get_conversation_state(project, "unconstrained")
    assert state["can_new"] is False
    assert state["can_stop"] is True
    assert state["can_start"] is False
    assert state["unconstrained_done"] is False

    with pytest.raises(ValueError, match="停止或启动"):
        request_conversation(project, "unconstrained", "new")

    monkeypatch.setattr(pipeline, "start_audit", lambda pid: None)
    with TestClient(app) as client:
        denied = client.post(
            f"/api/projects/{project}/conversation",
            json={"log_phase": "mine", "action": "stop"},
        )
        assert denied.status_code == 400
        stopped = client.post(
            f"/api/projects/{project}/conversation",
            json={"log_phase": "unconstrained", "action": "stop"},
        )
        assert stopped.status_code == 200
        body = stopped.json()
        assert body["action"] == "stop"
        assert body["unconstrained_done"] is True
        assert body["project_completed"] is True

    state = get_conversation_state(project, "unconstrained")
    assert state["can_stop"] is False
    assert state["can_start"] is True
    assert state["unconstrained_done"] is True
    assert state["can_new"] is False

    with TestClient(app) as client:
        started = client.post(
            f"/api/projects/{project}/conversation",
            json={"log_phase": "unconstrained", "action": "start"},
        )
        assert started.status_code == 200
        assert started.json()["unconstrained_done"] is False

    state = get_conversation_state(project, "unconstrained")
    assert state["can_start"] is False
    assert state["can_stop"] is True
    assert state["unconstrained_done"] is False

"""Pause / restart continues the same AgentLoop messages instead of a new prompt."""

from __future__ import annotations

import json
import threading
import time

from app.agent.checkpoint import (
    LoopCheckpoint,
    checkpoint_exists,
    clear_checkpoint,
    load_checkpoint,
    save_checkpoint,
)
from app.agent.loop import INTERRUPT_RESUME, TRANSIENT_RESUME, AgentLoop, TransientError
from app.models import utcnow
from app.services import pipeline
from app.services.ingest import build_file_index


def _usage() -> dict[str, int]:
    return {"prompt_tokens": 1, "completion_tokens": 1, "cached_tokens": 0, "total_tokens": 2}


def _done_chat(_self, messages, tools, remaining):
    return {"choices": [{"message": {"content": "done", "tool_calls": []}}]}, _usage(), None


def _sample_messages() -> list[dict]:
    return [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "orig-task"},
        {"role": "assistant", "content": "I was looking at login"},
        {"role": "tool", "tool_call_id": "1", "content": '{"ok":true}'},
    ]


def test_checkpoint_roundtrip(tmp_env, project):
    run_id = pipeline._new_phase_run(project, "worker", "worker", file_path="app/Main.java")
    cp = LoopCheckpoint(
        project_id=project,
        phase_run_id=run_id,
        role="worker",
        phase="worker",
        system_prompt="sys",
        user_prompt="orig-task",
        messages=_sample_messages(),
        state={"round_id": 3},
        file_path="app/Main.java",
        last_prompt_tokens=42,
    )
    save_checkpoint(cp, status="paused")
    loaded = load_checkpoint(project, run_id)
    assert loaded is not None
    assert loaded.messages[2]["content"] == "I was looking at login"
    assert loaded.state["round_id"] == 3
    assert loaded.file_path == "app/Main.java"
    pipeline._finish_phase_run(run_id, "completed")
    assert load_checkpoint(project, run_id) is None
    assert checkpoint_exists(project, run_id) is False


def test_resumed_loop_announces_next_chat(tmp_env, project):
    loop = AgentLoop(
        project_id=project,
        role="worker",
        phase="worker",
        system_prompt="s",
        user_prompt="u",
        resumed=True,
    )
    assert loop._announce_next_chat is True
    fresh = AgentLoop(
        project_id=project,
        role="worker",
        phase="worker",
        system_prompt="s",
        user_prompt="u",
    )
    assert fresh._announce_next_chat is False


def test_resumed_loop_keeps_messages_not_initial_prompt(tmp_env, project, monkeypatch):
    captured: list[list[dict]] = []

    def fake_chat(self, messages, tools, remaining):
        captured.append(list(messages))
        return _done_chat(self, messages, tools, remaining)

    monkeypatch.setattr(AgentLoop, "_chat", fake_chat)
    run_id = pipeline._new_phase_run(project, "worker", "worker", file_path="app/Main.java")
    loop = AgentLoop(
        project_id=project,
        role="worker",
        phase="worker",
        system_prompt="sys",
        user_prompt="SHOULD-NOT-REPLACE-CONTEXT",
        phase_run_id=run_id,
        messages=_sample_messages(),
        resumed=True,
        stop_when=lambda st: True,
        file_path="app/Main.java",
    )
    result = loop.run()
    assert result.ok
    sent = captured[0]
    assert sent[0]["content"] == "sys"
    assert sent[1]["content"] == "orig-task"
    assert sent[2]["content"] == "I was looking at login"
    assert any((m.get("content") or "") == INTERRUPT_RESUME for m in sent)
    assert all((m.get("content") or "") != "SHOULD-NOT-REPLACE-CONTEXT" for m in sent)


def test_new_round_starts_fresh_prompt(tmp_env, project, monkeypatch):
    captured: list[list[dict]] = []

    def fake_chat(self, messages, tools, remaining):
        captured.append(list(messages))
        return _done_chat(self, messages, tools, remaining)

    monkeypatch.setattr(AgentLoop, "_chat", fake_chat)
    run_id = pipeline._new_phase_run(project, "worker", "worker")
    loop = AgentLoop(
        project_id=project,
        role="worker",
        phase="worker",
        system_prompt="sys",
        user_prompt="fresh-round",
        phase_run_id=run_id,
        stop_when=lambda st: True,
    )
    assert loop.run().ok
    sent = captured[0]
    assert [m.get("role") for m in sent] == ["system", "user"]
    assert sent[1]["content"] == "fresh-round"
    assert not any((m.get("content") or "") == INTERRUPT_RESUME for m in sent)


def test_transient_error_keeps_context_and_continues(tmp_env, project, monkeypatch):
    n = {"i": 0}
    captured: list[list[dict]] = []

    def fake_chat(self, messages, tools, remaining):
        n["i"] += 1
        captured.append(list(messages))
        if n["i"] == 1:
            raise TransientError("incomplete chunked read")
        return _done_chat(self, messages, tools, remaining)

    monkeypatch.setattr(AgentLoop, "_chat", fake_chat)
    run_id = pipeline._new_phase_run(project, "worker", "worker")
    loop = AgentLoop(
        project_id=project,
        role="worker",
        phase="worker",
        system_prompt="sys",
        user_prompt="task",
        phase_run_id=run_id,
        stop_when=lambda st: True,
    )
    result = loop.run()
    assert result.ok
    assert n["i"] == 2
    assert captured[1][-1]["content"] == TRANSIENT_RESUME
    assert captured[1][1]["content"] == "task"


def test_transient_error_exhausted_stops(tmp_env, project, monkeypatch):
    def fake_chat(self, messages, tools, remaining):
        raise TransientError("peer closed")

    monkeypatch.setattr(AgentLoop, "_chat", fake_chat)
    monkeypatch.setattr(AgentLoop, "_rescue_conclude", lambda self, messages: None)
    run_id = pipeline._new_phase_run(project, "worker", "worker")
    loop = AgentLoop(
        project_id=project,
        role="worker",
        phase="worker",
        system_prompt="sys",
        user_prompt="task",
        phase_run_id=run_id,
        stop_when=lambda st: True,
    )
    result = loop.run()
    assert not result.ok
    assert result.stop_reason == "transient_error"
    assert "peer closed" in (result.error or "")


def test_inprocess_pause_continues_same_messages(tmp_env, project, monkeypatch):
    captured: list[list[dict]] = []
    pause = threading.Event()
    pause.set()
    mine = {"id": None}

    def fake_chat(self, messages, tools, remaining):
        if self.phase_run_id == mine["id"]:
            captured.append(list(messages))
        return _done_chat(self, messages, tools, remaining)

    monkeypatch.setattr(AgentLoop, "_chat", fake_chat)
    run_id = pipeline._new_phase_run(project, "worker", "worker", file_path="app/Main.java")
    mine["id"] = run_id
    loop = AgentLoop(
        project_id=project,
        role="worker",
        phase="worker",
        system_prompt="sys",
        user_prompt="orig-task",
        phase_run_id=run_id,
        pause_event=pause,
        messages=_sample_messages(),
        stop_when=lambda st: True,
        file_path="app/Main.java",
    )

    def _resume() -> None:
        time.sleep(0.15)
        assert checkpoint_exists(project, run_id)
        pause.clear()

    t = threading.Thread(target=_resume, daemon=True)
    t.start()
    result = loop.run()
    t.join(timeout=2)
    assert result.ok
    ours = [m for m in captured if any((x.get("content") or "") == "I was looking at login" for x in m)]
    assert len(ours) == 1
    sent = ours[0]
    assert sent[2]["content"] == "I was looking at login"
    assert sent[0]["content"] == "sys"
    assert sent[1]["content"] == "orig-task"


def test_paused_loop_stops_when_phase_run_abandoned(tmp_env, project, monkeypatch):
    pause = threading.Event()
    pause.set()
    monkeypatch.setattr(AgentLoop, "_chat", _done_chat)
    run_id = pipeline._new_phase_run(project, "worker", "worker", file_path="app/Main.java")
    loop = AgentLoop(
        project_id=project,
        role="worker",
        phase="worker",
        system_prompt="sys",
        user_prompt="orig-task",
        phase_run_id=run_id,
        pause_event=pause,
        messages=_sample_messages(),
        stop_when=lambda st: True,
        file_path="app/Main.java",
    )

    def _abandon_and_resume() -> None:
        time.sleep(0.15)
        pipeline._finish_phase_run(run_id, "cancelled", "用户重置启发式挖掘进度")
        pause.clear()

    t = threading.Thread(target=_abandon_and_resume, daemon=True)
    t.start()
    result = loop.run()
    t.join(timeout=2)
    assert result.cancelled
    assert result.stop_reason == "cancelled"


def test_prepare_resume_keeps_checkpointed_claim_and_fix(tmp_env, project):
    build_file_index(project)
    models = tmp_env["models"]
    Session = tmp_env["Session"]
    run_id = pipeline._new_phase_run(
        project, "worker", "worker", worker_id="dead-worker", file_path="app/Main.java"
    )
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
    with Session() as db:
        for fw in db.query(models.FileWeight).filter(models.FileWeight.project_id == project).all():
            fw.weight = 50
            if fw.path == "app/Main.java":
                fw.claimed_by = "dead-worker"
                fw.claimed_at = utcnow()
            else:
                fw.claimed_by = "other"
                fw.claimed_at = utcnow()
        keep = models.Vuln(project_id=project, title="keep", vuln_type="sqli", status="fixing")
        drop = models.Vuln(project_id=project, title="drop", vuln_type="sqli", status="fixing")
        db.add_all([keep, drop])
        db.commit()
        keep_id, drop_id = keep.id, drop.id
    fix_run = pipeline._new_phase_run(project, "fix", "fix", vuln_id=keep_id)
    save_checkpoint(
        LoopCheckpoint(
            project_id=project,
            phase_run_id=fix_run,
            role="fix",
            phase="fix",
            system_prompt="s",
            user_prompt="u",
            messages=_sample_messages(),
            vuln_id=keep_id,
        ),
        status="paused",
    )

    pipeline._prepare_project_resume(project)
    with Session() as db:
        main = (
            db.query(models.FileWeight)
            .filter(models.FileWeight.project_id == project, models.FileWeight.path == "app/Main.java")
            .first()
        )
        other = (
            db.query(models.FileWeight)
            .filter(models.FileWeight.project_id == project, models.FileWeight.path != "app/Main.java")
            .first()
        )
        assert main.claimed_by == "dead-worker"
        assert other.claimed_by is None
        assert db.get(models.Vuln, keep_id).status == "fixing"
        assert db.get(models.Vuln, drop_id).status == "returned"


def test_pick_next_file_skips_checkpointed_path(tmp_env, project):
    build_file_index(project)
    models = tmp_env["models"]
    Session = tmp_env["Session"]
    with Session() as db:
        for fw in db.query(models.FileWeight).filter(models.FileWeight.project_id == project).all():
            fw.weight = 80
        db.commit()
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
        )
    )
    fw = pipeline._pick_next_file(project, "worker-b")
    assert fw is None or fw.path != "app/Main.java"


def test_adopt_resumable_then_release(tmp_env, project):
    pipeline._adopted_phase_runs.clear()
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
        )
    )
    cp = pipeline._adopt_resumable(project, "recon")
    assert cp is not None
    assert cp.phase_run_id == run_id
    assert pipeline._adopt_resumable(project, "recon") is None
    pipeline._release_adopted(project, run_id)
    cp2 = pipeline._adopt_resumable(project, "recon")
    assert cp2 is not None
    pipeline._release_adopted(project, run_id)
    clear_checkpoint(project, run_id)


def test_identical_tool_loop_redirects_then_aborts(tmp_env, project, monkeypatch):
    from app.tools import registry

    dispatched = {"n": 0}
    chats = {"n": 0}

    def fake_chat(self, messages, tools, remaining):
        chats["n"] += 1
        return {
            "choices": [
                {
                    "message": {
                        "content": "",
                        "tool_calls": [
                            {
                                "id": "c1",
                                "type": "function",
                                "function": {
                                    "name": "PowerShell",
                                    "arguments": json.dumps({"command": "echo same"}),
                                },
                            }
                        ],
                    }
                }
            ]
        }, _usage(), None

    def fake_dispatch(_ctx, _name, _args):
        dispatched["n"] += 1
        return {"ok": True, "stdout": "ok"}

    monkeypatch.setattr(AgentLoop, "_chat", fake_chat)
    monkeypatch.setattr(AgentLoop, "_rescue_conclude", lambda self, messages: None)
    monkeypatch.setattr(registry, "dispatch", fake_dispatch)
    run_id = pipeline._new_phase_run(project, "reviewer", "reviewer")
    loop = AgentLoop(
        project_id=project,
        role="reviewer",
        phase="reviewer",
        system_prompt="sys",
        user_prompt="task",
        phase_run_id=run_id,
        timeout_sec=60,
    )
    loop.watchdog.max_same_tool_calls = 2
    loop.watchdog.max_identical_threshold_hits = 5
    result = loop.run()
    assert result.loop_aborted is True
    assert result.ok is False
    assert result.stop_reason == "identical_tool_loop"
    assert "终止" in (result.error or "")
    assert dispatched["n"] == 5
    assert chats["n"] == 10
    assert loop.watchdog.identical_threshold_hits == 5

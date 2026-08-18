from __future__ import annotations

import json
import os
import time

from app.services.live_log import format_tool_command, format_tool_output, live_log


def test_format_tool_command_includes_args():
    cmd = format_tool_command("Read", {"path": "src/Main.java"})
    assert cmd.startswith("Read ")
    assert "src/Main.java" in cmd
    assert format_tool_command("Bash", {"command": "ls -la"}).startswith("Bash ls -la")


def test_tool_event_written(tmp_env, project, monkeypatch, tmp_path):
    path = tmp_path / "live.events.jsonl"
    monkeypatch.setattr("app.services.live_log.live_events_path", lambda _pid: path)
    live_log.tool(
        project,
        "Glob",
        {"pattern": "**/*.java"},
        {"ok": True, "matches": ["src/A.java"], "count": 1},
        phase="recon",
        role="recon",
    )
    page = live_log.read_events(project)
    assert page.offset >= 1
    assert page.done is True
    ev = page.events[-1]
    assert ev["kind"] == "cmd"
    assert ev["tool"] == "Glob"
    assert "**/*.java" in ev["command"]
    assert ev["exit_code"] == 0
    assert "src/A.java" in ev["output"]
    assert ev["phase"] == "recon"
    assert ev["role"] == "recon"


def test_events_are_written_by_phase_and_session(tmp_env, project, monkeypatch, tmp_path):
    path = tmp_path / "live.events.jsonl"
    monkeypatch.setattr("app.services.live_log.live_events_path", lambda _pid: path)
    live_log.reset_runtime_state()

    live_log.agent(project, "round-1", phase="worker", role="worker")
    live_log.begin_session(project, "worker")
    live_log.system(project, "挖掘阶段新跑，新开对话", phase="worker", session_start=True)
    live_log.agent(project, "round-2", phase="worker", role="worker")

    assert not path.exists()
    first = tmp_path / "live-events" / "worker" / "round-1.jsonl"
    second = tmp_path / "live-events" / "worker" / "round-2.jsonl"
    assert first.exists()
    assert second.exists()

    first_events = [json.loads(line) for line in first.read_text(encoding="utf-8").splitlines()]
    second_events = [json.loads(line) for line in second.read_text(encoding="utf-8").splitlines()]
    assert [e["text"] for e in first_events] == ["round-1"]
    assert [e["text"] for e in second_events] == ["挖掘阶段新跑，新开对话", "round-2"]
    assert first_events[0]["seq"] < second_events[0]["seq"] < second_events[1]["seq"]


def test_event_matches_phase_groups_fix_under_worker():
    from app.services.live_log import event_matches_phase

    assert event_matches_phase({"phase": "fix", "kind": "agent"}, "worker")
    assert event_matches_phase({"role": "fix", "kind": "cmd"}, "worker")
    assert event_matches_phase({"phase": "worker", "kind": "agent"}, "mine")
    assert not event_matches_phase({"phase": "fix", "kind": "agent"}, "mine")
    assert not event_matches_phase({"phase": "fast-worker", "kind": "agent"}, "mine")
    assert not event_matches_phase({"phase": "sink-triage", "kind": "agent"}, "mine")
    assert event_matches_phase({"phase": "fast-worker", "kind": "agent"}, "fast")
    assert event_matches_phase({"phase": "sink-triage", "kind": "agent"}, "fast")
    assert event_matches_phase({"role": "fast_worker", "kind": "cmd"}, "fast")
    assert not event_matches_phase({"phase": "worker", "kind": "agent"}, "fast")
    assert not event_matches_phase({"phase": "fix", "kind": "agent"}, "fast")
    assert event_matches_phase({"phase": "fast-worker", "kind": "agent"}, "worker")
    assert event_matches_phase({"phase": "sink-triage", "kind": "agent"}, "worker")
    assert event_matches_phase({"phase": "fix", "kind": "agent"}, "fix")
    assert not event_matches_phase({"phase": "worker", "kind": "agent"}, "fix")
    assert event_matches_phase({"phase": "recon-mark", "kind": "agent"}, "recon")
    assert event_matches_phase({"role": "recon_mark", "kind": "cmd"}, "recon")
    assert event_matches_phase({"phase": "recon-source-ext", "kind": "agent"}, "recon")
    assert event_matches_phase({"phase": "recon-source-ext", "kind": "agent"}, "recon-source-ext")
    assert not event_matches_phase({"phase": "recon-source-ext", "kind": "agent"}, "recon-map")
    assert event_matches_phase({"phase": "recon-old-vuln", "kind": "agent"}, "recon")
    assert event_matches_phase({"phase": "recon-old-vuln", "kind": "agent"}, "recon-old-vuln")
    assert event_matches_phase({"phase": "recon-old-vuln-ghsa", "kind": "agent"}, "recon")
    assert event_matches_phase({"phase": "recon-old-vuln-ghsa", "kind": "agent"}, "recon-old-vuln")
    assert not event_matches_phase({"phase": "recon-old-vuln-ghsa", "kind": "agent"}, "recon-map")
    assert event_matches_phase({"phase": "recon", "kind": "agent"}, "recon-map")
    assert not event_matches_phase({"phase": "recon-old-vuln", "kind": "agent"}, "recon-map")
    assert not event_matches_phase({"phase": "recon", "kind": "agent"}, "recon-old-vuln")
    assert not event_matches_phase({"phase": "fix", "kind": "agent"}, "recon")
    assert event_matches_phase({"phase": "reviewer-lab", "kind": "agent"}, "reviewer")
    assert event_matches_phase({"phase": "reviewer-lab", "kind": "agent"}, "reviewer-lab")
    assert event_matches_phase({"role": "reviewer_lab", "kind": "cmd"}, "reviewer")
    assert not event_matches_phase({"phase": "reviewer", "kind": "agent"}, "reviewer-lab")
    assert event_matches_phase({"phase": "reviewer", "kind": "agent"}, "reviewer-review")
    assert not event_matches_phase({"phase": "reviewer-lab", "kind": "agent"}, "reviewer-review")
    assert not event_matches_phase({"kind": "system", "text": "x"}, "reviewer")
    assert event_matches_phase({"phase": "verifier", "kind": "agent"}, "verifier")
    assert not event_matches_phase({"phase": "verifier", "kind": "agent"}, "reviewer")
    assert not event_matches_phase({"phase": "worker", "kind": "agent"}, "recon")


def test_read_events_tail_and_before(tmp_env, project, monkeypatch, tmp_path):
    path = tmp_path / "live.events.jsonl"
    monkeypatch.setattr("app.services.live_log.live_events_path", lambda _pid: path)
    for i in range(12):
        phase = "recon" if i < 4 else ("worker" if i < 8 else "fix")
        live_log.agent(project, f"line-{i}", phase=phase, role=phase)

    tail = live_log.read_events(project, limit=5, tail=True)
    assert [e["text"] for e in tail.events] == [f"line-{i}" for i in range(7, 12)]
    assert tail.has_older is True
    assert tail.total == 12
    assert all("seq" in e for e in tail.events)

    older = live_log.read_events(project, limit=5, before=tail.oldest)
    assert [e["text"] for e in older.events] == [f"line-{i}" for i in range(2, 7)]
    assert older.has_older is True

    worker = live_log.read_events(project, limit=10, tail=True, phase="worker")
    texts = [e["text"] for e in worker.events]
    assert texts == [f"line-{i}" for i in range(4, 12)]
    assert all(e["phase"] in ("worker", "fix") for e in worker.events)


def test_read_events_caught_up_keeps_offset(tmp_env, project, monkeypatch, tmp_path):
    path = tmp_path / "live.events.jsonl"
    monkeypatch.setattr("app.services.live_log.live_events_path", lambda _pid: path)
    for i in range(5):
        live_log.agent(project, f"line-{i}", phase="worker", role="worker")

    end = live_log.read_events(project, offset=0, limit=50)
    assert end.file_end == 5
    caught = live_log.read_events(project, offset=end.file_end, limit=200)
    assert caught.events == []
    assert caught.offset == end.file_end

    live_log.agent(project, "line-new", phase="worker", role="worker")
    nxt = live_log.read_events(project, offset=caught.offset, limit=200)
    assert [e["text"] for e in nxt.events] == ["line-new"]


def test_format_tool_output_clips():
    big = {"ok": True, "content": "x" * 8000}
    out = format_tool_output(big)
    assert len(out) <= 4000
    assert out.endswith("…")


def test_read_events_pages_by_session(tmp_env, project, monkeypatch, tmp_path):
    path = tmp_path / "live.events.jsonl"
    monkeypatch.setattr("app.services.live_log.live_events_path", lambda _pid: path)
    live_log.reset_runtime_state()
    live_log.agent(project, "s1-a", phase="worker", role="worker")
    live_log.agent(project, "s1-b", phase="worker", role="worker")
    live_log.begin_session(project, "worker")
    live_log.system(project, "挖掘阶段新跑，新开对话（按当前进度注入初始上下文）", phase="worker", session_start=True)
    live_log.agent(project, "s2-a", phase="worker", role="worker")

    latest = live_log.read_events(project, limit=10, tail=True, phase="worker")
    assert latest.session == 2
    assert latest.session_count == 2
    assert [e["text"] for e in latest.events] == [
        "挖掘阶段新跑，新开对话（按当前进度注入初始上下文）",
        "s2-a",
    ]

    first = live_log.read_events(project, limit=10, tail=True, phase="worker", session=1)
    assert first.session == 1
    assert [e["text"] for e in first.events] == ["s1-a", "s1-b"]
    assert first.has_older is False


def test_read_events_infers_session_from_marker(tmp_env, project, monkeypatch, tmp_path):
    path = tmp_path / "legacy.events.jsonl"
    monkeypatch.setattr("app.services.live_log.live_events_path", lambda _pid: path)
    live_log.reset_runtime_state()
    path.write_text(
        "\n".join(
            [
                '{"kind":"agent","text":"old-1","phase":"recon"}',
                '{"kind":"system","text":"侦察阶段新跑，新开对话","phase":"recon"}',
                '{"kind":"agent","text":"new-1","phase":"recon"}',
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    latest = live_log.read_events(project, limit=10, tail=True, phase="recon")
    assert latest.session_count == 2
    assert [e["text"] for e in latest.events] == ["侦察阶段新跑，新开对话", "new-1"]
    older = live_log.read_events(project, limit=10, tail=True, phase="recon", session=1)
    assert [e["text"] for e in older.events] == ["old-1"]


def test_resume_does_not_open_session(tmp_env, project, monkeypatch, tmp_path):
    path = tmp_path / "live.events.jsonl"
    monkeypatch.setattr("app.services.live_log.live_events_path", lambda _pid: path)
    live_log.reset_runtime_state()
    live_log.agent(project, "before", phase="worker", role="worker")
    live_log.system(project, "挖掘阶段续跑（1 个检查点接续上下文）", phase="worker")
    live_log.agent(project, "after", phase="worker", role="worker")
    page = live_log.read_events(project, limit=10, tail=True, phase="worker")
    assert page.session_count == 1
    assert [e["text"] for e in page.events] == ["before", "挖掘阶段续跑（1 个检查点接续上下文）", "after"]


def test_begin_session_if_used_keeps_first_page(tmp_env, project, monkeypatch, tmp_path):
    path = tmp_path / "live.events.jsonl"
    monkeypatch.setattr("app.services.live_log.live_events_path", lambda _pid: path)
    live_log.reset_runtime_state()
    assert live_log.begin_session(project, "reviewer", if_used=True) == 1
    assert live_log.begin_session(project, "reviewer", if_used=True) == 1
    live_log.agent(project, "rev-1", phase="reviewer", role="reviewer")
    assert live_log.begin_session(project, "reviewer", if_used=True) == 2
    live_log.system(project, "审核新开对话（漏洞 #2）", phase="reviewer", session_start=True)
    live_log.agent(project, "rev-2", phase="reviewer", role="reviewer")

    latest = live_log.read_events(project, limit=10, tail=True, phase="reviewer")
    assert latest.session == 2
    assert latest.session_count == 2
    assert [e["text"] for e in latest.events] == ["审核新开对话（漏洞 #2）", "rev-2"]
    first = live_log.read_events(project, limit=10, tail=True, phase="reviewer", session=1)
    assert [e["text"] for e in first.events] == ["rev-1"]


def test_start_log_session_pages_scheduler_conversations(tmp_env, project, monkeypatch, tmp_path):
    from app.services import pipeline

    path = tmp_path / "live.events.jsonl"
    monkeypatch.setattr("app.services.live_log.live_events_path", lambda _pid: path)
    live_log.reset_runtime_state()
    pipeline._start_log_session(project, "reviewer", extra="漏洞 #1")
    live_log.agent(project, "work-1", phase="reviewer", role="reviewer")
    pipeline._start_log_session(project, "reviewer", extra="漏洞 #2")
    live_log.agent(project, "work-2", phase="reviewer", role="reviewer")

    latest = live_log.read_events(project, limit=10, tail=True, phase="reviewer")
    assert latest.session_count == 2
    assert latest.events[0]["session_start"] is True
    assert "新开对话" in latest.events[0]["text"]
    first = live_log.read_events(project, limit=10, tail=True, phase="reviewer", session=1)
    assert first.events[0].get("session_start") is not True
    assert "开始" in first.events[0]["text"]
    assert [e["text"] for e in first.events][-1] == "work-1"


def test_hydrate_if_used_opens_next_page(tmp_env, project, monkeypatch, tmp_path):
    path = tmp_path / "legacy.events.jsonl"
    monkeypatch.setattr("app.services.live_log.live_events_path", lambda _pid: path)
    path.write_text(
        '{"kind":"agent","text":"old-rev","phase":"reviewer"}\n',
        encoding="utf-8",
    )
    live_log.reset_runtime_state()
    assert live_log.begin_session(project, "reviewer", if_used=True) == 2
    assert live_log.begin_session(project, "worker", if_used=True) == 1
    assert live_log.begin_session(project, "fix", if_used=True) == 1


def test_subphase_sessions_are_independent(tmp_env, project, monkeypatch, tmp_path):
    path = tmp_path / "live.events.jsonl"
    monkeypatch.setattr("app.services.live_log.live_events_path", lambda _pid: path)
    live_log.reset_runtime_state()

    live_log.agent(project, "map-1", phase="recon", role="recon")
    assert live_log.begin_session(project, "recon-mark", if_used=True) == 1
    live_log.agent(project, "mark-1", phase="recon-mark", role="recon_mark")
    assert live_log.begin_session(project, "recon-mark", if_used=True) == 2
    live_log.system(project, "侦察新开对话（盖章）", phase="recon-mark", role="recon_mark", session_start=True)
    live_log.agent(project, "mark-2", phase="recon-mark", role="recon_mark")

    assert (tmp_path / "live-events" / "recon" / "round-1.jsonl").exists()
    assert (tmp_path / "live-events" / "recon-mark" / "round-1.jsonl").exists()
    assert (tmp_path / "live-events" / "recon-mark" / "round-2.jsonl").exists()

    mapped = live_log.read_events(project, limit=10, tail=True, phase="recon-map")
    assert mapped.session_count == 1
    assert [e["text"] for e in mapped.events] == ["map-1"]

    mark_latest = live_log.read_events(project, limit=10, tail=True, phase="recon-mark")
    assert mark_latest.session == 2
    assert mark_latest.session_count == 2
    assert [e["text"] for e in mark_latest.events] == ["侦察新开对话（盖章）", "mark-2"]

    mark_first = live_log.read_events(project, limit=10, tail=True, phase="recon-mark", session=1)
    assert [e["text"] for e in mark_first.events] == ["mark-1"]

    live_log.agent(project, "mine-1", phase="worker", role="worker")
    assert live_log.begin_session(project, "fix", if_used=True) == 1
    live_log.agent(project, "fix-1", phase="fix", role="fix")
    assert live_log.begin_session(project, "fix", if_used=True) == 2
    live_log.system(project, "挖掘新开对话（漏洞 #1）", phase="fix", role="fix", session_start=True)
    live_log.agent(project, "fix-2", phase="fix", role="fix")

    mine = live_log.read_events(project, limit=10, tail=True, phase="mine")
    assert mine.session_count == 1
    assert [e["text"] for e in mine.events] == ["mine-1"]
    fix_latest = live_log.read_events(project, limit=10, tail=True, phase="fix")
    assert fix_latest.session_count == 2
    assert [e["text"] for e in fix_latest.events] == ["挖掘新开对话（漏洞 #1）", "fix-2"]
    assert live_log.current_session(project, "worker") == 1
    assert live_log.current_session(project, "fix") == 2
    assert live_log.current_session(project, "recon") == 1
    assert live_log.current_session(project, "recon-mark") == 2


def test_fast_worker_logs_are_separate_from_heuristic(tmp_env, project, monkeypatch, tmp_path):
    path = tmp_path / "live.events.jsonl"
    monkeypatch.setattr("app.services.live_log.live_events_path", lambda _pid: path)
    live_log.reset_runtime_state()

    live_log.agent(project, "heuristic-1", phase="worker", role="worker")
    live_log.agent(project, "triage-1", phase="sink-triage", role="sink_triage")
    live_log.begin_session(project, "fast-worker", if_used=True)
    live_log.system(project, "挖掘新开对话（Sink）", phase="fast-worker", role="fast_worker", session_start=True)
    live_log.agent(project, "fast-1", phase="fast-worker", role="fast_worker")

    assert (tmp_path / "live-events" / "worker" / "round-1.jsonl").exists()
    assert (tmp_path / "live-events" / "sink-triage" / "round-1.jsonl").exists()
    assert (tmp_path / "live-events" / "fast-worker" / "round-1.jsonl").exists()
    assert not (tmp_path / "live-events" / "system" / "round-1.jsonl").exists()

    mine = live_log.read_events(project, limit=10, tail=True, phase="mine")
    assert [e["text"] for e in mine.events] == ["heuristic-1"]
    fast = live_log.read_events(project, limit=10, tail=True, phase="fast")
    assert "heuristic-1" not in [e["text"] for e in fast.events]
    assert [e["text"] for e in fast.events] == ["triage-1", "挖掘新开对话（Sink）", "fast-1"]
    worker = live_log.read_events(project, limit=20, tail=True, phase="worker")
    assert [e["text"] for e in worker.events] == ["heuristic-1", "triage-1", "挖掘新开对话（Sink）", "fast-1"]


def test_legacy_fast_logs_in_system_dir_still_readable(tmp_env, project, monkeypatch, tmp_path):
    path = tmp_path / "live.events.jsonl"
    monkeypatch.setattr("app.services.live_log.live_events_path", lambda _pid: path)
    live_log.reset_runtime_state()
    legacy = tmp_path / "live-events" / "system" / "round-1.jsonl"
    legacy.parent.mkdir(parents=True, exist_ok=True)
    legacy.write_text(
        json.dumps(
            {
                "kind": "agent",
                "text": "old-fast",
                "phase": "fast-worker",
                "role": "fast_worker",
                "seq": 0,
            },
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    page = live_log.read_events(project, limit=10, tail=True, phase="fast")
    assert [e["text"] for e in page.events] == ["old-fast"]


def test_purge_older_than_keeps_recent_events(tmp_env, project):
    from app.services.paths import logs_dir, tool_exec_errors_path

    live_log.reset_runtime_state()
    live_log.agent(project, "old", phase="worker", role="worker")
    live_log.begin_session(project, "worker")
    live_log.agent(project, "new", phase="worker", role="worker")

    old_path = logs_dir(project) / "live-events" / "worker" / "round-1.jsonl"
    new_path = logs_dir(project) / "live-events" / "worker" / "round-2.jsonl"
    legacy = logs_dir(project) / "live.events.jsonl"
    legacy.write_text('{"kind":"agent","text":"legacy-old"}\n', encoding="utf-8")
    errors = tool_exec_errors_path(project)
    errors.write_text('{"error":"keep-me"}\n', encoding="utf-8")

    old_mtime = time.time() - 10 * 86400
    os.utime(old_path, (old_mtime, old_mtime))
    os.utime(legacy, (old_mtime, old_mtime))

    result = live_log.purge_older_than(7)
    assert result["older_than_days"] == 7
    assert result["files"] == 2
    assert result["projects"] == 1
    assert result["bytes"] > 0
    assert not old_path.exists()
    assert not legacy.exists()
    assert new_path.exists()
    assert errors.exists()
    assert errors.read_text(encoding="utf-8") == '{"error":"keep-me"}\n'

    page = live_log.read_events(project, limit=10, tail=True, phase="worker")
    assert [e["text"] for e in page.events] == ["new"]


def test_purge_older_than_zero_deletes_all_events(tmp_env, project):
    from app.services.paths import logs_dir

    live_log.reset_runtime_state()
    live_log.agent(project, "keep-or-not", phase="worker", role="worker")
    path = logs_dir(project) / "live-events" / "worker" / "round-1.jsonl"
    seq = logs_dir(project) / "live-events" / ".seq"
    assert path.exists()
    assert seq.exists()

    result = live_log.purge_older_than(0)
    assert result["files"] == 1
    assert result["projects"] == 1
    assert not path.exists()
    assert seq.exists()
    assert not (logs_dir(project) / "live-events" / "worker").exists()
    page = live_log.read_events(project, limit=10, tail=True, phase="worker")
    assert page.events == []

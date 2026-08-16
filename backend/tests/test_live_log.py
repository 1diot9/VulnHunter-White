from __future__ import annotations

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


def test_event_matches_phase_groups_fix_under_worker():
    from app.services.live_log import event_matches_phase

    assert event_matches_phase({"phase": "fix", "kind": "agent"}, "worker")
    assert event_matches_phase({"role": "fix", "kind": "cmd"}, "worker")
    assert event_matches_phase({"phase": "worker", "kind": "agent"}, "mine")
    assert not event_matches_phase({"phase": "fix", "kind": "agent"}, "mine")
    assert event_matches_phase({"phase": "fix", "kind": "agent"}, "fix")
    assert not event_matches_phase({"phase": "worker", "kind": "agent"}, "fix")
    assert event_matches_phase({"phase": "recon-mark", "kind": "agent"}, "recon")
    assert event_matches_phase({"role": "recon_mark", "kind": "cmd"}, "recon")
    assert event_matches_phase({"phase": "recon-old-vuln", "kind": "agent"}, "recon")
    assert event_matches_phase({"phase": "recon-old-vuln", "kind": "agent"}, "recon-old-vuln")
    assert event_matches_phase({"phase": "recon", "kind": "agent"}, "recon-map")
    assert not event_matches_phase({"phase": "recon-old-vuln", "kind": "agent"}, "recon-map")
    assert not event_matches_phase({"phase": "recon", "kind": "agent"}, "recon-old-vuln")
    assert not event_matches_phase({"phase": "fix", "kind": "agent"}, "recon")
    assert not event_matches_phase({"kind": "system", "text": "x"}, "reviewer")
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

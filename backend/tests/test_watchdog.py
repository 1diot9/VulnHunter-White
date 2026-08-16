from __future__ import annotations

from app.agent.watchdog import (
    IDENTICAL_TOOL_NUDGE,
    NO_TOOL_NUDGE,
    RECON_OLD_VULN_PERSIST_NUDGE,
    RECON_PERSIST_INTERVAL,
    RECON_PERSIST_NUDGE,
    WORKER_FINISH_INTERVAL,
    WORKER_FINISH_NUDGE,
    AgentWatchdog,
    identical_tool_nudge,
)


def test_no_tools_nudge_does_not_abort():
    w = AgentWatchdog()
    msg = w.note_no_tools()
    assert msg == NO_TOOL_NUDGE
    assert w.consecutive_no_tool_turns == 1
    assert w.note_no_tools()
    assert w.consecutive_no_tool_turns == 2
    assert w.reason is None


def test_tool_call_resets_no_tool_counter():
    w = AgentWatchdog(max_same_tool_calls=10)
    w.note_no_tools()
    w.note_no_tools()
    assert w.observe_tools([{"name": "Read", "arguments": {"path": "a.java"}}]) is None
    assert w.consecutive_no_tool_turns == 0


def test_repeated_identical_tool_calls():
    w = AgentWatchdog(max_same_tool_calls=3)
    call = {"name": "Read", "arguments": {"path": "a.java"}}
    assert w.observe_tools([call]) is None
    assert w.observe_tools([call]) is None
    reason = w.observe_tools([call])
    assert reason is not None
    assert "repeated identical tool call" in reason
    assert "Read" in reason
    # does not latch: a different call is allowed
    assert w.observe_tools([{"name": "Read", "arguments": {"path": "b.java"}}]) is None
    assert w.reason is None
    # same call again after a change is not yet a full window
    assert w.observe_tools([call]) is None


def test_identical_tool_nudge_text():
    msg = identical_tool_nudge("PowerShell", 4)
    assert msg == IDENTICAL_TOOL_NUDGE.format(name="PowerShell", n=4)
    assert "未执行" in msg
    assert "不要原样重试" in msg


def test_distinct_tool_calls_are_not_loops():
    w = AgentWatchdog(max_same_tool_calls=3)
    for i in range(20):
        reason = w.observe_tools([{"name": "Read", "arguments": {"path": f"f{i}.java"}}])
        assert reason is None


def test_recon_persist_nudge_every_50_turns():
    w = AgentWatchdog(phase="recon")
    assert w.persist_nudge_interval == RECON_PERSIST_INTERVAL == 50
    for i in range(1, 50):
        assert w.note_turn() is None
        assert w.turn_count == i
    msg = w.note_turn()
    assert msg is not None
    assert "50 轮" in msg
    assert "code-map.md" in msg
    assert "MarkSource" in msg
    assert "WriteOldVuln" not in msg
    assert "盖章" not in msg
    assert msg == RECON_PERSIST_NUDGE.format(n=50)
    assert w.note_turn() is None
    for _ in range(48):
        assert w.note_turn() is None
    msg100 = w.note_turn()
    assert msg100 is not None
    assert "100 轮" in msg100


def test_recon_persist_nudge_custom_interval():
    w = AgentWatchdog(phase="recon", persist_nudge_interval=2)
    assert w.note_turn() is None
    assert w.note_turn() is not None
    assert w.note_turn() is None
    assert w.note_turn() is not None


def test_recon_old_vuln_persist_nudge():
    w = AgentWatchdog(phase="recon-old-vuln", persist_nudge_interval=2)
    assert w.note_turn() is None
    msg = w.note_turn()
    assert msg is not None
    assert "WriteOldVuln" in msg
    assert "落盘不会结束本会话" in msg
    assert msg == RECON_OLD_VULN_PERSIST_NUDGE.format(n=2)


def test_worker_finish_nudge_every_50_turns():
    w = AgentWatchdog(phase="worker")
    assert w.worker_finish_interval == WORKER_FINISH_INTERVAL == 50
    for i in range(1, 50):
        assert w.note_turn() is None
        assert w.turn_count == i
    msg = w.note_turn()
    assert msg is not None
    assert "50 轮" in msg
    assert "FinishFile" in msg
    assert "FinishRound" in msg
    assert "非入口" in msg
    assert "不要只标一开始注入的入口文件" in msg
    assert "禁止立刻 FinishRound" in msg
    assert msg == WORKER_FINISH_NUDGE.format(n=50)
    assert "看门狗：挖掘连续 50 轮未 FinishFile，已提醒立刻标记非入口文件" == w.persist_nudge_log()
    assert w.note_turn() is None
    for _ in range(48):
        assert w.note_turn() is None
    msg100 = w.note_turn()
    assert msg100 is not None
    assert "100 轮" in msg100


def test_worker_finish_nudge_custom_interval():
    w = AgentWatchdog(phase="worker", worker_finish_interval=2)
    assert w.note_turn() is None
    assert w.note_turn() is not None
    assert w.note_turn() is None
    assert w.note_turn() is not None


def test_fix_and_reviewer_have_no_finish_nudge():
    for phase in ("fix", "reviewer", "recon-mark"):
        w = AgentWatchdog(phase=phase)
        for _ in range(60):
            assert w.note_turn() is None


def test_persist_nudge_disabled_when_interval_zero():
    w = AgentWatchdog(phase="recon", persist_nudge_interval=0)
    for _ in range(40):
        assert w.note_turn() is None
    w2 = AgentWatchdog(phase="worker", worker_finish_interval=0)
    for _ in range(60):
        assert w2.note_turn() is None


def test_idle_counter_resets_when_target_tool_called():
    w = AgentWatchdog(phase="worker", worker_finish_interval=3)
    assert w.note_turn(["Read"]) is None
    assert w.idle_turns == 1
    assert w.note_turn(["Grep"]) is None
    assert w.idle_turns == 2
    assert w.note_turn(["FinishFile", "Read"]) is None
    assert w.idle_turns == 0
    assert w.note_turn(["Read"]) is None
    assert w.idle_turns == 1
    assert w.note_turn() is None
    assert w.idle_turns == 2
    msg = w.note_turn(["Bash"])
    assert msg is not None
    assert "连续 3 轮未调用 FinishFile" in msg
    assert w.idle_turns == 3


def test_unrelated_tools_do_not_reset_recon_idle():
    w = AgentWatchdog(phase="recon", persist_nudge_interval=2)
    assert w.note_turn(["Read"]) is None
    msg = w.note_turn(["Grep", "Bash"])
    assert msg is not None
    assert "连续 2 轮未调用 Write / MarkSource" in msg
    assert w.note_turn(["Write"]) is None
    assert w.idle_turns == 0
    assert w.note_turn(["MarkSource"]) is None
    assert w.idle_turns == 0
    assert w.note_turn() is None
    assert w.note_turn(["Read"]) is not None


def test_write_old_vuln_resets_old_vuln_idle():
    w = AgentWatchdog(phase="recon-old-vuln", persist_nudge_interval=2)
    assert w.note_turn(["WebSearch"]) is None
    assert w.note_turn(["WriteOldVuln"]) is None
    assert w.idle_turns == 0
    assert w.note_turn() is None
    msg = w.note_turn(["SearchGHSA"])
    assert msg == RECON_OLD_VULN_PERSIST_NUDGE.format(n=2)


def test_idle_turns_restored_from_snapshot():
    w = AgentWatchdog(phase="worker", worker_finish_interval=3)
    w.note_turn(["Read"])
    w.note_turn(["Read"])
    restored = AgentWatchdog.restore(w.snapshot())
    assert restored.idle_turns == 2
    assert restored.note_turn(["Grep"]) is not None
    assert AgentWatchdog.restore({}).idle_turns == 0

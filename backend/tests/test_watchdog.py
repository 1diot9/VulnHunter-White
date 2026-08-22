from __future__ import annotations

from app.agent.watchdog import (
    FAILED_TOOL_NUDGE,
    IDENTICAL_ABORT_NUDGE,
    IDENTICAL_REDIRECT_NUDGE,
    IDENTICAL_TOOL_NUDGE,
    MAX_IDENTICAL_THRESHOLD_HITS,
    NO_TOOL_NUDGE,
    RECON_MARK_NO_TOOL_NUDGE,
    RECON_OLD_VULN_PERSIST_NUDGE,
    RECON_PERSIST_INTERVAL,
    WORKER_FINISH_INTERVAL,
    WORKER_FINISH_NUDGE,
    AgentWatchdog,
    identical_abort_nudge,
    identical_redirect_nudge,
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


def test_failed_tool_followup_is_not_no_tool():
    w = AgentWatchdog()
    w.observe_tools([{"name": "MarkSkip", "arguments": {"path": ".flattened-pom.xml"}}])
    w.note_tool_results(failed=True)
    assert w.consecutive_no_tool_turns == 0
    assert w.pending_tool_failure is True
    msg, kind = w.nudge_for_text_turn()
    assert kind == "failed_tool"
    assert msg == FAILED_TOOL_NUDGE
    assert "不等于没调用工具" in msg
    assert "没有调用任何工具" not in msg
    assert w.consecutive_no_tool_turns == 0
    assert w.pending_tool_failure is False
    assert "不视为未调用工具" in w.text_turn_log(kind)
    msg2, kind2 = w.nudge_for_text_turn()
    assert kind2 == "no_tools"
    assert msg2 == NO_TOOL_NUDGE
    assert w.consecutive_no_tool_turns == 1


def test_successful_tool_does_not_defer_no_tool_nudge():
    w = AgentWatchdog()
    w.observe_tools([{"name": "Read", "arguments": {"path": "a.java"}}])
    w.note_tool_results(failed=False)
    msg, kind = w.nudge_for_text_turn()
    assert kind == "no_tools"
    assert msg == NO_TOOL_NUDGE


def test_pending_tool_failure_restored_from_snapshot():
    w = AgentWatchdog()
    w.note_tool_results(failed=True)
    restored = AgentWatchdog.restore(w.snapshot())
    assert restored.pending_tool_failure is True
    msg, kind = restored.nudge_for_text_turn()
    assert kind == "failed_tool"
    assert msg == FAILED_TOOL_NUDGE


def test_repeated_identical_tool_calls():
    w = AgentWatchdog()
    assert w.max_same_tool_calls == 4
    call = {"name": "Read", "arguments": {"path": "a.java"}}
    assert w.observe_tools([call]) is None
    assert w.observe_tools([call]) is None
    assert w.observe_tools([call]) is None
    reason = w.observe_tools([call])
    assert reason is not None
    assert "repeated identical tool call" in reason
    assert "Read" in reason
    assert w.identical_threshold_hits == 1
    assert w.recent_tool_keys == []
    assert not w.identical_loop_exhausted()
    # window reset: same call is allowed again until the next threshold
    assert w.observe_tools([call]) is None
    assert w.observe_tools([{"name": "Read", "arguments": {"path": "b.java"}}]) is None
    assert w.reason is None


def test_identical_threshold_redirects_then_aborts_after_five_hits():
    w = AgentWatchdog(max_same_tool_calls=2, max_identical_threshold_hits=5)
    call = {"name": "PowerShell", "arguments": {"command": "docker exec db mysql"}}
    for hit in range(1, 5):
        assert w.observe_tools([call]) is None
        reason = w.observe_tools([call])
        assert reason is not None
        assert w.identical_threshold_hits == hit
        assert w.recent_tool_keys == []
        assert not w.identical_loop_exhausted()
    assert w.observe_tools([call]) is None
    reason = w.observe_tools([call])
    assert reason is not None
    assert w.identical_threshold_hits == 5
    assert w.identical_loop_exhausted()


def test_identical_threshold_hits_accumulate_across_different_calls():
    w = AgentWatchdog(max_same_tool_calls=2, max_identical_threshold_hits=5)
    a = {"name": "PowerShell", "arguments": {"command": "a"}}
    b = {"name": "PowerShell", "arguments": {"command": "b"}}
    assert w.observe_tools([a]) is None
    assert w.observe_tools([a]) is not None
    assert w.identical_threshold_hits == 1
    assert w.observe_tools([b]) is None
    assert w.observe_tools([b]) is not None
    assert w.identical_threshold_hits == 2


def test_identical_tool_nudge_text():
    msg = identical_tool_nudge("PowerShell", 3)
    assert msg == IDENTICAL_TOOL_NUDGE.format(name="PowerShell", n=3)
    assert "未执行" in msg
    assert "不要原样重试" in msg
    redirect = identical_redirect_nudge("PowerShell", 2, 5)
    assert redirect == IDENTICAL_REDIRECT_NUDGE.format(name="PowerShell", hit=2, max_hits=5)
    assert "导向" in redirect
    assert "2/5" in redirect
    abort = identical_abort_nudge("PowerShell", 5)
    assert abort == IDENTICAL_ABORT_NUDGE.format(name="PowerShell", hits=5)
    assert "终止" in abort
    assert MAX_IDENTICAL_THRESHOLD_HITS == 5


def test_distinct_tool_calls_are_not_loops():
    w = AgentWatchdog(max_same_tool_calls=3)
    for i in range(20):
        reason = w.observe_tools([{"name": "Read", "arguments": {"path": f"f{i}.java"}}])
        assert reason is None


def test_recon_map_auth_has_no_persist_nudge():
    w = AgentWatchdog(phase="recon")
    for i in range(1, 101):
        assert w.note_turn() is None
        assert w.turn_count == i
    w2 = AgentWatchdog(phase="recon", persist_nudge_interval=2)
    for _ in range(10):
        assert w2.note_turn(["Read"]) is None
        assert w2.note_turn(["Write", "MarkSource"]) is None


def test_recon_old_vuln_persist_nudge():
    assert AgentWatchdog(phase="recon-old-vuln").persist_nudge_interval == RECON_PERSIST_INTERVAL == 50
    w = AgentWatchdog(phase="recon-old-vuln", persist_nudge_interval=2)
    assert w.note_turn() is None
    msg = w.note_turn()
    assert msg is not None
    assert "WriteOldVuln" in msg
    assert "落盘不会结束本会话" in msg
    assert msg == RECON_OLD_VULN_PERSIST_NUDGE.format(n=2)
    assert "看门狗：侦察（历史漏洞）连续 2 轮未 WriteOldVuln，已提醒立即落盘" == w.persist_nudge_log()


def test_recon_source_ext_persist_nudge():
    from app.agent.watchdog import RECON_SOURCE_EXT_PERSIST_NUDGE

    w = AgentWatchdog(phase="recon-source-ext", persist_nudge_interval=2)
    assert w.note_turn(["Glob"]) is None
    msg = w.note_turn(["Read"])
    assert msg == RECON_SOURCE_EXT_PERSIST_NUDGE.format(n=2)
    assert "AddSourceExt" in msg
    assert w.note_turn(["AddSourceExt"]) is None
    assert w.idle_turns == 0
    assert "看门狗：侦察（扩展名）连续 2 轮未 AddSourceExt，已提醒立即落盘" == AgentWatchdog(
        phase="recon-source-ext", idle_turns=2
    ).persist_nudge_log()


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
    assert "不能当入口" in msg
    assert "不要只标一开始注入的焦点文件" in msg
    assert "禁止立刻 FinishRound" in msg
    assert msg == WORKER_FINISH_NUDGE.format(n=50)
    assert "看门狗：挖掘连续 50 轮未 FinishFile，已提醒立刻标记已确认无漏洞的文件" == w.persist_nudge_log()
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


def test_reviewer_lab_no_tool_nudge():
    from app.agent.watchdog import LAB_NO_TOOL_NUDGE, AgentWatchdog

    w = AgentWatchdog(phase="reviewer-lab")
    assert w.note_no_tools() == LAB_NO_TOOL_NUDGE
    assert "被测应用" in LAB_NO_TOOL_NUDGE
    assert "旧版应用镜像" in LAB_NO_TOOL_NUDGE
    w2 = AgentWatchdog(phase="reviewer")
    assert "ConfirmVuln" in w2.note_no_tools()
    w3 = AgentWatchdog(phase="verifier")
    assert "FofaSearch" in w3.note_no_tools()
    assert "FinishVerifier" in w3.note_no_tools()
    w4 = AgentWatchdog(phase="recon-mark")
    assert w4.note_no_tools() == RECON_MARK_NO_TOOL_NUDGE
    assert "MarkSource" in RECON_MARK_NO_TOOL_NUDGE
    assert "MarkSkip" in RECON_MARK_NO_TOOL_NUDGE
    assert AgentWatchdog(phase="recon_mark").note_no_tools() == RECON_MARK_NO_TOOL_NUDGE


def test_fix_and_reviewer_have_no_finish_nudge():
    for phase in ("fix", "reviewer", "recon-mark", "recon", "verifier"):
        w = AgentWatchdog(phase=phase)
        for _ in range(60):
            assert w.note_turn() is None


def test_persist_nudge_disabled_when_interval_zero():
    w = AgentWatchdog(phase="recon-old-vuln", persist_nudge_interval=0)
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


def test_write_old_vuln_resets_old_vuln_idle():
    w = AgentWatchdog(phase="recon-old-vuln", persist_nudge_interval=2)
    assert w.note_turn(["Read"]) is None
    assert w.note_turn(["WriteOldVuln"]) is None
    assert w.idle_turns == 0
    assert w.note_turn() is None
    msg = w.note_turn(["SearchOldVuln"])
    assert msg == RECON_OLD_VULN_PERSIST_NUDGE.format(n=2)


def test_idle_turns_restored_from_snapshot():
    w = AgentWatchdog(phase="worker", worker_finish_interval=3)
    w.note_turn(["Read"])
    w.note_turn(["Read"])
    restored = AgentWatchdog.restore(w.snapshot())
    assert restored.idle_turns == 2
    assert restored.note_turn(["Grep"]) is not None
    assert AgentWatchdog.restore({}).idle_turns == 0


def test_identical_hits_restored_from_snapshot():
    w = AgentWatchdog(max_same_tool_calls=2)
    call = {"name": "Read", "arguments": {"path": "a.java"}}
    w.observe_tools([call])
    w.observe_tools([call])
    restored = AgentWatchdog.restore(w.snapshot())
    assert restored.identical_threshold_hits == 1
    assert restored.max_identical_threshold_hits == MAX_IDENTICAL_THRESHOLD_HITS
    assert restored.recent_tool_keys == []
    assert restored.observe_tools([call]) is None
    assert restored.observe_tools([call]) is not None
    assert restored.identical_threshold_hits == 2


def test_bypass_finish_nudge_and_no_tool():
    from app.agent.watchdog import BYPASS_FINISH_NUDGE, BYPASS_NO_TOOL_NUDGE

    w = AgentWatchdog(phase="bypass-worker", worker_finish_interval=2)
    assert w.note_no_tools() == BYPASS_NO_TOOL_NUDGE
    assert w.note_turn(["Read"]) is None
    msg = w.note_turn(["Grep"])
    assert msg == BYPASS_FINISH_NUDGE.format(n=2)
    assert "FinishBypass" in w.persist_nudge_log()
    assert w.note_turn(["FinishBypass"]) is None
    assert w.idle_turns == 0


def test_cli_indexer_watchdog_nudges():
    from app.agent.watchdog import CLI_INDEXER_FINISH_NUDGE, CLI_INDEXER_NO_TOOL_NUDGE

    w = AgentWatchdog(phase="cli-indexer")
    assert w.note_no_tools() == CLI_INDEXER_NO_TOOL_NUDGE
    for _ in range(7):
        assert w.note_turn(["Read"]) is None
    msg = w.note_turn(["Grep"])
    assert msg == CLI_INDEXER_FINISH_NUDGE.format(n=8)
    assert w.note_turn(["FinishIndex"]) is None
    assert w.idle_turns == 0

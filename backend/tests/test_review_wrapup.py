"""Reviewer wrap-up grace: detect verified+docs finishing and extend once."""

from __future__ import annotations

import time
from unittest.mock import MagicMock

from app.agent.loop import AgentLoop
from app.agent.review_wrapup import (
    GRACE_REMAINING_THRESHOLD,
    is_doc_write_tool,
    is_wrapup_tool,
    note_tool_for_wrapup,
    path_under_vuln,
    recent_tools_are_wrapup,
    should_grant_wrapup_grace,
    wrapup_grace_nudge,
)
from app.config import settings
from app.services import pipeline
from app.services.llm_thread import SlotHandle


def _usage():
    return {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}


def test_path_under_vuln():
    assert path_under_vuln("vulns/12/report.md", 12) is True
    assert path_under_vuln("vulns\\12\\advisory.md", 12) is True
    assert path_under_vuln("vulns/12/report.md", 99) is False
    assert path_under_vuln("src/app.py", 12) is False
    assert path_under_vuln("vulns/12/report.md", None) is True


def test_is_wrapup_and_doc_write():
    assert is_wrapup_tool("SetCveRecordField", {"path": "x", "value": 1}, vuln_id=1)
    assert is_doc_write_tool("SetCveRecordField", {"path": "x", "value": 1}, vuln_id=1)
    assert is_wrapup_tool("Write", {"path": "vulns/1/report.md"}, vuln_id=1)
    assert is_doc_write_tool("Write", {"path": "vulns/1/report.md"}, vuln_id=1)
    assert is_wrapup_tool("Read", {"path": "vulns/1/report.md"}, vuln_id=1)
    assert not is_doc_write_tool("Read", {"path": "vulns/1/report.md"}, vuln_id=1)
    assert not is_wrapup_tool("Write", {"path": "src/main.py"}, vuln_id=1)
    assert not is_wrapup_tool("Grep", {"pattern": "x"}, vuln_id=1)
    assert not is_wrapup_tool("TodoWrite", {"todos": []}, vuln_id=1)


def test_note_runcode_success_marks_verified():
    state: dict = {}
    note_tool_for_wrapup(
        state,
        name="RunCode",
        arguments={"code": "print(1)", "language": "python"},
        result={"ok": True, "exit_code": 0},
        vuln_id=7,
    )
    assert state["review_verified"] is True
    note_tool_for_wrapup(
        state,
        name="Write",
        arguments={"path": "vulns/7/advisory.md", "content": "# t"},
        result={"ok": True},
        vuln_id=7,
    )
    note_tool_for_wrapup(
        state,
        name="SetCveRecordField",
        arguments={"path": "containers.cna.descriptions[0].value", "value": "x"},
        result={"ok": True},
        vuln_id=7,
    )
    note_tool_for_wrapup(
        state,
        name="Read",
        arguments={"path": "vulns/7/report.md"},
        result={"ok": True},
        vuln_id=7,
    )
    assert recent_tools_are_wrapup(state) is True
    assert should_grant_wrapup_grace(state, phase="reviewer", remaining=30) is True


def test_recent_grep_blocks_grace():
    state: dict = {}
    note_tool_for_wrapup(
        state,
        name="RunCode",
        arguments={"code": "print(1)"},
        result={"ok": True},
        vuln_id=1,
    )
    note_tool_for_wrapup(
        state,
        name="Write",
        arguments={"path": "vulns/1/report.md", "content": "x"},
        result={"ok": True},
        vuln_id=1,
    )
    note_tool_for_wrapup(
        state,
        name="Grep",
        arguments={"pattern": "pull", "root": "src"},
        result={"ok": True, "hits": []},
        vuln_id=1,
    )
    note_tool_for_wrapup(
        state,
        name="Write",
        arguments={"path": "vulns/1/advisory.md", "content": "x"},
        result={"ok": True},
        vuln_id=1,
    )
    # Last three tracked: Write, Grep, Write — Grep is not wrapup
    assert recent_tools_are_wrapup(state) is False
    assert should_grant_wrapup_grace(state, phase="reviewer", remaining=10) is False


def test_read_only_without_verify_or_write_no_grace():
    state: dict = {}
    note_tool_for_wrapup(
        state,
        name="Read",
        arguments={"path": "vulns/1/report.md"},
        result={"ok": True},
        vuln_id=1,
    )
    note_tool_for_wrapup(
        state,
        name="ReadCveRecord",
        arguments={},
        result={"ok": True},
        vuln_id=1,
    )
    note_tool_for_wrapup(
        state,
        name="Read",
        arguments={"path": "vulns/1/advisory.md"},
        result={"ok": True},
        vuln_id=1,
    )
    # All wrapup but no doc write and not verified
    assert recent_tools_are_wrapup(state) is False
    assert should_grant_wrapup_grace(state, phase="reviewer", remaining=10) is False


def test_static_wrapup_via_doc_writes():
    state: dict = {}
    note_tool_for_wrapup(
        state,
        name="Write",
        arguments={"path": "vulns/3/report.md", "content": "# fixed"},
        result={"ok": True},
        vuln_id=3,
    )
    note_tool_for_wrapup(
        state,
        name="SetCveRecordField",
        arguments={"path": "containers.cna.descriptions[0].value", "value": "long"},
        result={"ok": True},
        vuln_id=3,
    )
    note_tool_for_wrapup(
        state,
        name="Read",
        arguments={"path": "vulns/3/advisory.md"},
        result={"ok": True},
        vuln_id=3,
    )
    assert state["review_verified"] is False
    assert state["review_wrote_docs"] is True
    assert recent_tools_are_wrapup(state) is True
    assert should_grant_wrapup_grace(state, phase="reviewer", remaining=0) is True


def test_poc_shell_marks_verified():
    state: dict = {}
    note_tool_for_wrapup(
        state,
        name="Bash",
        arguments={"command": "python vulns/9/poc.py -u http://127.0.0.1:8080"},
        result={"ok": True, "exit_code": 0},
        vuln_id=9,
    )
    assert state["review_verified"] is True


def test_confirm_doc_gate_rejection_marks_verified():
    state: dict = {}
    note_tool_for_wrapup(
        state,
        name="ConfirmVuln",
        arguments={"vuln_id": 1, "attack_surface": "frontend"},
        result={
            "ok": False,
            "error": "局部验证（harness）确认前，报告须含「### 漏洞代码」章节：写明路径。",
        },
        vuln_id=1,
    )
    assert state["review_verified"] is True
    assert recent_tools_are_wrapup(state) is False  # need doc write in window
    note_tool_for_wrapup(
        state,
        name="Write",
        arguments={"path": "vulns/1/report.md", "content": "### 漏洞代码\n"},
        result={"ok": True},
        vuln_id=1,
    )
    note_tool_for_wrapup(
        state,
        name="ConfirmVuln",
        arguments={"vuln_id": 1},
        result={"ok": False, "error": "请 Write 报告后再 ConfirmVuln(evidence_level=harness)。"},
        vuln_id=1,
    )
    assert recent_tools_are_wrapup(state) is True


def test_grace_only_for_reviewer_phase_and_once():
    state: dict = {
        "review_verified": True,
        "review_wrote_docs": True,
        "review_wrapup_grace_used": False,
        "review_recent_tools": [
            {"name": "Write", "wrapup": True, "doc_write": True},
            {"name": "SetCveRecordField", "wrapup": True, "doc_write": True},
            {"name": "Read", "wrapup": True, "doc_write": False},
        ],
    }
    assert should_grant_wrapup_grace(state, phase="worker", remaining=0) is False
    assert should_grant_wrapup_grace(state, phase="reviewer", remaining=GRACE_REMAINING_THRESHOLD + 1) is False
    assert should_grant_wrapup_grace(state, phase="reviewer", remaining=10) is True
    state["review_wrapup_grace_used"] = True
    assert should_grant_wrapup_grace(state, phase="reviewer", remaining=0) is False


def test_wrapup_grace_nudge_text():
    text = wrapup_grace_nudge(verified=True, grace_sec=600)
    assert "ConfirmVuln" in text
    assert "600" in text
    assert "已验证" in text
    text2 = wrapup_grace_nudge(verified=False, grace_sec=120)
    assert "文档" in text2
    assert "120" in text2


def test_config_wrapup_grace_default():
    assert settings.timeout_reviewer_wrapup_grace == 600
    assert settings.timeout_reviewer_static == 2700


def test_maybe_grant_method_once(tmp_env, project):
    loop = AgentLoop(
        project_id=project,
        role="reviewer",
        phase="reviewer",
        system_prompt="sys",
        user_prompt="task",
        vuln_id=1,
        timeout_sec=60,
    )
    loop.state.update(
        {
            "review_verified": True,
            "review_wrote_docs": True,
            "review_wrapup_grace_used": False,
            "review_recent_tools": [
                {"name": "Write", "wrapup": True, "doc_write": True},
                {"name": "SetCveRecordField", "wrapup": True, "doc_write": True},
                {"name": "Read", "wrapup": True, "doc_write": False},
            ],
        }
    )
    messages: list[dict] = [{"role": "user", "content": "task"}]
    assert loop._maybe_grant_review_wrapup_grace(messages, remaining=15) is True
    assert loop.state["review_wrapup_grace_used"] is True
    assert messages[-1]["role"] == "user"
    assert "ConfirmVuln" in messages[-1]["content"]
    assert "收尾宽限" in messages[-1]["content"]
    # Second grant blocked
    assert loop._maybe_grant_review_wrapup_grace(messages, remaining=0) is False


def test_reviewer_loop_grants_grace_once_then_times_out(tmp_env, project, monkeypatch):
    monkeypatch.setattr(settings, "timeout_reviewer_wrapup_grace", 100)
    chats = {"n": 0}
    logs: list[str] = []
    # Controllable clock. AgentLoop uses max(60, timeout_sec) for the deadline.
    clock = {"t": 1000.0}

    def fake_time() -> float:
        return clock["t"]

    def fake_chat(self, messages, tools, remaining):  # noqa: ANN001
        chats["n"] += 1
        # After grace (base 60 + grace 100 → deadline 1160), burn the budget.
        if chats["n"] == 1:
            clock["t"] = 1159.0
        else:
            clock["t"] = 1161.0
        return (
            {
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": f"still working {chats['n']}",
                        }
                    }
                ]
            },
            _usage(),
            None,
        )

    monkeypatch.setattr(time, "time", fake_time)
    monkeypatch.setattr(AgentLoop, "_chat", fake_chat)
    monkeypatch.setattr(AgentLoop, "_rescue_conclude", lambda self, messages: None)
    monkeypatch.setattr(AgentLoop, "_persist", lambda self, messages, status="running": None)
    monkeypatch.setattr(AgentLoop, "_enforce_token_budget", lambda self: False)

    run_id = pipeline._new_phase_run(project, "reviewer", "reviewer", vuln_id=1)
    loop = AgentLoop(
        project_id=project,
        role="reviewer",
        phase="reviewer",
        system_prompt="sys",
        user_prompt="task",
        phase_run_id=run_id,
        vuln_id=1,
        timeout_sec=60,
    )
    loop.state.update(
        {
            "review_verified": True,
            "review_wrote_docs": True,
            "review_wrapup_grace_used": False,
            "review_recent_tools": [
                {"name": "Write", "wrapup": True, "doc_write": True},
                {"name": "SetCveRecordField", "wrapup": True, "doc_write": True},
                {"name": "Read", "wrapup": True, "doc_write": False},
            ],
        }
    )
    loop._live = MagicMock()
    loop._live.system = MagicMock(
        side_effect=lambda *a, **k: logs.append(str(a[1] if len(a) > 1 else k.get("text", "")))
    )
    loop._live.error = MagicMock()
    loop._live.cmd = MagicMock()
    loop._live.tokens = MagicMock()
    loop._live.agent = MagicMock()
    loop._live.reasoning = MagicMock()
    loop._slot_handle = SlotHandle(endpoint_id="test", ticket=1)

    # t=1000, remaining=60 <= 120 → grant +100 → deadline=1160, continue
    # chat #1 advances t to 1159; text nudge; continue with remaining=1
    # chat #2 advances t to 1161 → remaining < 0 → timeout (grace already used)
    result = loop._run_loop_inner()

    assert result.timed_out is True
    assert result.stop_reason == "timeout"
    assert loop.state.get("review_wrapup_grace_used") is True
    assert any("审核收尾宽限" in t for t in logs)
    assert chats["n"] >= 1
    assert sum(1 for t in logs if "审核收尾宽限" in t) == 1


def test_reviewer_loop_no_grace_without_wrapup(tmp_env, project, monkeypatch):
    monkeypatch.setattr(settings, "timeout_reviewer_wrapup_grace", 500)
    clock = {"t": 1000.0}

    def fake_time() -> float:
        return clock["t"]

    def fake_chat(self, messages, tools, remaining):  # noqa: ANN001
        clock["t"] = 1100.0  # past base deadline 1060
        return (
            {"choices": [{"message": {"role": "assistant", "content": "thinking"}}]},
            _usage(),
            None,
        )

    monkeypatch.setattr(time, "time", fake_time)
    monkeypatch.setattr(AgentLoop, "_chat", fake_chat)
    monkeypatch.setattr(AgentLoop, "_rescue_conclude", lambda self, messages: None)
    monkeypatch.setattr(AgentLoop, "_persist", lambda self, messages, status="running": None)
    monkeypatch.setattr(AgentLoop, "_enforce_token_budget", lambda self: False)

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
    note_tool_for_wrapup(
        loop.state,
        name="Grep",
        arguments={"pattern": "x"},
        result={"ok": True, "hits": []},
        vuln_id=None,
    )
    loop._live = MagicMock()
    loop._live.system = MagicMock()
    loop._live.error = MagicMock()
    loop._live.cmd = MagicMock()
    loop._live.tokens = MagicMock()
    loop._live.agent = MagicMock()
    loop._live.reasoning = MagicMock()
    loop._slot_handle = SlotHandle(endpoint_id="test", ticket=1)

    # remaining=60 <= 120 but not wrapup → no grace; after chat, t=1100 → timeout
    result = loop._run_loop_inner()
    assert result.timed_out is True
    assert loop.state.get("review_wrapup_grace_used") is not True


def test_note_tool_ignores_failed_grep_and_todowrite():
    state: dict = {}
    note_tool_for_wrapup(
        state,
        name="TodoWrite",
        arguments={"todos": [{"id": "1", "content": "x", "status": "pending"}]},
        result={"ok": True},
        vuln_id=1,
    )
    note_tool_for_wrapup(
        state,
        name="Grep",
        arguments={"pattern": "x"},
        result={"ok": False, "error": "bad"},
        vuln_id=1,
    )
    assert state.get("review_recent_tools") == []

"""Integration tests for Python Debug MCP.

Run: pytest tests/test_integration.py -v
"""

from __future__ import annotations

import asyncio
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from debug_session import DebugSessionManager, SessionState

TARGET_SCRIPT = os.path.join(os.path.dirname(__file__), "test_target.py")


@pytest.fixture
async def session():
    """Launch test_target.py under debugpy via adapter, stopped at entry."""
    mgr = DebugSessionManager()
    await mgr.launch(TARGET_SCRIPT, stop_on_entry=True)
    yield mgr
    if mgr.state != SessionState.DISCONNECTED:
        await mgr.detach()


class TestLaunchDetach:
    async def test_launch_and_status(self, session: DebugSessionManager):
        assert session.state == SessionState.SUSPENDED
        status = await session.status()
        assert status["state"] == "suspended"

    async def test_detach(self, session: DebugSessionManager):
        result = await session.detach()
        assert result["status"] == "detached"
        assert session.state == SessionState.DISCONNECTED


class TestBreakpoints:
    async def test_set_and_list_breakpoint(self, session: DebugSessionManager):
        bp = await session.set_breakpoint(TARGET_SCRIPT, 7)
        assert bp["id"] == "bp-1"
        assert bp["line"] == 7

        bps = await session.list_breakpoints()
        assert len(bps) == 1
        assert bps[0]["id"] == "bp-1"

    async def test_remove_breakpoint(self, session: DebugSessionManager):
        bp = await session.set_breakpoint(TARGET_SCRIPT, 7)
        result = await session.remove_breakpoint(bp["id"])
        assert result["removed"] == bp["id"]

        bps = await session.list_breakpoints()
        assert len(bps) == 0

    async def test_conditional_breakpoint(self, session: DebugSessionManager):
        bp = await session.set_breakpoint(TARGET_SCRIPT, 14, condition="i == 5")
        assert bp["condition"] == "i == 5"

    async def test_multiple_breakpoints_same_file(self, session: DebugSessionManager):
        bp1 = await session.set_breakpoint(TARGET_SCRIPT, 7)
        bp2 = await session.set_breakpoint(TARGET_SCRIPT, 14)
        bps = await session.list_breakpoints()
        assert len(bps) == 2

        await session.remove_breakpoint(bp1["id"])
        bps = await session.list_breakpoints()
        assert len(bps) == 1
        assert bps[0]["id"] == bp2["id"]


class TestExecutionControl:
    async def test_set_breakpoint_and_continue_to_hit(self, session: DebugSessionManager):
        await session.set_breakpoint(TARGET_SCRIPT, 7)
        result = await session.continue_execution(wait_timeout=10.0)
        assert session.state == SessionState.SUSPENDED
        assert result.get("reason") == "breakpoint"

    async def test_step_over(self, session: DebugSessionManager):
        await session.set_breakpoint(TARGET_SCRIPT, 7)
        await session.continue_execution(wait_timeout=10.0)
        assert session.state == SessionState.SUSPENDED

        result = await session.step("over", wait_timeout=10.0)
        assert session.state == SessionState.SUSPENDED
        assert result.get("reason") == "step"

    async def test_step_into(self, session: DebugSessionManager):
        await session.set_breakpoint(TARGET_SCRIPT, 41)
        await session.continue_execution(wait_timeout=10.0)

        result = await session.step("into", wait_timeout=10.0)
        assert session.state == SessionState.SUSPENDED

    async def test_step_out(self, session: DebugSessionManager):
        await session.set_breakpoint(TARGET_SCRIPT, 7)
        await session.continue_execution(wait_timeout=10.0)

        result = await session.step("out", wait_timeout=10.0)
        assert session.state == SessionState.SUSPENDED

    async def test_continue_to_end(self, session: DebugSessionManager):
        # Program is stopped on entry, continue without breakpoints should run to end
        result = await session.continue_execution(wait_timeout=10.0)
        assert result.get("status") in ("terminated", "exited") or result.get("waitTimedOut")


class TestInspection:
    async def _suspend_at_line_7(self, session: DebugSessionManager):
        await session.set_breakpoint(TARGET_SCRIPT, 7)
        await session.continue_execution(wait_timeout=10.0)
        assert session.state == SessionState.SUSPENDED

    async def test_list_threads(self, session: DebugSessionManager):
        await self._suspend_at_line_7(session)
        threads = await session.list_threads()
        assert len(threads) >= 1
        assert any(t["isCurrent"] for t in threads)

    async def test_get_stack_trace(self, session: DebugSessionManager):
        await self._suspend_at_line_7(session)
        frames = await session.get_stack_trace()
        assert len(frames) >= 1
        top_frame = frames[0]
        assert "greet" in top_frame["name"]
        assert top_frame["line"] == 7

    async def test_get_locals(self, session: DebugSessionManager):
        await self._suspend_at_line_7(session)
        locals_result = await session.get_locals(frame_index=0)
        assert "scopes" in locals_result
        local_scope = locals_result["scopes"].get("Locals", [])
        var_names = [v["name"] for v in local_scope]
        assert "name" in var_names

    async def test_evaluate_expression(self, session: DebugSessionManager):
        await self._suspend_at_line_7(session)
        result = await session.evaluate_expression("name.upper()")
        assert result["result"] == "'WORLD'"

    async def test_evaluate_complex_expression(self, session: DebugSessionManager):
        await self._suspend_at_line_7(session)
        result = await session.evaluate_expression("len(name)")
        assert "5" in result["result"]

    async def test_inspect_variable(self, session: DebugSessionManager):
        await session.set_breakpoint(TARGET_SCRIPT, 21)
        await session.continue_execution(wait_timeout=10.0)

        locals_result = await session.get_locals(frame_index=0)
        local_scope = locals_result["scopes"].get("Locals", [])

        items_var = next((v for v in local_scope if v["name"] == "items"), None)
        if items_var and items_var.get("variablesReference"):
            children = await session.inspect_variable(items_var["variablesReference"])
            assert len(children) >= 1


class TestEvents:
    async def test_events_recorded(self, session: DebugSessionManager):
        events = session.get_events()
        assert len(events) >= 1
        event_types = [e["type"] for e in events]
        assert "launched" in event_types

    async def test_stop_event_recorded(self, session: DebugSessionManager):
        await session.set_breakpoint(TARGET_SCRIPT, 7)
        await session.continue_execution(wait_timeout=10.0)

        stop = session.get_last_stop_event()
        assert stop is not None
        assert stop["reason"] == "breakpoint"

    async def test_events_since_id(self, session: DebugSessionManager):
        events = session.get_events()
        last_id = events[-1]["id"]

        await session.set_breakpoint(TARGET_SCRIPT, 7)
        new_events = session.get_events(since_id=last_id)
        assert len(new_events) >= 1
        assert all(e["id"] > last_id for e in new_events)


class TestStandaloneLaunch:
    async def test_launch_and_full_debug_cycle(self):
        mgr = DebugSessionManager()
        try:
            result = await mgr.launch(TARGET_SCRIPT, stop_on_entry=True)
            assert result["status"] == "launched"
            assert mgr.state == SessionState.SUSPENDED

            await mgr.set_breakpoint(TARGET_SCRIPT, 7)
            stop = await mgr.continue_execution(wait_timeout=10.0)
            assert mgr.state == SessionState.SUSPENDED
            assert stop.get("reason") == "breakpoint"

            frames = await mgr.get_stack_trace()
            assert len(frames) >= 1
            assert "greet" in frames[0]["name"]

            locals_result = await mgr.get_locals(frame_index=0)
            assert "scopes" in locals_result

            eval_result = await mgr.evaluate_expression("name + '!'")
            assert "World!" in eval_result["result"]
        finally:
            await mgr.detach()


class TestErrorHandling:
    async def test_step_without_suspend_raises(self, session: DebugSessionManager):
        # Session starts suspended (stopOnEntry), continue first to get it running
        # then it should not be steppable (either it hits end or runs)
        await session.continue_execution(wait_timeout=10.0)
        # After running to end, state should be terminated, not suspended
        if session.state != SessionState.SUSPENDED:
            with pytest.raises(RuntimeError, match="not suspended"):
                await session.step("over")

    async def test_get_locals_without_suspend_raises(self):
        mgr = DebugSessionManager()
        try:
            await mgr.launch(TARGET_SCRIPT, stop_on_entry=False)
            # Wait for program to finish
            await asyncio.sleep(2)
            if mgr.state != SessionState.SUSPENDED:
                with pytest.raises(RuntimeError, match="not suspended"):
                    await mgr.get_locals()
        finally:
            if mgr.state != SessionState.DISCONNECTED:
                await mgr.detach()

    async def test_invalid_step_kind_raises(self, session: DebugSessionManager):
        await session.set_breakpoint(TARGET_SCRIPT, 7)
        await session.continue_execution(wait_timeout=10.0)
        with pytest.raises(ValueError, match="Invalid step kind"):
            await session.step("invalid")

    async def test_remove_nonexistent_breakpoint_raises(self, session: DebugSessionManager):
        with pytest.raises(ValueError, match="not found"):
            await session.remove_breakpoint("bp-999")

    async def test_double_launch_raises(self, session: DebugSessionManager):
        with pytest.raises(RuntimeError, match="already in state"):
            await session.launch("nonexistent.py")


class TestFunctionBreakpoints:
    async def test_set_function_breakpoint(self, session: DebugSessionManager):
        fbp = await session.set_function_breakpoint("greet")
        assert fbp["id"] == "fbp-1"
        assert fbp["functionName"] == "greet"
        assert fbp["verified"] is True

    async def test_function_breakpoint_hit(self, session: DebugSessionManager):
        await session.set_function_breakpoint("greet")
        result = await session.continue_execution(wait_timeout=10.0)
        assert result.get("reason") in ("breakpoint", "function breakpoint")
        assert session.state == SessionState.SUSPENDED
        frames = await session.get_stack_trace()
        assert "greet" in frames[0]["name"]

    async def test_list_includes_function_breakpoints(self, session: DebugSessionManager):
        await session.set_breakpoint(TARGET_SCRIPT, 7)
        await session.set_function_breakpoint("compute_sum")
        bps = await session.list_breakpoints()
        assert len(bps) == 2
        ids = [b["id"] for b in bps]
        assert "bp-1" in ids
        assert "fbp-1" in ids

    async def test_remove_function_breakpoint(self, session: DebugSessionManager):
        fbp = await session.set_function_breakpoint("greet")
        await session.remove_breakpoint(fbp["id"])
        bps = await session.list_breakpoints()
        assert len(bps) == 0


class TestDeferredBreakpoints:
    async def test_deferred_line_breakpoint(self):
        mgr = DebugSessionManager()
        try:
            bp = await mgr.set_breakpoint(TARGET_SCRIPT, 7)
            assert bp["verified"] is False

            await mgr.launch(TARGET_SCRIPT, stop_on_entry=True)
            assert mgr.state == SessionState.SUSPENDED

            result = await mgr.continue_execution(wait_timeout=10.0)
            assert result.get("reason") == "breakpoint"
            assert mgr.state == SessionState.SUSPENDED
        finally:
            if mgr.state != SessionState.DISCONNECTED:
                await mgr.detach()

    async def test_deferred_function_breakpoint(self):
        mgr = DebugSessionManager()
        try:
            fbp = await mgr.set_function_breakpoint("greet")
            assert fbp["verified"] is False

            await mgr.launch(TARGET_SCRIPT, stop_on_entry=True)
            assert mgr.state == SessionState.SUSPENDED

            result = await mgr.continue_execution(wait_timeout=10.0)
            assert result.get("reason") in ("breakpoint", "function breakpoint")
            frames = await mgr.get_stack_trace()
            assert "greet" in frames[0]["name"]
        finally:
            if mgr.state != SessionState.DISCONNECTED:
                await mgr.detach()


class TestExpressionCapture:
    async def _suspend_at_line_7(self, session: DebugSessionManager):
        await session.set_breakpoint(TARGET_SCRIPT, 7)
        await session.continue_execution(wait_timeout=10.0)
        assert session.state == SessionState.SUSPENDED

    async def test_capture_output_print(self, session: DebugSessionManager):
        await self._suspend_at_line_7(session)
        result = await session.evaluate_expression(
            "print('captured_text')", capture_output=True,
        )
        assert "captured_text" in result["result"]

    async def test_capture_output_returns_value_when_not_none(self, session: DebugSessionManager):
        await self._suspend_at_line_7(session)
        result = await session.evaluate_expression(
            "name.upper()", capture_output=True,
        )
        assert "WORLD" in result["result"]


class TestSetVariable:
    async def test_set_variable_value(self, session: DebugSessionManager):
        await session.set_breakpoint(TARGET_SCRIPT, 7)
        await session.continue_execution(wait_timeout=10.0)

        result = await session.set_variable("name", "'Changed'")
        assert "Changed" in result["result"]

        eval_result = await session.evaluate_expression("name")
        assert "Changed" in eval_result["result"]


class TestModules:
    async def test_list_modules(self, session: DebugSessionManager):
        await session.set_breakpoint(TARGET_SCRIPT, 7)
        await session.continue_execution(wait_timeout=10.0)

        modules = await session.list_modules()
        assert isinstance(modules, list)
        assert len(modules) >= 1
        module_names = [m["name"] for m in modules]
        assert any("test_target" in name or "__main__" in name for name in module_names)


class TestWatchSinks:
    async def test_watch_specific_category(self, session: DebugSessionManager):
        result = await session.watch_sinks(categories=["code_execution"])
        assert result["sinksWatched"] > 0
        assert "code_execution" in result["categories"]

        bps = await session.list_breakpoints()
        fbp_ids = [b["id"] for b in bps if b["id"].startswith("fbp-")]
        assert len(fbp_ids) > 0

    async def test_watch_custom_sinks(self, session: DebugSessionManager):
        result = await session.watch_sinks(
            categories=[], custom_sinks=["greet"],
        )
        assert result["sinksWatched"] == 1

    async def test_watch_sinks_invalid_category(self, session: DebugSessionManager):
        with pytest.raises(ValueError, match="Unknown sink category"):
            await session.watch_sinks(categories=["nonexistent"])

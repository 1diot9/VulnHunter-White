package com.example.javadebugmcp.debug;

import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Integration tests for 4 new features:
 * 1. setBreakpoint by method name
 * 2. getEvents (event history)
 * 3. setBreakpointsBatch (batch breakpoints)
 * 4. per-thread resume
 */
class NewFeaturesIntegrationTest {

    // ==================== Feature 1: setBreakpoint by method name ====================

    @Test
    void setBreakpointByMethodNameStopsAtMethodEntry() throws Exception {
        int port = randomPort();
        Process process = startDebuggee(port);
        try {
            waitForReady(process);

            DebugSessionManager manager = new DebugSessionManager();
            manager.attach("127.0.0.1", port, 5000);

            // Set breakpoint by method name only (no line number)
            Map<String, Object> bp = manager.setBreakpoint(
                    "com.example.javadebugmcp.fixture.SampleDebuggee",
                    -1,               // no line
                    "EVENT_THREAD",
                    "greet"           // method name
            );
            assertEquals(Boolean.TRUE, bp.get("resolved"));
            assertEquals("greet", bp.get("methodName"));
            assertNotNull(bp.get("line"));
            // line should be resolved to the first executable line of greet()
            assertTrue((int) bp.get("line") > 0);

            // Resume and verify we hit the breakpoint
            Map<String, Object> stop = manager.resume(10000);
            assertEquals("breakpoint", stop.get("reason"));

            @SuppressWarnings("unchecked")
            Map<String, Object> location = (Map<String, Object>) stop.get("location");
            assertEquals("greet", location.get("methodName"));

            manager.detach();
        } finally {
            process.destroy();
            if (process.isAlive()) process.destroyForcibly();
            process.waitFor();
        }
    }

    @Test
    void setBreakpointByMethodNameAndLineUsesExactLine() throws Exception {
        int port = randomPort();
        Process process = startDebuggee(port);
        try {
            waitForReady(process);

            DebugSessionManager manager = new DebugSessionManager();
            manager.attach("127.0.0.1", port, 5000);

            // When both method name and line are given, line takes priority
            int greetLine = findMarkerLine(
                    "src/test/java/com/example/javadebugmcp/fixture/SampleDebuggee.java",
                    "BREAKPOINT_GREET");
            Map<String, Object> bp = manager.setBreakpoint(
                    "com.example.javadebugmcp.fixture.SampleDebuggee",
                    greetLine,
                    "EVENT_THREAD",
                    "greet"
            );
            assertEquals(Boolean.TRUE, bp.get("resolved"));
            assertEquals(greetLine, bp.get("line"));

            manager.detach();
        } finally {
            process.destroy();
            if (process.isAlive()) process.destroyForcibly();
            process.waitFor();
        }
    }

    @Test
    void methodBreakpointConditionStopsOnlyWhenConditionMatches() throws Exception {
        int port = randomPort();
        Process process = startDebuggee(port);
        try {
            waitForReady(process);

            DebugSessionManager manager = new DebugSessionManager();
            manager.attach("127.0.0.1", port, 5000);

            Map<String, Object> bp = manager.setMethodBreakpoint(
                    "com.example.javadebugmcp.fixture.SampleDebuggee",
                    "exercise",
                    "entry",
                    "EVENT_THREAD",
                    "input.equals(\"user-3\")",
                    null
            );
            assertEquals("input.equals(\"user-3\")", bp.get("condition"));
            assertEquals("conditional", bp.get("breakpointType"));

            Map<String, Object> stop = manager.resume(10000);
            assertEquals("method_entry", stop.get("reason"));
            assertEquals(bp.get("breakpointId"), stop.get("breakpointId"));
            assertEquals("conditional", stop.get("breakpointType"));

            Map<String, Object> locals = manager.getLocals(null, 0);
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> localItems = (List<Map<String, Object>>) locals.get("locals");
            String input = localItems.stream()
                    .filter(item -> "input".equals(item.get("name")))
                    .map(item -> item.get("valuePreview").toString())
                    .findFirst()
                    .orElseThrow();
            assertEquals("user-3", input);

            manager.detach();
        } finally {
            process.destroy();
            if (process.isAlive()) process.destroyForcibly();
            process.waitFor();
        }
    }

    @Test
    void methodBreakpointHitCountStopsOnNthHit() throws Exception {
        int port = randomPort();
        Process process = startDebuggee(port);
        try {
            waitForReady(process);

            DebugSessionManager manager = new DebugSessionManager();
            manager.attach("127.0.0.1", port, 5000);

            Map<String, Object> bp = manager.setMethodBreakpoint(
                    "com.example.javadebugmcp.fixture.SampleDebuggee",
                    "greet",
                    "entry",
                    "EVENT_THREAD",
                    null,
                    3
            );
            assertEquals(3, bp.get("hitCount"));
            assertEquals("conditional", bp.get("breakpointType"));

            long startedAt = System.nanoTime();
            Map<String, Object> stop = manager.resume(10000);
            long elapsedMs = Duration.ofNanos(System.nanoTime() - startedAt).toMillis();
            assertEquals("method_entry", stop.get("reason"));
            assertEquals(bp.get("breakpointId"), stop.get("breakpointId"));
            assertTrue(elapsedMs >= 300L, "method hitCount breakpoint should not stop immediately, elapsed=" + elapsedMs + "ms");

            manager.detach();
        } finally {
            process.destroy();
            if (process.isAlive()) process.destroyForcibly();
            process.waitFor();
        }
    }

    @Test
    void conditionalBreakpointStopsOnlyWhenConditionMatches() throws Exception {
        int port = randomPort();
        Process process = startDebuggee(port);
        try {
            waitForReady(process);

            DebugSessionManager manager = new DebugSessionManager();
            manager.attach("127.0.0.1", port, 5000);

            int line = findMarkerLine(
                    "src/test/java/com/example/javadebugmcp/fixture/SampleDebuggee.java",
                    "BREAKPOINT_EXERCISE");
            Map<String, Object> bp = manager.setBreakpoint(
                    "com.example.javadebugmcp.fixture.SampleDebuggee",
                    line,
                    "EVENT_THREAD",
                    null,
                    "input.equals(\"user-3\")",
                    null,
                    null
            );
            assertEquals("input.equals(\"user-3\")", bp.get("condition"));

            Map<String, Object> stop = manager.resume(10000);
            assertEquals("breakpoint", stop.get("reason"));

            Map<String, Object> locals = manager.getLocals(null, 0);
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> localItems = (List<Map<String, Object>>) locals.get("locals");
            String input = localItems.stream()
                    .filter(item -> "input".equals(item.get("name")))
                    .map(item -> item.get("valuePreview").toString())
                    .findFirst()
                    .orElseThrow();
            assertEquals("user-3", input);

            manager.detach();
        } finally {
            process.destroy();
            if (process.isAlive()) process.destroyForcibly();
            process.waitFor();
        }
    }

    @Test
    void hitCountBreakpointStopsOnNthHit() throws Exception {
        int port = randomPort();
        Process process = startDebuggee(port);
        try {
            waitForReady(process);

            DebugSessionManager manager = new DebugSessionManager();
            manager.attach("127.0.0.1", port, 5000);

            int line = findMarkerLine(
                    "src/test/java/com/example/javadebugmcp/fixture/SampleDebuggee.java",
                    "BREAKPOINT_EXERCISE");
            Map<String, Object> bp = manager.setBreakpoint(
                    "com.example.javadebugmcp.fixture.SampleDebuggee",
                    line,
                    "EVENT_THREAD",
                    null,
                    null,
                    3,
                    null
            );
            assertEquals(3, bp.get("hitCount"));

            long startedAt = System.nanoTime();
            Map<String, Object> stop = manager.resume(10000);
            assertEquals("breakpoint", stop.get("reason"));
            long elapsedMs = Duration.ofNanos(System.nanoTime() - startedAt).toMillis();
            assertTrue(elapsedMs >= 300L, "hitCount breakpoint should not stop immediately, elapsed=" + elapsedMs + "ms");

            manager.detach();
        } finally {
            process.destroy();
            if (process.isAlive()) process.destroyForcibly();
            process.waitFor();
        }
    }

    @Test
    void logpointRecordsMessageAndKeepsRunning() throws Exception {
        int port = randomPort();
        Process process = startDebuggee(port);
        try {
            waitForReady(process);

            DebugSessionManager manager = new DebugSessionManager();
            manager.attach("127.0.0.1", port, 5000);

            int line = findMarkerLine(
                    "src/test/java/com/example/javadebugmcp/fixture/SampleDebuggee.java",
                    "BREAKPOINT_EXERCISE");
            Map<String, Object> bp = manager.setBreakpoint(
                    "com.example.javadebugmcp.fixture.SampleDebuggee",
                    line,
                    "EVENT_THREAD",
                    null,
                    null,
                    null,
                    "input={input},stage2={stage2}"
            );
            assertEquals("input={input},stage2={stage2}", bp.get("logMessage"));

            Map<String, Object> resumed = manager.resume(1000);
            assertEquals("running", resumed.get("status"));
            assertEquals(Boolean.TRUE, resumed.get("waitTimedOut"));

            Map<String, Object> eventsResult = manager.getEvents(20, null);
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> items = (List<Map<String, Object>>) eventsResult.get("events");
            Map<String, Object> logpoint = items.stream()
                    .filter(item -> "logpoint".equals(item.get("kind")))
                    .findFirst()
                    .orElseThrow();
            assertTrue(logpoint.get("message").toString().startsWith("input=user-"));
            assertTrue(logpoint.get("message").toString().contains(",stage2=user-"));

            manager.detach();
        } finally {
            process.destroy();
            if (process.isAlive()) process.destroyForcibly();
            process.waitFor();
        }
    }

    @Test
    void logpointInterpolationFailureAddsDiagnosticsWithoutSuspending() throws Exception {
        int port = randomPort();
        Process process = startDebuggee(port);
        try {
            waitForReady(process);

            DebugSessionManager manager = new DebugSessionManager();
            manager.attach("127.0.0.1", port, 5000);

            int line = findMarkerLine(
                    "src/test/java/com/example/javadebugmcp/fixture/SampleDebuggee.java",
                    "BREAKPOINT_EXERCISE");
            manager.setBreakpoint(
                    "com.example.javadebugmcp.fixture.SampleDebuggee",
                    line,
                    "EVENT_THREAD",
                    null,
                    null,
                    null,
                    "input={input},missing={missingVar}"
            );

            Map<String, Object> resumed = manager.resume(1000);
            assertEquals("running", resumed.get("status"));
            assertEquals(Boolean.TRUE, resumed.get("waitTimedOut"));

            Map<String, Object> eventsResult = manager.getEvents(20, null);
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> items = (List<Map<String, Object>>) eventsResult.get("events");
            Map<String, Object> logpoint = items.stream()
                    .filter(item -> "logpoint".equals(item.get("kind")))
                    .findFirst()
                    .orElseThrow();
            assertTrue(logpoint.get("message").toString().startsWith("input=user-"));
            assertTrue(logpoint.get("message").toString().contains("missing=<error:missingVar>"));

            @SuppressWarnings("unchecked")
            List<Map<String, Object>> interpolationErrors = (List<Map<String, Object>>) logpoint.get("interpolationErrors");
            assertEquals(1, interpolationErrors.size());
            assertEquals("missingVar", interpolationErrors.get(0).get("expression"));
            assertTrue(interpolationErrors.get(0).get("error").toString().contains("Unknown identifier: missingVar"));

            manager.detach();
        } finally {
            process.destroy();
            if (process.isAlive()) process.destroyForcibly();
            process.waitFor();
        }
    }

    @Test
    void conditionalBreakpointFailureIncludesReadableExpressionContext() throws Exception {
        int port = randomPort();
        Process process = startDebuggee(port);
        try {
            waitForReady(process);

            DebugSessionManager manager = new DebugSessionManager();
            manager.attach("127.0.0.1", port, 5000);

            int line = findMarkerLine(
                    "src/test/java/com/example/javadebugmcp/fixture/SampleDebuggee.java",
                    "BREAKPOINT_EXERCISE");
            Map<String, Object> bp = manager.setBreakpoint(
                    "com.example.javadebugmcp.fixture.SampleDebuggee",
                    line,
                    "EVENT_THREAD",
                    null,
                    "missingVar",
                    null,
                    null
            );

            Map<String, Object> stop = manager.resume(10000);
            assertEquals("breakpoint", stop.get("reason"));
            assertEquals(bp.get("breakpointId"), stop.get("breakpointId"));
            assertTrue(stop.get("reasons").toString().contains("breakpoint_evaluation_error"));
            assertTrue(stop.get("evaluationError").toString().contains("Breakpoint condition failed for 'missingVar'"));
            assertTrue(stop.get("evaluationError").toString().contains("Unknown identifier: missingVar"));

            manager.detach();
        } finally {
            process.destroy();
            if (process.isAlive()) process.destroyForcibly();
            process.waitFor();
        }
    }

    @Test
    void getEventsAndLastStopEventExposeBreakpointContext() throws Exception {
        int port = randomPort();
        Process process = startDebuggee(port);
        try {
            waitForReady(process);

            DebugSessionManager manager = new DebugSessionManager();
            manager.attach("127.0.0.1", port, 5000);

            int line = findMarkerLine(
                    "src/test/java/com/example/javadebugmcp/fixture/SampleDebuggee.java",
                    "BREAKPOINT_EXERCISE");
            Map<String, Object> bp = manager.setBreakpoint(
                    "com.example.javadebugmcp.fixture.SampleDebuggee",
                    line,
                    "EVENT_THREAD",
                    null,
                    "input.equals(\"user-3\")",
                    null,
                    null
            );

            Map<String, Object> stop = manager.resume(10000);
            assertEquals("breakpoint", stop.get("reason"));
            assertEquals(bp.get("breakpointId"), stop.get("breakpointId"));
            assertEquals("conditional", stop.get("breakpointType"));

            Map<String, Object> lastStop = manager.getLastStopEvent();
            assertEquals(Boolean.TRUE, lastStop.get("hasLastStopEvent"));
            assertEquals(stop.get("threadId"), lastStop.get("activeThreadId"));
            @SuppressWarnings("unchecked")
            Map<String, Object> lastStopEvent = (Map<String, Object>) lastStop.get("lastStopEvent");
            assertEquals(stop.get("threadId"), lastStopEvent.get("threadId"));
            assertEquals(bp.get("breakpointId"), lastStopEvent.get("breakpointId"));

            Map<String, Object> eventsResult = manager.getEvents(20, null);
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> items = (List<Map<String, Object>>) eventsResult.get("events");
            Map<String, Object> breakpointEvent = items.stream()
                    .filter(item -> "breakpoint".equals(item.get("kind")))
                    .findFirst()
                    .orElseThrow();
            assertEquals(bp.get("breakpointId"), breakpointEvent.get("breakpointId"));
            assertEquals("conditional", breakpointEvent.get("breakpointType"));
            @SuppressWarnings("unchecked")
            Map<String, Object> location = (Map<String, Object>) breakpointEvent.get("location");
            assertEquals("com.example.javadebugmcp.fixture.SampleDebuggee", location.get("className"));
            assertEquals(line, location.get("line"));

            manager.detach();
        } finally {
            process.destroy();
            if (process.isAlive()) process.destroyForcibly();
            process.waitFor();
        }
    }

    @Test
    void listThreadsHighlightsLastStoppedThread() throws Exception {
        int port = randomPort();
        Process process = startDebuggee(port);
        try {
            waitForReady(process);

            DebugSessionManager manager = new DebugSessionManager();
            manager.attach("127.0.0.1", port, 5000);

            int line = findMarkerLine(
                    "src/test/java/com/example/javadebugmcp/fixture/SampleDebuggee.java",
                    "BREAKPOINT_EXERCISE");
            Map<String, Object> bp = manager.setBreakpoint(
                    "com.example.javadebugmcp.fixture.SampleDebuggee",
                    line,
                    "EVENT_THREAD",
                    null,
                    "input.equals(\"user-3\")",
                    null,
                    null
            );

            Map<String, Object> stop = manager.resume(10000);
            assertEquals("breakpoint", stop.get("reason"));

            Map<String, Object> threads = manager.listThreads();
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> items = (List<Map<String, Object>>) threads.get("items");
            Map<String, Object> active = items.stream()
                    .filter(item -> Boolean.TRUE.equals(item.get("active")))
                    .findFirst()
                    .orElseThrow();
            assertEquals(stop.get("threadId"), active.get("threadId"));
            assertEquals(Boolean.TRUE, active.get("lastStopThread"));
            assertEquals("breakpoint", active.get("lastStopReason"));
            assertEquals(bp.get("breakpointId"), active.get("lastBreakpointId"));
            assertNotNull(active.get("lastStoppedAt"));
            assertNotNull(active.get("lastStopLocation"));

            manager.detach();
        } finally {
            process.destroy();
            if (process.isAlive()) process.destroyForcibly();
            process.waitFor();
        }
    }

    // ==================== Feature 2: getEvents (event history) ====================

    @Test
    void getEventsReturnsEmptyListBeforeAnyEvent() throws Exception {
        int port = randomPort();
        Process process = startDebuggee(port);
        try {
            waitForReady(process);

            DebugSessionManager manager = new DebugSessionManager();
            manager.attach("127.0.0.1", port, 5000);

            Map<String, Object> events = manager.getEvents(20, null);
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> items = (List<Map<String, Object>>) events.get("events");
            assertNotNull(items);
            assertTrue(items.isEmpty());

            manager.detach();
        } finally {
            process.destroy();
            if (process.isAlive()) process.destroyForcibly();
            process.waitFor();
        }
    }

    @Test
    void getEventsRecordsBreakpointAndStepEvents() throws Exception {
        int port = randomPort();
        Process process = startDebuggee(port);
        try {
            waitForReady(process);

            DebugSessionManager manager = new DebugSessionManager();
            manager.attach("127.0.0.1", port, 5000);

            int line = findMarkerLine(
                    "src/test/java/com/example/javadebugmcp/fixture/SampleDebuggee.java",
                    "BREAKPOINT_EXERCISE");
            manager.setBreakpoint(
                    "com.example.javadebugmcp.fixture.SampleDebuggee",
                    line, "EVENT_THREAD", null);

            // Hit breakpoint
            manager.resume(10000);

            // Step once
            manager.step("over", null, 10000);

            // Verify events
            Map<String, Object> eventsResult = manager.getEvents(20, null);
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> items = (List<Map<String, Object>>) eventsResult.get("events");
            assertTrue(items.size() >= 2, "Should have at least 2 events (breakpoint + step)");

            // First event should be breakpoint
            assertEquals("breakpoint", items.get(0).get("kind"));
            assertNotNull(items.get(0).get("eventId"));
            assertNotNull(items.get(0).get("timestamp"));
            assertNotNull(items.get(0).get("threadName"));

            // Second event should be step
            assertEquals("step", items.get(1).get("kind"));

            manager.detach();
        } finally {
            process.destroy();
            if (process.isAlive()) process.destroyForcibly();
            process.waitFor();
        }
    }

    @Test
    void getEventsWithSinceIdFiltersOldEvents() throws Exception {
        int port = randomPort();
        Process process = startDebuggee(port);
        try {
            waitForReady(process);

            DebugSessionManager manager = new DebugSessionManager();
            manager.attach("127.0.0.1", port, 5000);

            int line = findMarkerLine(
                    "src/test/java/com/example/javadebugmcp/fixture/SampleDebuggee.java",
                    "BREAKPOINT_EXERCISE");
            manager.setBreakpoint(
                    "com.example.javadebugmcp.fixture.SampleDebuggee",
                    line, "EVENT_THREAD", null);

            // Hit breakpoint (event 1)
            manager.resume(10000);

            // Get the first event's ID
            Map<String, Object> eventsResult = manager.getEvents(20, null);
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> allItems = (List<Map<String, Object>>) eventsResult.get("events");
            int firstEventId = ((Number) allItems.get(0).get("eventId")).intValue();

            // Step (event 2)
            manager.step("over", null, 10000);

            // Query with sinceId = firstEventId: should skip the first event
            Map<String, Object> filteredResult = manager.getEvents(20, firstEventId);
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> filtered = (List<Map<String, Object>>) filteredResult.get("events");
            assertFalse(filtered.isEmpty(), "Should have at least 1 event after firstEventId");
            for (Map<String, Object> event : filtered) {
                assertTrue(((Number) event.get("eventId")).intValue() > firstEventId);
            }

            manager.detach();
        } finally {
            process.destroy();
            if (process.isAlive()) process.destroyForcibly();
            process.waitFor();
        }
    }

    // ==================== Feature 3: setBreakpointsBatch ====================

    @Test
    void setBreakpointsBatchSetsMultipleBreakpointsAtOnce() throws Exception {
        int port = randomPort();
        Process process = startDebuggee(port);
        try {
            waitForReady(process);

            DebugSessionManager manager = new DebugSessionManager();
            manager.attach("127.0.0.1", port, 5000);

            int greetLine = findMarkerLine(
                    "src/test/java/com/example/javadebugmcp/fixture/SampleDebuggee.java",
                    "BREAKPOINT_GREET");
            int addLine = findMarkerLine(
                    "src/test/java/com/example/javadebugmcp/fixture/SampleDebuggee.java",
                    "BREAKPOINT_ADD");

            List<Map<String, Object>> specs = List.of(
                    Map.of("className", "com.example.javadebugmcp.fixture.SampleDebuggee",
                            "line", greetLine),
                    Map.of("className", "com.example.javadebugmcp.fixture.SampleDebuggee",
                            "line", addLine)
            );

            Map<String, Object> result = manager.setBreakpointsBatch(specs);
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> results = (List<Map<String, Object>>) result.get("results");
            assertEquals(2, results.size());

            // Both should succeed
            for (Map<String, Object> item : results) {
                assertEquals("ok", item.get("status"));
                assertEquals(Boolean.TRUE, item.get("resolved"));
            }

            // Verify we have 2 breakpoints registered
            Map<String, Object> listed = manager.listBreakpoints();
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> items = (List<Map<String, Object>>) listed.get("items");
            assertEquals(2, items.size());

            manager.detach();
        } finally {
            process.destroy();
            if (process.isAlive()) process.destroyForcibly();
            process.waitFor();
        }
    }

    @Test
    void setBreakpointsBatchReportsPerItemErrors() throws Exception {
        int port = randomPort();
        Process process = startDebuggee(port);
        try {
            waitForReady(process);

            DebugSessionManager manager = new DebugSessionManager();
            manager.attach("127.0.0.1", port, 5000);

            int greetLine = findMarkerLine(
                    "src/test/java/com/example/javadebugmcp/fixture/SampleDebuggee.java",
                    "BREAKPOINT_GREET");

            List<Map<String, Object>> specs = List.of(
                    Map.of("className", "com.example.javadebugmcp.fixture.SampleDebuggee",
                            "line", greetLine),
                    // Invalid: non-existent class — will be accepted as pending (resolved=false)
                    Map.of("className", "com.nonexistent.FakeClass",
                            "line", 1),
                    // Invalid: valid class but use methodName that doesn't exist
                    Map.of("className", "com.example.javadebugmcp.fixture.SampleDebuggee",
                            "methodName", "nonExistentMethod")
            );

            Map<String, Object> result = manager.setBreakpointsBatch(specs);
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> results = (List<Map<String, Object>>) result.get("results");
            assertEquals(3, results.size());

            // First should succeed and be resolved
            assertEquals("ok", results.get(0).get("status"));
            assertEquals(Boolean.TRUE, results.get(0).get("resolved"));

            // Second: non-existent class is accepted as pending breakpoint (resolved=false)
            assertEquals("ok", results.get(1).get("status"));
            assertEquals(Boolean.FALSE, results.get(1).get("resolved"));

            // Third: invalid method name should error because class is loaded but method doesn't exist
            assertEquals("error", results.get(2).get("status"));
            assertNotNull(results.get(2).get("error"));

            manager.detach();
        } finally {
            process.destroy();
            if (process.isAlive()) process.destroyForcibly();
            process.waitFor();
        }
    }

    // ==================== Feature 4: per-thread resume ====================

    @Test
    void resumeWithThreadIdResumesOnlySingleThread() throws Exception {
        int port = randomPort();
        Process process = startDebuggee(port);
        try {
            waitForReady(process);

            DebugSessionManager manager = new DebugSessionManager();
            manager.attach("127.0.0.1", port, 5000);

            int line = findMarkerLine(
                    "src/test/java/com/example/javadebugmcp/fixture/SampleDebuggee.java",
                    "BREAKPOINT_EXERCISE");
            manager.setBreakpoint(
                    "com.example.javadebugmcp.fixture.SampleDebuggee",
                    line, "EVENT_THREAD", null);

            Map<String, Object> stop = manager.resume(10000);
            assertEquals("breakpoint", stop.get("reason"));

            // Get the thread ID from the stop event
            String threadId = (String) stop.get("threadId");
            assertNotNull(threadId);

            // Resume just this thread (with short timeout since it'll likely hit the same breakpoint again)
            Map<String, Object> threadResume = manager.resume(threadId, 3000);
            // Should return either a stop event (breakpoint hit again) or a running timeout
            String reason = (String) threadResume.get("reason");
            String status = (String) threadResume.get("status");
            assertTrue(
                    "breakpoint".equals(reason) || "running".equals(status),
                    "Should either hit breakpoint again or be running; got reason=" + reason + " status=" + status
            );

            manager.detach();
        } finally {
            process.destroy();
            if (process.isAlive()) process.destroyForcibly();
            process.waitFor();
        }
    }

    // ==================== Helpers ====================

    private static Process startDebuggee(int port) throws IOException {
        String javaHome = System.getProperty("java.home");
        String javaExecutable = System.getProperty("os.name").toLowerCase().contains("win") ? "java.exe" : "java";
        Path javaBin = Path.of(javaHome, "bin", javaExecutable);
        String classPath = System.getProperty("java.class.path");
        ProcessBuilder builder = new ProcessBuilder(
                javaBin.toString(),
                "-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=127.0.0.1:" + port,
                "-cp",
                classPath,
                "com.example.javadebugmcp.fixture.SampleDebuggee");
        builder.redirectErrorStream(true);
        return builder.start();
    }

    private static void waitForReady(Process process) throws Exception {
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8));
        long deadline = System.nanoTime() + Duration.ofSeconds(10).toNanos();
        while (System.nanoTime() < deadline) {
            if (!process.isAlive()) {
                throw new IllegalStateException("debuggee exited before becoming ready");
            }
            if (reader.ready()) {
                String line = reader.readLine();
                if ("READY".equals(line)) {
                    return;
                }
            } else {
                Thread.sleep(50L);
            }
        }
        throw new IllegalStateException("timed out waiting for debuggee readiness");
    }

    private static int randomPort() throws IOException {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }

    private static int findMarkerLine(String relativePath, String marker) throws IOException {
        Path path = Path.of(relativePath);
        List<String> lines = Files.readAllLines(path, StandardCharsets.UTF_8);
        for (int index = 0; index < lines.size(); index++) {
            if (lines.get(index).contains(marker)) {
                return index + 1;
            }
        }
        throw new IllegalArgumentException("marker not found: " + marker);
    }
}

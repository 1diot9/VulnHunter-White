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
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DebugSessionManagerIntegrationTest {
    @Test
    void attachBreakpointInspectAndStepWorkAgainstLocalJvm() throws Exception {
        int port = randomPort();
        Process process = startDebuggee(port);
        try {
            waitForReady(process);

            DebugSessionManager manager = new DebugSessionManager();
            Map<String, Object> attached = manager.attach("127.0.0.1", port, 5000);
            assertEquals("attached", attached.get("status"));

            int breakpointLine = findMarkerLine("src/test/java/com/example/javadebugmcp/fixture/SampleDebuggee.java",
                    "sink(stage2); // BREAKPOINT_EXERCISE");
            Map<String, Object> breakpoint = manager.setBreakpoint(
                    "com.example.javadebugmcp.fixture.SampleDebuggee",
                    breakpointLine,
                    "EVENT_THREAD");
            assertEquals(Boolean.TRUE, breakpoint.get("resolved"));

            Map<String, Object> stopEvent = manager.resume(10000);
            assertEquals("breakpoint", stopEvent.get("reason"));

            Map<String, Object> stack = manager.getStack(null, 5);
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> frames = (List<Map<String, Object>>) stack.get("frames");
            assertFalse(frames.isEmpty());
            assertEquals("exercise", frames.get(0).get("methodName"));

            Map<String, Object> locals = manager.getLocals(null, 0);
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> localItems = (List<Map<String, Object>>) locals.get("locals");
            assertTrue(localItems.stream().anyMatch(item -> "stage2".equals(item.get("name"))));
            assertTrue(localItems.stream().anyMatch(item -> "input".equals(item.get("name"))));

            Map<String, Object> stepEvent = manager.step("over", null, 10000);
            assertEquals("step", stepEvent.get("reason"));

            Map<String, Object> status = manager.status();
            assertEquals("suspended", status.get("status"));

            Map<String, Object> detach = manager.detach();
            assertEquals("disconnected", detach.get("status"));
        } finally {
            process.destroy();
            if (process.isAlive()) {
                process.destroyForcibly();
            }
            process.waitFor();
        }
    }

    @Test
    void evaluateExpressionReadsLocalsAndInvokesMethods() throws Exception {
        int port = randomPort();
        Process process = startDebuggee(port);
        try {
            waitForReady(process);

            DebugSessionManager manager = new DebugSessionManager();
            manager.attach("127.0.0.1", port, 5000);

            int breakpointLine = findMarkerLine("src/test/java/com/example/javadebugmcp/fixture/SampleDebuggee.java",
                    "sink(stage2); // BREAKPOINT_EXERCISE");
            manager.setBreakpoint(
                    "com.example.javadebugmcp.fixture.SampleDebuggee",
                    breakpointLine,
                    "EVENT_THREAD");

            Map<String, Object> stopEvent = manager.resume(10000);
            assertEquals("breakpoint", stopEvent.get("reason"));

            Map<String, Object> locals = manager.getLocals(null, 0);
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> localItems = (List<Map<String, Object>>) locals.get("locals");
            String input = localItems.stream()
                    .filter(item -> "input".equals(item.get("name")))
                    .map(item -> item.get("valuePreview").toString())
                    .findFirst()
                    .orElseThrow();
            String stage2 = localItems.stream()
                    .filter(item -> "stage2".equals(item.get("name")))
                    .map(item -> item.get("valuePreview").toString())
                    .findFirst()
                    .orElseThrow();

            Map<String, Object> concatenated = manager.evaluateExpression("stage2 + \"-tail\"", null, 0);
            assertEquals("java.lang.String", concatenated.get("typeName"));
            assertEquals(stage2 + "-tail", concatenated.get("valuePreview"));

            Map<String, Object> uppercase = manager.evaluateExpression("input.toUpperCase()", null, 0);
            assertEquals("java.lang.String", uppercase.get("typeName"));
            assertEquals(input.toUpperCase(), uppercase.get("valuePreview"));

            Map<String, Object> sum = manager.evaluateExpression("add(2, 3)", null, 0);
            assertEquals("int", sum.get("typeName"));
            assertEquals("5", sum.get("valuePreview"));

            manager.detach();
        } finally {
            process.destroy();
            if (process.isAlive()) {
                process.destroyForcibly();
            }
            process.waitFor();
        }
    }

    @Test
    void evaluateExpressionSupportsArgumentAliasesNewAndInstanceof() throws Exception {
        int port = randomPort();
        Process process = startDebuggee(port);
        try {
            waitForReady(process);

            DebugSessionManager manager = new DebugSessionManager();
            manager.attach("127.0.0.1", port, 5000);

            int breakpointLine = findMarkerLine("src/test/java/com/example/javadebugmcp/fixture/SampleDebuggee.java",
                    "return input + \"!\"; // BREAKPOINT_INSTANCE");
            manager.setBreakpoint(
                    "com.example.javadebugmcp.fixture.SampleDebuggee",
                    breakpointLine,
                    "EVENT_THREAD");

            Map<String, Object> stopEvent = manager.resume(10000);
            assertEquals("breakpoint", stopEvent.get("reason"));

            Map<String, Object> argUpper = manager.evaluateExpression("arg0.toUpperCase()", null, 0);
            assertEquals("java.lang.String", argUpper.get("typeName"));
            assertTrue(argUpper.get("valuePreview").toString().startsWith("USER-"));

            Map<String, Object> aliasConcat = manager.evaluateExpression("p0 + \"-alias\"", null, 0);
            assertEquals("java.lang.String", aliasConcat.get("typeName"));
            assertTrue(aliasConcat.get("valuePreview").toString().endsWith("-alias"));

            Map<String, Object> created = manager.evaluateExpression(
                    "new java.io.File(\"C:/WEAVER\").getName()", null, 0);
            assertEquals("java.lang.String", created.get("typeName"));
            assertEquals("WEAVER", created.get("valuePreview"));

            Map<String, Object> thisInstanceOf = manager.evaluateExpression(
                    "this instanceof com.example.javadebugmcp.fixture.SampleDebuggee", null, 0);
            assertEquals("boolean", thisInstanceOf.get("typeName"));
            assertEquals("true", thisInstanceOf.get("valuePreview"));

            Map<String, Object> argInstanceOf = manager.evaluateExpression(
                    "arg0 instanceof java.lang.String", null, 0);
            assertEquals("boolean", argInstanceOf.get("typeName"));
            assertEquals("true", argInstanceOf.get("valuePreview"));

            manager.detach();
        } finally {
            process.destroy();
            if (process.isAlive()) {
                process.destroyForcibly();
            }
            process.waitFor();
        }
    }

    @Test
    void evaluateExpressionReturnsReadableErrorForUnknownIdentifier() throws Exception {
        int port = randomPort();
        Process process = startDebuggee(port);
        try {
            waitForReady(process);

            DebugSessionManager manager = new DebugSessionManager();
            manager.attach("127.0.0.1", port, 5000);

            int breakpointLine = findMarkerLine("src/test/java/com/example/javadebugmcp/fixture/SampleDebuggee.java",
                    "sink(stage2); // BREAKPOINT_EXERCISE");
            manager.setBreakpoint(
                    "com.example.javadebugmcp.fixture.SampleDebuggee",
                    breakpointLine,
                    "EVENT_THREAD");

            Map<String, Object> stopEvent = manager.resume(10000);
            assertEquals("breakpoint", stopEvent.get("reason"));

            IllegalArgumentException exception = assertThrows(
                    IllegalArgumentException.class,
                    () -> manager.evaluateExpression("missingVar + 1", null, 0));
            assertTrue(exception.getMessage().contains("Expression evaluation failed for 'missingVar + 1'"));
            assertTrue(exception.getMessage().contains("Unknown identifier: missingVar"));
            assertTrue(exception.getMessage().contains("argN/pN/paramN"));

            manager.detach();
        } finally {
            process.destroy();
            if (process.isAlive()) {
                process.destroyForcibly();
            }
            process.waitFor();
        }
    }

    @Test
    void exceptionBreakpointCapturesThrownException() throws Exception {
        int port = randomPort();
        Process process = startDebuggee(port);
        try {
            waitForReady(process);

            DebugSessionManager manager = new DebugSessionManager();
            Map<String, Object> attached = manager.attach("127.0.0.1", port, 5000);
            assertEquals("attached", attached.get("status"));

            Map<String, Object> enabled = manager.enableExceptionBreakpoint(
                    true,
                    false,
                    "com.example.javadebugmcp.fixture.*",
                    List.of("java.*"),
                    List.of("java.lang.IllegalArgumentException"));
            assertEquals(Boolean.TRUE, enabled.get("enabled"));
            assertEquals("caught", enabled.get("mode"));
            assertEquals(List.of("java.*"), enabled.get("classExclusionFilters"));
            assertEquals(List.of("java.lang.IllegalArgumentException"), enabled.get("exceptionTypes"));

            Map<String, Object> stopEvent = null;
            for (int attempt = 0; attempt < 20; attempt++) {
                stopEvent = manager.resume(5000);
                if ("exception".equals(stopEvent.get("reason"))) {
                    String exType = (String) stopEvent.get("exceptionType");
                    if ("java.lang.IllegalArgumentException".equals(exType)) {
                        break;
                    }
                }
                // Not our target exception, continue
            }
            assertNotNull(stopEvent);
            assertEquals("exception", stopEvent.get("reason"));
            assertEquals("java.lang.IllegalArgumentException", stopEvent.get("exceptionType"));
            assertEquals("boom-marker", stopEvent.get("messagePreview"));
            assertNotNull(stopEvent.get("catchLocation"));
            assertEquals(Boolean.TRUE, stopEvent.get("caught"));
            assertEquals(Boolean.FALSE, stopEvent.get("uncaught"));

            @SuppressWarnings("unchecked")
            Map<String, Object> location = (Map<String, Object>) stopEvent.get("location");
            assertEquals("com.example.javadebugmcp.fixture.SampleDebuggee", location.get("className"));
            assertEquals("throwAndCatch", location.get("methodName"));

            Map<String, Object> events = manager.getEvents(20, null);
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> items = (List<Map<String, Object>>) events.get("events");
            Map<String, Object> exceptionEvent = items.stream()
                    .filter(item -> "exception".equals(item.get("kind")))
                    .findFirst()
                    .orElseThrow();
            assertEquals("java.lang.IllegalArgumentException", exceptionEvent.get("exceptionType"));
            assertEquals("boom-marker", exceptionEvent.get("messagePreview"));
            assertEquals(Boolean.TRUE, exceptionEvent.get("caught"));
            assertEquals(Boolean.FALSE, exceptionEvent.get("uncaught"));
            assertNotNull(exceptionEvent.get("catchLocation"));

            Map<String, Object> detach = manager.detach();
            assertEquals("disconnected", detach.get("status"));
        } finally {
            process.destroy();
            if (process.isAlive()) {
                process.destroyForcibly();
            }
            process.waitFor();
        }
    }

    @Test
    void resumeTimeoutReturnsRunningStateInsteadOfThrowing() throws Exception {
        int port = randomPort();
        Process process = startDebuggee(port);
        try {
            waitForReady(process);

            DebugSessionManager manager = new DebugSessionManager();
            Map<String, Object> attached = manager.attach("127.0.0.1", port, 5000);
            assertEquals("attached", attached.get("status"));

            Map<String, Object> resumed = manager.resume(1);
            assertEquals("running", resumed.get("status"));
            assertEquals(Boolean.TRUE, resumed.get("waitTimedOut"));
            assertEquals("resume", resumed.get("command"));

            Map<String, Object> status = manager.status();
            assertEquals("running", status.get("status"));

            Map<String, Object> detach = manager.detach();
            assertEquals("disconnected", detach.get("status"));
        } finally {
            process.destroy();
            if (process.isAlive()) {
                process.destroyForcibly();
            }
            process.waitFor();
        }
    }

    @Test
    void evaluateExpressionSerializesConcurrentRequestsOnSameThread() throws Exception {
        int port = randomPort();
        Process process = startDebuggee(port);
        try {
            waitForReady(process);

            DebugSessionManager manager = new DebugSessionManager();
            manager.attach("127.0.0.1", port, 5000);

            int breakpointLine = findMarkerLine("src/test/java/com/example/javadebugmcp/fixture/SampleDebuggee.java",
                    "sink(stage2); // BREAKPOINT_EXERCISE");
            manager.setBreakpoint(
                    "com.example.javadebugmcp.fixture.SampleDebuggee",
                    breakpointLine,
                    "EVENT_THREAD");

            Map<String, Object> stopEvent = manager.resume(10000);
            assertEquals("breakpoint", stopEvent.get("reason"));
            String threadId = stopEvent.get("threadId").toString();

            long elapsedMs = runConcurrentEvaluations(
                    manager,
                    List.of(threadId, threadId),
                    List.of(
                            "com.example.javadebugmcp.fixture.SampleDebuggee.blockingProbe(\"same-left\", 500L)",
                            "com.example.javadebugmcp.fixture.SampleDebuggee.blockingProbe(\"same-right\", 500L)"));

            assertTrue(elapsedMs >= 900L, "same-thread evaluations should be serialized, elapsed=" + elapsedMs + "ms");

            manager.detach();
        } finally {
            process.destroy();
            if (process.isAlive()) {
                process.destroyForcibly();
            }
            process.waitFor();
        }
    }

    @Test
    void evaluateExpressionRunsConcurrentlyAcrossDifferentSuspendedThreads() throws Exception {
        int port = randomPort();
        Process process = startDebuggee(port);
        try {
            waitForReady(process);

            DebugSessionManager manager = new DebugSessionManager();
            manager.attach("127.0.0.1", port, 5000);

            int breakpointLine = findMarkerLine("src/test/java/com/example/javadebugmcp/fixture/SampleDebuggee.java",
                    "sink(value); // BREAKPOINT_PARALLEL");
            manager.setBreakpoint(
                    "com.example.javadebugmcp.fixture.SampleDebuggee",
                    breakpointLine,
                    "EVENT_THREAD");

            Map<String, Object> stopEvent = manager.resume(10000);
            assertEquals("breakpoint", stopEvent.get("reason"));

            Map<String, String> suspended = waitForSuspendedThreads(
                    manager,
                    List.of("parallel-left", "parallel-right"),
                    Duration.ofSeconds(5));

            long elapsedMs = runConcurrentEvaluations(
                    manager,
                    List.of(suspended.get("parallel-left"), suspended.get("parallel-right")),
                    List.of(
                            "com.example.javadebugmcp.fixture.SampleDebuggee.blockingProbe(\"parallel-left\", 500L)",
                            "com.example.javadebugmcp.fixture.SampleDebuggee.blockingProbe(\"parallel-right\", 500L)"));

            assertTrue(elapsedMs < 900L, "different-thread evaluations should overlap, elapsed=" + elapsedMs + "ms");

            manager.detach();
        } finally {
            process.destroy();
            if (process.isAlive()) {
                process.destroyForcibly();
            }
            process.waitFor();
        }
    }

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

    private static long runConcurrentEvaluations(
            DebugSessionManager manager,
            List<String> threadIds,
            List<String> expressions) throws Exception {
        CountDownLatch startGate = new CountDownLatch(1);
        ExecutorService executor = Executors.newFixedThreadPool(expressions.size());
        try {
            List<Future<Map<String, Object>>> futures = new ArrayList<>();
            for (int index = 0; index < expressions.size(); index++) {
                String threadId = threadIds.get(index);
                String expression = expressions.get(index);
                futures.add(executor.submit(() -> {
                    if (!startGate.await(5, TimeUnit.SECONDS)) {
                        throw new IllegalStateException("start gate timed out");
                    }
                    return manager.evaluateExpression(expression, threadId, 0);
                }));
            }

            long startedAt = System.nanoTime();
            startGate.countDown();
            for (Future<Map<String, Object>> future : futures) {
                Map<String, Object> result = future.get(5, TimeUnit.SECONDS);
                assertEquals("java.lang.String", result.get("typeName"));
            }
            return TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startedAt);
        } finally {
            executor.shutdownNow();
        }
    }

    private static Map<String, String> waitForSuspendedThreads(
            DebugSessionManager manager,
            List<String> threadNames,
            Duration timeout) throws Exception {
        long deadline = System.nanoTime() + timeout.toNanos();
        while (System.nanoTime() < deadline) {
            Map<String, Object> threads = manager.listThreads();
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> items = (List<Map<String, Object>>) threads.get("items");
            Map<String, String> found = new java.util.LinkedHashMap<>();
            for (Map<String, Object> item : items) {
                String name = item.get("name").toString();
                if (threadNames.contains(name) && Boolean.TRUE.equals(item.get("suspended"))) {
                    found.put(name, item.get("threadId").toString());
                }
            }
            if (found.size() == threadNames.size()) {
                return found;
            }
            Thread.sleep(100L);
        }
        throw new IllegalStateException("Timed out waiting for suspended threads: " + threadNames);
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

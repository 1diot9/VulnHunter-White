package com.example.javadebugmcp.mcp;

import com.example.javadebugmcp.debug.DebugSessionManager;
import io.modelcontextprotocol.server.McpServerFeatures;

import java.util.List;
import java.util.Map;

final class DebugToolSpecifications {
    private final DebugSessionManager debugSessionManager;
    private final McpToolSupport support;

    DebugToolSpecifications(DebugSessionManager debugSessionManager, McpToolSupport support) {
        this.debugSessionManager = debugSessionManager;
        this.support = support;
    }

    McpServerFeatures.SyncToolSpecification[] build() {
        return new McpServerFeatures.SyncToolSpecification[]{
                support.spec("debug_attach", "Attach to a remote JVM JDWP endpoint.",
                        support.schema("host", "string", true, "port", "integer", true, "timeoutMs", "integer", false),
                        arguments -> debugSessionManager.attach(
                                support.requiredText(arguments, "host"),
                                support.intValue(arguments, "port", 0),
                                support.intValue(arguments, "timeoutMs", 5000))),
                support.spec("debug_detach", "Detach the active debug session.", support.emptySchema(),
                        arguments -> debugSessionManager.detach()),
                support.spec("debug_status", "Return active session status.", support.emptySchema(),
                        arguments -> debugSessionManager.status()),
                support.spec("debug_set_breakpoint",
                        "Set a breakpoint. Provide 'line' for a line breakpoint, or 'methodName' to break at a method's first line. "
                                + "Both can be combined; if only methodName is given, the first executable line of that method is used. "
                                + "Optional condition/hitCount/logMessage turn it into a conditional breakpoint or logpoint.",
                        support.schema("className", "string", true,
                                "line", "integer", false,
                                "suspendPolicy", "string", false,
                                "methodName", "string", false,
                                "condition", "string", false,
                                "hitCount", "integer", false,
                                "logMessage", "string", false),
                        arguments -> debugSessionManager.setBreakpoint(
                                support.requiredText(arguments, "className"),
                                support.intValue(arguments, "line", -1),
                                support.text(arguments, "suspendPolicy", "EVENT_THREAD"),
                                support.nullableText(arguments, "methodName"),
                                support.nullableText(arguments, "condition"),
                                support.nullableInt(arguments, "hitCount"),
                                support.nullableText(arguments, "logMessage"))),
                support.spec("debug_remove_breakpoint",
                        "Remove a breakpoint by id. Works for both line breakpoints (bp-*) and method breakpoints (mbp-*).",
                        support.schema("breakpointId", "string", true),
                        arguments -> debugSessionManager.removeBreakpoint(support.requiredText(arguments, "breakpointId"))),
                support.spec("debug_list_breakpoints",
                        "List all registered breakpoints (line breakpoints and method breakpoints).",
                        support.emptySchema(),
                        arguments -> debugSessionManager.listBreakpoints()),
                support.spec("debug_resume",
                        "Resume execution and wait for the next stop. If threadId is provided, resumes only that single thread; otherwise resumes all threads.",
                        support.schema("threadId", "string", false, "waitTimeoutMs", "integer", false),
                        arguments -> debugSessionManager.resume(
                                support.nullableText(arguments, "threadId"),
                                support.intValue(arguments, "waitTimeoutMs", 10000))),
                support.spec("debug_step", "Perform a step action and wait for the next stop.",
                        support.schema("kind", "string", true, "threadId", "string", false, "waitTimeoutMs", "integer", false),
                        arguments -> debugSessionManager.step(
                                support.requiredText(arguments, "kind"),
                                support.nullableText(arguments, "threadId"),
                                support.intValue(arguments, "waitTimeoutMs", 10000))),
                support.spec("debug_list_threads", "List all threads in the current VM.", support.emptySchema(),
                        arguments -> debugSessionManager.listThreads()),
                support.spec("debug_get_stack", "Read stack frames from a suspended thread.",
                        support.schema("threadId", "string", false, "maxFrames", "integer", false),
                        arguments -> debugSessionManager.getStack(
                                support.nullableText(arguments, "threadId"),
                                support.intValue(arguments, "maxFrames", 20))),
                support.spec("debug_get_locals",
                        "Read local variables from a suspended frame. If the target class has no local variable table, the result falls back to synthetic argument aliases like arg0/p0/param0 instead of original parameter names.",
                        support.schema("threadId", "string", false, "frameIndex", "integer", true),
                        arguments -> debugSessionManager.getLocals(
                                support.nullableText(arguments, "threadId"),
                                support.intValue(arguments, "frameIndex", -1))),
                support.spec("debug_evaluate_expression",
                        "Evaluate a Java expression in a suspended frame. Only a single Java expression is supported here, not statements, assignments, or lambdas. "
                                + "Method invocations run inside the debuggee JVM and may execute target code. "
                                + "If the target class has no local variable table, original parameter names may be unavailable; use synthetic argument aliases such as arg0, p0, or param0 in expressions. "
                                + "Expression evaluation is serialized per suspended threadId; different suspended threadIds may evaluate concurrently. To avoid ambiguity, prefer passing threadId explicitly. "
                                + "Set allowOtherThreads=true when the expression may involve multi-threaded operations (caches, network calls, locks) to avoid deadlocks caused by single-threaded invocation mode.",
                        support.schema("expression", "string", true, "threadId", "string", false, "frameIndex", "integer", false,
                                "timeoutMs", "integer", false, "allowOtherThreads", "boolean", false),
                        arguments -> debugSessionManager.evaluateExpression(
                                support.requiredText(arguments, "expression"),
                                support.nullableText(arguments, "threadId"),
                                support.intValue(arguments, "frameIndex", 0),
                                support.intValue(arguments, "timeoutMs", 30000),
                                support.booleanValue(arguments, "allowOtherThreads", false))),
                support.spec("debug_inspect_object", "Inspect object fields from a stored object handle.",
                        support.schema("objectHandleId", "string", true, "maxFields", "integer", false),
                        arguments -> debugSessionManager.inspectObject(
                                support.requiredText(arguments, "objectHandleId"),
                                support.intValue(arguments, "maxFields", 20))),
                support.spec("debug_enable_exception_breakpoint", "Break on exceptions.",
                        support.schema("caught", "boolean", false,
                                "uncaught", "boolean", false,
                                "classFilter", "string", false,
                                "classExclusionFilters", "array", false,
                                "exceptionTypes", "array", false),
                        arguments -> debugSessionManager.enableExceptionBreakpoint(
                                support.booleanValue(arguments, "caught", true),
                                support.booleanValue(arguments, "uncaught", true),
                                support.nullableText(arguments, "classFilter"),
                                support.stringList(arguments, "classExclusionFilters"),
                                support.stringList(arguments, "exceptionTypes"))),
                support.spec("debug_clear_exception_breakpoint", "Remove the active exception breakpoint.", support.emptySchema(),
                        arguments -> debugSessionManager.clearExceptionBreakpoint()),
                support.spec("debug_set_method_breakpoint",
                        "Set a method entry/exit breakpoint. kind: 'entry' (default), 'exit', or 'both'. methodName can be empty to match all methods in the class.",
                        support.schema("className", "string", true,
                                "methodName", "string", false,
                                "kind", "string", false,
                                "suspendPolicy", "string", false,
                                "condition", "string", false,
                                "hitCount", "integer", false),
                        arguments -> debugSessionManager.setMethodBreakpoint(
                                support.requiredText(arguments, "className"),
                                support.nullableText(arguments, "methodName"),
                                support.text(arguments, "kind", "entry"),
                                support.text(arguments, "suspendPolicy", "EVENT_THREAD"),
                                support.nullableText(arguments, "condition"),
                                support.nullableInt(arguments, "hitCount"))),
                support.spec("debug_get_events",
                        "Get recent debug events (breakpoint hits, steps, exceptions). Returns up to 'limit' events. Use 'sinceId' for incremental polling.",
                        support.schema("limit", "integer", false, "sinceId", "integer", false),
                        arguments -> debugSessionManager.getEvents(
                                support.intValue(arguments, "limit", 20),
                                support.nullableInt(arguments, "sinceId"))),
                support.spec("debug_get_last_stop_event", "Get the latest suspended stop event with thread and location context.",
                        support.emptySchema(),
                        arguments -> debugSessionManager.getLastStopEvent()),
                support.spec("debug_set_breakpoints_batch",
                        "Set multiple breakpoints in one call. Each spec: {className, line?, methodName?, suspendPolicy?}. Returns per-item results with status 'ok' or 'error'.",
                        support.breakpointBatchSchema(),
                        arguments -> debugSessionManager.setBreakpointsBatch(
                                support.objectMapList(arguments, "breakpoints")))
        };
    }
}

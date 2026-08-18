package com.example.javadebugmcp.debug;

import com.example.javadebugmcp.debug.ValueFormatter.ObjectHandleRegistry;
import com.sun.jdi.AbsentInformationException;
import com.sun.jdi.ArrayReference;
import com.sun.jdi.Bootstrap;
import com.sun.jdi.BooleanValue;
import com.sun.jdi.ClassNotLoadedException;
import com.sun.jdi.IncompatibleThreadStateException;
import com.sun.jdi.InvalidTypeException;
import com.sun.jdi.InvocationException;
import com.sun.jdi.Location;
import com.sun.jdi.Method;
import com.sun.jdi.ObjectReference;
import com.sun.jdi.StackFrame;
import com.sun.jdi.StringReference;
import com.sun.jdi.ThreadReference;
import com.sun.jdi.Value;
import com.sun.jdi.VirtualMachine;
import com.sun.jdi.connect.AttachingConnector;
import com.sun.jdi.connect.Connector;
import com.sun.jdi.connect.IllegalConnectorArgumentsException;
import com.sun.jdi.event.BreakpointEvent;
import com.sun.jdi.event.ClassPrepareEvent;
import com.sun.jdi.event.Event;
import com.sun.jdi.event.EventIterator;
import com.sun.jdi.event.EventQueue;
import com.sun.jdi.event.EventSet;
import com.sun.jdi.event.ExceptionEvent;
import com.sun.jdi.event.MethodEntryEvent;
import com.sun.jdi.event.MethodExitEvent;
import com.sun.jdi.event.StepEvent;
import com.sun.jdi.event.VMDeathEvent;
import com.sun.jdi.event.VMDisconnectEvent;
import com.sun.jdi.request.BreakpointRequest;
import com.sun.jdi.request.ClassPrepareRequest;
import com.sun.jdi.request.EventRequest;
import com.sun.jdi.request.EventRequestManager;
import com.sun.jdi.request.ExceptionRequest;
import com.sun.jdi.request.MethodEntryRequest;
import com.sun.jdi.request.MethodExitRequest;
import com.sun.jdi.request.StepRequest;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public final class DebugSessionManager {
    private static final long DEFAULT_EVALUATION_TIMEOUT_MS = 30_000;
    private static final ExecutorService EVALUATION_EXECUTOR = Executors.newCachedThreadPool(runnable -> {
        Thread thread = new Thread(runnable);
        thread.setDaemon(true);
        thread.setName("expr-eval-" + thread.getId());
        return thread;
    });

    private final Object monitor = new Object();
    private DebugSession session;

    public Map<String, Object> attach(String host, int port, int timeoutMs)
            throws IOException, IllegalConnectorArgumentsException {
        detachIfPresent();
        AttachingConnector connector = socketConnector();
        Map<String, Connector.Argument> arguments = connector.defaultArguments();
        arguments.get("hostname").setValue(host);
        arguments.get("port").setValue(Integer.toString(port));
        Connector.Argument timeoutArgument = arguments.get("timeout");
        if (timeoutArgument != null) {
            timeoutArgument.setValue(Integer.toString(timeoutMs));
        }

        VirtualMachine vm = connector.attach(arguments);
        DebugSession newSession = new DebugSession(vm, host, port, timeoutMs);
        synchronized (monitor) {
            session = newSession;
        }
        newSession.startEventPump();
        return newSession.describe();
    }

    public Map<String, Object> detach() throws IOException {
        DebugSession existing = currentSession(false);
        if (existing == null) {
            return Map.of("status", "disconnected");
        }
        existing.close();
        synchronized (monitor) {
            session = null;
        }
        return Map.of("status", "disconnected");
    }

    public Map<String, Object> status() {
        DebugSession existing = currentSession(false);
        if (existing == null) {
            return Map.of("status", "disconnected");
        }
        return existing.status();
    }

    public Map<String, Object> setBreakpoint(String className, int line, String suspendPolicy) {
        return currentSession(true).setBreakpoint(className, line, suspendPolicy, null, null, null, null);
    }

    public Map<String, Object> setBreakpoint(String className, int line, String suspendPolicy, String methodName) {
        return currentSession(true).setBreakpoint(className, line, suspendPolicy, methodName, null, null, null);
    }

    public Map<String, Object> setBreakpoint(
            String className,
            int line,
            String suspendPolicy,
            String methodName,
            String condition,
            Integer hitCount,
            String logMessage) {
        return currentSession(true).setBreakpoint(className, line, suspendPolicy, methodName, condition, hitCount, logMessage);
    }

    public Map<String, Object> removeBreakpoint(String breakpointId) {
        if (breakpointId.startsWith("mbp-")) {
            return currentSession(true).removeMethodBreakpoint(breakpointId);
        }
        return currentSession(true).removeBreakpoint(breakpointId);
    }

    public Map<String, Object> listBreakpoints() {
        return currentSession(true).listAllBreakpoints();
    }

    public Map<String, Object> resume(int waitTimeoutMs)
            throws ExecutionException, InterruptedException {
        return resume(null, waitTimeoutMs);
    }

    public Map<String, Object> resume(String threadId, int waitTimeoutMs)
            throws ExecutionException, InterruptedException {
        if (threadId != null && !threadId.isBlank()) {
            return currentSession(true).resumeThread(threadId, waitTimeoutMs);
        }
        return currentSession(true).resume(waitTimeoutMs);
    }

    public Map<String, Object> step(String kind, String threadId, int waitTimeoutMs)
            throws IncompatibleThreadStateException, ExecutionException, InterruptedException {
        return currentSession(true).step(kind, threadId, waitTimeoutMs);
    }

    public Map<String, Object> listThreads() {
        return currentSession(true).listThreads();
    }

    public Map<String, Object> getStack(String threadId, int maxFrames) throws IncompatibleThreadStateException {
        return currentSession(true).getStack(threadId, maxFrames);
    }

    public Map<String, Object> getLocals(String threadId, int frameIndex)
            throws IncompatibleThreadStateException, AbsentInformationException {
        return currentSession(true).getLocals(threadId, frameIndex);
    }

    public Map<String, Object> evaluateExpression(String expression, String threadId, int frameIndex)
            throws IncompatibleThreadStateException, InvalidTypeException, ClassNotLoadedException, InvocationException {
        return evaluateExpression(expression, threadId, frameIndex, DEFAULT_EVALUATION_TIMEOUT_MS, false);
    }

    public Map<String, Object> evaluateExpression(String expression, String threadId, int frameIndex,
            long timeoutMs, boolean allowOtherThreads)
            throws IncompatibleThreadStateException, InvalidTypeException, ClassNotLoadedException, InvocationException {
        long effectiveTimeout = timeoutMs > 0 ? timeoutMs : DEFAULT_EVALUATION_TIMEOUT_MS;
        CompletableFuture<Map<String, Object>> future = CompletableFuture.supplyAsync(() -> {
            try {
                return currentSession(true).evaluateExpression(expression, threadId, frameIndex, allowOtherThreads);
            } catch (RuntimeException exception) {
                throw exception;
            } catch (Exception exception) {
                throw new CompletionException(exception);
            }
        }, EVALUATION_EXECUTOR);
        try {
            return future.get(effectiveTimeout, TimeUnit.MILLISECONDS);
        } catch (TimeoutException exception) {
            future.cancel(true);
            String hint = allowOtherThreads
                    ? ""
                    : " Consider retrying with allowOtherThreads=true if the expression involves "
                            + "multi-threaded operations (caches, network calls, locks).";
            throw new IllegalStateException(
                    "Expression evaluation timed out after " + effectiveTimeout
                            + "ms. The expression may still be executing in the target JVM."
                            + hint + " Expression: " + expression);
        } catch (ExecutionException exception) {
            Throwable cause = exception.getCause();
            if (cause instanceof CompletionException completionException && completionException.getCause() != null) {
                cause = completionException.getCause();
            }
            if (cause instanceof IncompatibleThreadStateException typed) throw typed;
            if (cause instanceof InvalidTypeException typed) throw typed;
            if (cause instanceof ClassNotLoadedException typed) throw typed;
            if (cause instanceof InvocationException typed) throw typed;
            if (cause instanceof RuntimeException typed) throw typed;
            throw new IllegalStateException("Expression evaluation failed", cause);
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Expression evaluation interrupted");
        }
    }

    public Map<String, Object> inspectObject(String objectHandleId, int maxFields) {
        return currentSession(true).inspectObject(objectHandleId, maxFields);
    }

    public Map<String, Object> enableExceptionBreakpoint(boolean caught, boolean uncaught, String classFilter) {
        return enableExceptionBreakpoint(caught, uncaught, classFilter, List.of(), List.of());
    }

    public Map<String, Object> enableExceptionBreakpoint(
            boolean caught,
            boolean uncaught,
            String classFilter,
            List<String> classExclusionFilters,
            List<String> exceptionTypes) {
        return currentSession(true).enableExceptionBreakpoint(caught, uncaught, classFilter, classExclusionFilters, exceptionTypes);
    }

    public Map<String, Object> clearExceptionBreakpoint() {
        return currentSession(true).clearExceptionBreakpoint();
    }

    public Map<String, Object> setMethodBreakpoint(
            String className,
            String methodName,
            String kind,
            String suspendPolicy,
            String condition,
            Integer hitCount) {
        return currentSession(true).setMethodBreakpoint(className, methodName, kind, suspendPolicy, condition, hitCount);
    }


    public Map<String, Object> getEvents(int limit, Integer sinceId) {
        return currentSession(true).getEvents(limit, sinceId);
    }

    public Map<String, Object> getLastStopEvent() {
        return currentSession(true).getLastStopEvent();
    }

    public Map<String, Object> setBreakpointsBatch(List<Map<String, Object>> specs) {
        return currentSession(true).setBreakpointsBatch(specs);
    }


    private void detachIfPresent() throws IOException {
        DebugSession existing;
        synchronized (monitor) {
            existing = session;
        }
        if (existing != null) {
            existing.close();
        }
        synchronized (monitor) {
            session = null;
        }
    }

    private DebugSession currentSession(boolean required) {
        synchronized (monitor) {
            if (session == null && required) {
                throw new IllegalStateException("No active debug session");
            }
            return session;
        }
    }

    private AttachingConnector socketConnector() {
        for (AttachingConnector connector : Bootstrap.virtualMachineManager().attachingConnectors()) {
            if ("com.sun.jdi.SocketAttach".equals(connector.name())) {
                return connector;
            }
        }
        throw new IllegalStateException("SocketAttach connector not available");
    }

    private static final class DebugSession {
        private final VirtualMachine vm;
        private final String sessionId;
        private final String host;
        private final int port;
        private final int timeoutMs;
        private final ObjectHandleRegistry objectHandleRegistry = new ObjectHandleRegistry();
        // ConcurrentHashMap：事件泵线程与MCP请求线程并发访问安全
        private final Map<String, com.example.javadebugmcp.debug.ManagedBreakpoint> breakpoints = new ConcurrentHashMap<>();
        private final Map<String, com.example.javadebugmcp.debug.ManagedMethodBreakpoint> methodBreakpoints = new ConcurrentHashMap<>();
        private final List<Map<String, Object>> eventHistory = new ArrayList<>();
        private final Object eventHistoryLock = new Object();
        private static final int MAX_EVENT_HISTORY = 100;
        private int eventCounter;
        private final Object stateLock = new Object();
        private final ReentrantReadWriteLock evaluationLifecycleLock = new ReentrantReadWriteLock(true);
        private final Map<Long, ReentrantLock> evaluationThreadLocks = new ConcurrentHashMap<>();
        private volatile com.example.javadebugmcp.debug.SessionState state = com.example.javadebugmcp.debug.SessionState.ATTACHED;
        private volatile com.example.javadebugmcp.debug.StopEventData lastStopEvent;
        private volatile ThreadReference activeThread;
        private volatile CompletableFuture<com.example.javadebugmcp.debug.StopEventData> nextStopFuture;
        private volatile ExceptionRequest exceptionRequest;
        private volatile com.example.javadebugmcp.debug.ExceptionBreakpointConfig exceptionBreakpointConfig;
        private volatile boolean closed;
        private volatile ClassPrepareRequest classPrepareRequest;

        private DebugSession(VirtualMachine vm, String host, int port, int timeoutMs) {
            this.vm = vm;
            this.host = host;
            this.port = port;
            this.timeoutMs = timeoutMs;
            this.sessionId = UUID.randomUUID().toString();
        }

        private Map<String, Object> describe() {
            Map<String, Object> result = new LinkedHashMap<>(status());
            result.put("sessionId", sessionId);
            result.put("vmDescription", vm.description());
            result.put("vmName", vm.name());
            result.put("vmVersion", vm.version());
            result.put("capabilities", Map.of(
                    "canGetBytecodes", vm.canGetBytecodes(),
                    "canGetSyntheticAttribute", vm.canGetSyntheticAttribute(),
                    "canWatchFieldModification", vm.canWatchFieldModification(),
                    "canWatchFieldAccess", vm.canWatchFieldAccess(),
                    "canGetOwnedMonitorInfo", vm.canGetOwnedMonitorInfo()
            ));
            return result;
        }

        private Map<String, Object> status() {
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("sessionId", sessionId);
            result.put("status", state.name().toLowerCase());
            result.put("target", Map.of("host", host, "port", port, "timeoutMs", timeoutMs));
            result.put("breakpointCount", breakpoints.size());
            result.put("activeThreadId", activeThread == null ? null : Long.toString(activeThread.uniqueID()));
            result.put("lastStopEvent", lastStopEvent == null ? null : lastStopEvent.asMap());
            return result;
        }

        private void startEventPump() {
            Thread eventThread = new Thread(this::pumpEvents, "jdwp-event-pump");
            eventThread.setDaemon(true);
            eventThread.start();
        }

        private Map<String, Object> setBreakpoint(
                String className,
                int line,
                String suspendPolicy,
                String methodName,
                String condition,
                Integer hitCount,
                String logMessage) {
            ensureOpen();
            // When methodName is provided but no valid line, resolve to the method's first executable line
            int resolvedLine = line;
            if (resolvedLine <= 0 && methodName != null && !methodName.isBlank()) {
                resolvedLine = resolveMethodFirstLine(className, methodName);
            }
            if (resolvedLine <= 0) {
                throw new IllegalArgumentException("Must provide a valid line or methodName");
            }
            if (hitCount != null && hitCount <= 0) {
                throw new IllegalArgumentException("hitCount must be > 0");
            }
            com.example.javadebugmcp.debug.ManagedBreakpoint breakpoint = new com.example.javadebugmcp.debug.ManagedBreakpoint(
                    className, resolvedLine, suspendPolicy, condition, hitCount, logMessage);
            breakpoints.put(breakpoint.breakpointId, breakpoint);
            bindBreakpointToLoadedClasses(breakpoint);
            ensureClassPrepareRequest();
            return breakpoint.asMap();
        }

        private int resolveMethodFirstLine(String className, String methodName) {
            for (com.sun.jdi.ReferenceType refType : vm.classesByName(className)) {
                for (Method method : refType.methods()) {
                    if (method.name().equals(methodName)) {
                        try {
                            List<Location> allLocations = method.allLineLocations();
                            if (!allLocations.isEmpty()) {
                                return allLocations.get(0).lineNumber();
                            }
                        } catch (AbsentInformationException ignored) {
                            // fall through
                        }
                    }
                }
            }
            throw new IllegalArgumentException(
                    "Method '" + methodName + "' not found in loaded class '" + className + "'");
        }

        private Map<String, Object> removeBreakpoint(String breakpointId) {
            ensureOpen();
            com.example.javadebugmcp.debug.ManagedBreakpoint breakpoint = breakpoints.remove(breakpointId);
            if (breakpoint == null) {
                throw new IllegalArgumentException("Unknown breakpoint: " + breakpointId);
            }
            if (breakpoint.request != null) {
                vm.eventRequestManager().deleteEventRequest(breakpoint.request);
            }
            return Map.of("removed", true, "breakpointId", breakpointId);
        }

        private Map<String, Object> listAllBreakpoints() {
            ensureOpen();
            List<Map<String, Object>> items = new ArrayList<>();
            for (com.example.javadebugmcp.debug.ManagedBreakpoint breakpoint : breakpoints.values()) {
                items.add(breakpoint.asMap());
            }
            for (com.example.javadebugmcp.debug.ManagedMethodBreakpoint bp : methodBreakpoints.values()) {
                items.add(bp.asMap());
            }
            return Map.of("items", items);
        }

        private Map<String, Object> resume(int waitTimeoutMs)
                throws ExecutionException, InterruptedException {
            lockSessionMutation();
            try {
                ensureOpen();
                CompletableFuture<com.example.javadebugmcp.debug.StopEventData> future;
                synchronized (stateLock) {
                    if (state == com.example.javadebugmcp.debug.SessionState.RUNNING) {
                        // 超时后 session 保持 RUNNING 状态，重用已有 future 继续等待，不重复 vm.resume()
                        future = nextStopFuture;
                    } else {
                        nextStopFuture = new CompletableFuture<>();
                        future = nextStopFuture;
                        state = com.example.javadebugmcp.debug.SessionState.RUNNING;
                        vm.resume();
                    }
                }
                try {
                    return future.get(waitTimeoutMs, TimeUnit.MILLISECONDS).asMap();
                } catch (TimeoutException ignored) {
                    return runningResult("resume", waitTimeoutMs);
                }
            } finally {
                unlockSessionMutation();
            }
        }

        private Map<String, Object> step(String kind, String threadId, int waitTimeoutMs)
                throws IncompatibleThreadStateException, ExecutionException, InterruptedException {
            lockSessionMutation();
            try {
                ensureOpen();
                ThreadReference targetThread = resolveThread(threadId);
                if (!targetThread.isSuspended()) {
                    throw new IllegalStateException("Selected thread is not suspended");
                }

                EventRequestManager requestManager = vm.eventRequestManager();
                for (StepRequest existing : requestManager.stepRequests()) {
                    if (existing.thread().equals(targetThread)) {
                        requestManager.deleteEventRequest(existing);
                    }
                }

                int depth = switch (kind) {
                    case "into" -> StepRequest.STEP_INTO;
                    case "over" -> StepRequest.STEP_OVER;
                    case "out" -> StepRequest.STEP_OUT;
                    default -> throw new IllegalArgumentException("Unsupported step kind: " + kind);
                };

                StepRequest request = requestManager.createStepRequest(targetThread, StepRequest.STEP_LINE, depth);
                request.setSuspendPolicy(EventRequest.SUSPEND_EVENT_THREAD);
                request.addCountFilter(1);
                request.enable();

                CompletableFuture<com.example.javadebugmcp.debug.StopEventData> future;
                synchronized (stateLock) {
                    nextStopFuture = new CompletableFuture<>();
                    future = nextStopFuture;
                    state = com.example.javadebugmcp.debug.SessionState.RUNNING;
                }
                vm.resume();
                try {
                    return future.get(waitTimeoutMs, TimeUnit.MILLISECONDS).asMap();
                } catch (TimeoutException ignored) {
                    return runningResult("step", waitTimeoutMs);
                }
            } finally {
                unlockSessionMutation();
            }
        }

        private Map<String, Object> listThreads() {
            ensureOpen();
            String activeThreadId = activeThread == null ? null : Long.toString(activeThread.uniqueID());
            String lastStopThreadId = lastStopEvent == null ? null : lastStopEvent.threadId;
            List<Map<String, Object>> items = new ArrayList<>();
            for (ThreadReference thread : vm.allThreads()) {
                Map<String, Object> item = new LinkedHashMap<>();
                item.put("threadId", Long.toString(thread.uniqueID()));
                item.put("name", thread.name());
                item.put("status", thread.status());
                item.put("suspended", thread.isSuspended());
                item.put("atBreakpoint", thread.isAtBreakpoint());
                item.put("active", Objects.equals(item.get("threadId"), activeThreadId));
                item.put("lastStopThread", Objects.equals(item.get("threadId"), lastStopThreadId));
                if (Objects.equals(item.get("threadId"), lastStopThreadId) && lastStopEvent != null) {
                    item.put("lastStopReason", lastStopEvent.reason);
                    item.put("lastStoppedAt", lastStopEvent.stoppedAt.toString());
                    item.put("lastStopLocation", lastStopEvent.locationMap());
                    if (lastStopEvent.breakpointId != null) {
                        item.put("lastBreakpointId", lastStopEvent.breakpointId);
                    }
                }
                items.add(item);
            }
            return Map.of("items", items);
        }

        private Map<String, Object> getStack(String threadId, int maxFrames) throws IncompatibleThreadStateException {
            ensureOpen();
            ThreadReference thread = requireSuspendedThread(threadId);
            List<StackFrame> frames = thread.frames(0, Math.min(maxFrames, thread.frameCount()));
            List<Map<String, Object>> items = new ArrayList<>();
            for (int index = 0; index < frames.size(); index++) {
                StackFrame frame = frames.get(index);
                items.add(frameSummary(index, frame));
            }
            return Map.of("threadId", Long.toString(thread.uniqueID()), "threadName", thread.name(), "frames", items);
        }

        private Map<String, Object> getLocals(String threadId, int frameIndex)
                throws IncompatibleThreadStateException, AbsentInformationException {
            ensureOpen();
            if (frameIndex < 0) {
                throw new IllegalArgumentException("frameIndex must be >= 0");
            }
            ThreadReference thread = requireSuspendedThread(threadId);
            StackFrame frame = thread.frame(frameIndex);
            List<Map<String, Object>> locals = new ArrayList<>();
            boolean debugInfoPresent = true;
            try {
                var variables = frame.visibleVariables();
                var values = frame.getValues(variables);
                for (var variable : variables) {
                    Map<String, Object> local = new LinkedHashMap<>();
                    local.put("name", variable.name());
                    local.put("declaredType", variable.typeName());
                    local.putAll(ValueFormatter.formatValue(values.get(variable), objectHandleRegistry));
                    locals.add(local);
                }
            } catch (AbsentInformationException ignored) {
                debugInfoPresent = false;
                appendSyntheticArguments(frame, locals);
            }
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("threadId", Long.toString(thread.uniqueID()));
            result.put("frameIndex", frameIndex);
            result.put("debugInfoPresent", debugInfoPresent);
            if (!debugInfoPresent) {
                result.put("note", "Local variable table is unavailable; exposing arguments as argN/pN/paramN aliases");
            }
            result.put("locals", locals);
            return result;
        }

        private Map<String, Object> evaluateExpression(String expression, String threadId, int frameIndex,
                boolean allowOtherThreads)
                throws IncompatibleThreadStateException, InvalidTypeException, ClassNotLoadedException, InvocationException {
            ThreadReference thread = resolveThread(threadId);
            ReentrantLock threadLock = evaluationThreadLock(thread);
            lockEvaluation(thread, threadLock);
            try {
                ensureOpen();
                if (!thread.isSuspended()) {
                    throw new IllegalStateException("Thread is not suspended");
                }
                if (frameIndex < 0) {
                    throw new IllegalArgumentException("frameIndex must be >= 0");
                }
                if (frameIndex >= thread.frameCount()) {
                    throw new IllegalArgumentException("frameIndex out of range: " + frameIndex);
                }
                try {
                    int invocationOptions = allowOtherThreads ? 0 : ObjectReference.INVOKE_SINGLE_THREADED;
                    return ExpressionEvaluator.evaluate(vm, thread, frameIndex, objectHandleRegistry, expression, invocationOptions);
                } catch (IllegalArgumentException | IllegalStateException exception) {
                    throw expressionFailure("Expression evaluation", expression, exception.getMessage(), exception);
                } catch (InvalidTypeException | ClassNotLoadedException exception) {
                    throw expressionFailure("Expression evaluation", expression, exception.getMessage(), exception);
                } catch (InvocationException exception) {
                    throw expressionFailure("Expression evaluation", expression, describeInvocationFailure(exception), exception);
                }
            } finally {
                unlockEvaluation(thread, threadLock);
            }
        }

        private Map<String, Object> inspectObject(String objectHandleId, int maxFields) {
            ensureOpen();
            ObjectReference reference = objectHandleRegistry.get(objectHandleId);
            if (reference instanceof ArrayReference arrayReference) {
                List<Map<String, Object>> elements = new ArrayList<>();
                int limit = Math.min(maxFields, arrayReference.length());
                for (int index = 0; index < limit; index++) {
                    Map<String, Object> element = new LinkedHashMap<>();
                    element.put("index", index);
                    element.putAll(ValueFormatter.formatValue(arrayReference.getValue(index), objectHandleRegistry));
                    elements.add(element);
                }
                return Map.of(
                        "objectHandleId", objectHandleId,
                        "typeName", arrayReference.referenceType().name(),
                        "length", arrayReference.length(),
                        "elements", elements,
                        "truncated", arrayReference.length() > limit
                );
            }
            return ValueFormatter.inspectObject(reference, objectHandleRegistry, maxFields);
        }

        private Map<String, Object> enableExceptionBreakpoint(
                boolean caught,
                boolean uncaught,
                String classFilter,
                List<String> classExclusionFilters,
                List<String> exceptionTypes) {
            ensureOpen();
            if (!caught && !uncaught) {
                throw new IllegalArgumentException("At least one of caught or uncaught must be true");
            }
            clearExceptionBreakpoint();
            ExceptionRequest request = vm.eventRequestManager().createExceptionRequest(null, caught, uncaught);
            request.setSuspendPolicy(EventRequest.SUSPEND_EVENT_THREAD);
            if (classFilter != null && !classFilter.isBlank()) {
                request.addClassFilter(classFilter);
            }
            List<String> normalizedExclusions = normalizeFilters(classExclusionFilters);
            for (String filter : normalizedExclusions) {
                request.addClassExclusionFilter(filter);
            }
            request.enable();
            this.exceptionRequest = request;
            this.exceptionBreakpointConfig = new com.example.javadebugmcp.debug.ExceptionBreakpointConfig(
                    caught,
                    uncaught,
                    classFilter,
                    normalizedExclusions,
                    normalizeClassNames(exceptionTypes));
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("enabled", true);
            result.put("caught", caught);
            result.put("uncaught", uncaught);
            result.put("mode", describeExceptionMode(caught, uncaught));
            result.put("classFilter", classFilter);
            result.put("classExclusionFilters", normalizedExclusions);
            result.put("exceptionTypes", exceptionBreakpointConfig.exceptionTypes);
            return result;
        }

        private Map<String, Object> clearExceptionBreakpoint() {
            ensureOpen();
            if (exceptionRequest != null) {
                vm.eventRequestManager().deleteEventRequest(exceptionRequest);
                exceptionRequest = null;
            }
            exceptionBreakpointConfig = null;
            return Map.of("cleared", true);
        }

        private void close() throws IOException {
            lockSessionMutation();
            try {
                closed = true;
                try {
                    vm.dispose();
                } catch (RuntimeException ignored) {
                }
                objectHandleRegistry.clear();
            } finally {
                unlockSessionMutation();
            }
        }

        private void pumpEvents() {
            EventQueue queue = vm.eventQueue();
            while (!closed) {
                try {
                    EventSet eventSet = queue.remove();
                    if (eventSet == null) {
                        continue;
                    }

                    boolean keepSuspended = false;
                    com.example.javadebugmcp.debug.StopEventData stopEvent = null;
                    List<String> reasons = new ArrayList<>();
                    EventIterator iterator = eventSet.eventIterator();
                    while (iterator.hasNext()) {
                        Event event = iterator.nextEvent();
                        if (event instanceof ClassPrepareEvent classPrepareEvent) {
                            bindPendingBreakpoints(classPrepareEvent.referenceType());
                        } else if (event instanceof BreakpointEvent breakpointEvent) {
                            BreakpointHandlingOutcome outcome = handleBreakpointEvent(breakpointEvent, reasons);
                            stopEvent = outcome.stopEvent();
                            keepSuspended = outcome.keepSuspended();
                        } else if (event instanceof StepEvent stepEvent) {
                            stopEvent = com.example.javadebugmcp.debug.StopEventData.fromLocation("step", reasons, stepEvent.thread(), stepEvent.location(), null, null);
                            vm.eventRequestManager().deleteEventRequest(stepEvent.request());
                            keepSuspended = true;
                        } else if (event instanceof MethodEntryEvent methodEntryEvent) {
                            BreakpointHandlingOutcome outcome = handleMethodEvent(
                                    methodEntryEvent.request(),
                                    methodEntryEvent.thread(),
                                    methodEntryEvent.location(),
                                    "method_entry",
                                    reasons);
                            stopEvent = outcome.stopEvent();
                            keepSuspended = outcome.keepSuspended();
                        } else if (event instanceof MethodExitEvent methodExitEvent) {
                            BreakpointHandlingOutcome outcome = handleMethodEvent(
                                    methodExitEvent.request(),
                                    methodExitEvent.thread(),
                                    methodExitEvent.location(),
                                    "method_exit",
                                    reasons);
                            stopEvent = outcome.stopEvent();
                            keepSuspended = outcome.keepSuspended();
                        } else if (event instanceof ExceptionEvent exceptionEvent) {
                            com.example.javadebugmcp.debug.StopEventData exceptionStopEvent = handleExceptionEvent(exceptionEvent, reasons);
                            if (exceptionStopEvent != null) {
                                stopEvent = exceptionStopEvent;
                                keepSuspended = true;
                            }
                        } else if (event instanceof VMDeathEvent || event instanceof VMDisconnectEvent) {
                            com.example.javadebugmcp.debug.StopEventData terminal = com.example.javadebugmcp.debug.StopEventData.terminal();
                            synchronized (stateLock) {
                                state = com.example.javadebugmcp.debug.SessionState.TERMINATED;
                                lastStopEvent = terminal;
                                if (nextStopFuture != null && !nextStopFuture.isDone()) {
                                    nextStopFuture.complete(terminal);
                                }
                            }
                            closed = true;
                        }
                    }

                    if (stopEvent != null) {
                        recordEvent(stopEvent.reason, stopEvent);
                        synchronized (stateLock) {
                            activeThread = stopEvent.thread;
                            state = com.example.javadebugmcp.debug.SessionState.SUSPENDED;
                            lastStopEvent = stopEvent;
                            if (nextStopFuture != null && !nextStopFuture.isDone()) {
                                nextStopFuture.complete(stopEvent);
                            }
                        }
                    }

                    if (!keepSuspended && !closed) {
                        eventSet.resume();
                    }
                } catch (InterruptedException ignored) {
                    Thread.currentThread().interrupt();
                    return;
                } catch (Exception exception) {
                    synchronized (stateLock) {
                        state = com.example.javadebugmcp.debug.SessionState.ERROR;
                        if (nextStopFuture != null && !nextStopFuture.isDone()) {
                            nextStopFuture.completeExceptionally(exception);
                        }
                    }
                    return;
                }
            }
        }

        private BreakpointHandlingOutcome handleBreakpointEvent(BreakpointEvent breakpointEvent, List<String> reasons) {
            com.example.javadebugmcp.debug.ManagedBreakpoint breakpoint = findManagedBreakpoint(breakpointEvent.request());
            if (breakpoint == null) {
                return new BreakpointHandlingOutcome(
                        com.example.javadebugmcp.debug.StopEventData.fromLocation("breakpoint", reasons, breakpointEvent.thread(), breakpointEvent.location(), null, null),
                        true);
            }

            try {
                Value conditionValue = null;
                if (breakpoint.condition != null) {
                    conditionValue = evaluateValueWithReadableErrors(
                            breakpointEvent.thread(),
                            0,
                            breakpoint.condition,
                            "Breakpoint condition");
                    if (!evaluateBreakpointCondition(conditionValue)) {
                        recordLogEvent("breakpoint_skip", breakpointEvent.thread(), breakpointEvent.location(), null);
                        return new BreakpointHandlingOutcome(null, false);
                    }
                }

                if (breakpoint.logMessage != null) {
                    RenderedLogMessage rendered = renderLogMessage(breakpointEvent.thread(), breakpoint.logMessage);
                    recordLogEvent(
                            "logpoint",
                            breakpointEvent.thread(),
                            breakpointEvent.location(),
                            rendered.message(),
                            rendered.interpolationErrors());
                    return new BreakpointHandlingOutcome(null, false);
                }
                return new BreakpointHandlingOutcome(
                        com.example.javadebugmcp.debug.StopEventData.fromLocation("breakpoint", reasons, breakpointEvent.thread(), breakpointEvent.location(),
                                breakpoint.breakpointId, breakpoint.breakpointType()),
                        true);
            } catch (Exception exception) {
                return new BreakpointHandlingOutcome(
                        com.example.javadebugmcp.debug.StopEventData.fromBreakpointEvaluationError(
                                reasons,
                                breakpointEvent.thread(),
                                breakpointEvent.location(),
                                breakpoint.breakpointId,
                                breakpoint.breakpointType(),
                                exception.getMessage() == null ? exception.getClass().getName() : exception.getMessage()),
                        true);
            }
        }

        private BreakpointHandlingOutcome handleMethodEvent(
                EventRequest request,
                ThreadReference thread,
                Location location,
                String reason,
                List<String> reasons) {
            com.example.javadebugmcp.debug.ManagedMethodBreakpoint breakpoint = findManagedMethodBreakpoint(request, location.method());
            if (breakpoint == null) {
                return new BreakpointHandlingOutcome(null, false);
            }

            try {
                if (!breakpoint.shouldStopOnCurrentHit()) {
                    recordLogEvent("method_breakpoint_skip", thread, location, null);
                    return new BreakpointHandlingOutcome(null, false);
                }
                if (breakpoint.condition != null) {
                    Value conditionValue = evaluateValueWithReadableErrors(
                            thread,
                            0,
                            breakpoint.condition,
                            "Method breakpoint condition");
                    if (!evaluateBreakpointCondition(conditionValue)) {
                        recordLogEvent("method_breakpoint_skip", thread, location, null);
                        return new BreakpointHandlingOutcome(null, false);
                    }
                }

                return new BreakpointHandlingOutcome(
                        com.example.javadebugmcp.debug.StopEventData.fromLocation(
                                reason,
                                reasons,
                                thread,
                                location,
                                breakpoint.breakpointId,
                                breakpoint.breakpointType()),
                        true);
            } catch (Exception exception) {
                return new BreakpointHandlingOutcome(
                        com.example.javadebugmcp.debug.StopEventData.fromBreakpointEvaluationError(
                                reasons,
                                thread,
                                location,
                                breakpoint.breakpointId,
                                breakpoint.breakpointType(),
                                exception.getMessage() == null ? exception.getClass().getName() : exception.getMessage()),
                        true);
            }
        }

        private com.example.javadebugmcp.debug.ManagedBreakpoint findManagedBreakpoint(EventRequest request) {
            for (com.example.javadebugmcp.debug.ManagedBreakpoint breakpoint : breakpoints.values()) {
                if (request.equals(breakpoint.request)) {
                    return breakpoint;
                }
            }
            return null;
        }

        private com.example.javadebugmcp.debug.ManagedMethodBreakpoint findManagedMethodBreakpoint(EventRequest request, Method method) {
            String declaringClass = method.declaringType().name();
            String methodName = method.name();
            Object breakpointId = request.getProperty("breakpointId");
            if (breakpointId instanceof String id) {
                com.example.javadebugmcp.debug.ManagedMethodBreakpoint direct = methodBreakpoints.get(id);
                if (direct != null && direct.matches(declaringClass, methodName)) {
                    return direct;
                }
            }
            for (com.example.javadebugmcp.debug.ManagedMethodBreakpoint breakpoint : methodBreakpoints.values()) {
                boolean requestMatches = request.equals(breakpoint.entryRequest) || request.equals(breakpoint.exitRequest);
                if (requestMatches && breakpoint.matches(declaringClass, methodName)) {
                    return breakpoint;
                }
            }
            return null;
        }

        private boolean evaluateBreakpointCondition(Value value) {
            if (value instanceof BooleanValue booleanValue) {
                return booleanValue.booleanValue();
            }
            if (value instanceof ObjectReference objectReference
                    && "java.lang.Boolean".equals(objectReference.referenceType().name())) {
                var field = objectReference.referenceType().fieldByName("value");
                if (field != null && objectReference.getValue(field) instanceof BooleanValue booleanValue) {
                    return booleanValue.booleanValue();
                }
            }
            throw new IllegalArgumentException("Breakpoint condition must evaluate to boolean");
        }

        private Value evaluateValueWithReadableErrors(
                ThreadReference thread,
                int frameIndex,
                String expression,
                String usage)
                throws IncompatibleThreadStateException, InvalidTypeException, ClassNotLoadedException, InvocationException {
            try {
                return ExpressionEvaluator.evaluateValue(vm, thread, frameIndex, expression,
                        ObjectReference.INVOKE_SINGLE_THREADED);
            } catch (IllegalArgumentException | IllegalStateException exception) {
                throw expressionFailure(usage, expression, exception.getMessage(), exception);
            } catch (InvalidTypeException | ClassNotLoadedException exception) {
                throw expressionFailure(usage, expression, exception.getMessage(), exception);
            } catch (InvocationException exception) {
                throw expressionFailure(usage, expression, describeInvocationFailure(exception), exception);
            }
        }

        private IllegalArgumentException expressionFailure(
                String usage,
                String expression,
                String detail,
                Exception cause) {
            StringBuilder message = new StringBuilder();
            message.append(usage).append(" failed for '").append(expression).append("'");
            if (!isBlank(detail)) {
                message.append(": ").append(detail);
            }
            String hint = expressionHint(detail);
            if (hint != null) {
                message.append(". Hint: ").append(hint);
            }
            return new IllegalArgumentException(message.toString(), cause);
        }

        private String expressionHint(String detail) {
            if (isBlank(detail)) {
                return null;
            }
            if (detail.startsWith("Unknown identifier:")) {
                return "Check locals, fields, and class names in the current frame; if local variable tables are unavailable, use argN/pN/paramN aliases.";
            }
            if (detail.startsWith("Invalid expression:")
                    || detail.startsWith("Unsupported expression syntax:")
                    || detail.startsWith("Expression did not resolve to a value")) {
                return "Only a single Java expression is supported here; statements, assignments, and lambdas are not.";
            }
            if (detail.contains("Thread is not suspended")) {
                return "Stop on a breakpoint first, then evaluate on the suspended thread.";
            }
            if (detail.contains("No active suspended thread")) {
                return "Stop on a breakpoint first, or pass threadId explicitly when multiple threads may be involved.";
            }
            if (detail.startsWith("Class not loaded")) {
                return "The target type must already be loaded in the debuggee JVM before evaluation.";
            }
            return null;
        }

        private String describeInvocationFailure(InvocationException exception) {
            ObjectReference target = exception.exception();
            String typeName = target == null ? "unknown" : target.referenceType().name();
            String message = DebugValueSupport.readObjectMessage(target);
            if (isBlank(message)) {
                return "Target method threw " + typeName;
            }
            return "Target method threw " + typeName + ": " + message;
        }

        private RenderedLogMessage renderLogMessage(ThreadReference thread, String logMessage)
                throws IncompatibleThreadStateException, InvalidTypeException, ClassNotLoadedException, InvocationException {
            StringBuilder builder = new StringBuilder();
            List<Map<String, Object>> interpolationErrors = new ArrayList<>();
            int cursor = 0;
            while (cursor < logMessage.length()) {
                int open = logMessage.indexOf('{', cursor);
                if (open < 0) {
                    builder.append(logMessage, cursor, logMessage.length());
                    break;
                }
                int close = logMessage.indexOf('}', open + 1);
                if (close < 0) {
                    builder.append(logMessage, cursor, logMessage.length());
                    break;
                }
                builder.append(logMessage, cursor, open);
                String expression = logMessage.substring(open + 1, close).trim();
                if (!expression.isEmpty()) {
                    try {
                        Value value = evaluateValueWithReadableErrors(thread, 0, expression, "Logpoint placeholder");
                        builder.append(valueToLogText(value));
                    } catch (IllegalArgumentException exception) {
                        builder.append("<error:").append(expression).append(">");
                        Map<String, Object> error = new LinkedHashMap<>();
                        error.put("expression", expression);
                        error.put("error", exception.getMessage());
                        interpolationErrors.add(error);
                    }
                }
                cursor = close + 1;
            }
            return new RenderedLogMessage(builder.toString(), List.copyOf(interpolationErrors));
        }

        private String valueToLogText(Value value) {
            if (value == null) {
                return "null";
            }
            if (value instanceof StringReference stringReference) {
                return stringReference.value();
            }
            Map<String, Object> formatted = ValueFormatter.formatValue(value, objectHandleRegistry);
            Object preview = formatted.get("valuePreview");
            return preview == null ? "null" : preview.toString();
        }

        private record RenderedLogMessage(String message, List<Map<String, Object>> interpolationErrors) {
        }

        private com.example.javadebugmcp.debug.StopEventData handleExceptionEvent(ExceptionEvent exceptionEvent, List<String> reasons) {
            com.example.javadebugmcp.debug.StopEventData stopEvent = com.example.javadebugmcp.debug.StopEventData.fromException(reasons, exceptionEvent);
            if (!matchesExceptionBreakpointFilters(stopEvent)) {
                recordLogEvent("exception_skip", exceptionEvent.thread(), exceptionEvent.location(), stopEvent.exceptionType);
                return null;
            }
            return stopEvent;
        }

        private boolean matchesExceptionBreakpointFilters(com.example.javadebugmcp.debug.StopEventData stopEvent) {
            com.example.javadebugmcp.debug.ExceptionBreakpointConfig config = exceptionBreakpointConfig;
            if (config == null || config.exceptionTypes.isEmpty()) {
                return true;
            }
            return config.exceptionTypes.contains(stopEvent.exceptionType);
        }

        private void recordLogEvent(String kind, ThreadReference thread, Location location, String message) {
            recordLogEvent(kind, thread, location, message, null);
        }

        private void recordLogEvent(
                String kind,
                ThreadReference thread,
                Location location,
                String message,
                List<Map<String, Object>> interpolationErrors) {
            Map<String, Object> entry = new LinkedHashMap<>();
            synchronized (eventHistoryLock) {
                eventCounter++;
                entry.put("eventId", eventCounter);
            }
            entry.put("timestamp", Instant.now().toString());
            entry.put("kind", kind);
            entry.put("threadId", Long.toString(thread.uniqueID()));
            entry.put("threadName", thread.name());
            entry.put("className", location.declaringType().name());
            entry.put("methodName", location.method().name());
            entry.put("line", location.lineNumber());
            if (message != null) {
                entry.put("message", message);
            }
            if (interpolationErrors != null && !interpolationErrors.isEmpty()) {
                entry.put("interpolationErrors", interpolationErrors);
            }
            synchronized (eventHistoryLock) {
                if (eventHistory.size() >= MAX_EVENT_HISTORY) {
                    eventHistory.remove(0);
                }
                eventHistory.add(entry);
            }
        }

        private void bindPendingBreakpoints(com.sun.jdi.ReferenceType referenceType) {
            for (com.example.javadebugmcp.debug.ManagedBreakpoint breakpoint : breakpoints.values()) {
                if (!breakpoint.resolved && Objects.equals(breakpoint.className, referenceType.name())) {
                    installBreakpoint(referenceType, breakpoint);
                }
            }
        }

        private void bindBreakpointToLoadedClasses(com.example.javadebugmcp.debug.ManagedBreakpoint breakpoint) {
            for (com.sun.jdi.ReferenceType referenceType : vm.classesByName(breakpoint.className)) {
                installBreakpoint(referenceType, breakpoint);
            }
        }

        private void installBreakpoint(com.sun.jdi.ReferenceType referenceType, com.example.javadebugmcp.debug.ManagedBreakpoint breakpoint) {
            try {
                List<Location> locations = referenceType.locationsOfLine(breakpoint.line);
                if (locations.isEmpty()) {
                    return;
                }
                Location location = locations.get(0);
                BreakpointRequest request = vm.eventRequestManager().createBreakpointRequest(location);
                request.setSuspendPolicy(parseSuspendPolicy(breakpoint.suspendPolicy));
                if (breakpoint.hitCount != null) {
                    request.addCountFilter(breakpoint.hitCount);
                }
                request.enable();
                breakpoint.request = request;
                breakpoint.resolved = true;
                breakpoint.methodName = safeMethodName(location.method());
                breakpoint.sourceName = safeSourceName(location);
            } catch (AbsentInformationException ignored) {
                breakpoint.sourceName = null;
            }
        }

        private void ensureClassPrepareRequest() {
            if (classPrepareRequest != null) {
                return;
            }
            ClassPrepareRequest request = vm.eventRequestManager().createClassPrepareRequest();
            request.setSuspendPolicy(EventRequest.SUSPEND_NONE);
            request.enable();
            classPrepareRequest = request;
        }

        private int parseSuspendPolicy(String policy) {
            if (policy == null) {
                return EventRequest.SUSPEND_EVENT_THREAD;
            }
            return switch (policy.toUpperCase()) {
                case "ALL" -> EventRequest.SUSPEND_ALL;
                case "NONE" -> EventRequest.SUSPEND_NONE;
                default -> EventRequest.SUSPEND_EVENT_THREAD;
            };
        }

        private Map<String, Object> setMethodBreakpoint(
                String className,
                String methodName,
                String kind,
                String suspendPolicy,
                String condition,
                Integer hitCount) {
            ensureOpen();
            if (hitCount != null && hitCount <= 0) {
                throw new IllegalArgumentException("hitCount must be > 0");
            }
            com.example.javadebugmcp.debug.ManagedMethodBreakpoint bp =
                    new com.example.javadebugmcp.debug.ManagedMethodBreakpoint(className, methodName, kind, suspendPolicy, condition, hitCount);
            methodBreakpoints.put(bp.breakpointId, bp);
            installMethodBreakpoint(bp);
            return bp.asMap();
        }

        private Map<String, Object> removeMethodBreakpoint(String breakpointId) {
            ensureOpen();
            com.example.javadebugmcp.debug.ManagedMethodBreakpoint bp = methodBreakpoints.remove(breakpointId);
            if (bp == null) {
                throw new IllegalArgumentException("Unknown method breakpoint: " + breakpointId);
            }
            EventRequestManager erm = vm.eventRequestManager();
            if (bp.entryRequest != null) {
                erm.deleteEventRequest(bp.entryRequest);
            }
            if (bp.exitRequest != null) {
                erm.deleteEventRequest(bp.exitRequest);
            }
            return Map.of("removed", true, "breakpointId", breakpointId);
        }


        private void recordEvent(String kind, com.example.javadebugmcp.debug.StopEventData stopEvent) {
            Map<String, Object> entry = new LinkedHashMap<>();
            synchronized (eventHistoryLock) {
                eventCounter++;
                entry.put("eventId", eventCounter);
            }
            entry.put("timestamp", Instant.now().toString());
            entry.put("kind", kind);
            entry.put("threadId", stopEvent.threadId);
            entry.put("threadName", stopEvent.threadName);
            if (stopEvent.className != null) {
                entry.put("className", stopEvent.className);
            }
            if (stopEvent.methodName != null) {
                entry.put("methodName", stopEvent.methodName);
            }
            entry.put("line", stopEvent.line);
            entry.put("reason", stopEvent.reason);
            entry.put("reasons", stopEvent.reasons);
            entry.put("stoppedAt", stopEvent.stoppedAt.toString());
            entry.put("location", stopEvent.locationMap());
            if (stopEvent.exceptionType != null) {
                entry.put("exceptionType", stopEvent.exceptionType);
                entry.put("messagePreview", stopEvent.messagePreview);
                entry.put("catchLocation", stopEvent.catchLocation);
                entry.put("caught", stopEvent.caught);
                entry.put("uncaught", stopEvent.uncaught);
            }
            if (stopEvent.breakpointId != null) {
                entry.put("breakpointId", stopEvent.breakpointId);
            }
            if (stopEvent.breakpointType != null) {
                entry.put("breakpointType", stopEvent.breakpointType);
            }
            if (stopEvent.evaluationError != null) {
                entry.put("evaluationError", stopEvent.evaluationError);
            }
            synchronized (eventHistoryLock) {
                if (eventHistory.size() >= MAX_EVENT_HISTORY) {
                    eventHistory.remove(0);
                }
                eventHistory.add(entry);
            }
        }

        private Map<String, Object> getEvents(int limit, Integer sinceId) {
            ensureOpen();
            List<Map<String, Object>> result;
            synchronized (eventHistoryLock) {
                if (sinceId != null) {
                    result = new ArrayList<>();
                    for (Map<String, Object> event : eventHistory) {
                        int id = ((Number) event.get("eventId")).intValue();
                        if (id > sinceId) {
                            result.add(event);
                        }
                    }
                } else {
                    result = new ArrayList<>(eventHistory);
                }
            }
            if (result.size() > limit) {
                result = result.subList(result.size() - limit, result.size());
            }
            return Map.of("events", result);
        }

        private Map<String, Object> getLastStopEvent() {
            ensureOpen();
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("sessionId", sessionId);
            result.put("status", state.name().toLowerCase());
            result.put("activeThreadId", activeThread == null ? null : Long.toString(activeThread.uniqueID()));
            result.put("hasLastStopEvent", lastStopEvent != null);
            result.put("lastStopEvent", lastStopEvent == null ? null : lastStopEvent.asMap());
            return result;
        }

        private Map<String, Object> setBreakpointsBatch(List<Map<String, Object>> specs) {
            ensureOpen();
            List<Map<String, Object>> results = new ArrayList<>();
            for (Map<String, Object> spec : specs) {
                try {
                    String className = (String) spec.get("className");
                    int line = spec.containsKey("line") ? ((Number) spec.get("line")).intValue() : -1;
                    String suspendPolicy = (String) spec.getOrDefault("suspendPolicy", "EVENT_THREAD");
                    String methodName = (String) spec.get("methodName");
                    String condition = (String) spec.get("condition");
                    Integer hitCount = spec.containsKey("hitCount") ? ((Number) spec.get("hitCount")).intValue() : null;
                    String logMessage = (String) spec.get("logMessage");
                    Map<String, Object> bp = setBreakpoint(className, line, suspendPolicy, methodName, condition, hitCount, logMessage);
                    Map<String, Object> entry = new LinkedHashMap<>(bp);
                    entry.put("status", "ok");
                    results.add(entry);
                } catch (Exception e) {
                    Map<String, Object> entry = new LinkedHashMap<>();
                    entry.put("className", spec.get("className"));
                    entry.put("line", spec.get("line"));
                    entry.put("methodName", spec.get("methodName"));
                    entry.put("status", "error");
                    entry.put("error", e.getMessage());
                    results.add(entry);
                }
            }
            return Map.of("results", results);
        }

        private Map<String, Object> resumeThread(String threadId, int waitTimeoutMs)
                throws ExecutionException, InterruptedException {
            lockSessionMutation();
            try {
                ensureOpen();
                ThreadReference thread = requireSuspendedThread(threadId);
                CompletableFuture<com.example.javadebugmcp.debug.StopEventData> future;
                synchronized (stateLock) {
                    nextStopFuture = new CompletableFuture<>();
                    future = nextStopFuture;
                    state = com.example.javadebugmcp.debug.SessionState.RUNNING;
                }
                thread.resume();
                try {
                    return future.get(waitTimeoutMs, TimeUnit.MILLISECONDS).asMap();
                } catch (TimeoutException ignored) {
                    return runningResult("resumeThread", waitTimeoutMs);
                }
            } finally {
                unlockSessionMutation();
            }
        }

        private void installMethodBreakpoint(com.example.javadebugmcp.debug.ManagedMethodBreakpoint bp) {
            EventRequestManager erm = vm.eventRequestManager();
            int policy = parseSuspendPolicy(bp.suspendPolicy);
            boolean wantEntry = "entry".equalsIgnoreCase(bp.kind) || "both".equalsIgnoreCase(bp.kind);
            boolean wantExit = "exit".equalsIgnoreCase(bp.kind) || "both".equalsIgnoreCase(bp.kind);

            if (wantEntry) {
                MethodEntryRequest req = erm.createMethodEntryRequest();
                req.addClassFilter(bp.className);
                req.putProperty("breakpointId", bp.breakpointId);
                req.setSuspendPolicy(policy);
                req.enable();
                bp.entryRequest = req;
            }
            if (wantExit) {
                MethodExitRequest req = erm.createMethodExitRequest();
                req.addClassFilter(bp.className);
                req.putProperty("breakpointId", bp.breakpointId);
                req.setSuspendPolicy(policy);
                req.enable();
                bp.exitRequest = req;
            }
            bp.installed = true;
        }

        private ThreadReference requireSuspendedThread(String threadId) {
            ThreadReference thread = resolveThread(threadId);
            if (!thread.isSuspended()) {
                throw new IllegalStateException("Thread is not suspended");
            }
            return thread;
        }

        private ThreadReference resolveThread(String threadId) {
            if (threadId == null || threadId.isBlank()) {
                if (activeThread == null) {
                    throw new IllegalStateException("No active suspended thread");
                }
                return activeThread;
            }
            long numericId = Long.parseLong(threadId);
            for (ThreadReference thread : vm.allThreads()) {
                if (thread.uniqueID() == numericId) {
                    return thread;
                }
            }
            throw new IllegalArgumentException("Unknown threadId: " + threadId);
        }

        private Map<String, Object> frameSummary(int frameIndex, StackFrame frame) {
            Location location = frame.location();
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("frameIndex", frameIndex);
            item.put("className", location.declaringType().name());
            item.put("methodName", safeMethodName(location.method()));
            item.put("line", location.lineNumber());
            item.put("sourceName", safeSourceName(location));
            return item;
        }

        private String safeSourceName(Location location) {
            try {
                return location.sourceName();
            } catch (AbsentInformationException ignored) {
                return null;
            }
        }

        private String safeMethodName(Method method) {
            return method == null ? null : method.name();
        }

        private void appendSyntheticArguments(StackFrame frame, List<Map<String, Object>> locals) {
            List<Value> arguments = frame.getArgumentValues();
            List<String> argumentTypes = frame.location().method().argumentTypeNames();
            for (int index = 0; index < arguments.size(); index++) {
                Map<String, Object> local = new LinkedHashMap<>();
                local.put("name", "arg" + index);
                local.put("declaredType", index < argumentTypes.size() ? argumentTypes.get(index) : null);
                local.put("synthetic", true);
                local.put("aliases", List.of("p" + index, "param" + index));
                local.putAll(ValueFormatter.formatValue(arguments.get(index), objectHandleRegistry));
                locals.add(local);
            }
        }

        private ReentrantLock evaluationThreadLock(ThreadReference thread) {
            return evaluationThreadLocks.computeIfAbsent(thread.uniqueID(), ignored -> new ReentrantLock(true));
        }

        private void lockEvaluation(ThreadReference thread, ReentrantLock threadLock) {
            evaluationLifecycleLock.readLock().lock();
            threadLock.lock();
        }

        private void unlockEvaluation(ThreadReference thread, ReentrantLock threadLock) {
            try {
                threadLock.unlock();
            } finally {
                evaluationLifecycleLock.readLock().unlock();
                if (!threadLock.isLocked() && !threadLock.hasQueuedThreads()) {
                    evaluationThreadLocks.remove(thread.uniqueID(), threadLock);
                }
            }
        }

        private void lockSessionMutation() {
            evaluationLifecycleLock.writeLock().lock();
        }

        private void unlockSessionMutation() {
            evaluationLifecycleLock.writeLock().unlock();
        }

        private void ensureOpen() {
            if (closed || state == com.example.javadebugmcp.debug.SessionState.TERMINATED || state == com.example.javadebugmcp.debug.SessionState.ERROR) {
                throw new IllegalStateException("Debug session is closed or in error state: " + state);
            }
        }

        private Map<String, Object> runningResult(String command, int waitTimeoutMs) {
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("status", "running");
            result.put("waitTimedOut", true);
            result.put("command", command);
            result.put("waitTimeoutMs", waitTimeoutMs);
            result.put("activeThreadId", activeThread == null ? null : Long.toString(activeThread.uniqueID()));
            result.put("lastStopEvent", lastStopEvent == null ? null : lastStopEvent.asMap());
            return result;
        }

        private static boolean isBlank(String value) {
            return value == null || value.isBlank();
        }

        private List<String> normalizeFilters(List<String> values) {
            List<String> result = new ArrayList<>();
            if (values == null) {
                return result;
            }
            for (String value : values) {
                if (value == null) {
                    continue;
                }
                String normalized = value.trim();
                if (!normalized.isEmpty()) {
                    result.add(normalized);
                }
            }
            return result;
        }

        private List<String> normalizeClassNames(List<String> values) {
            return normalizeFilters(values);
        }

        private String describeExceptionMode(boolean caught, boolean uncaught) {
            if (caught && uncaught) {
                return "both";
            }
            if (caught) {
                return "caught";
            }
            return "uncaught";
        }

        private record BreakpointHandlingOutcome(com.example.javadebugmcp.debug.StopEventData stopEvent, boolean keepSuspended) {
        }
    }

    private static final class ManagedBreakpoint {
        private final String breakpointId = "bp-" + UUID.randomUUID();
        private final String className;
        private final int line;
        private final String suspendPolicy;
        private final String condition;
        private final Integer hitCount;
        private final String logMessage;
        // volatile：installBreakpoint() 在事件泵线程写入，asMap() 在请求线程读取
        private volatile String methodName;
        private volatile String sourceName;
        private volatile BreakpointRequest request;
        private volatile boolean resolved;

        private ManagedBreakpoint(
                String className,
                int line,
                String suspendPolicy,
                String condition,
                Integer hitCount,
                String logMessage) {
            this.className = className;
            this.line = line;
            this.suspendPolicy = suspendPolicy;
            this.condition = condition == null || condition.isBlank() ? null : condition;
            this.hitCount = hitCount;
            this.logMessage = logMessage == null || logMessage.isBlank() ? null : logMessage;
        }

        private Map<String, Object> asMap() {
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("breakpointId", breakpointId);
            result.put("type", breakpointType());
            result.put("className", className);
            result.put("line", line);
            result.put("methodName", methodName);
            result.put("sourceName", sourceName);
            result.put("suspendPolicy", suspendPolicy);
            result.put("condition", condition);
            result.put("hitCount", hitCount);
            result.put("logMessage", logMessage);
            result.put("resolved", resolved);
            result.put("pendingClassPrepare", !resolved);
            return result;
        }

        String breakpointType() {
            if (logMessage != null) {
                return "logpoint";
            }
            if (condition != null || hitCount != null) {
                return "conditional";
            }
            return "line";
        }
    }

    private static final class ManagedMethodBreakpoint {
        private final String breakpointId = "mbp-" + UUID.randomUUID();
        private final String className;
        private final String methodName;
        private final String kind; // "entry", "exit", "both"
        private final String suspendPolicy;
        private final String condition;
        private final Integer hitCount;
        private final AtomicInteger hitCounter = new AtomicInteger();
        private volatile MethodEntryRequest entryRequest;
        private volatile MethodExitRequest exitRequest;
        private volatile boolean installed;

        private ManagedMethodBreakpoint(
                String className,
                String methodName,
                String kind,
                String suspendPolicy,
                String condition,
                Integer hitCount) {
            this.className = className;
            this.methodName = methodName;
            this.kind = kind == null ? "entry" : kind;
            this.suspendPolicy = suspendPolicy;
            this.condition = condition == null || condition.isBlank() ? null : condition;
            this.hitCount = hitCount;
        }

        private Map<String, Object> asMap() {
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("breakpointId", breakpointId);
            result.put("type", "method");
            result.put("className", className);
            result.put("methodName", methodName);
            result.put("kind", kind);
            result.put("suspendPolicy", suspendPolicy);
            result.put("condition", condition);
            result.put("hitCount", hitCount);
            result.put("breakpointType", breakpointType());
            result.put("installed", installed);
            return result;
        }

        String breakpointType() {
            return condition != null || hitCount != null ? "conditional" : "method";
        }

        private boolean matches(String declaringClass, String matchedMethodName) {
            return Objects.equals(className, declaringClass)
                    && (methodName == null || methodName.isEmpty() || Objects.equals(methodName, matchedMethodName));
        }

        private boolean shouldStopOnCurrentHit() {
            if (hitCount == null) {
                return true;
            }
            int current = hitCounter.incrementAndGet();
            return current == hitCount;
        }
    }

    private static final class ExceptionBreakpointConfig {
        private final boolean caught;
        private final boolean uncaught;
        private final String classFilter;
        private final List<String> classExclusionFilters;
        private final List<String> exceptionTypes;

        private ExceptionBreakpointConfig(
                boolean caught,
                boolean uncaught,
                String classFilter,
                List<String> classExclusionFilters,
                List<String> exceptionTypes) {
            this.caught = caught;
            this.uncaught = uncaught;
            this.classFilter = classFilter;
            this.classExclusionFilters = List.copyOf(classExclusionFilters);
            this.exceptionTypes = List.copyOf(exceptionTypes);
        }
    }

    private static final class StopEventData {
        private final String reason;
        private final List<String> reasons;
        private final ThreadReference thread;
        private final String threadId;
        private final String threadName;
        private final String className;
        private final String methodName;
        private final int line;
        private final String sourceName;
        private final String exceptionType;
        private final String messagePreview;
        private final String catchLocation;
        private final boolean caught;
        private final boolean uncaught;
        private final String evaluationError;
        private final String breakpointId;
        private final String breakpointType;
        private final Instant stoppedAt;

        private StopEventData(String reason, List<String> reasons, ThreadReference thread, String className, String methodName,
                              int line, String sourceName, String exceptionType, String messagePreview,
                              String catchLocation, boolean caught, boolean uncaught,
                              String evaluationError, String breakpointId, String breakpointType) {
            this.reason = reason;
            this.reasons = reasons;
            this.thread = thread;
            this.threadId = thread == null ? null : Long.toString(thread.uniqueID());
            this.threadName = thread == null ? null : thread.name();
            this.className = className;
            this.methodName = methodName;
            this.line = line;
            this.sourceName = sourceName;
            this.exceptionType = exceptionType;
            this.messagePreview = messagePreview;
            this.catchLocation = catchLocation;
            this.caught = caught;
            this.uncaught = uncaught;
            this.evaluationError = evaluationError;
            this.breakpointId = breakpointId;
            this.breakpointType = breakpointType;
            this.stoppedAt = Instant.now();
        }

        private static StopEventData fromLocation(
                String reason,
                List<String> reasons,
                ThreadReference thread,
                Location location,
                String breakpointId,
                String breakpointType) {
            reasons.add(reason);
            return new StopEventData(reason, List.copyOf(reasons), thread, location.declaringType().name(),
                    location.method().name(), location.lineNumber(), safeSourceName(location),
                    null, null, null, false, false, null, breakpointId, breakpointType);
        }

        private static StopEventData fromException(List<String> reasons, ExceptionEvent event) {
            reasons.add("exception");
            String catchLocation = null;
            if (event.catchLocation() != null) {
                Location location = event.catchLocation();
                catchLocation = location.declaringType().name() + "#" + location.method().name() + ":" + location.lineNumber();
            }
            String message = DebugValueSupport.readObjectMessage(event.exception());
            Location location = event.location();
            boolean isCaught = event.catchLocation() != null;
            return new StopEventData("exception", List.copyOf(reasons), event.thread(),
                    location.declaringType().name(), location.method().name(), location.lineNumber(),
                    safeSourceName(location), event.exception().referenceType().name(), message,
                    catchLocation, isCaught, !isCaught, null, null, null);
        }

        private static StopEventData fromBreakpointEvaluationError(
                List<String> reasons,
                ThreadReference thread,
                Location location,
                String breakpointId,
                String breakpointType,
                String evaluationError) {
            reasons.add("breakpoint");
            reasons.add("breakpoint_evaluation_error");
            return new StopEventData(
                    "breakpoint",
                    List.copyOf(reasons),
                    thread,
                    location.declaringType().name(),
                    location.method().name(),
                    location.lineNumber(),
                    safeSourceName(location),
                    null,
                    null,
                    null,
                    false,
                    false,
                    evaluationError,
                    breakpointId,
                    breakpointType);
        }

        private static StopEventData terminal() {
            return new StopEventData("vm_disconnect", Collections.singletonList("vm_disconnect"), null,
                    null, null, -1, null, null, null, null, false, false, null, null, null);
        }

        private Map<String, Object> asMap() {
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("reason", reason);
            result.put("reasons", reasons);
            result.put("threadId", threadId);
            result.put("threadName", threadName);
            result.put("location", locationMap());
            result.put("exceptionType", exceptionType);
            result.put("messagePreview", messagePreview);
            result.put("catchLocation", catchLocation);
            result.put("caught", caught);
            result.put("uncaught", uncaught);
            result.put("evaluationError", evaluationError);
            result.put("breakpointId", breakpointId);
            result.put("breakpointType", breakpointType);
            result.put("stoppedAt", stoppedAt.toString());
            return result;
        }

        private Map<String, Object> locationMap() {
            Map<String, Object> location = new LinkedHashMap<>();
            location.put("className", className);
            location.put("methodName", methodName);
            location.put("line", line);
            location.put("sourceName", sourceName);
            return location;
        }

        private static String safeSourceName(Location location) {
            try {
                return location.sourceName();
            } catch (AbsentInformationException ignored) {
                return null;
            }
        }
    }
}

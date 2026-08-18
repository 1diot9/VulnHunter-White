package com.example.javadebugmcp.debug;

import com.sun.jdi.AbsentInformationException;
import com.sun.jdi.Location;
import com.sun.jdi.ThreadReference;
import com.sun.jdi.event.ExceptionEvent;

import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

final class StopEventData {
    final String reason;
    final List<String> reasons;
    final ThreadReference thread;
    final String threadId;
    final String threadName;
    final String className;
    final String methodName;
    final int line;
    final String sourceName;
    final String exceptionType;
    final String messagePreview;
    final String catchLocation;
    final boolean caught;
    final boolean uncaught;
    final String evaluationError;
    final String breakpointId;
    final String breakpointType;
    final Instant stoppedAt;

    private StopEventData(
            String reason,
            List<String> reasons,
            ThreadReference thread,
            String className,
            String methodName,
            int line,
            String sourceName,
            String exceptionType,
            String messagePreview,
            String catchLocation,
            boolean caught,
            boolean uncaught,
            String evaluationError,
            String breakpointId,
            String breakpointType) {
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

    static StopEventData fromLocation(
            String reason,
            List<String> reasons,
            ThreadReference thread,
            Location location,
            String breakpointId,
            String breakpointType) {
        reasons.add(reason);
        return new StopEventData(
                reason,
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
                null,
                breakpointId,
                breakpointType);
    }

    static StopEventData fromException(List<String> reasons, ExceptionEvent event) {
        reasons.add("exception");
        String stopCatchLocation = null;
        if (event.catchLocation() != null) {
            Location location = event.catchLocation();
            stopCatchLocation = location.declaringType().name() + "#" + location.method().name() + ":" + location.lineNumber();
        }
        String message = DebugValueSupport.readObjectMessage(event.exception());
        Location location = event.location();
        boolean isCaught = event.catchLocation() != null;
        return new StopEventData(
                "exception",
                List.copyOf(reasons),
                event.thread(),
                location.declaringType().name(),
                location.method().name(),
                location.lineNumber(),
                safeSourceName(location),
                event.exception().referenceType().name(),
                message,
                stopCatchLocation,
                isCaught,
                !isCaught,
                null,
                null,
                null);
    }

    static StopEventData fromBreakpointEvaluationError(
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

    static StopEventData terminal() {
        return new StopEventData(
                "vm_disconnect",
                Collections.singletonList("vm_disconnect"),
                null,
                null,
                null,
                -1,
                null,
                null,
                null,
                null,
                false,
                false,
                null,
                null,
                null);
    }

    Map<String, Object> asMap() {
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

    Map<String, Object> locationMap() {
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

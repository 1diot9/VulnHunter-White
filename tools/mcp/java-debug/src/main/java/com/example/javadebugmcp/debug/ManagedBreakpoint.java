package com.example.javadebugmcp.debug;

import com.sun.jdi.request.BreakpointRequest;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

final class ManagedBreakpoint {
    final String breakpointId = "bp-" + UUID.randomUUID();
    final String className;
    final int line;
    final String suspendPolicy;
    final String condition;
    final Integer hitCount;
    final String logMessage;
    volatile String methodName;
    volatile String sourceName;
    volatile BreakpointRequest request;
    volatile boolean resolved;

    ManagedBreakpoint(
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

    Map<String, Object> asMap() {
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

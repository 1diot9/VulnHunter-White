package com.example.javadebugmcp.debug;

import com.sun.jdi.request.MethodEntryRequest;
import com.sun.jdi.request.MethodExitRequest;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

final class ManagedMethodBreakpoint {
    final String breakpointId = "mbp-" + UUID.randomUUID();
    final String className;
    final String methodName;
    final String kind;
    final String suspendPolicy;
    final String condition;
    final Integer hitCount;
    final AtomicInteger hitCounter = new AtomicInteger();
    volatile MethodEntryRequest entryRequest;
    volatile MethodExitRequest exitRequest;
    volatile boolean installed;

    ManagedMethodBreakpoint(
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

    Map<String, Object> asMap() {
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

    boolean matches(String declaringClass, String matchedMethodName) {
        return Objects.equals(className, declaringClass)
                && (methodName == null || methodName.isEmpty() || Objects.equals(methodName, matchedMethodName));
    }

    boolean shouldStopOnCurrentHit() {
        if (hitCount == null) {
            return true;
        }
        int current = hitCounter.incrementAndGet();
        return current == hitCount;
    }

    String breakpointType() {
        return condition != null || hitCount != null ? "conditional" : "method";
    }
}

package com.example.javadebugmcp.debug;

import com.example.javadebugmcp.debug.ValueFormatter.ObjectHandleRegistry;
import com.sun.jdi.ObjectReference;
import com.sun.jdi.Value;

import java.util.Map;

final class DebugValueSupport {
    private DebugValueSupport() {
    }

    static String readObjectMessage(ObjectReference reference) {
        if (reference == null) {
            return null;
        }
        try {
            var field = reference.referenceType().fieldByName("detailMessage");
            if (field == null) {
                return null;
            }
            Value value = reference.getValue(field);
            Map<String, Object> formatted = ValueFormatter.formatValue(value, new ObjectHandleRegistry());
            Object preview = formatted.get("valuePreview");
            return preview == null ? null : preview.toString();
        } catch (RuntimeException ignored) {
            return null;
        }
    }
}

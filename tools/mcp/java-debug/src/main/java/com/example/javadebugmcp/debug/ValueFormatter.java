package com.example.javadebugmcp.debug;

import com.sun.jdi.ArrayReference;
import com.sun.jdi.BooleanValue;
import com.sun.jdi.ByteValue;
import com.sun.jdi.CharValue;
import com.sun.jdi.DoubleValue;
import com.sun.jdi.Field;
import com.sun.jdi.FloatValue;
import com.sun.jdi.IntegerValue;
import com.sun.jdi.LongValue;
import com.sun.jdi.ObjectReference;
import com.sun.jdi.ReferenceType;
import com.sun.jdi.ShortValue;
import com.sun.jdi.StringReference;
import com.sun.jdi.Value;

import java.util.LinkedHashMap;
import java.util.Map;

public final class ValueFormatter {
    private ValueFormatter() {
    }

    public static Map<String, Object> formatValue(Value value, ObjectHandleRegistry handleRegistry) {
        Map<String, Object> result = new LinkedHashMap<>();
        if (value == null) {
            result.put("valueKind", "null");
            result.put("valuePreview", "null");
            return result;
        }

        if (value instanceof BooleanValue || value instanceof ByteValue || value instanceof CharValue
                || value instanceof ShortValue || value instanceof IntegerValue || value instanceof LongValue
                || value instanceof FloatValue || value instanceof DoubleValue) {
            result.put("valueKind", "primitive");
            result.put("valuePreview", value.toString());
            return result;
        }

        if (value instanceof StringReference stringReference) {
            String raw = stringReference.value();
            result.put("valueKind", "string");
            result.put("valuePreview", raw);
            result.put("length", raw.length());
            result.put("objectHandleId", handleRegistry.put(stringReference));
            return result;
        }

        if (value instanceof ArrayReference arrayReference) {
            result.put("valueKind", "array");
            result.put("valuePreview", arrayReference.referenceType().name() + "[size=" + arrayReference.length() + "]");
            result.put("length", arrayReference.length());
            result.put("objectHandleId", handleRegistry.put(arrayReference));
            return result;
        }

        if (value instanceof ObjectReference objectReference) {
            result.put("valueKind", "object");
            result.put("valuePreview", describeObject(objectReference.referenceType()));
            result.put("objectHandleId", handleRegistry.put(objectReference));
            return result;
        }

        result.put("valueKind", "unknown");
        result.put("valuePreview", value.toString());
        return result;
    }

    public static Map<String, Object> inspectObject(ObjectReference reference, ObjectHandleRegistry handleRegistry, int maxFields) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("objectHandleId", handleRegistry.put(reference));
        result.put("typeName", reference.referenceType().name());
        result.put("uniqueId", reference.uniqueID());

        var fields = reference.referenceType().allFields();
        var fieldValues = reference.getValues(fields);
        var items = new java.util.ArrayList<Map<String, Object>>();
        int count = 0;
        for (Field field : fields) {
            if (count >= maxFields) {
                break;
            }
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("fieldName", field.name());
            item.put("type", field.typeName());
            item.putAll(formatValue(fieldValues.get(field), handleRegistry));
            items.add(item);
            count++;
        }
        result.put("fields", items);
        result.put("truncated", fields.size() > maxFields);
        result.put("totalFields", fields.size());
        return result;
    }

    private static String describeObject(ReferenceType referenceType) {
        return referenceType.name();
    }

    public static final class ObjectHandleRegistry {
        private final Map<String, ObjectReference> handles = new LinkedHashMap<>();
        private long nextId = 1L;

        public synchronized String put(ObjectReference reference) {
            for (Map.Entry<String, ObjectReference> entry : handles.entrySet()) {
                if (entry.getValue().equals(reference)) {
                    return entry.getKey();
                }
            }
            String handle = "obj-" + nextId++;
            handles.put(handle, reference);
            return handle;
        }

        public synchronized ObjectReference get(String handle) {
            ObjectReference reference = handles.get(handle);
            if (reference == null) {
                throw new IllegalArgumentException("Unknown object handle: " + handle);
            }
            return reference;
        }

        public synchronized void clear() {
            handles.clear();
            nextId = 1L;
        }
    }
}

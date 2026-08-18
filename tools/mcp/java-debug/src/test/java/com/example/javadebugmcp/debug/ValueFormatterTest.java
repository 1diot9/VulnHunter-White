package com.example.javadebugmcp.debug;

import com.sun.jdi.StringReference;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class ValueFormatterTest {
    @Test
    void nullValueProducesNullPreview() {
        Map<String, Object> result = ValueFormatter.formatValue(null, new ValueFormatter.ObjectHandleRegistry());
        assertEquals("null", result.get("valueKind"));
        assertEquals("null", result.get("valuePreview"));
    }

    @Test
    void stringValueKeepsFullPreview() {
        String longText = "0123456789".repeat(30);
        StringReference reference = stringReference(longText);

        Map<String, Object> result = ValueFormatter.formatValue(reference, new ValueFormatter.ObjectHandleRegistry());

        assertEquals("string", result.get("valueKind"));
        assertEquals(longText, result.get("valuePreview"));
        assertEquals(longText.length(), result.get("length"));
        assertNotNull(result.get("objectHandleId"));
    }

    private static StringReference stringReference(String value) {
        return (StringReference) Proxy.newProxyInstance(
                ValueFormatterTest.class.getClassLoader(),
                new Class[]{StringReference.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "value" -> value;
                    case "toString" -> value;
                    case "equals" -> proxy == args[0];
                    case "hashCode" -> System.identityHashCode(proxy);
                    default -> throw new UnsupportedOperationException("Unexpected call: " + method.getName());
                });
    }
}

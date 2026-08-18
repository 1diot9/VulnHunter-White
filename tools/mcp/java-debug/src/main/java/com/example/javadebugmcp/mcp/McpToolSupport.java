package com.example.javadebugmcp.mcp;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.modelcontextprotocol.json.McpJsonMapper;
import io.modelcontextprotocol.server.McpServerFeatures;
import io.modelcontextprotocol.spec.McpSchema;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

final class McpToolSupport {
    private final ObjectMapper objectMapper;
    private final McpJsonMapper mcpJsonMapper;

    McpToolSupport(ObjectMapper objectMapper, McpJsonMapper mcpJsonMapper) {
        this.objectMapper = objectMapper;
        this.mcpJsonMapper = mcpJsonMapper;
    }

    McpServerFeatures.SyncToolSpecification spec(
            String name,
            String description,
            String inputSchema,
            ThrowingToolHandler handler) {
        McpSchema.Tool tool = McpSchema.Tool.builder()
                .name(name)
                .description(description)
                .inputSchema(mcpJsonMapper, inputSchema)
                .build();
        return new McpServerFeatures.SyncToolSpecification(tool, (exchange, arguments) -> {
            try {
                return toCallToolResult(handler.handle(arguments));
            } catch (Exception exception) {
                return errorResult(exception);
            }
        });
    }

    String emptySchema() {
        return "{\"type\":\"object\",\"properties\":{},\"required\":[]}";
    }

    String schema(Object... values) {
        try {
            var root = objectMapper.createObjectNode();
            root.put("type", "object");
            var properties = root.putObject("properties");
            var required = root.putArray("required");
            for (int index = 0; index < values.length; index += 3) {
                String fieldName = (String) values[index];
                String fieldType = (String) values[index + 1];
                boolean isRequired = (boolean) values[index + 2];
                properties.putObject(fieldName).put("type", fieldType);
                if (isRequired) {
                    required.add(fieldName);
                }
            }
            return objectMapper.writeValueAsString(root);
        } catch (JsonProcessingException exception) {
            throw new IllegalStateException("Failed to serialize tool schema", exception);
        }
    }

    String requiredText(Map<String, Object> arguments, String field) {
        Object value = arguments.get(field);
        if (value == null) {
            throw new IllegalArgumentException("Missing required field: " + field);
        }
        String text = value.toString();
        if (text.isBlank()) {
            throw new IllegalArgumentException("Missing required field: " + field);
        }
        return text;
    }

    String text(Map<String, Object> arguments, String field, String defaultValue) {
        Object value = arguments.get(field);
        if (value == null) {
            return defaultValue;
        }
        String text = value.toString();
        return text.isBlank() ? defaultValue : text;
    }

    String nullableText(Map<String, Object> arguments, String field) {
        Object value = arguments.get(field);
        if (value == null) {
            return null;
        }
        String text = value.toString();
        return text.isBlank() ? null : text;
    }

    int intValue(Map<String, Object> arguments, String field, int defaultValue) {
        Object value = arguments.get(field);
        if (value == null) {
            return defaultValue;
        }
        if (value instanceof Number number) {
            return number.intValue();
        }
        return Integer.parseInt(value.toString());
    }

    boolean booleanValue(Map<String, Object> arguments, String field, boolean defaultValue) {
        Object value = arguments.get(field);
        if (value == null) {
            return defaultValue;
        }
        if (value instanceof Boolean booleanValue) {
            return booleanValue;
        }
        return Boolean.parseBoolean(value.toString());
    }

    Integer nullableInt(Map<String, Object> arguments, String field) {
        Object value = arguments.get(field);
        if (value == null) {
            return null;
        }
        if (value instanceof Number number) {
            return number.intValue();
        }
        return Integer.parseInt(value.toString());
    }

    List<String> stringList(Map<String, Object> arguments, String field) {
        Object value = arguments.get(field);
        if (value == null) {
            return List.of();
        }
        if (!(value instanceof List<?> items)) {
            throw new IllegalArgumentException("Field must be an array: " + field);
        }
        List<String> result = new ArrayList<>();
        for (Object item : items) {
            if (item == null) {
                continue;
            }
            String text = item.toString().trim();
            if (!text.isEmpty()) {
                result.add(text);
            }
        }
        return result;
    }

    List<Map<String, Object>> objectMapList(Map<String, Object> arguments, String field) {
        Object value = arguments.get(field);
        if (value == null) {
            throw new IllegalArgumentException("Missing required field: " + field);
        }
        if (!(value instanceof List<?> items)) {
            throw new IllegalArgumentException("Field must be an array: " + field);
        }
        List<Map<String, Object>> result = new ArrayList<>();
        int index = 0;
        for (Object item : items) {
            if (item == null) {
                throw new IllegalArgumentException("Array item must not be null: " + field + "[" + index + "]");
            }
            if (item instanceof Map<?, ?> mapItem) {
                @SuppressWarnings("unchecked")
                Map<String, Object> typed = (Map<String, Object>) mapItem;
                result.add(typed);
            } else if (item instanceof String text) {
                result.add(parseJsonObject(text, field, index));
            } else {
                throw new IllegalArgumentException(
                        "Array item must be an object or JSON object string: " + field + "[" + index + "]");
            }
            index++;
        }
        return result;
    }

    String breakpointBatchSchema() {
        return "{"
                + "\"type\":\"object\","
                + "\"properties\":{"
                + "\"breakpoints\":{"
                + "\"type\":\"array\","
                + "\"items\":{"
                + "\"type\":\"object\","
                + "\"properties\":{"
                + "\"className\":{\"type\":\"string\"},"
                + "\"line\":{\"type\":\"integer\"},"
                + "\"methodName\":{\"type\":\"string\"},"
                + "\"suspendPolicy\":{\"type\":\"string\"},"
                + "\"condition\":{\"type\":\"string\"},"
                + "\"hitCount\":{\"type\":\"integer\"},"
                + "\"logMessage\":{\"type\":\"string\"}"
                + "},"
                + "\"required\":[\"className\"]"
                + "}"
                + "}"
                + "},"
                + "\"required\":[\"breakpoints\"]"
                + "}";
    }

    private Map<String, Object> parseJsonObject(String text, String field, int index) {
        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> parsed = objectMapper.readValue(text, Map.class);
            return parsed;
        } catch (JsonProcessingException exception) {
            throw new IllegalArgumentException(
                    "Array item must be a JSON object string: " + field + "[" + index + "]", exception);
        }
    }

    private McpSchema.CallToolResult toCallToolResult(Map<String, Object> data) {
        try {
            return McpSchema.CallToolResult.builder()
                    .structuredContent(data)
                    .addTextContent(objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(data))
                    .isError(false)
                    .build();
        } catch (JsonProcessingException exception) {
            throw new IllegalStateException("Failed to serialize tool result", exception);
        }
    }

    private McpSchema.CallToolResult errorResult(Exception exception) {
        return McpSchema.CallToolResult.builder()
                .addTextContent(exception.getMessage() == null ? exception.getClass().getName() : exception.getMessage())
                .isError(true)
                .build();
    }

    @FunctionalInterface
    interface ThrowingToolHandler {
        Map<String, Object> handle(Map<String, Object> arguments) throws Exception;
    }
}

package com.example.javadebugmcp.mcp;

import com.example.javadebugmcp.debug.DebugSessionManager;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.modelcontextprotocol.server.McpServer;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.server.transport.StdioServerTransportProvider;
import io.modelcontextprotocol.json.McpJsonMapper;
import io.modelcontextprotocol.json.jackson.JacksonMcpJsonMapper;
import io.modelcontextprotocol.spec.McpSchema;

import java.util.concurrent.CountDownLatch;

public final class OfficialMcpServerBootstrap {
    private final DebugSessionManager debugSessionManager;
    private final ObjectMapper objectMapper;
    private final McpJsonMapper mcpJsonMapper;
    private final McpToolSupport toolSupport;

    public OfficialMcpServerBootstrap(DebugSessionManager debugSessionManager) {
        this.debugSessionManager = debugSessionManager;
        this.objectMapper = new ObjectMapper();
        this.mcpJsonMapper = new JacksonMcpJsonMapper(objectMapper);
        this.toolSupport = new McpToolSupport(objectMapper, mcpJsonMapper);
    }

    public void run() throws Exception {
        StdioServerTransportProvider transportProvider = new StdioServerTransportProvider(mcpJsonMapper);
        McpSyncServer server = McpServer.sync(transportProvider)
                .jsonMapper(mcpJsonMapper)
                .serverInfo("java-debug-mcp", "0.1.0")
                .capabilities(McpSchema.ServerCapabilities.builder().tools(true).build())
                .tools(new DebugToolSpecifications(debugSessionManager, toolSupport).build())
                .build();
        Runtime.getRuntime().addShutdownHook(new Thread(server::closeGracefully, "mcp-shutdown"));
        new CountDownLatch(1).await();
    }
}

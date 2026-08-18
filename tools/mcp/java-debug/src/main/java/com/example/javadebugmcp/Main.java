package com.example.javadebugmcp;

import com.example.javadebugmcp.debug.DebugSessionManager;
import com.example.javadebugmcp.mcp.OfficialMcpServerBootstrap;

public final class Main {
    private Main() {
    }

    public static void main(String[] args) throws Exception {
        DebugSessionManager debugSessionManager = new DebugSessionManager();
        OfficialMcpServerBootstrap bootstrap = new OfficialMcpServerBootstrap(debugSessionManager);
        bootstrap.run();
    }
}

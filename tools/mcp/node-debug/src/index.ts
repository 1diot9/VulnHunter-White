#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { CDPDebugger } from "./debug/debug-session.js";

function jsonResult(data: any) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }],
  };
}

function errorResult(err: unknown) {
  const message = err instanceof Error ? err.message : String(err);
  return {
    isError: true as const,
    content: [{ type: "text" as const, text: message }],
  };
}

const session = new CDPDebugger();

const server = new McpServer(
  { name: "node-debug-mcp", version: "1.0.0" },
  { capabilities: { tools: {} } },
);

// ── Connection ────────────────────────────────────────────────────

server.registerTool(
  "debug_connect",
  {
    description:
      "Connect to a Node.js process started with --inspect or --inspect-brk.",
    inputSchema: {
      host: z
        .string()
        .optional()
        .default("127.0.0.1")
        .describe("Debug host"),
      port: z
        .number()
        .int()
        .min(1)
        .max(65535)
        .optional()
        .default(9229)
        .describe("Debug port (default: 9229)"),
    },
  },
  async ({ host, port }) => {
    try {
      return jsonResult(await session.connect(host, port));
    } catch (err) {
      return errorResult(err);
    }
  },
);

server.registerTool(
  "debug_disconnect",
  {
    description: "Disconnect from the Node.js debug session.",
    inputSchema: {},
  },
  async () => {
    try {
      return jsonResult(await session.disconnect());
    } catch (err) {
      return errorResult(err);
    }
  },
);

server.registerTool(
  "debug_status",
  {
    description: "Return current debug session status.",
    inputSchema: {},
  },
  async () => {
    try {
      return jsonResult(session.getStatus());
    } catch (err) {
      return errorResult(err);
    }
  },
);

// ── Scripts ───────────────────────────────────────────────────────

server.registerTool(
  "debug_list_scripts",
  {
    description: "List loaded JavaScript files. Use filter to narrow results.",
    inputSchema: {
      filter: z
        .string()
        .optional()
        .describe("Filter scripts by URL substring"),
      includeNodeModules: z
        .boolean()
        .optional()
        .default(false)
        .describe("Include node_modules scripts"),
    },
  },
  async ({ filter, includeNodeModules }) => {
    try {
      let scripts = session.listScripts(filter);
      if (!includeNodeModules) {
        scripts = scripts.filter((s) => !s.url.includes("node_modules"));
      }
      return jsonResult({ count: scripts.length, scripts });
    } catch (err) {
      return errorResult(err);
    }
  },
);

server.registerTool(
  "debug_get_script_source",
  {
    description: "Get the source code of a loaded script.",
    inputSchema: {
      scriptId: z.string().describe("Script ID from debug_list_scripts"),
    },
  },
  async ({ scriptId }) => {
    try {
      return jsonResult({ scriptId, source: await session.getScriptSource(scriptId) });
    } catch (err) {
      return errorResult(err);
    }
  },
);

server.registerTool(
  "debug_search_in_scripts",
  {
    description: "Search for a string or regex across all loaded scripts.",
    inputSchema: {
      query: z.string().describe("Search query"),
      caseSensitive: z.boolean().optional().default(false),
      isRegex: z.boolean().optional().default(false),
    },
  },
  async ({ query, caseSensitive, isRegex }) => {
    try {
      const results = await session.searchInScripts(query, caseSensitive, isRegex);
      const totalMatches = results.reduce((s, r) => s + r.matches.length, 0);
      return jsonResult({ query, totalMatches, results });
    } catch (err) {
      return errorResult(err);
    }
  },
);

// ── Breakpoints ───────────────────────────────────────────────────

server.registerTool(
  "debug_set_breakpoint",
  {
    description:
      "Set a breakpoint by file URL/path and line number. Supports conditional breakpoints.",
    inputSchema: {
      url: z
        .string()
        .optional()
        .describe("File URL or path (smart-matched against loaded scripts)"),
      scriptId: z
        .string()
        .optional()
        .describe("Script ID (alternative to url)"),
      lineNumber: z.number().int().min(0).describe("Line number (0-based)"),
      columnNumber: z.number().int().min(0).optional(),
      condition: z
        .string()
        .optional()
        .describe("Condition expression for conditional breakpoint"),
    },
  },
  async ({ url, scriptId, lineNumber, columnNumber, condition }) => {
    try {
      return jsonResult(
        await session.setBreakpoint({ url, scriptId, lineNumber, columnNumber, condition }),
      );
    } catch (err) {
      return errorResult(err);
    }
  },
);

server.registerTool(
  "debug_remove_breakpoint",
  {
    description: 'Remove a breakpoint by its ID (e.g., "bp-1").',
    inputSchema: {
      breakpointId: z.string().describe('Breakpoint ID (e.g., "bp-1")'),
    },
  },
  async ({ breakpointId }) => {
    try {
      return jsonResult(await session.removeBreakpoint(breakpointId));
    } catch (err) {
      return errorResult(err);
    }
  },
);

server.registerTool(
  "debug_list_breakpoints",
  {
    description: "List all active breakpoints.",
    inputSchema: {},
  },
  async () => {
    try {
      return jsonResult({ breakpoints: session.listBreakpoints() });
    } catch (err) {
      return errorResult(err);
    }
  },
);

// ── Execution Control ─────────────────────────────────────────────

server.registerTool(
  "debug_wait_for_pause",
  {
    description:
      "Wait for the next breakpoint hit or pause event. Use after setting a breakpoint and triggering the code path (e.g., sending an HTTP request).",
    inputSchema: {
      waitTimeoutMs: z
        .number()
        .int()
        .min(1000)
        .max(120000)
        .optional()
        .default(30000)
        .describe("Max wait time in ms (default: 30000)"),
    },
  },
  async ({ waitTimeoutMs }) => {
    try {
      return jsonResult(await session.waitForPause(waitTimeoutMs));
    } catch (err) {
      return errorResult(err);
    }
  },
);

server.registerTool(
  "debug_pause",
  {
    description: "Force-pause JavaScript execution immediately.",
    inputSchema: {},
  },
  async () => {
    try {
      return jsonResult(await session.pause());
    } catch (err) {
      return errorResult(err);
    }
  },
);

server.registerTool(
  "debug_resume",
  {
    description:
      "Resume execution. Blocks until the next breakpoint hit or timeout.",
    inputSchema: {
      waitTimeoutMs: z
        .number()
        .int()
        .min(1000)
        .max(120000)
        .optional()
        .default(30000)
        .describe("Max wait time in ms (default: 30000)"),
    },
  },
  async ({ waitTimeoutMs }) => {
    try {
      return jsonResult(await session.resume(waitTimeoutMs));
    } catch (err) {
      return errorResult(err);
    }
  },
);

server.registerTool(
  "debug_step",
  {
    description: 'Step through code: "into", "over", or "out".',
    inputSchema: {
      kind: z.enum(["into", "over", "out"]).describe("Step kind"),
      waitTimeoutMs: z
        .number()
        .int()
        .min(1000)
        .max(120000)
        .optional()
        .default(30000),
    },
  },
  async ({ kind, waitTimeoutMs }) => {
    try {
      return jsonResult(await session.step(kind, waitTimeoutMs));
    } catch (err) {
      return errorResult(err);
    }
  },
);

// ── Inspection ────────────────────────────────────────────────────

server.registerTool(
  "debug_evaluate",
  {
    description:
      "Evaluate a JavaScript expression. When paused, evaluates in the call frame context. Supports await when running.",
    inputSchema: {
      expression: z.string().describe("JavaScript expression"),
      frameIndex: z
        .number()
        .int()
        .min(0)
        .optional()
        .describe("Stack frame index (0 = top, only when paused)"),
    },
  },
  async ({ expression, frameIndex }) => {
    try {
      return jsonResult(await session.evaluate(expression, frameIndex));
    } catch (err) {
      return errorResult(err);
    }
  },
);

server.registerTool(
  "debug_get_call_stack",
  {
    description: "Get the current call stack (only when paused).",
    inputSchema: {},
  },
  async () => {
    try {
      return jsonResult(session.getCallStack());
    } catch (err) {
      return errorResult(err);
    }
  },
);

server.registerTool(
  "debug_get_scope_variables",
  {
    description:
      "Get variables from a scope in the call stack (only when paused). Skips the global scope by default.",
    inputSchema: {
      frameIndex: z.number().int().min(0).optional().default(0).describe("Stack frame index"),
      scopeIndex: z
        .number()
        .int()
        .min(0)
        .optional()
        .describe("Scope index within the frame. Omit for all non-global scopes."),
      maxProperties: z
        .number()
        .int()
        .min(1)
        .optional()
        .describe(
          "Maximum number of variables to return per scope. Use to avoid oversized responses from large scopes.",
        ),
      includeModuleScope: z
        .boolean()
        .optional()
        .default(false)
        .describe(
          "Include module-level scope variables. Default false to avoid large output from module globals.",
        ),
    },
  },
  async ({ frameIndex, scopeIndex, maxProperties, includeModuleScope }) => {
    try {
      return jsonResult(
        await session.getScopeVariables(frameIndex, scopeIndex, maxProperties, includeModuleScope),
      );
    } catch (err) {
      return errorResult(err);
    }
  },
);

server.registerTool(
  "debug_get_object_properties",
  {
    description:
      "Expand an object to see its properties. Use the objectId from evaluate or scope variables.",
    inputSchema: {
      objectId: z.string().describe("Remote object ID"),
      ownOnly: z
        .boolean()
        .optional()
        .default(true)
        .describe("Only own properties (exclude inherited)"),
    },
  },
  async ({ objectId, ownOnly }) => {
    try {
      return jsonResult({ properties: await session.getObjectProperties(objectId, ownOnly) });
    } catch (err) {
      return errorResult(err);
    }
  },
);

server.registerTool(
  "debug_get_runtime_info",
  {
    description: "Get Node.js runtime information (memory, version, process info).",
    inputSchema: {},
  },
  async () => {
    try {
      return jsonResult(await session.getRuntimeInfo());
    } catch (err) {
      return errorResult(err);
    }
  },
);

// ── Events ────────────────────────────────────────────────────────

server.registerTool(
  "debug_get_events",
  {
    description:
      "Get recent debug events (breakpoint hits, steps, exceptions). Use sinceId for incremental polling.",
    inputSchema: {
      limit: z.number().int().min(1).max(200).optional().default(50),
      sinceId: z
        .number()
        .int()
        .optional()
        .describe("Only return events with id > sinceId"),
    },
  },
  async ({ limit, sinceId }) => {
    try {
      return jsonResult({ events: session.getEvents(limit, sinceId) });
    } catch (err) {
      return errorResult(err);
    }
  },
);

server.registerTool(
  "debug_get_last_stop_event",
  {
    description: "Get the most recent stop event with full context.",
    inputSchema: {},
  },
  async () => {
    try {
      return jsonResult(session.getLastStopEvent());
    } catch (err) {
      return errorResult(err);
    }
  },
);

// ── Start ─────────────────────────────────────────────────────────

const transport = new StdioServerTransport();
await server.connect(transport);
console.error("[node-debug-mcp] Server started on stdio");

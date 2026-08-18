/**
 * MCP End-to-End Test — simulates an AI agent using the Node Debug MCP
 * to analyze a vulnerable web application.
 *
 * Usage:
 *   1. node --inspect demo/vuln-app/app.mjs
 *   2. node test/mcp-e2e.mjs
 */
import { spawn } from "node:child_process";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const MCP_BIN = path.resolve(__dirname, "..", "dist", "index.js");

// ── MCP Client ──────────────────────────────────────────────────

class McpClient {
  constructor() {
    this._id = 0;
    this._pending = new Map();
    this._buf = "";
    this._proc = null;
  }

  start() {
    return new Promise((resolve, reject) => {
      this._proc = spawn("node", [MCP_BIN], {
        stdio: ["pipe", "pipe", "pipe"],
      });
      this._proc.stdout.on("data", (d) => this._onData(d.toString()));
      this._proc.stderr.on("data", (d) => process.stderr.write(d));
      this._proc.on("error", reject);

      this.call("initialize", {
        protocolVersion: "2024-11-05",
        capabilities: {},
        clientInfo: { name: "mcp-e2e-test", version: "1.0" },
      }).then((r) => {
        this._send({ jsonrpc: "2.0", method: "notifications/initialized" });
        resolve(r);
      });
    });
  }

  async call(method, params) {
    const id = ++this._id;
    return new Promise((resolve, reject) => {
      this._pending.set(id, { resolve, reject });
      this._send({ jsonrpc: "2.0", id, method, params });
      setTimeout(() => {
        if (this._pending.has(id)) {
          this._pending.delete(id);
          reject(new Error(`MCP call '${method}' timed out`));
        }
      }, 60000);
    });
  }

  async tool(name, args = {}) {
    const r = await this.call("tools/call", { name, arguments: args });
    const text = r.content?.[0]?.text;
    if (!text) return r;
    const parsed = JSON.parse(text);
    if (r.isError) throw new Error(text);
    return parsed;
  }

  stop() {
    this._proc?.kill();
  }

  _send(msg) {
    this._proc.stdin.write(JSON.stringify(msg) + "\n");
  }

  _onData(chunk) {
    this._buf += chunk;
    const lines = this._buf.split("\n");
    this._buf = lines.pop();
    for (const line of lines) {
      if (!line.trim()) continue;
      try {
        const msg = JSON.parse(line);
        if (msg.id && this._pending.has(msg.id)) {
          const p = this._pending.get(msg.id);
          this._pending.delete(msg.id);
          if (msg.error) p.reject(new Error(msg.error.message));
          else p.resolve(msg.result);
        }
      } catch { /* skip non-JSON lines */ }
    }
  }
}

// ── HTTP Helper ─────────────────────────────────────────────────

function httpRequest(method, urlPath, body) {
  return new Promise((resolve, reject) => {
    const opts = { hostname: "127.0.0.1", port: 4000, path: urlPath, method };
    if (body) opts.headers = { "Content-Type": "application/json" };
    const req = http.request(opts, (res) => {
      let data = "";
      res.on("data", (c) => (data += c));
      res.on("end", () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(data) }); }
        catch { resolve({ status: res.statusCode, body: data }); }
      });
    });
    req.on("error", reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

// ── Test Runner ─────────────────────────────────────────────────

let total = 0, passed = 0, failed = 0;
function ok(cond, msg) {
  total++;
  if (cond) { passed++; console.log(`  ✓ ${msg}`); }
  else      { failed++; console.error(`  ✗ ${msg}`); }
}

async function run() {
  console.log("\n╔══════════════════════════════════════════════╗");
  console.log("║     MCP End-to-End Debugging Workflow Test   ║");
  console.log("╚══════════════════════════════════════════════╝\n");

  const mcp = new McpClient();
  await mcp.start();

  // ── Phase 1: Connection ───────────────────────────────────────
  console.log("── Phase 1: Connect to target ──");

  const conn = await mcp.tool("debug_connect", { host: "127.0.0.1", port: 9229 });
  ok(conn.status === "connected", `Connected: state=${conn.state}, scripts=${conn.scriptsLoaded}`);

  const status = await mcp.tool("debug_status");
  ok(status.state === "running", `Status: ${status.state}`);

  // ── Phase 2: Reconnaissance ───────────────────────────────────
  console.log("\n── Phase 2: Recon — scripts & runtime ──");

  const scripts = await mcp.tool("debug_list_scripts", { filter: "vuln-app" });
  ok(scripts.count > 0, `Found target script: ${scripts.scripts[0]?.url}`);
  const targetScriptId = scripts.scripts[0]?.scriptId;

  const src = await mcp.tool("debug_get_script_source", { scriptId: targetScriptId });
  ok(src.source.includes("findUser"), "Source contains findUser function");
  ok(src.source.includes("exec(cmd"), "Source contains exec() call");
  ok(src.source.includes("eval(expr)"), "Source contains eval() — SSTI vulnerability");

  const searchExec = await mcp.tool("debug_search_in_scripts", { query: "exec\\(", isRegex: true });
  ok(searchExec.totalMatches > 0, `Found ${searchExec.totalMatches} exec() calls`);

  const searchEval = await mcp.tool("debug_search_in_scripts", { query: "eval(" });
  ok(searchEval.totalMatches > 0, `Found eval() in ${searchEval.results.length} scripts`);

  const info = await mcp.tool("debug_get_runtime_info");
  ok(info.process.version !== undefined, `Node ${info.process.version}, PID ${info.process.pid}`);
  ok(info.heap.usedSize > 0, `Heap: ${(info.heap.usedSize / 1024 / 1024).toFixed(1)}MB used`);

  // ── Phase 3: SQL Injection Analysis ───────────────────────────
  console.log("\n── Phase 3: SQL Injection — breakpoint on findUser ──");

  // Find the line number of findUser
  const findUserSearch = await mcp.tool("debug_search_in_scripts", {
    query: "const query = `SELECT",
    caseSensitive: true,
  });
  ok(findUserSearch.totalMatches > 0, "Located SQL query construction line");
  const sqlLine = findUserSearch.results[0]?.matches[0]?.lineNumber;
  console.log(`    SQL query at line ${sqlLine}`);

  const bp1 = await mcp.tool("debug_set_breakpoint", {
    scriptId: targetScriptId,
    lineNumber: sqlLine,
  });
  ok(bp1.id === "bp-1", `Breakpoint set: ${bp1.id} at line ${sqlLine}`);

  // Trigger normal login
  console.log("    Triggering POST /login ...");
  const loginPromise = httpRequest("POST", "/login", {
    username: "admin",
    password: "admin123",
  });

  const wait1 = await mcp.tool("debug_wait_for_pause", { waitTimeoutMs: 5000 });
  ok(wait1.status === "stopped", `Paused in ${wait1.topFrame?.functionName} at line ${wait1.topFrame?.lineNumber}`);

  // Inspect the SQL query being built
  const stack1 = await mcp.tool("debug_get_call_stack");
  ok(stack1.frames[0].functionName === "findUser", `Top frame: ${stack1.frames[0].functionName}`);

  const vars1 = await mcp.tool("debug_get_scope_variables", { frameIndex: 0 });
  const fieldVar = vars1.scopes[0]?.variables?.find((v) => v.name === "field");
  const valueVar = vars1.scopes[0]?.variables?.find((v) => v.name === "value");
  ok(fieldVar?.value === "username", `field = "${fieldVar?.value}"`);
  ok(valueVar?.value === "admin", `value = "${valueVar?.value}"`);

  // Step over to see the constructed query
  const step1 = await mcp.tool("debug_step", { kind: "over" });
  ok(step1.status === "stopped", "Stepped over query construction");

  const queryEval = await mcp.tool("debug_evaluate", { expression: "query" });
  ok(
    queryEval.value.includes("SELECT * FROM users WHERE username = 'admin'"),
    `Query: ${queryEval.value}`,
  );

  // Resume and complete the login
  await mcp.tool("debug_resume", { waitTimeoutMs: 2000 });
  const loginResult = await loginPromise;
  ok(loginResult.status === 200, `Login succeeded: ${loginResult.body.user?.username}`);
  const adminToken = loginResult.body.token;

  // ── Phase 4: SQL Injection Attack ─────────────────────────────
  console.log("\n── Phase 4: SQL Injection attack payload ──");

  const sqliPromise = httpRequest("POST", "/login", {
    username: "' OR '1'='1",
    password: "anything",
  });

  const wait2 = await mcp.tool("debug_wait_for_pause", { waitTimeoutMs: 5000 });
  ok(wait2.status === "stopped", "Breakpoint hit for SQLi payload");

  const sqliVars = await mcp.tool("debug_get_scope_variables", { frameIndex: 0 });
  const sqliValue = sqliVars.scopes[0]?.variables?.find((v) => v.name === "value");
  ok(sqliValue?.value === "' OR '1'='1", `Injected value: "${sqliValue?.value}"`);

  await mcp.tool("debug_step", { kind: "over" });
  const sqliQuery = await mcp.tool("debug_evaluate", { expression: "query" });
  ok(
    sqliQuery.value.includes("' OR '1'='1"),
    `Injected query: ${sqliQuery.value}`,
  );

  // Evaluate what the query would return
  const sqliResult = await mcp.tool("debug_evaluate", {
    expression: "value.includes(\"' OR '1'='1\")",
  });
  ok(sqliResult.value === true, "Injection condition evaluates to true → returns all users");

  await mcp.tool("debug_resume", { waitTimeoutMs: 2000 });
  const sqliResponse = await sqliPromise;
  ok(sqliResponse.status === 200, `SQLi login succeeded: got token`);

  // Remove SQL breakpoint
  await mcp.tool("debug_remove_breakpoint", { breakpointId: "bp-1" });

  // ── Phase 5: SSTI Analysis ────────────────────────────────────
  console.log("\n── Phase 5: SSTI — breakpoint on renderTemplate ──");

  const evalSearch = await mcp.tool("debug_search_in_scripts", {
    query: "return String(eval(expr))",
  });
  const evalLine = evalSearch.results[0]?.matches[0]?.lineNumber;
  ok(evalLine !== undefined, `eval() sink at line ${evalLine}`);

  const bp2 = await mcp.tool("debug_set_breakpoint", {
    scriptId: targetScriptId,
    lineNumber: evalLine,
  });
  ok(bp2.id === "bp-2", `Breakpoint set: ${bp2.id} at eval() line ${evalLine}`);

  // Trigger SSTI
  console.log("    Triggering POST /render with SSTI payload ...");
  const sstiPromise = httpRequest("POST", "/render", {
    template: "Result: ${7*7}",
    data: { name: "test" },
  });

  const wait3 = await mcp.tool("debug_wait_for_pause", { waitTimeoutMs: 5000 });
  ok(wait3.status === "stopped", `Paused at eval(): ${wait3.topFrame?.functionName}`);

  const exprEval = await mcp.tool("debug_evaluate", { expression: "expr" });
  ok(exprEval.value === "7*7", `Expression being eval'd: "${exprEval.value}"`);

  // Check what eval would produce
  const evalResultCheck = await mcp.tool("debug_evaluate", {
    expression: "String(eval(expr))",
  });
  ok(evalResultCheck.value === "49", `eval("7*7") = ${evalResultCheck.value}`);

  await mcp.tool("debug_resume", { waitTimeoutMs: 2000 });
  const sstiResponse = await sstiPromise;
  ok(
    sstiResponse.body.rendered === "Result: 49",
    `SSTI rendered: "${sstiResponse.body.rendered}"`,
  );

  await mcp.tool("debug_remove_breakpoint", { breakpointId: "bp-2" });

  // ── Phase 6: Command Injection ────────────────────────────────
  console.log("\n── Phase 6: Command Injection — breakpoint on exec() ──");

  const execSearch = await mcp.tool("debug_search_in_scripts", {
    query: "exec(cmd,",
  });
  const execLine = execSearch.results[0]?.matches[0]?.lineNumber;

  const bp3 = await mcp.tool("debug_set_breakpoint", {
    scriptId: targetScriptId,
    lineNumber: execLine,
  });
  ok(bp3.id === "bp-3", `Breakpoint at exec() line ${execLine}`);

  // Trigger command injection (need admin session)
  console.log("    Triggering GET /exec?cmd=id with admin token ...");
  const execPromise = new Promise((resolve, reject) => {
    const req = http.request(
      { hostname: "127.0.0.1", port: 4000, path: "/exec?cmd=id", method: "GET",
        headers: { Authorization: `Bearer ${adminToken}` } },
      (res) => {
        let data = "";
        res.on("data", (c) => (data += c));
        res.on("end", () => resolve(JSON.parse(data)));
      },
    );
    req.on("error", reject);
    req.end();
  });

  const wait4 = await mcp.tool("debug_wait_for_pause", { waitTimeoutMs: 5000 });
  ok(wait4.status === "stopped", "Paused at exec()");

  const cmdEval = await mcp.tool("debug_evaluate", { expression: "cmd" });
  ok(cmdEval.value === "id", `Command: "${cmdEval.value}"`);

  // Check the full call stack to trace who called exec()
  const execStack = await mcp.tool("debug_get_call_stack");
  console.log("    Call stack:");
  for (const f of execStack.frames.slice(0, 4)) {
    console.log(`      ${f.index}: ${f.functionName || "(anonymous)"} @ line ${f.lineNumber}`);
  }
  ok(execStack.frames.length >= 2, `Stack depth: ${execStack.frames.length}`);

  await mcp.tool("debug_resume", { waitTimeoutMs: 5000 });
  const execResponse = await execPromise;
  ok(execResponse.stdout !== undefined, `exec() output: "${execResponse.stdout}"`);

  await mcp.tool("debug_remove_breakpoint", { breakpointId: "bp-3" });

  // ── Phase 7: Runtime Introspection ────────────────────────────
  console.log("\n── Phase 7: Runtime introspection via evaluate ──");

  // ESM modules scope variables privately — to access `db`, we need to
  // pause inside the module and evaluate on the call frame.
  // Set a breakpoint on the /debug endpoint which accesses db.
  const debugSearch = await mcp.tool("debug_search_in_scripts", {
    query: "users: db.users.length",
  });
  const debugLine = debugSearch.results[0]?.matches[0]?.lineNumber;
  const bp4 = await mcp.tool("debug_set_breakpoint", {
    scriptId: targetScriptId,
    lineNumber: debugLine,
  });

  const debugPromise = httpRequest("GET", "/debug");
  const wait5 = await mcp.tool("debug_wait_for_pause", { waitTimeoutMs: 5000 });
  ok(wait5.status === "stopped", `Paused in /debug handler at line ${debugLine}`);

  // Now we can evaluate module-scoped variables on the call frame
  const dbState = await mcp.tool("debug_evaluate", {
    expression: "JSON.stringify({ users: db.users.length, sessions: db.sessions.size })",
  });
  const dbStateStr = dbState.value || dbState.description || JSON.stringify(dbState);
  ok(dbStateStr.includes("users"), `DB state: ${dbStateStr}`);

  // Inspect the users array via call-frame evaluation
  const usersEval = await mcp.tool("debug_evaluate", {
    expression: "db.users.map(u => u.username + ':' + u.role)",
  });
  if (usersEval.objectId) {
    const propsResult = await mcp.tool("debug_get_object_properties", {
      objectId: usersEval.objectId,
    });
    const props = propsResult.properties || propsResult;
    const userList = (Array.isArray(props) ? props : [])
      .filter((p) => p.type === "string")
      .map((p) => p.value)
      .join(", ");
    ok(userList?.includes("admin"), `Users: ${userList}`);
  } else {
    ok(false, "Could not inspect users array");
  }

  // Check sessions — still paused in module scope
  const sessionCount = await mcp.tool("debug_evaluate", {
    expression: "db.sessions.size",
  });
  ok(sessionCount.value >= 1, `Active sessions: ${sessionCount.value}`);

  // Resume and cleanup the introspection breakpoint
  await mcp.tool("debug_resume", { waitTimeoutMs: 2000 });
  await debugPromise;
  await mcp.tool("debug_remove_breakpoint", { breakpointId: bp4.id });

  // ── Phase 8: Events & Cleanup ─────────────────────────────────
  console.log("\n── Phase 8: Events & cleanup ──");

  const events = await mcp.tool("debug_get_events", { limit: 100 });
  ok(events.events.length > 0, `Total events recorded: ${events.events.length}`);

  const stopEvents = events.events.filter((e) => e.type === "stopped");
  ok(stopEvents.length >= 4, `Breakpoint hits: ${stopEvents.length}`);

  const bpList = await mcp.tool("debug_list_breakpoints");
  ok(bpList.breakpoints.length === 0, `Remaining breakpoints: ${bpList.breakpoints.length}`);

  await mcp.tool("debug_disconnect");
  const finalStatus = await mcp.tool("debug_status");
  ok(finalStatus.state === "disconnected", "Disconnected");

  mcp.stop();

  // ── Summary ───────────────────────────────────────────────────
  console.log("\n╔══════════════════════════════════════════════╗");
  console.log(`║  Results: ${passed} passed, ${failed} failed, ${total} total       ║`);
  console.log("╚══════════════════════════════════════════════╝\n");
  process.exit(failed > 0 ? 1 : 0);
}

run().catch((err) => {
  console.error("\nFATAL:", err);
  process.exit(1);
});

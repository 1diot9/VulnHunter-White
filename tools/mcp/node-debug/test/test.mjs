import { CDPDebugger } from "../dist/debug/debug-session.js";
import http from "node:http";

const dbg = new CDPDebugger();
let passed = 0;
let failed = 0;

function assert(cond, msg) {
  if (cond) {
    console.log(`  ✓ ${msg}`);
    passed++;
  } else {
    console.error(`  ✗ ${msg}`);
    failed++;
  }
}

function httpGet(path) {
  return new Promise((resolve, reject) => {
    http.get(`http://localhost:3456${path}`, (res) => {
      let data = "";
      res.on("data", (c) => (data += c));
      res.on("end", () => resolve(JSON.parse(data)));
    }).on("error", reject);
  });
}

async function run() {
  console.log("\n=== Node Debug MCP - Test Suite ===\n");

  // 1. Connect
  console.log("[1] Connection");
  const conn = await dbg.connect("127.0.0.1", 9229);
  assert(conn.status === "connected", `connect: ${conn.status}`);
  assert(conn.scriptsLoaded > 0, `scripts loaded: ${conn.scriptsLoaded}`);

  // 2. Status
  console.log("[2] Status");
  const status = dbg.getStatus();
  assert(status.state === "running" || status.state === "suspended", `state: ${status.state}`);

  // 3. List scripts
  console.log("[3] Scripts");
  const scripts = dbg.listScripts("target-app");
  assert(scripts.length > 0, `found target script: ${scripts[0]?.url}`);
  const targetScriptId = scripts[0]?.scriptId;

  // 4. Get script source
  console.log("[4] Script source");
  const source = await dbg.getScriptSource(targetScriptId);
  assert(source.includes("fibonacci"), "source contains fibonacci");

  // 5. Search in scripts
  console.log("[5] Search");
  const searchResults = await dbg.searchInScripts("processQuery");
  assert(searchResults.length > 0, `search found processQuery in ${searchResults.length} files`);

  // 6. Runtime info
  console.log("[6] Runtime info");
  const info = await dbg.getRuntimeInfo();
  assert(info.process.version !== undefined, `node version: ${info.process.version}`);

  // 7. Evaluate (running state)
  console.log("[7] Evaluate (running)");
  const evalResult = await dbg.evaluate("2 + 3");
  assert(evalResult.value === 5, `2 + 3 = ${evalResult.value}`);

  const evalResult2 = await dbg.evaluate("JSON.stringify({a: 1, b: 2})");
  assert(evalResult2.value === '{"a":1,"b":2}', `JSON.stringify works`);

  // 8. Set breakpoint
  console.log("[8] Breakpoints");
  const bp = await dbg.setBreakpoint({
    url: scripts[0].url,
    lineNumber: 8, // inside greet function: const message = `Hello, ${name}!`;
  });
  assert(bp.id === "bp-1", `breakpoint set: ${bp.id}`);

  const bpList = dbg.listBreakpoints();
  assert(bpList.length === 1, `breakpoint count: ${bpList.length}`);

  // 9. Trigger breakpoint via HTTP request (async)
  console.log("[9] Trigger breakpoint");
  const httpPromise = httpGet("/greet?name=TestUser").catch(() => null);

  // Wait for the breakpoint to be hit
  const waitResult = await dbg.waitForPause(5000);
  assert(waitResult.status === "stopped", `wait stopped: ${waitResult.status}`);
  if (waitResult.topFrame) {
    assert(
      waitResult.topFrame.functionName === "greet",
      `stopped in: ${waitResult.topFrame.functionName}`,
    );
  }

  // 10. Call stack
  console.log("[10] Call stack");
  const stack = dbg.getCallStack();
  assert(stack.frames.length > 0, `frame count: ${stack.frames.length}`);
  assert(stack.frames[0].functionName === "greet", `top function: ${stack.frames[0].functionName}`);

  // 11. Scope variables
  console.log("[11] Scope variables");
  const scopeVars = await dbg.getScopeVariables(0);
  assert(scopeVars.scopes.length > 0, `scopes: ${scopeVars.scopes.length}`);
  const localVars = scopeVars.scopes.find((s) => s.type === "local");
  if (localVars) {
    const nameVar = localVars.variables.find((v) => v.name === "name");
    assert(nameVar?.value === "TestUser", `name = ${nameVar?.value}`);
  }

  // 12. Evaluate on frame
  console.log("[12] Evaluate (paused)");
  const frameEval = await dbg.evaluate("name.toUpperCase()");
  assert(frameEval.value === "TESTUSER", `name.toUpperCase() = ${frameEval.value}`);

  // 13. Step
  console.log("[13] Step over");
  const stepResult = await dbg.step("over", 5000);
  assert(stepResult.status === "stopped", `step result: ${stepResult.status}`);

  // 14. Resume to completion
  console.log("[14] Resume");
  const resume2 = await dbg.resume(5000);
  // Either hits the breakpoint again or runs to timeout
  await httpPromise;

  // 15. Conditional breakpoint
  console.log("[15] Conditional breakpoint");
  await dbg.removeBreakpoint("bp-1");
  const condBp = await dbg.setBreakpoint({
    url: scripts[0].url,
    lineNumber: 8,
    condition: 'name === "Special"',
  });
  assert(condBp.condition === 'name === "Special"', "conditional bp set");

  // Regular name - should NOT trigger
  const httpPromise2 = httpGet("/greet?name=Regular").catch(() => null);
  const resume3 = await dbg.waitForPause(2000);
  assert(resume3.waitTimedOut === true, "conditional bp did not trigger for Regular");
  await httpPromise2;

  // Special name - SHOULD trigger
  const httpPromise3 = httpGet("/greet?name=Special").catch(() => null);
  const resume4 = await dbg.waitForPause(5000);
  assert(resume4.status === "stopped", "conditional bp triggered for Special");
  if (resume4.status === "stopped") {
    const ev = await dbg.evaluate("name");
    assert(ev.value === "Special", `name = ${ev.value}`);
    await dbg.resume(2000);
  }
  await httpPromise3;

  // 16. Events
  console.log("[16] Events");
  const events = dbg.getEvents(10);
  assert(events.length > 0, `event count: ${events.length}`);

  // 17. Object properties
  console.log("[17] Object properties");
  const objEval = await dbg.evaluate("({x: 1, y: [2,3], z: {nested: true}})");
  if (objEval.objectId) {
    const props = await dbg.getObjectProperties(objEval.objectId);
    assert(props.length >= 3, `object has ${props.length} properties`);
  }

  // 18. Cleanup
  console.log("[18] Disconnect");
  await dbg.removeBreakpoint(condBp.id);
  const disc = await dbg.disconnect();
  assert(disc.status === "disconnected", `disconnect: ${disc.status}`);

  // Summary
  console.log(`\n=== Results: ${passed} passed, ${failed} failed ===\n`);
  process.exit(failed > 0 ? 1 : 0);
}

run().catch((err) => {
  console.error("Test failed:", err);
  process.exit(1);
});

import WebSocket from "ws";
import http from "node:http";
import {
  SessionState,
  type ScriptInfo,
  type ManagedBreakpoint,
  type StopEventData,
  type CDPCallFrame,
  type EventRecord,
  MAX_EVENT_HISTORY,
  DEFAULT_COMMAND_TIMEOUT_MS,
  DEFAULT_WAIT_TIMEOUT_MS,
} from "./types.js";

interface PendingRequest {
  resolve: (result: any) => void;
  reject: (err: Error) => void;
  timer: ReturnType<typeof setTimeout>;
}

interface StopWaiter {
  promise: Promise<StopEventData>;
  resolve: (data: StopEventData) => void;
  reject: (err: Error) => void;
}

export class CDPDebugger {
  private _ws: WebSocket | null = null;
  private _state: SessionState = SessionState.DISCONNECTED;
  private _nextRequestId = 1;
  private _pendingRequests = new Map<number, PendingRequest>();

  private _scripts = new Map<string, ScriptInfo>();

  private _breakpoints = new Map<string, ManagedBreakpoint>();
  private _cdpBpToInternal = new Map<string, string>();
  private _nextBreakpointId = 1;

  private _stopWaiter: StopWaiter | null = null;
  private _lastStopEvent: StopEventData | null = null;
  private _currentCallFrames: CDPCallFrame[] = [];

  private _eventHistory: EventRecord[] = [];
  private _nextEventId = 1;

  private _host = "";
  private _port = 0;

  get state(): SessionState {
    return this._state;
  }

  // ── Connection ────────────────────────────────────────────────

  async connect(host = "127.0.0.1", port = 9229): Promise<Record<string, any>> {
    if (this._state !== SessionState.DISCONNECTED) {
      throw new Error(`Already connected (state: ${this._state})`);
    }
    this._host = host;
    this._port = port;

    const wsUrl = await this._discoverWsUrl(host, port);
    await this._connectWs(wsUrl);
    this._state = SessionState.RUNNING;

    await this._send("Debugger.enable", {});
    await this._send("Runtime.enable", {});
    await this._send("Runtime.setAsyncCallStackDepth", { maxDepth: 32 });

    // Required for --inspect-brk: tells the runtime to continue loading,
    // which triggers the initial Debugger.paused("Break on start") event.
    await this._send("Runtime.runIfWaitingForDebugger", {});

    // Allow the pause event to arrive
    await new Promise((r) => setTimeout(r, 100));

    this._recordEvent("connected", { host, port, wsUrl });

    return {
      status: "connected",
      host,
      port,
      webSocketUrl: wsUrl,
      state: this._state,
      scriptsLoaded: this._scripts.size,
    };
  }

  async disconnect(): Promise<Record<string, any>> {
    if (this._state === SessionState.DISCONNECTED) {
      return { status: "already_disconnected" };
    }
    try {
      await this._send("Debugger.disable", {});
      await this._send("Runtime.disable", {});
    } catch {
      /* ignore cleanup errors */
    }
    this._cleanup();
    return { status: "disconnected" };
  }

  getStatus(): Record<string, any> {
    return {
      state: this._state,
      host: this._host,
      port: this._port,
      scriptsLoaded: this._scripts.size,
      breakpointsSet: this._breakpoints.size,
      lastStopReason: this._lastStopEvent?.reason ?? null,
    };
  }

  // ── Scripts ───────────────────────────────────────────────────

  listScripts(filter?: string): Array<{ scriptId: string; url: string }> {
    const scripts = Array.from(this._scripts.values())
      .filter((s) => s.url && !s.url.startsWith("node:"))
      .map((s) => ({ scriptId: s.scriptId, url: s.url }));

    if (filter) {
      const lower = filter.toLowerCase();
      return scripts.filter((s) => s.url.toLowerCase().includes(lower));
    }
    return scripts;
  }

  async getScriptSource(scriptId: string): Promise<string> {
    this._ensureConnected();
    const result = await this._send("Debugger.getScriptSource", { scriptId });
    return result.scriptSource;
  }

  async searchInScripts(
    query: string,
    caseSensitive = false,
    isRegex = false,
  ): Promise<any[]> {
    this._ensureConnected();
    const results: any[] = [];

    for (const [scriptId, script] of this._scripts) {
      if (!script.url || script.url.startsWith("node:")) continue;
      try {
        const { result } = await this._send("Debugger.searchInContent", {
          scriptId,
          query,
          caseSensitive,
          isRegex,
        });
        if (result?.length > 0) {
          results.push({ scriptId, url: script.url, matches: result });
        }
      } catch {
        /* skip unsearchable scripts */
      }
    }
    return results;
  }

  // ── Breakpoints ───────────────────────────────────────────────

  async setBreakpoint(params: {
    url?: string;
    scriptId?: string;
    lineNumber: number;
    columnNumber?: number;
    condition?: string;
  }): Promise<ManagedBreakpoint> {
    this._ensureConnected();

    let result: any;
    if (params.scriptId) {
      result = await this._send("Debugger.setBreakpoint", {
        location: {
          scriptId: params.scriptId,
          lineNumber: params.lineNumber,
          columnNumber: params.columnNumber,
        },
        condition: params.condition,
      });
      result.locations = result.actualLocation ? [result.actualLocation] : [];
    } else {
      const resolved = this._resolveScriptUrl(params.url ?? "");
      result = await this._send("Debugger.setBreakpointByUrl", {
        lineNumber: params.lineNumber,
        columnNumber: params.columnNumber,
        condition: params.condition,
        ...resolved,
      });
    }

    const internalId = `bp-${this._nextBreakpointId++}`;
    const bp: ManagedBreakpoint = {
      id: internalId,
      breakpointId: result.breakpointId,
      url: params.url,
      scriptId: params.scriptId,
      lineNumber: params.lineNumber,
      columnNumber: params.columnNumber,
      condition: params.condition,
      locations: result.locations ?? [],
    };

    this._breakpoints.set(internalId, bp);
    this._cdpBpToInternal.set(result.breakpointId, internalId);
    this._recordEvent("breakpointSet", {
      id: internalId,
      breakpointId: result.breakpointId,
      url: params.url,
      lineNumber: params.lineNumber,
    });
    return bp;
  }

  async removeBreakpoint(id: string): Promise<Record<string, any>> {
    this._ensureConnected();
    const bp = this._breakpoints.get(id);
    if (!bp) throw new Error(`Breakpoint not found: ${id}`);

    await this._send("Debugger.removeBreakpoint", {
      breakpointId: bp.breakpointId,
    });
    this._breakpoints.delete(id);
    this._cdpBpToInternal.delete(bp.breakpointId);
    this._recordEvent("breakpointRemoved", { id });
    return { status: "removed", id };
  }

  listBreakpoints(): ManagedBreakpoint[] {
    return Array.from(this._breakpoints.values());
  }

  // ── Execution Control ─────────────────────────────────────────

  async waitForPause(timeoutMs = DEFAULT_WAIT_TIMEOUT_MS): Promise<Record<string, any>> {
    this._ensureConnected();
    if (this._state === SessionState.SUSPENDED) {
      return {
        status: "already_paused",
        ...this._formatStopResult(this._lastStopEvent!),
      };
    }

    const waiter = this._createStopWaiter();
    try {
      const event = (await Promise.race([
        waiter.promise,
        this._timeout(timeoutMs),
      ])) as StopEventData;
      return { status: "stopped", ...this._formatStopResult(event) };
    } catch {
      return { status: "running", waitTimedOut: true };
    } finally {
      this._stopWaiter = null;
    }
  }

  async pause(): Promise<Record<string, any>> {
    this._ensureConnected();
    if (this._state === SessionState.SUSPENDED) {
      return {
        status: "already_paused",
        reason: this._lastStopEvent?.reason,
        ...this._formatStopResult(this._lastStopEvent!),
      };
    }

    const waiter = this._createStopWaiter();
    await this._send("Debugger.pause", {});

    try {
      const event = (await Promise.race([
        waiter.promise,
        this._timeout(DEFAULT_WAIT_TIMEOUT_MS),
      ])) as StopEventData;
      return { status: "paused", ...this._formatStopResult(event) };
    } catch {
      return { status: "pause_sent", note: "No stop event within timeout" };
    } finally {
      this._stopWaiter = null;
    }
  }

  async resume(waitTimeoutMs = DEFAULT_WAIT_TIMEOUT_MS): Promise<Record<string, any>> {
    this._ensureSuspended();
    const waiter = this._createStopWaiter();
    this._state = SessionState.RUNNING;
    await this._send("Debugger.resume", {});

    try {
      const event = (await Promise.race([
        waiter.promise,
        this._timeout(waitTimeoutMs),
      ])) as StopEventData;
      return { status: "stopped", ...this._formatStopResult(event) };
    } catch {
      return { status: "running", waitTimedOut: true };
    } finally {
      this._stopWaiter = null;
    }
  }

  async step(
    kind: "into" | "over" | "out",
    waitTimeoutMs = DEFAULT_WAIT_TIMEOUT_MS,
  ): Promise<Record<string, any>> {
    this._ensureSuspended();
    const method: Record<string, string> = {
      into: "Debugger.stepInto",
      over: "Debugger.stepOver",
      out: "Debugger.stepOut",
    };

    const waiter = this._createStopWaiter();
    this._state = SessionState.RUNNING;
    await this._send(method[kind], {});

    try {
      const event = (await Promise.race([
        waiter.promise,
        this._timeout(waitTimeoutMs),
      ])) as StopEventData;
      return { status: "stopped", ...this._formatStopResult(event) };
    } catch {
      return { status: "running", waitTimedOut: true };
    } finally {
      this._stopWaiter = null;
    }
  }

  // ── Inspection ────────────────────────────────────────────────

  async evaluate(
    expression: string,
    frameIndex?: number,
  ): Promise<Record<string, any>> {
    this._ensureConnected();

    if (
      this._state === SessionState.SUSPENDED &&
      this._currentCallFrames.length > 0
    ) {
      const idx = frameIndex ?? 0;
      if (idx >= this._currentCallFrames.length) {
        throw new Error(
          `Frame index ${idx} out of range (${this._currentCallFrames.length} frames)`,
        );
      }
      const result = await this._send("Debugger.evaluateOnCallFrame", {
        callFrameId: this._currentCallFrames[idx].callFrameId,
        expression,
        generatePreview: true,
        includeCommandLineAPI: true,
        returnByValue: false,
      });
      return this._formatEvalResult(result);
    }

    const result = await this._send("Runtime.evaluate", {
      expression,
      generatePreview: true,
      includeCommandLineAPI: true,
      awaitPromise: true,
      returnByValue: false,
    });
    return this._formatEvalResult(result);
  }

  getCallStack(): Record<string, any> {
    this._ensureSuspended();
    return {
      frames: this._currentCallFrames.map((f, i) => {
        const scriptUrl =
          this._scripts.get(f.location.scriptId)?.url ?? f.url;
        return {
          index: i,
          callFrameId: f.callFrameId,
          functionName: f.functionName || "(anonymous)",
          url: scriptUrl,
          lineNumber: f.location.lineNumber,
          columnNumber: f.location.columnNumber,
          scopes: f.scopeChain.map((s) => ({
            type: s.type,
            name: s.name,
            objectId: s.object.objectId,
          })),
        };
      }),
    };
  }

  async getScopeVariables(
    frameIndex = 0,
    scopeIndex?: number,
    maxProperties?: number,
    includeModuleScope = false,
  ): Promise<Record<string, any>> {
    this._ensureSuspended();
    if (frameIndex >= this._currentCallFrames.length) {
      throw new Error(
        `Frame index ${frameIndex} out of range (${this._currentCallFrames.length} frames)`,
      );
    }

    const frame = this._currentCallFrames[frameIndex];
    const excludeTypes = new Set(["global"]);
    if (!includeModuleScope) excludeTypes.add("module");

    const scopes =
      scopeIndex !== undefined
        ? [frame.scopeChain[scopeIndex]]
        : frame.scopeChain.filter((s) => !excludeTypes.has(s.type));

    const result: any[] = [];
    for (const scope of scopes) {
      if (!scope?.object.objectId) continue;
      const { result: props } = await this._send("Runtime.getProperties", {
        objectId: scope.object.objectId,
        ownProperties: true,
        generatePreview: true,
      });
      let formatted = this._formatProperties(props);
      if (maxProperties !== undefined && formatted.length > maxProperties) {
        const total = formatted.length;
        formatted = formatted.slice(0, maxProperties);
        result.push({
          type: scope.type,
          name: scope.name,
          variables: formatted,
          truncated: { shown: maxProperties, total },
        });
      } else {
        result.push({
          type: scope.type,
          name: scope.name,
          variables: formatted,
        });
      }
    }
    return { frameIndex, scopes: result };
  }

  async getObjectProperties(
    objectId: string,
    ownOnly = true,
  ): Promise<any[]> {
    this._ensureConnected();
    const { result: props, internalProperties } = await this._send(
      "Runtime.getProperties",
      { objectId, ownProperties: ownOnly, generatePreview: true },
    );
    const formatted = this._formatProperties(props);
    if (internalProperties?.length > 0) {
      for (const p of internalProperties) {
        formatted.push({
          name: `[[${p.name}]]`,
          ...this._formatRemoteObject(p.value),
        });
      }
    }
    return formatted;
  }

  async getRuntimeInfo(): Promise<Record<string, any>> {
    this._ensureConnected();

    let heapInfo: Record<string, any> = {};
    try {
      heapInfo = await this._send("Runtime.getHeapUsage", {});
    } catch {
      /* may not be available */
    }

    let processInfo: Record<string, any> = {};
    try {
      const evalResult = await this._send("Runtime.evaluate", {
        expression: `JSON.stringify({
          pid: process.pid,
          version: process.version,
          platform: process.platform,
          arch: process.arch,
          uptime: process.uptime(),
          memoryUsage: process.memoryUsage(),
          cwd: process.cwd(),
          execPath: process.execPath,
          argv: process.argv,
          nodeVersion: process.versions,
        })`,
        returnByValue: true,
        awaitPromise: false,
      });
      if (evalResult.result?.value) {
        processInfo = JSON.parse(evalResult.result.value);
      }
    } catch {
      /* may fail when paused */
    }

    return {
      heap: heapInfo,
      process: processInfo,
      scripts: this._scripts.size,
      state: this._state,
    };
  }

  // ── Events ────────────────────────────────────────────────────

  getEvents(limit = 50, sinceId?: number): EventRecord[] {
    let events = this._eventHistory;
    if (sinceId !== undefined) {
      events = events.filter((e) => e.id > sinceId);
    }
    return events.slice(-limit);
  }

  getLastStopEvent(): StopEventData | { message: string } {
    return this._lastStopEvent ?? { message: "No stop events recorded" };
  }

  // ── Private: Connection ───────────────────────────────────────

  private _discoverWsUrl(host: string, port: number): Promise<string> {
    return new Promise((resolve, reject) => {
      const req = http.get(`http://${host}:${port}/json`, (res) => {
        let data = "";
        res.on("data", (chunk) => (data += chunk));
        res.on("end", () => {
          try {
            const targets = JSON.parse(data);
            const target =
              targets.find((t: any) => t.type === "node") ?? targets[0];
            if (!target?.webSocketDebuggerUrl) {
              reject(new Error("No debuggable target found"));
              return;
            }
            resolve(target.webSocketDebuggerUrl);
          } catch (err) {
            reject(new Error(`Failed to parse debug targets: ${err}`));
          }
        });
      });
      req.on("error", (err) => {
        reject(
          new Error(
            `Cannot reach Node.js debug port at ${host}:${port}: ${err.message}`,
          ),
        );
      });
      req.setTimeout(5000, () => {
        req.destroy();
        reject(new Error(`Connection to ${host}:${port} timed out`));
      });
    });
  }

  private _connectWs(wsUrl: string): Promise<void> {
    return new Promise((resolve, reject) => {
      this._ws = new WebSocket(wsUrl);

      this._ws.on("open", () => resolve());

      this._ws.on("message", (raw) => {
        try {
          this._handleMessage(JSON.parse(raw.toString()));
        } catch (err) {
          console.error("[CDP] bad message:", err);
        }
      });

      this._ws.on("close", () => this._handleDisconnect());
      this._ws.on("error", (err) => {
        if (this._state === SessionState.DISCONNECTED) {
          reject(err);
        } else {
          console.error("[CDP] ws error:", err.message);
          this._handleDisconnect();
        }
      });

      setTimeout(() => {
        if (this._ws?.readyState !== WebSocket.OPEN) {
          this._ws?.close();
          reject(new Error("WebSocket connection timed out"));
        }
      }, 10000);
    });
  }

  // ── Private: Message Handling ─────────────────────────────────

  private _handleMessage(msg: any): void {
    if (msg.id !== undefined) {
      const pending = this._pendingRequests.get(msg.id);
      if (pending) {
        clearTimeout(pending.timer);
        this._pendingRequests.delete(msg.id);
        if (msg.error) {
          pending.reject(
            new Error(`CDP error: ${msg.error.message} (code: ${msg.error.code})`),
          );
        } else {
          pending.resolve(msg.result ?? {});
        }
      }
      return;
    }
    if (msg.method) {
      this._handleEvent(msg.method, msg.params ?? {});
    }
  }

  private _handleEvent(method: string, params: any): void {
    switch (method) {
      case "Debugger.scriptParsed":
        this._onScriptParsed(params);
        break;
      case "Debugger.paused":
        this._onPaused(params);
        break;
      case "Debugger.resumed":
        break;
      case "Debugger.breakpointResolved":
        this._onBreakpointResolved(params);
        break;
      case "Runtime.exceptionThrown":
        this._recordEvent("exception", {
          text: params.exceptionDetails?.text,
          exception: params.exceptionDetails?.exception?.description,
          url: params.exceptionDetails?.url,
          line: params.exceptionDetails?.lineNumber,
        });
        break;
      case "Runtime.consoleAPICalled":
        this._recordEvent("console", {
          type: params.type,
          args: params.args?.map(
            (a: any) => a.description ?? a.value ?? a.type,
          ),
        });
        break;
    }
  }

  private _onScriptParsed(params: any): void {
    this._scripts.set(params.scriptId, {
      scriptId: params.scriptId,
      url: params.url,
      startLine: params.startLine,
      startColumn: params.startColumn,
      endLine: params.endLine,
      endColumn: params.endColumn,
      hash: params.hash,
      sourceMapURL: params.sourceMapURL,
    });
  }

  private _onPaused(params: any): void {
    const event: StopEventData = {
      reason: params.reason,
      callFrames: params.callFrames,
      hitBreakpoints: params.hitBreakpoints,
      data: params.data,
      asyncStackTrace: params.asyncStackTrace,
    };

    this._state = SessionState.SUSPENDED;
    this._lastStopEvent = event;
    this._currentCallFrames = params.callFrames;

    const top = params.callFrames?.[0];
    this._recordEvent("stopped", {
      reason: params.reason,
      function: top?.functionName || "(anonymous)",
      file:
        this._scripts.get(top?.location?.scriptId)?.url ?? top?.url ?? "unknown",
      line: top?.location?.lineNumber,
      hitBreakpoints: params.hitBreakpoints,
    });

    this._stopWaiter?.resolve(event);
  }

  private _onBreakpointResolved(params: any): void {
    const internalId = this._cdpBpToInternal.get(params.breakpointId);
    if (internalId) {
      const bp = this._breakpoints.get(internalId);
      if (bp) {
        bp.locations = [params.location];
        this._recordEvent("breakpointResolved", {
          id: internalId,
          location: params.location,
        });
      }
    }
  }

  private _handleDisconnect(): void {
    const wasConnected = this._state !== SessionState.DISCONNECTED;
    this._state = SessionState.DISCONNECTED;

    for (const [, pending] of this._pendingRequests) {
      clearTimeout(pending.timer);
      pending.reject(new Error("Connection lost"));
    }
    this._pendingRequests.clear();

    if (this._stopWaiter) {
      this._stopWaiter.reject(new Error("Connection lost"));
      this._stopWaiter = null;
    }

    if (wasConnected) this._recordEvent("disconnected", {});
    this._ws = null;
  }

  private _cleanup(): void {
    if (this._ws) {
      this._ws.removeAllListeners();
      try {
        this._ws.close();
      } catch {
        /* ignore */
      }
    }
    this._ws = null;
    this._state = SessionState.DISCONNECTED;
    this._pendingRequests.clear();
    this._scripts.clear();
    this._breakpoints.clear();
    this._cdpBpToInternal.clear();
    this._nextBreakpointId = 1;
    this._stopWaiter = null;
    this._lastStopEvent = null;
    this._currentCallFrames = [];
    this._eventHistory = [];
    this._nextEventId = 1;
    this._nextRequestId = 1;
  }

  // ── Private: CDP Send ─────────────────────────────────────────

  private _send(
    method: string,
    params: Record<string, any>,
    timeoutMs = DEFAULT_COMMAND_TIMEOUT_MS,
  ): Promise<any> {
    return new Promise((resolve, reject) => {
      if (!this._ws || this._ws.readyState !== WebSocket.OPEN) {
        reject(new Error("Not connected"));
        return;
      }
      const id = this._nextRequestId++;
      const timer = setTimeout(() => {
        this._pendingRequests.delete(id);
        reject(new Error(`CDP '${method}' timed out after ${timeoutMs}ms`));
      }, timeoutMs);

      this._pendingRequests.set(id, { resolve, reject, timer });
      this._ws.send(JSON.stringify({ id, method, params }));
    });
  }

  // ── Private: Guards ───────────────────────────────────────────

  private _ensureConnected(): void {
    if (this._state === SessionState.DISCONNECTED) {
      throw new Error("Not connected. Use debug_connect first.");
    }
  }

  private _ensureSuspended(): void {
    if (this._state !== SessionState.SUSPENDED) {
      throw new Error(
        `Execution is not paused (state: ${this._state}). Use debug_pause first.`,
      );
    }
  }

  // ── Private: Helpers ──────────────────────────────────────────

  private _createStopWaiter(): StopWaiter {
    let resolve!: (data: StopEventData) => void;
    let reject!: (err: Error) => void;
    const promise = new Promise<StopEventData>((res, rej) => {
      resolve = res;
      reject = rej;
    });
    const waiter = { promise, resolve, reject };
    this._stopWaiter = waiter;
    return waiter;
  }

  private _timeout(ms: number): Promise<never> {
    return new Promise((_, reject) =>
      setTimeout(() => reject(new Error("Timeout")), ms),
    );
  }

  private _recordEvent(type: string, data: Record<string, any>): void {
    this._eventHistory.push({
      id: this._nextEventId++,
      type,
      timestamp: Date.now(),
      data,
    });
    if (this._eventHistory.length > MAX_EVENT_HISTORY) {
      this._eventHistory.shift();
    }
  }

  private _resolveScriptUrl(input: string): { url?: string; urlRegex?: string } {
    if (
      input.startsWith("file://") ||
      input.startsWith("http://") ||
      input.startsWith("https://")
    ) {
      return { url: input };
    }
    for (const script of this._scripts.values()) {
      if (
        script.url === input ||
        script.url.endsWith("/" + input) ||
        script.url.endsWith("\\" + input)
      ) {
        return { url: script.url };
      }
    }
    if (input.startsWith("/")) {
      return { url: `file://${input}` };
    }
    const escaped = input.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    return { urlRegex: `${escaped}$` };
  }

  // ── Private: Formatting ───────────────────────────────────────

  private _formatStopResult(event: StopEventData): Record<string, any> {
    const top = event.callFrames?.[0];
    const scriptUrl = top
      ? this._scripts.get(top.location.scriptId)?.url ?? top.url
      : "unknown";
    return {
      reason: event.reason,
      hitBreakpoints: event.hitBreakpoints?.map(
        (cdpId) => this._cdpBpToInternal.get(cdpId) ?? cdpId,
      ),
      topFrame: top
        ? {
            functionName: top.functionName || "(anonymous)",
            url: scriptUrl,
            lineNumber: top.location.lineNumber,
            columnNumber: top.location.columnNumber,
          }
        : null,
      frameCount: event.callFrames?.length ?? 0,
      exceptionData: event.reason === "exception" ? event.data : undefined,
    };
  }

  private _formatEvalResult(result: any): Record<string, any> {
    if (result.exceptionDetails) {
      return {
        error: true,
        text: result.exceptionDetails.text,
        exception: result.exceptionDetails.exception
          ? this._formatRemoteObject(result.exceptionDetails.exception)
          : undefined,
        lineNumber: result.exceptionDetails.lineNumber,
        columnNumber: result.exceptionDetails.columnNumber,
      };
    }
    return this._formatRemoteObject(result.result);
  }

  private _formatRemoteObject(obj: any): Record<string, any> {
    if (!obj) return { type: "undefined" };
    const out: Record<string, any> = { type: obj.type };
    if (obj.subtype) out.subtype = obj.subtype;
    if (obj.className) out.className = obj.className;
    if (obj.description !== undefined) out.description = obj.description;
    if (obj.objectId) out.objectId = obj.objectId;
    if (obj.value !== undefined) out.value = obj.value;
    if (obj.unserializableValue) out.value = obj.unserializableValue;
    if (obj.preview) out.preview = this._formatPreview(obj.preview);
    return out;
  }

  private _formatPreview(preview: any): Record<string, any> {
    const out: Record<string, any> = {
      type: preview.type,
      overflow: preview.overflow,
    };
    if (preview.subtype) out.subtype = preview.subtype;
    if (preview.description) out.description = preview.description;
    if (preview.properties) {
      out.properties = preview.properties.map((p: any) => ({
        name: p.name,
        type: p.type,
        value: p.value,
        ...(p.subtype ? { subtype: p.subtype } : {}),
      }));
    }
    if (preview.entries) {
      out.entries = preview.entries.map((e: any) => ({
        key: e.key
          ? { type: e.key.type, description: e.key.description }
          : undefined,
        value: { type: e.value.type, description: e.value.description },
      }));
    }
    return out;
  }

  private _formatProperties(properties: any[]): any[] {
    return properties
      .filter((p: any) => !p.symbol)
      .map((p: any) => ({
        name: p.name,
        enumerable: p.enumerable,
        writable: p.writable,
        isAccessor: !!(p.get || p.set),
        ...this._formatRemoteObject(p.value ?? p.get),
      }));
  }
}

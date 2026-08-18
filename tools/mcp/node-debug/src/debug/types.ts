export enum SessionState {
  DISCONNECTED = "disconnected",
  RUNNING = "running",
  SUSPENDED = "suspended",
}

export interface ScriptInfo {
  scriptId: string;
  url: string;
  startLine: number;
  startColumn: number;
  endLine: number;
  endColumn: number;
  hash: string;
  sourceMapURL?: string;
}

export interface ManagedBreakpoint {
  id: string;
  breakpointId: string;
  url?: string;
  scriptId?: string;
  lineNumber: number;
  columnNumber?: number;
  condition?: string;
  locations: Array<{ scriptId: string; lineNumber: number; columnNumber: number }>;
}

export interface StopEventData {
  reason: string;
  callFrames: CDPCallFrame[];
  hitBreakpoints?: string[];
  data?: any;
  asyncStackTrace?: any;
}

export interface CDPCallFrame {
  callFrameId: string;
  functionName: string;
  location: { scriptId: string; lineNumber: number; columnNumber: number };
  url: string;
  scopeChain: CDPScope[];
  this: CDPRemoteObject;
  returnValue?: CDPRemoteObject;
}

export interface CDPScope {
  type: string;
  object: CDPRemoteObject;
  name?: string;
  startLocation?: { scriptId: string; lineNumber: number; columnNumber: number };
  endLocation?: { scriptId: string; lineNumber: number; columnNumber: number };
}

export interface CDPRemoteObject {
  type: string;
  subtype?: string;
  className?: string;
  value?: any;
  unserializableValue?: string;
  description?: string;
  objectId?: string;
  preview?: any;
}

export interface EventRecord {
  id: number;
  type: string;
  timestamp: number;
  data: Record<string, any>;
}

export const MAX_EVENT_HISTORY = 200;
export const DEFAULT_COMMAND_TIMEOUT_MS = 30000;
export const DEFAULT_WAIT_TIMEOUT_MS = 30000;

# Node Debug MCP

基于 [Chrome DevTools Protocol (CDP)](https://chromedevtools.github.io/devtools-protocol/) 的 MCP 调试服务器，为 AI Agent（Claude Code 等）提供 Node.js 远程调试能力。

连接到以 `--inspect` 启动的 Node.js 进程，通过 20 个 MCP 工具实现完整的交互式调试 —— 断点管理、单步执行、变量检查、表达式求值、脚本搜索等。

## 架构

```
┌──────────────┐    stdio/JSON-RPC   ┌──────────────┐   WebSocket/CDP   ┌──────────────┐
│  AI Agent    │ ◄─────────────────► │  MCP Server  │ ◄───────────────► │  Node.js App │
│ (Claude Code)│                     │  (index.ts)  │                   │  (--inspect)  │
└──────────────┘                     └──────┬───────┘                   └──────────────┘
                                            │
                                     ┌──────▼───────┐
                                     │ CDPDebugger  │
                                     │(debug-session│
                                     │     .ts)     │
                                     └──────────────┘
```

连接流程：

1. Node.js 启动时使用 `--inspect` 或 `--inspect-brk` 开放调试端口（默认 9229）
2. MCP Server 通过 `GET http://host:port/json` 发现目标的 WebSocket URL
3. 建立 WebSocket 连接，发送 `Debugger.enable` + `Runtime.enable`
4. 开始接收脚本加载事件，可以设置断点、暂停、检查状态

## 安装

```bash
git clone <repo-url>
cd node-debug-mcp
npm install
npm run build
```

## MCP 配置

### Claude Code

在 **项目目录** 的 `.mcp.json` 中添加（仅对当前项目生效）：

```json
{
  "mcpServers": {
    "node-debug": {
      "command": "node",
      "args": ["/absolute/path/to/node-debug-mcp/dist/index.js"]
    }
  }
}
```

或者在 **全局配置** `~/.claude.json` 中添加（对所有项目生效）：

```json
{
  "mcpServers": {
    "node-debug": {
      "command": "node",
      "args": ["/absolute/path/to/node-debug-mcp/dist/index.js"]
    }
  }
}
```

> **注意**：`args` 中的路径必须是**绝对路径**。

### Cursor

在 `.cursor/mcp.json` 中：

```json
{
  "mcpServers": {
    "node-debug": {
      "command": "node",
      "args": ["/absolute/path/to/node-debug-mcp/dist/index.js"]
    }
  }
}
```

### 通用 MCP 客户端

MCP Server 通过 **stdio** 传输 JSON-RPC 消息，兼容任何支持 stdio 传输的 MCP 客户端。手动启动：

```bash
node dist/index.js
# 日志输出到 stderr，JSON-RPC 通过 stdin/stdout
```

## 快速开始

### 1. 启动目标 Node.js 应用

```bash
# 普通模式 — 应用正常运行，可随时附加调试
node --inspect app.js

# 暂停模式 — 在第一行暂停，等待调试器连接后再执行
node --inspect-brk app.js

# 自定义端口
node --inspect=0.0.0.0:9230 app.js
```

### 2. 通过 MCP 工具调试

```
# 连接
debug_connect(port=9229)
→ { status: "connected", scriptsLoaded: 150 }

# 查找目标脚本
debug_list_scripts(filter="app.js")
→ [{ scriptId: "86", url: "file:///path/to/app.js" }]

# 搜索关键代码
debug_search_in_scripts(query="password")
→ [{ url: "app.js", matches: [{ lineNumber: 42, lineContent: "..." }] }]

# 设置断点
debug_set_breakpoint(url="/path/to/app.js", lineNumber=42)
→ { id: "bp-1", breakpointId: "1:42:0:..." }

# 触发代码路径（如发送 HTTP 请求），然后等待断点命中
debug_wait_for_pause()
→ { status: "stopped", topFrame: { functionName: "handleLogin", lineNumber: 42 } }

# 查看调用栈
debug_get_call_stack()
→ { frames: [{ functionName: "handleLogin", url: "app.js", lineNumber: 42 }, ...] }

# 查看局部变量
debug_get_scope_variables(frameIndex=0)
→ { scopes: [{ type: "local", variables: [{ name: "username", value: "admin" }, ...] }] }

# 求值表达式
debug_evaluate(expression="req.headers")
→ { type: "object", objectId: "...", preview: { properties: [...] } }

# 展开对象
debug_get_object_properties(objectId="...")
→ { properties: [{ name: "host", value: "localhost" }, ...] }

# 单步执行
debug_step(kind="over")
→ { status: "stopped", topFrame: { lineNumber: 43 } }

# 恢复执行
debug_resume()
→ { status: "running", waitTimedOut: true }

# 断开
debug_disconnect()
```

## 完整调试流程示例

以分析一个 SQL 注入漏洞为例：

```
# 1. 连接到目标
debug_connect(port=9229)

# 2. 定位关键代码
debug_search_in_scripts(query="SELECT.*FROM", isRegex=true)
→ app.js line 45: const query = `SELECT * FROM users WHERE ${field} = '${value}'`;

# 3. 在 SQL 查询构造处设置断点
debug_set_breakpoint(url="app.js", lineNumber=45)

# 4. 发送恶意请求（通过浏览器或 curl），然后等待
debug_wait_for_pause(waitTimeoutMs=10000)
→ { status: "stopped", topFrame: { functionName: "findUser" } }

# 5. 检查传入的参数
debug_get_scope_variables()
→ field = "username", value = "' OR '1'='1"

# 6. 单步执行，观察拼接后的 SQL
debug_step(kind="over")
debug_evaluate(expression="query")
→ "SELECT * FROM users WHERE username = '' OR '1'='1'"
# 确认 SQL 注入漏洞 ✓

# 7. 继续运行并清理
debug_resume()
debug_remove_breakpoint(breakpointId="bp-1")
debug_disconnect()
```

## 工具参考

共 20 个 MCP 工具，按功能分为 7 类。

### 连接管理

| 工具 | 参数 | 说明 |
|------|------|------|
| `debug_connect` | `host?` (默认 127.0.0.1), `port?` (默认 9229) | 连接到 Node.js 调试端口 |
| `debug_disconnect` | — | 断开调试会话 |
| `debug_status` | — | 返回当前会话状态（连接信息、断点数、最后停止原因） |

### 脚本检索

| 工具 | 参数 | 说明 |
|------|------|------|
| `debug_list_scripts` | `filter?`, `includeNodeModules?` (默认 false) | 列出已加载脚本，默认过滤 node\_modules 和 node: 内部模块 |
| `debug_get_script_source` | `scriptId` | 获取脚本源码 |
| `debug_search_in_scripts` | `query`, `caseSensitive?`, `isRegex?` | 在所有脚本中搜索文本或正则 |

### 断点

| 工具 | 参数 | 说明 |
|------|------|------|
| `debug_set_breakpoint` | `lineNumber`, `url?` / `scriptId?`, `columnNumber?`, `condition?` | 设置断点；url 支持智能匹配（绝对路径、相对路径、file:// URL）|
| `debug_remove_breakpoint` | `breakpointId` (如 `"bp-1"`) | 移除断点 |
| `debug_list_breakpoints` | — | 列出所有活跃断点 |

### 执行控制

| 工具 | 参数 | 说明 |
|------|------|------|
| `debug_wait_for_pause` | `waitTimeoutMs?` (默认 30000) | 被动等待下一次暂停事件（断点命中、异常等） |
| `debug_pause` | — | 强制暂停执行 |
| `debug_resume` | `waitTimeoutMs?` (默认 30000) | 恢复执行，阻塞等待下一次断点命中或超时 |
| `debug_step` | `kind` (`"into"` / `"over"` / `"out"`), `waitTimeoutMs?` | 单步执行 |

### 状态检查

| 工具 | 参数 | 说明 |
|------|------|------|
| `debug_evaluate` | `expression`, `frameIndex?` | 求值 JS 表达式；暂停时在调用帧上下文执行，运行时在全局执行（支持 await） |
| `debug_get_call_stack` | — | 获取当前调用栈（仅暂停时） |
| `debug_get_scope_variables` | `frameIndex?` (默认 0), `scopeIndex?` | 获取作用域变量，默认跳过 global scope |
| `debug_get_object_properties` | `objectId`, `ownOnly?` (默认 true) | 展开对象属性，使用 evaluate 或 scope variables 返回的 objectId |
| `debug_get_runtime_info` | — | 获取 Node.js 运行时信息（内存、版本、PID、argv 等） |

### 事件

| 工具 | 参数 | 说明 |
|------|------|------|
| `debug_get_events` | `limit?` (默认 50), `sinceId?` | 获取调试事件历史，sinceId 支持增量轮询 |
| `debug_get_last_stop_event` | — | 获取最近一次暂停事件的完整上下文 |

## `--inspect` vs `--inspect-brk`

| 标志 | 行为 | 适用场景 |
|------|------|----------|
| `--inspect` | 应用正常启动运行，调试器可随时连接 | Web 服务器等长运行进程 |
| `--inspect-brk` | 应用在第一行代码暂停，等待调试器 | 需要从入口开始调试的场景 |

使用 `--inspect-brk` 时，`debug_connect` 返回 `state: "suspended"`，可以在入口处设置断点后再 `debug_resume`。

## 断点类型

### 行断点

```
debug_set_breakpoint(url="app.js", lineNumber=42)
```

### 条件断点

仅在条件为 `true` 时触发：

```
debug_set_breakpoint(url="app.js", lineNumber=42, condition="user.role === 'admin'")
```

### 通过 scriptId 设置

先通过 `debug_list_scripts` 获取 scriptId，再精确设置：

```
debug_set_breakpoint(scriptId="86", lineNumber=42)
```

### URL 智能匹配

`url` 参数支持多种格式，MCP 会自动解析：

| 输入 | 匹配方式 |
|------|----------|
| `file:///path/to/app.js` | 精确匹配 |
| `/path/to/app.js` | 转为 `file://` URL |
| `app.js` | 尝试匹配已加载脚本的 URL 后缀 |
| `routes/index.js` | 正则匹配 URL 末尾 |

## ESM 模块变量访问

Node.js ESM 模块（`.mjs` 或 `"type": "module"`）中的顶层变量是**模块私有**的，`Runtime.evaluate` 无法在全局作用域中访问它们。

解决方法：**在模块内部的代码上设置断点**，暂停后通过 `debug_evaluate` 在调用帧上下文中访问模块变量。

```
# 设置断点在模块内部的某一行
debug_set_breakpoint(url="app.js", lineNumber=50)

# 触发并等待暂停
debug_wait_for_pause()

# 现在可以访问模块变量
debug_evaluate(expression="db.users.length")
→ 3
```

## 技术细节

### CDP 协议通信

Node.js 的 V8 Inspector 通过 WebSocket 暴露 Chrome DevTools Protocol，本项目直接使用 `ws` 库连接：

- **请求**：`{ id: N, method: "Domain.method", params: {...} }`
- **响应**：`{ id: N, result: {...} }` 或 `{ id: N, error: { code, message } }`
- **事件**：`{ method: "Domain.event", params: {...} }`

主要使用的 CDP 域：
- `Debugger` — 断点、暂停、单步、脚本管理
- `Runtime` — 表达式求值、对象检查、堆信息

### Promise 阻塞式执行控制

`debug_resume`、`debug_step`、`debug_wait_for_pause` 使用 Stop-Waiter 模式：

1. 创建 `Promise`（暴露 `resolve`/`reject` 句柄）
2. 发送 CDP 命令（或被动等待）
3. `Promise.race([waiterPromise, timeoutPromise])` 阻塞
4. `Debugger.paused` 事件触发时调用 `resolve` → 返回停止信息
5. 超时时返回 `{ status: "running", waitTimedOut: true }`

### 事件环形缓冲

- 容量：200 条
- 自增 ID（monotonic counter）
- `debug_get_events(sinceId=N)` 支持增量轮询
- 事件类型：`connected`、`stopped`、`disconnected`、`breakpointSet`、`breakpointRemoved`、`breakpointResolved`、`exception`、`console`

### 状态机

```
DISCONNECTED ──connect──► RUNNING ◄──resume/step──► SUSPENDED
     ▲                       │                          │
     └───disconnect──────────┴────connection lost────────┘
```

## 项目结构

```
node-debug-mcp/
├── package.json
├── tsconfig.json
├── src/
│   ├── index.ts                  # MCP Server 入口 + 20 个工具注册
│   └── debug/
│       ├── types.ts              # 类型定义（SessionState, ScriptInfo, ManagedBreakpoint 等）
│       └── debug-session.ts      # CDP 客户端（WebSocket 连接、协议通信、状态机、断点管理）
├── demo/
│   └── vuln-app/
│       └── app.mjs               # 演示用漏洞 Web 应用（SQLi, SSTI, CmdInj, SSRF, Path Traversal）
└── test/
    ├── target-app.mjs            # 简单测试目标
    ├── test.mjs                  # 单元测试（26 项）
    └── mcp-e2e.mjs               # MCP 端到端测试（43 项）
```

## 依赖

| 包 | 用途 |
|----|------|
| `@modelcontextprotocol/sdk` ^1.12.1 | MCP 服务器框架 |
| `ws` ^8.18.0 | WebSocket 客户端（CDP 通信） |
| `zod` ^3.25.1 | MCP 工具入参校验 |

## 运行测试

```bash
# 构建
npm run build

# 单元测试 — 启动测试目标，然后运行
node --inspect test/target-app.mjs &
node test/test.mjs

# MCP 端到端测试 — 启动漏洞应用，然后运行
node --inspect demo/vuln-app/app.mjs &
node test/mcp-e2e.mjs
```

测试覆盖范围：
- 连接 / 断开 / 状态查询
- 脚本列表 / 源码获取 / 内容搜索
- 断点增删查、条件断点
- 暂停 / 恢复 / 单步（over/into/out）
- 调用栈 / 作用域变量 / 对象属性展开
- 表达式求值（运行时 + 暂停时）
- 运行时信息 / 事件历史
- `--inspect-brk` 初始暂停检测

## 对照参考实现

| 特性 | Java-debug-mcp | Python-debug-mcp | Php-debug-mcp | **Node-debug-mcp** |
|------|:---:|:---:|:---:|:---:|
| 协议 | JDI/JDWP | DAP (debugpy) | DBGp (Xdebug) | **CDP (V8 Inspector)** |
| 语言 | Java | Python | TypeScript | **TypeScript** |
| 连接模型 | 主动附着 | 启动/附着 | 反向连接 | **主动连接** |
| 工具数 | 14 | 18 | 15 | **20** |
| 执行阻塞 | CompletableFuture | asyncio.Future | Promise | **Promise** |
| 事件缓冲 | 100 条 | 200 条 | 200 条 | **200 条** |

## License

MIT

# Debug MCP（随仓库）

Reviewer 改写 PoC 时用的 Java / Node / Python 动态调试 MCP 放在本目录，路径相对仓库根目录，不依赖 `D:\AI\MCP_Tools`。

**用途**：动态验证先跑当前 `poc.py`。PoC 由 Reviewer 收口；仅当缺失、跑不通或复现失败，且需要自己改写/调试时，才 attach 本目录 MCP（断点、看 sink 是否到达、payload 如何被处理）。不要作为首选验证方式，也不要为此打回 Worker。未构建时 Reviewer 只走普通动态（HTTP PoC + docker exec）。

| 运行时 | 目录 | 启动 |
|--------|------|------|
| Java | `tools/mcp/java-debug` | 先 `mvn package`，再用 fat jar |
| Node | `tools/mcp/node-debug` | `npx tsx src/index.ts`（需已 `npm install`） |
| Python | `tools/mcp/python-debug` | `python server.py`（需 `mcp`、`debugpy`） |

构建产物（`target/`、`dist/`、`node_modules/`）不要提交。

环境变量可覆盖目录：`VULNHUNTER_MCP_JAVA` / `VULNHUNTER_MCP_NODE` / `VULNHUNTER_MCP_PYTHON`（相对仓库根或绝对路径）。

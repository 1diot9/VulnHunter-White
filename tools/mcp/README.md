# Debug MCP（随仓库）

Reviewer 动态验证用的 Java / Node / Python debug MCP 放在本目录，路径相对仓库根目录，不依赖 `D:\AI\MCP_Tools`。

| 运行时 | 目录 | 启动 |
|--------|------|------|
| Java | `tools/mcp/java-debug` | 先 `mvn package`，再用 fat jar |
| Node | `tools/mcp/node-debug` | `npx tsx src/index.ts`（需已 `npm install`） |
| Python | `tools/mcp/python-debug` | `python server.py`（需 `mcp`、`debugpy`） |

构建产物（`target/`、`dist/`、`node_modules/`）不要提交。未构建时 Reviewer 会走普通动态（HTTP PoC + docker exec），不强制 MCP。

环境变量可覆盖目录：`VULNHUNTER_MCP_JAVA` / `VULNHUNTER_MCP_NODE` / `VULNHUNTER_MCP_PYTHON`（相对仓库根或绝对路径）。

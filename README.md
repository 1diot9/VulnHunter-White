# VulnHunter

白盒审计 Agent：导入 GitHub / zip Web 项目，Recon（含历史漏洞）→ 启发式 Worker（历史漏洞收集完毕后）和/或快速扫描和/或历史漏洞绕过 → Reviewer 审核（默认仅静态；可选靶场动态先跑 HTTP PoC，或局部验证用沙箱 harness）；可选 Verifier 对已确认前台漏洞做 FOFA 互联网复测。

## 一键启停

双击仓库根目录：

- `start.cmd` — 启动后端（8000）+ 前端（5173）；首次会自动建 venv / `npm install`。默认不热更新，开发时加 `--reload`
- `stop.cmd` — 停止两服务（按窗口标题 + 端口）

日志：`data\logs\backend.log`、`data\logs\frontend.log`。

## 单元测试

```bash
cd backend
.venv\Scripts\activate
pip install -r requirements.txt
pytest
```

或运行 `scripts\run-tests.cmd`。覆盖：漏洞类型、看门狗、上下文压缩/429 识别、沙箱、入库索引、工具 ACL/门闩、API、环境端口重映射等。

### 代理

设置页配置出站代理（WebSearch / SearchGHSA / SearchGitHubIssues / FOFA）；**留空则直连**，不再默认走 `10808`。Chat Completions / Anthropic Messages 默认直连，需要时在设置页填 Chat 代理。代理连不上时自动改走直连。设置页尚未保存过时，可用 `.env` 的 `VULNHUNTER_HTTP_PROXY` / `VULNHUNTER_CHAT_PROXY` 回退。

### Debug MCP

Java / Node / Python debug MCP 源码在 `tools/mcp/`（相对仓库根目录）。靶场动态时 Reviewer 先跑当前 HTTP PoC 并负责改到可复现；PoC 缺失、跑不通或复现失败且需自己改写时，才用 debug MCP 动态调试。未构建时走普通动态验证。详见 `tools/mcp/README.md`。

### 局部验证沙箱

局部验证用宿主机 Docker 拉起一次性 `vulnhunter/sandbox:latest` 兄弟容器（无网、跑完删除），不把被审计项目整套部署起来。先构建镜像：

```bat
scripts\build-sandbox.cmd
```

或 `docker build -t vulnhunter/sandbox:latest docker/sandbox`。无 Docker 或镜像不存在时退回静态，不因此判误报。

## 手动启动

### 后端

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --reload-dir app --timeout-graceful-shutdown 2 --host 127.0.0.1 --port 8000
```

### 前端

```bash
cd frontend
npm install
npm run dev
```

打开 http://127.0.0.1:5173 ，在「设置」选择接口协议（OpenAI Chat Completions 或 Anthropic Messages），再配置 API Base URL / API Key / 模型；若开启 Verifier，再配置 FOFA Key。

## 能力概览

- 凡 Web 项目均可审计（不限语言）
- 创建项目时选择赏金模式（默认）、全量模式或自定义模式，并可勾选挖掘路径：启发式（默认开，可再开轻量版只挖权重 100）、快速扫描（默认关）和/或历史漏洞绕过（默认关），至少开一条。每个项目可单独选择模型，不选则使用设置页全局模型
- 启发式在历史漏洞收集完毕后按文件定权挖掘：权重 100 为用户可控入口（HTTP 以及 WebSocket / RPC / MQ / 回调等）；更低权按角色回推、控面或薄扫。可勾选轻量版，只把权重 100 的文件当入口。快速扫描在 Recon 后用 Semgrep 找 Sink，经代码筛和短 Agent 筛选后按条回推。快速路径覆盖 SAST Sink，缺鉴权/IDOR/业务逻辑仍靠启发式。历史漏洞绕过以收集到的历史漏洞文档为输入，每轮尝试绕过一条补丁或确认未修复洞仍可打。开启的路径都结束后项目才 completed
- 设置页可管理命名自定义审计模式提示词；内置赏金/全量提示词只读可复制。项目选用自定义时写入快照，改库不影响已绑定项目
- 赏金模式按可利用高危害类型收口（含存储型 XSS、有服务端机密危害的源码硬编码密钥；前端传输混淆 AES / 公开下发密钥不入库）；全量模式保留低危害难利用项（CORS、反射 XSS、缺速率限制等）；自定义模式无赏金硬闸门，完全按提示词判定
- 可选动态验证：创建项目时默认关闭（只做静态复核）。勾选后 Reviewer 才搭建 Docker 靶场，并先跑当前 HTTP PoC（`poc.py -u` + docker exec/日志）复现；PoC 由 Reviewer 收口，不要打回 Worker 改 PoC。PoC 缺失、跑不通或复现失败且需自己改写时，才用 Java/Node/Python debug MCP 动态调试。Worker / Reviewer 的 `poc.py` 用 `-u/--url` 对任意目标复测，必须支持 `--proxy` 设 HTTP 代理（空则直连），RCE 支持 `-c/--cmd` 并打印回显。自建镜像 `{项目名}-{项目ID}:lab`，Web 容器 `{项目名}-{项目ID}`，依赖容器加 `-{role}`
- 可选 Verifier：创建项目时默认关闭，也可在项目设置中开启。Reviewer 确认前台漏洞后，用 FOFA 默认搜 10 个同款目标并按报告复测，成功 3 个即结束；当前这批不足 3 个则保留已成功的并再搜下一轮，最多 5 轮（合计最多 50 个目标）。应用指纹按项目采集一次（源码 + 互联网检索）并复用；FOFA 有命中后共享，0 条可改写最多 3 次。报告会列出全部目标并标注成功 / 失败 / 未测，复现成功须附上搜索语法。任意文件删除、DoS、SQL 增删改等会中断或篡改业务的漏洞不测互联网目标
- LLM 报错对齐 AutoPoc：429 休眠续跑、超时 conclude、死循环新开、阶段最多再试 2 次
- 全局 LLM 总线程数默认 6：所有运行中项目的侦察 / 挖掘 / 审核等会话合计占用，超出排队顺序放行
- 设置页可手动清理 X 天前的实时日志（SSE）
- 历史漏洞：先 GHSA / GitHub Issues 爬虫交给 Agent 落盘（第一阶段禁止 WebSearch），再 WebSearch 补漏；阶段只收集不读源码。公开洞标 `patched`，未修复仅来自未关闭 GitHub Issues（`unpatched`）
- 可重置启发式 Worker 挖掘进度（保留漏洞产出与侦察文档），用于更换模型重审启发式路径。快速扫描 Sink 队列与历史漏洞绕过进度不重置

## 目录

- `backend/app` — FastAPI、Agent 循环、工具、调度
- `frontend` — React + Tailwind UI
- `templates` — 文档模板
- `data/projects/{id}` — 项目隔离工作区

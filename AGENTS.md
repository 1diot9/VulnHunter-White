# AGENTS.md

本文件给后续在本仓库工作的 AI agent 使用。先读 `README.md`，再按本文约定修改代码。

## 项目概览

VulnHunter 是一个白盒审计 Agent 平台：导入 GitHub 仓库或源码 zip 后，按 Recon、启发式 Worker（历史漏洞收集完毕后）和/或快速扫描和/或历史漏洞绕过、Reviewer 流程进行漏洞挖掘与验证；Reviewer 默认仅静态复核，可三选一关闭 / 靶场动态 / 局部验证；可选开启 Verifier，在 Reviewer 确认前台漏洞后用 FOFA 搜索同款目标并复测；可选开启攻击链串联，在挖掘与审核结束后根据已确认漏洞尝试多步利用。

- 后端：`backend/app`，FastAPI + SQLAlchemy + SQLite，负责项目导入、阶段调度、Agent 循环、工具注册、报告与漏洞数据。
- 前端：`frontend`，Vite + React + TypeScript + Tailwind，用于审计项目、实时日志、阶段报告、漏洞列表和设置页。
- 模板：`templates`，阶段报告和提示词相关模板。漏洞中文报告对齐 `templates/vuln-report.md`，英文 GitHub Advisory 填表稿对齐 `templates/vuln-advisory.md`（写入 `vulns/{id}/advisory.md`）。
- 运行态数据：`data/projects/{id}`、`data/logs`、`data/app.db`。除非任务明确要求，不要手工改运行态数据或提交生成文件。

## 常用命令

在 Windows 环境优先使用仓库脚本：

```bat
start.cmd
stop.cmd
scripts\run-tests.cmd
```

手动后端：

```bat
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --reload-dir app --timeout-graceful-shutdown 2 --host 127.0.0.1 --port 8000
```

手动前端：

```bat
cd frontend
npm install
npm run dev
npm run build
```

后端测试：

```bat
cd backend
.venv\Scripts\activate
pytest
```

## 后端约定

- API 路由放在 `backend/app/api`，Pydantic schema 放在 `backend/app/schemas.py`，数据库模型放在 `backend/app/models.py`。
- 使用 `SessionLocal` 时保持短生命周期，优先用 `with SessionLocal() as db:`；测试会 monkeypatch 已导入的 `SessionLocal`。
- SQLite schema 变更要更新 `models.py` 中的模型，并在 `_ensure_columns()` 里补充已有库的兼容列迁移。
- 项目路径相关逻辑优先使用 `backend/app/services/paths.py`，不要散落拼接 `data/projects/{id}`。
- 阶段调度、暂停/恢复/取消逻辑集中在 `backend/app/services/pipeline.py`；Agent 循环相关逻辑在 `backend/app/agent`。
- 可重置启发式 Worker 挖掘进度：`POST /api/projects/{id}/reset-progress`，仅暂停或终态（completed/cancelled/error）可用。清文件 `audited`/认领/启发式轮次摘要与 Worker 检查点；快速扫描 Sink 队列与历史漏洞绕过进度不重置，Semgrep 产物与冻结名单保留。保留漏洞产出、侦察文档、定权/跳过和环境；重置后保持暂停，便于换模型或改挖掘模式后再续跑。
- 侦察子阶段重跑：`POST /api/projects/{id}/recon-subphases/{map|old_vulns}/rerun`。仅「地图/鉴权」与「历史漏洞」在已完成后可点；保留原产出文档，按原子阶段流程再跑一遍以更新文档。SSE 日志并入对应小阶段并新开一轮对话（无独立「重跑」日志列）。地图重跑须 Agent 调用 `FinishReconMap` 结束。项目级「全部暂停 / 全部续跑」保留；大阶段级暂停/续跑/新跑已移除。
- 项目挖掘模式（赏金模式 `bounty` / 全量模式 `full` / 自定义模式 `custom`）在创建时确定，默认赏金模式；创建后仅当项目暂停或完成才可更改。已完成项目保持 `completed`，不可点暂停改成 `paused`。赏金/全量规则与闸门在 `backend/app/audit_mode.py` 和 `backend/app/prompts/modes/`；自定义模式在设置页维护命名提示词库，项目选用时快照正文，无赏金代码硬闸门，完全依赖提示词。续跑后下一轮 Agent 按新规则生效。
- 挖掘路径与赏金/全量正交：`heuristic_enabled`（默认 true）/ `fast_enabled`（默认 false）/ `bypass_enabled`（默认 false）描述「怎么挖」。至少开一条；暂停或完成后可改。启发式在历史漏洞收集完毕后按文件挖。盖章时权重 100 / `MarkSource` 覆盖用户可控入口（HTTP 以及 WebSocket / RPC / MQ / 回调等），不要只标 HTTP；Service / 过滤器 70–90，执行面 40–60，DTO/常量 10–30。Worker 按焦点角色挖：入口正向 source→sink，Service/过滤器回推或控面，低权薄扫。可开 `heuristic_lite`（默认 false）只把权重 100 的文件当入口，更低权重不阻塞完成。快速扫描 Recon 后 Semgrep → 代码筛（候选 200）→ SinkTriage → 冻结约 60 条 → Fast Worker 每轮 1 个 Sink 回推。历史漏洞绕过在历史漏洞收集完毕后把 `docs/old-vulns/` 文档冻结成队列，Bypass Worker 每轮注入 1 条尝试绕过补丁或确认未修复洞仍可打。`mining_complete` 须所有开启路径都结束且无 returned/fixing。SubmitVuln 按角色写入 `vulns.mining_path`（`heuristic` / `fast` / `bypass`），漏洞产出列表与详情展示对应中文标签。规则在 `backend/app/mining_paths.py`、`backend/app/services/sink_filter.py`、`backend/app/services/bypass_queue.py`。
- 验证方式在创建时三选一，默认关闭（Reviewer 只做静态复核）：`dynamic_verify_mode=off|lab|harness`（`dynamic_verify_enabled` 与 mode≠off 同步；旧库仅有布尔且为 true 视为 lab）。靶场动态：Reviewer 走独立环境轮搭建/复用 Docker 靶场（被测应用用导入的 `src/` 当前代码，禁止换成旧发行版 / 旧 tag / 旧应用镜像），并先跑当前 HTTP PoC；PoC 缺失或复现失败且需改写时才用 debug MCP。**PoC 与报告包装由 Reviewer 收口**（Worker 只交静态草案）；打回 Worker 仅用于入口/sink/根因分析债务，默认不打回改 PoC。误报用 `MarkFalsePositive`。打回上限 `max_review_rejects=1`，超过直接误报。同一条洞审核连续超时 2 轮（`review_timeouts_before_static`）后，下一轮强制仅静态（`evidence_level=static_only`），不再走靶场/局部验证与 Shell。局部验证：跳过环境轮，Reviewer 用 `RunCode` 在 sibling 沙箱跑 mock/harness，确认用 `evidence_level=harness`（列表与 `dynamic`/`mcp` 区分）；沙箱不可用或 mock 失败不因此误报。仅 harness 确认的前台洞不入队 Verifier。未开启时 ConfirmVuln 使用 `evidence_level=static_only`。已仅静态确认的漏洞可按当前模式追加靶场动态或局部验证。自建 lab 镜像 `{项目名}-{id}:lab`，Web 容器 `{项目名}-{id}`，依赖容器 `{项目名}-{id}-{role}`，compose 项目名 `{项目名}-{id}`；项目名会清洗成 Docker 合法字符，无法清洗时回退 `vulnhunter-{id}`。局部验证沙箱镜像 `vulnhunter/sandbox:latest`（`scripts\build-sandbox.cmd`）。Worker / Reviewer 产出的 `poc.py` 必须 CLI 参数化（`-u/--url` 任意目标，`--proxy` 设 HTTP 代理且空则直连，有代理时 `127.0.0.1` 也须强制走代理，RCE 另支持 `-c/--cmd` 并打印回显），harness 另存 `harness.py`，细则见 `backend/app/prompts/poc.md`。
- 可选 Verifier（互联网验证）在创建时由用户决定，默认关闭；创建后可在项目设置中开启。开启后，Reviewer 确认前台漏洞会排队用 FOFA 搜索同款目标并按报告复测，默认每批 10 个、成功 3 个即结束；当前这批不足 3 个则保留已成功的，再按同一语法补搜下一轮，最多 5 轮（合计最多 50 个目标）。应用指纹（FOFA/X 语句）按项目采集一次（源码 + 互联网检索，有靶场时可升级），写入 `docs/app-fingerprints.json`，所有漏洞复用。FOFA 有命中后项目内共享；占位或 0 条时可改写语法最多 3 次。报告与漏洞详情会列出全部 FOFA 目标并标注成功 / 失败 / 未测；互联网复现成功须附上搜索语法。任意文件删除、DoS、SQL 增删改等会中断或篡改业务的漏洞由 Verifier 调用 `AskUser` 询问用户：用户可跳过或给出自定义指示后继续；等待确认的项不阻塞项目完成，前端「验证确认」页统一展示。仅局部验证（harness）确认、无可对任意 URL 复测的 HTTP PoC 时仍自动跳过。FOFA Key 配在设置页或 `VULNHUNTER_FOFA_KEY`。
- 可选攻击链串联在创建时由用户决定，默认关闭；创建后可在项目设置中开启。开启后，在挖掘完成且审核队列清空后启动一轮 Agent：用 `SearchOldVuln`（仅本项目已确认产出）+ `Read`/`Grep` 推理多步串联；危害最大、利用最简单的最多 3 条经 `SubmitAttackChain` 写详文，其余经 `IndexAttackChain` 写入索引简述；已确认洞少于 2 条时跳过。与 Verifier 互不依赖，可并行；`project_complete_gates` 在开启时须等 `attack_chain_done`。重置启发式挖掘进度会清 `attack_chain_done` 以便再跑。
- 每个项目可单独设置 `llm_model`（创建时或项目配置中）；空则使用设置页全局 `default_model`。解析在 `resolve_llm(..., project_id=)`，对下一轮 Agent 生效。
- 模型商协议由 Provider 的 `wire_api` 决定：`chat` 为 OpenAI Chat Completions（默认），`anthropic` 为 Anthropic Messages（`POST /v1/messages`，system 独立、工具为 tool_use / tool_result）。检查点内部仍保存 Chat Completions 形状的消息。
- 全局 LLM 线程上限（设置页「总线程数」，默认 6）约束所有运行中项目的侦察 / 挖掘 / 审核 / 修复 / 验证 / 攻击链会话；每个与 LLM 交互的 Agent 会话占 1 个名额，超出的工作按到达顺序排队放行。
- 设置页可手动清理 X 天前的 SSE 实时日志（`live-events` / `live.events.jsonl`），实现集中在 `live_log.purge_older_than`。
- 历史漏洞阶段只收集、不读源码。先跑 GHSA / GitHub Issues 爬虫并把结果交给 Agent 落盘（第一阶段禁止 WebSearch）；完成后再由 Agent 用 WebSearch 补漏。公开 CVE/公告标 `patched`；未修复洞只从本仓库未关闭 GitHub Issues 收集，默认 `unpatched`。来源含爬虫（GHSA、本仓库 GitHub Issues）与 WebSearch 补漏。框架 CVE 清单 / 安全政策帖写进索引 `note`，不要一条一文。
- 工具实现放在 `backend/app/tools`，新增工具后确认会被 `register_all_tools()` 注册，并补充工具 ACL、阶段门闩或相关测试。
- 出站 HTTP、Chat 代理优先用设置页；未保存过时可用 `VULNHUNTER_HTTP_PROXY` / `VULNHUNTER_CHAT_PROXY`。不要硬编码代理地址。代理不可用时自动直连。
- Debug MCP 放在 `tools/mcp/`，用相对仓库根目录的路径；可用 `VULNHUNTER_MCP_JAVA` / `VULNHUNTER_MCP_NODE` / `VULNHUNTER_MCP_PYTHON` 覆盖。
- 不要在代码、测试、文档中写入真实 API Key、GitHub PAT、FOFA Key、CEYE token 或代理凭据。

## 前端约定

- API 类型和请求封装集中在 `frontend/src/api.ts`；新增后端字段时同步更新 TypeScript 类型。
- 页面放在 `frontend/src/pages`，可复用组件放在 `frontend/src/components`，基础 UI 组件放在 `frontend/src/components/ui`。
- 优先复用现有 UI 组件、Tailwind token 和 `cn()` 工具，不为小改动引入新的样式体系。
- 保持 React 函数组件风格；涉及轮询/可见性状态时先看 `frontend/src/lib/visibilityPoll.ts` 和现有页面实现。
- 前端构建以 `npm run build` 为准；改动类型或接口契约后至少运行构建。

## 测试与验证

- 后端行为改动优先补充 `backend/tests` 下的 pytest，尤其是 API、阶段状态、工具、漏洞审核、报告读取、上下文压缩和沙箱逻辑。
- 涉及数据库、项目工作区或运行态状态时，使用现有 `tmp_env`、`project` 等 fixture，保持测试隔离。
- 前端 UI 或类型改动至少运行 `cd frontend && npm run build`。
- 跨前后端契约变更要同时验证后端 pytest 和前端 build。

## 工作边界

- 不要提交 `frontend/dist`、`frontend/node_modules`、`backend/.venv`、`.pytest_cache`、`data/logs`、`data/projects`、`data/app.db` 等生成/运行态文件，除非用户明确要求。
- 不要随意清空或重建 `data/`，其中可能包含用户审计项目和日志。
- 需要启动服务前先确认是否已有后端 8000 或前端 5173 进程在运行，避免重复启动。
- 若改动 Agent 提示词、阶段流程或漏洞判定逻辑，要保持已有中文术语一致：Recon、Worker、Reviewer、Verifier、Fix、历史漏洞、历史漏洞绕过、漏洞产出、审计项目、赏金模式、全量模式、自定义模式、启发式挖掘、快速扫描、攻击链、攻击链串联。

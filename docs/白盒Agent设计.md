# 白盒 Agent（VulnHunter）设计

本文按当前仓库实现整理，覆盖导入、侦察、三条挖掘路径、审核、互联网验证与攻击链串联。实现以 `backend/app` 为准。

## 支持的模型

默认使用 **Chat Completions**（`wire_api=chat`），同时支持 **Anthropic Messages**（`wire_api=anthropic`）以及 OpenAI **Responses**（`wire_api=responses`，设置存储兼容）。凡兼容 Chat Completions 或 Anthropic Messages 协议的模型商均可接入。Anthropic 走 `POST /v1/messages`（`system` 独立、工具为 `tool_use` / `tool_result`），内部检查点仍按 Chat Completions 形状保存。

解析顺序（`resolve_llm(..., project_id=)`，对下一轮 Agent 生效）：

1. 项目级 `llm_model`（创建时或项目配置中指定；空则用全局）
2. 角色级供应商绑定（设置页可为 recon / worker / reviewer / verifier 指定不同 Provider）
3. 设置页全局 `default_model` / `default_base_url` / `default_api_key`

Chat Completions 默认直连；需要时代理走设置页「Chat 代理」，与工具出站代理分开。工具出站（WebSearch / GHSA / GitHub Issues / FOFA）走「HTTP 代理」。设置页尚未保存过时，可用环境变量 `VULNHUNTER_CHAT_PROXY` / `VULNHUNTER_HTTP_PROXY` 回退。代理连不上时自动直连。

全局 LLM 总线程数（设置页，默认 6）约束所有运行中项目的侦察 / 挖掘 / 审核 / 修复 / 验证 / 攻击链会话；每个与 LLM 交互的 Agent 会话占 1 个名额，超出按到达顺序排队。429 有进程级共享冷却。

## 工作流程

1. **导入源码**。GitHub 仓库地址或源码 zip。每个项目隔离工作区 `data/projects/{id}/`（`src/`、`docs/`、`workspace/`、`vulns/`、`env/`、`logs/`）。
2. **项目侦察（Recon）**。四个子阶段**串行**：代码地图/鉴权 → 扩展名补齐 → 历史漏洞（爬虫落盘 + WebSearch 补漏）→ 文件盖章。
3. **漏洞挖掘（Worker）**。与赏金/全量正交的三条路径，创建时至少开一条，暂停或完成后可改：
   - **启发式**（默认开）：历史漏洞收集完毕后按文件挖；可再开轻量版，只注入权重 100 的入口。
   - **快速扫描**（默认关）：Recon 完成后 Semgrep → 代码筛 → SinkTriage → 冻结约 60 条 → Fast Worker 每轮 1 个 Sink 回推。
   - **历史漏洞绕过**（默认关）：历史漏洞收集完毕后冻结 `docs/old-vulns/` 队列，Bypass Worker 每轮 1 条。
4. **审核（Reviewer）**。验证方式三选一，默认关闭（仅静态复核）：关闭 / 靶场动态 / 局部验证。明显误报用 `MarkFalsePositive`；PoC/报告包装由 Reviewer 本轮改完确认。仅入口/sink/根因分析错了才打回 Worker，默认最多打回 1 次，超过直接误报。
5. **互联网验证（Verifier）**。可选，默认关闭。Reviewer 确认**前台**漏洞后，用 FOFA 搜同款目标并按报告复测。
6. **攻击链串联**。可选，默认关闭。挖掘完成且审核队列清空后，根据已确认漏洞尝试多步串联。与 Verifier 互不依赖，可并行。

项目 `completed` 须：开启的挖掘路径都结束、无 pending/returned/fixing；若开了 Verifier 还须无 pending 前台复测；若开了攻击链还须 `attack_chain_done`。

## 挖掘模式与挖掘路径

二者正交。

### 挖掘模式（挖什么）

创建时确定，默认赏金模式；仅暂停或完成后可改。已完成项目保持 `completed`，不可点暂停改成 `paused`。

| 模式 | 代码 | 说明 |
| --- | --- | --- |
| 赏金模式 | `bounty` | 只收可利用高危害类型；代码硬闸门在 `audit_mode.py` |
| 全量模式 | `full` | 含 CORS、反射 XSS、缺速率限制等低危害难利用项 |
| 自定义模式 | `custom` | 设置页维护命名提示词库；项目选用时快照正文；无赏金硬闸门，完全按提示词 |

续跑后下一轮 Agent 按新规则生效。

### 挖掘路径（怎么挖）

| 开关 | 默认 | 角色 | `vulns.mining_path` |
| --- | --- | --- | --- |
| `heuristic_enabled` | true | `worker` | `heuristic` |
| `heuristic_lite` | false | 同上，仅权重 100 当入口 | 同上 |
| `fast_enabled` | false | `fast_worker` / `sink_triage` | `fast` |
| `bypass_enabled` | false | `bypass_worker` | `bypass` |

`mining_complete`：所有开启路径结束，且无 returned/fixing。轻量版未盖章 / 低权文件不阻塞启发式完成。快速扫描的 SAST Sink 覆盖命令/反序列化/SQL/文件等；鉴权 / IDOR / 业务逻辑仍靠启发式。

可重置启发式挖掘进度（`POST /api/projects/{id}/reset-progress`）：仅暂停或终态可用。清文件 `audited`/认领/启发式轮次摘要与 Worker 检查点；**不重置**快速扫描 Sink 队列与绕过进度。保留漏洞产出、侦察文档、定权/跳过和环境。重置后保持暂停，并清 `attack_chain_done` 以便再跑攻击链。

## 公共工具集

工具有统一注册入口 `register_all_tools()` 与统一调度 `registry.dispatch()`。按角色 ACL 注入；调用失败必须返回具体 `error`（`error_class` 为 `call` 或 `local`）。本地执行失败额外写入 `logs/tool-exec-errors.jsonl`。调用会记入 `tool_logs`（时间、入参、出参、耗时），并经 SSE 实时日志展示。

同一轮内可并行的只读工具：`Read`、`Grep`、`Glob`、`SearchOldVuln`、`WebSearch`。`Write` 与 shell 不可并行。主机只注入一种 shell（Windows 优先 PowerShell，否则 Bash）。

| 工具 | 用途 |
| --- | --- |
| `Read` | 读一个或多个文件（禁止直接读 `docs/old-vulns`）。返回带行号；大文件按 `offset`/`limit` 分页 |
| `Glob` | 按模式列文件（自动跳过 `node_modules`/`target`/`dist`/`build` 等） |
| `Grep` | 源码正则搜索（同样跳过噪声目录） |
| `Write` | 写 `workspace`/`docs`/`vulns`/`env`；不可写 `docs/old-vulns` |
| `Bash` / `PowerShell` | 工作区沙箱执行。禁止递归全库列举；禁止删除项目自身与被审计源码。timeout 默认 120s、最多 180s，另有硬超时 |
| `TodoWrite` | 维护**本阶段自己的**运行时待办（按角色分文件，互不覆盖） |
| `WebSearch` | 仅历史漏洞第二轮（搜索补漏） |
| `SearchGHSA` / `SearchGitHubIssues` | 补漏轮兜底；爬虫落盘轮禁止 |
| `SearchOldVuln` | 搜本项目漏洞库。默认标题+摘要；传 `title`/`#id` 看全文。`kind=old` 为侦察历史洞，`kind=found` 为本项目已提交报告 |

沙箱：路径限制在项目工作区内，禁止 `..`；`docs/old-vulns` 只允许 `SearchOldVuln` / `WriteOldVuln`；shell 不可破坏仓库与 `src/`。

## 状态机

调度集中在 `backend/app/services/pipeline.py`。项目级「全部暂停 / 全部续跑」保留；大阶段级暂停/续跑/新跑已移除。侦察子阶段可重跑：`POST /api/projects/{id}/recon-subphases/{map\|old_vulns}/rerun`（仅已完成后；保留原文档再跑一遍；SSE 并入对应小阶段并新开一轮；地图重跑须 `FinishReconMap`）。

多数阶段**没有**「结束工具」：门闩满足后系统自动结束。已移除 `FinishRecon` / `FinishAudit`。

### 1. 项目侦察

四个子阶段严格串行。

#### 1.1 代码地图 / 鉴权（`recon`）

整体查看 `src/`，边做边 `Write`：

- `docs/code-map.md`：模块、HTTP 与非 HTTP 入口、技术栈、模板引擎 / ORM
- `docs/auth.md`：登录、角色、session、显式允许的能力

每确认一个用户可控入口立刻 `MarkSource`（HTTP / WebSocket / RPC / MQ / 回调等，自动权重 100）。不要扫全库标权重。两份文档齐全后系统结束本会话。若是**重跑更新**，写回后须 `FinishReconMap`。

#### 1.2 扩展名（`recon-source-ext`）

根据代码地图把默认未入库的执行面扩展名补进索引（如 `.ftl`、MyBatis `.xml`）。工具：`AddSourceExt`。无需追加则 `none=true`；全部确认后 `done=true`。不要改地图/鉴权，不要标权重。

#### 1.3 历史漏洞（`recon-old-vuln` → `recon-old-vuln-ghsa`）

**只收集、不读源码。** 两类口径：

| 类型 | 来源 | `fix_status` | 用途 |
| --- | --- | --- | --- |
| 公开且已修复 | GHSA / 公开 CVE 公告 / WebSearch | `patched` | 历史漏洞绕过线索；不要当新洞再报 |
| 公开未修复 | 仅本仓库**未关闭** GitHub Issues | `unpatched` | 启发式去重 |

流程：

1. 系统先跑 GHSA + GitHub Issues 爬虫，结果写入 `workspace/ghsa_new.json`。
2. Agent 只根据爬虫结果 `WriteOldVuln` 落盘（第一轮**禁止** WebSearch）。
3. 完成后再开一轮，用 WebSearch 按产品短名补漏公开 CVE/公告。

每确认一条立刻写一条；落盘不会结束会话。本轮结束再 `WriteOldVuln(done=true)`；无符合口径则 `no_findings=true`。框架 CVE 清单 / 安全政策帖写进索引 `note`，不要一条一文。文档必须有 YAML 元数据（标题、摘要）。禁止用 `Read`/`Write`/`Shell` 直接碰 `docs/old-vulns/`。

启发式与绕过路径在**历史漏洞收集完毕**后即可启动，不必等盖章结束。盖章未完成前，系统不会因「启发式文件未审完」而结束项目。

#### 1.4 文件盖章（`recon-mark`）

盖章前先按白名单扩展名（含 Agent 追加的）对文件建库。每轮由代码注入最多 **150** 个未标记文件。只对本批 `MarkSource` / `MarkWeight` / `MarkSkip`，不要读全文。标完本批系统自动结束并注入下一批。

权重约定：

| 角色 | 权重 | 标记 |
| --- | --- | --- |
| 用户可控入口（HTTP 及 WebSocket / RPC / MQ / 回调等） | 100 | 优先 `MarkSource` |
| Service / 过滤器 / 鉴权 | 70–90 | `MarkWeight` |
| Mapper / 模板 / 危险工具 | 40–60 | `MarkWeight` |
| DTO / 常量 / 启动类 | 10–30 | `MarkWeight` |
| 测试 / 生成代码 / 静态资源 | 跳过 | `MarkSkip` |

当**任意文件已有权重**后，启发式即可同步挖（仍须历史漏洞已收齐）。Recon 未全部结束前，系统按门闩结束挖掘范围，Agent 无需也不再调用 `FinishAudit`。

全部文档落盘且所有未 skip 文件都有权重后，系统标记 `recon_done`，并采集一次项目级应用指纹到 `docs/app-fingerprints.json`（源码标题/静态资源/仓库 favicon + 互联网检索的 FOFA 语句），后续漏洞复用。

| 工具 | 用途 |
| --- | --- |
| `MarkSource` | 标记一个或多个 source 方法与文件，自动权重 100 |
| `MarkWeight` | 为文件标记 0–100 权重 |
| `MarkSkip` | 跳过低价值文件 |
| `AddSourceExt` | 追加源码扩展名并入库 |
| `WriteOldVuln` | 逐条写入 `docs/old-vulns/` 并更新 `index.md` |
| `FinishReconMap` | 仅地图/鉴权重跑会话使用 |

### 2. 漏洞挖掘

提交一律走 `SubmitVuln`（按角色写入 `mining_path`）。必填：title、vuln_type、cwe、file_path、line_no、source_sink、auth_premise、config_premise、http_request、poc_code、expected_evidence。`config_premise` 为 `default`（默认配置）或 `specific`（特定配置；不含官方已警示的风险开关）。严重度入库为 `pending`，由 Reviewer 校准。同一根因同一危害只交一份：填 `root_cause_key`（`类型:稳定锚点`）；已有 pending 同根因用 `AppendAffectedLocations`，不要再 Submit。

`poc.py` 必须 CLI 参数化：`-u/--url` 为目标 origin；`--proxy` 设 HTTP 代理（空则直连）并接到全部 HTTP 请求；有代理时访问 `127.0.0.1`/`localhost` 也必须强制走代理（覆盖 `proxy_bypass`）。RCE 另支持 `-c/--cmd` 并打印回显。细则见 `backend/app/prompts/poc.md`。报告对齐 `templates/vuln-report.md`。

#### 启发式扫描

历史漏洞收集完毕后，每轮由代码注入当前权重最高且未审计的文件（优先 `has_source`）。注入的是本轮**焦点**，不是唯一可读文件。确认无独立审计价值的文件立刻 `FinishFile`（不会结束本轮）；仅当焦点已按角色分析完后，才 `FinishFile` 该焦点并 `FinishRound`（须先成功过一次 `FinishFile`，且焦点必须已标）。`FinishRound` 须附对齐 `templates/round-report.md` 的中文摘要。范围内文件都 `audited` 后，系统结束启发式，无需结束工具。

Reviewer 打回（仅分析债务）会新开 Fix 线程（独立于挖掘池），改完 `FinishFix` 重新入队。PoC 跑不通不要打回。

按角色挖掘，不是一律当 HTTP source：

| 角色 | 方向 |
| --- | --- |
| 权重 100 / `has_source` | 正向 source→sink（含非 HTTP） |
| 过滤器 / 鉴权 | 控面（匹配、绕过、失败开放） |
| Service | 危险操作与鉴权缺口，回推 caller / 二阶 |
| Util / Mapper / 模板 | 执行面或 sink 回推 |
| DTO / 常量 / 死代码 | 薄扫后收工，禁止拿本轮去填上一轮的洞 |

**轻量版**（`heuristic_lite`）：只把权重 100 的文件当入口；更低权不阻塞完成。其余规则同上。

新一轮开始前，系统注入 `docs/code-map.md`、`docs/auth.md`、最近最多 10 轮挖掘摘要、当前焦点文件片段（上限约 80KB）。

| 工具 | 用途 |
| --- | --- |
| `SubmitVuln` | 提交待审核漏洞 |
| `AppendAffectedLocations` | 向已有 pending 报告追加同根因受影响点 |
| `FinishFile` | 标记文件不必再作为后续轮次注入焦点 |
| `FinishRound` | 结束本轮（须先 FinishFile 本轮焦点） |
| `FinishFix` | 完成分析债务修改，重新入审核队列 |

#### 快速扫描

Recon 完成后：

1. Semgrep 扫 Sink（超时 `timeout_semgrep`，默认 1800s）
2. 确定性代码初筛，候选最多 **200**
3. 短 Agent `SinkTriage`（禁止读代码）：keep / drop / defer，冻结约 **60** 条
4. Fast Worker 每轮注入 1 个 Sink，从 sink 回推用户可控入口
5. `FinishSink(verdict=vuln_submitted|unreachable|sanitized|intended|noise)` 结束本轮

| 工具 | 用途 |
| --- | --- |
| `FinishSinkTriage` | 提交本批 keep/drop/defer |
| `FinishSink` | 结束本轮注入的这一条 Sink |

#### 历史漏洞绕过

历史漏洞文档冻结成队列后，每轮注入 1 条全文。已修复看补丁是否完整（黑名单、只修代表点、编码/别名绕过）；未修复则确认当前源码仍可打。`FinishBypass(verdict=bypass_submitted|still_patched|unreachable|incomplete|intended)`。

| 工具 | 用途 |
| --- | --- |
| `FinishBypass` | 结束本轮注入的这一条历史漏洞 |

### 3. 审核（Reviewer）

验证方式 `dynamic_verify_mode=off|lab|harness`（与 `dynamic_verify_enabled` 同步；旧库仅有布尔且为 true 视为 lab）。默认 `off`。

流程对每条 pending 漏洞：

1. 读 `vulns/{id}/report.md`、`request.http`、`poc.py`，静态复核。明显误报 → `MarkFalsePositive`。PoC/报告包装本轮自己改，不要打回。
2. `SearchOldVuln kind=found` 查重。同根因同危害用 `MergeIntoVuln` 并入主报告，不要打回/误报/改已确认报告。危害或鉴权不同的相关变体才标 `duplicate_grouped` 并原样复用 `root_cause_key`。
3. 按验证方式取证（见下）。
4. `ConfirmVuln` 必须标：`attack_surface`（前台/后台）、后台再标 `required_account`（user/admin）、`impact` / `exploit_complexity` / `defense_status`、`submission_tier` / `submission_reason`。核对并可纠正 `config_premise`。`ConfirmVuln`、`MarkFalsePositive` 或 `ReturnToWorker` 后本会话结束。

打回仅用于入口/sink/根因分析债务。上限 `max_review_rejects=1`。超过直接误报。

#### 关闭（仅静态）

不搭 Docker、不跑 poc.py、不用 MCP。`evidence_level=static_only`。已仅静态确认的漏洞，可按当前模式**追加**靶场动态或局部验证。

#### 靶场动态（`lab`）

独立环境轮（`reviewer-lab`）在审核漏洞之前搭建/复用 Docker 靶场，不审核漏洞。优先复用 `src/` 里已有 Dockerfile/compose。完成后 `FinishLab`；无法搭建则 `FinishLab(skipped=true)`。环境起不来但静态已能证明默认可利用 → 仍可 `static_only` 确认。

命名（项目名清洗成 Docker 合法字符，无法清洗时回退 `vulnhunter-{id}`）：

| 资源 | 名称 |
| --- | --- |
| 自建 lab 镜像 | `{项目名}-{id}:lab` |
| Web 容器 | `{项目名}-{id}` |
| 依赖容器 | `{项目名}-{id}-{role}` |
| compose 项目 | `{项目名}-{id}` |

容器与自建镜像须带标签 `vulnhunter=1`、`vulnhunter.project={id}`。写出 `env/env.json`，系统据此写 `docs/lab.md`。官方镜像（mysql/redis 等）保持原名。

人工靶场：创建/配置时填写环境地址与凭据（`manual_lab` + `manual_lab_prompt`），跳过 Docker 环境轮，审核时自动注入。

审核阶梯：

1. **先跑当前 HTTP PoC**：`python vulns/{id}/poc.py -u <target_url>`（需要抓包时加 `--proxy`），结合 docker exec / 日志**观察**冲击。写死地址或缺 `--proxy` 只改 CLI 形态；同链 payload 不对由 Reviewer 改，不算分析债务。
2. **debug MCP 仅当** PoC 缺失、跑不通或复现失败，且 Reviewer 需要自己改写/调试时才用。不要一上来挂 MCP，禁止往靶场种 payload 制造利用条件。
3. 复现成功：`evidence_level=dynamic`（HTTP PoC）或 `mcp`（用了 debug MCP）。

有靶场且项目指纹仍缺标题/hash 时，用 `CollectLabFingerprints` 升级共享指纹。

#### 局部验证（`harness`）

跳过环境轮。Reviewer 用 `RunCode` 在一次性兄弟容器 `vulnhunter/sandbox:latest`（无网、跑完删除）里按**目标语言**跑 mock/harness，写入 `harness.py`（不要写进 `poc.py`）。打通且成立性满足 → `evidence_level=harness`。沙箱不可用或 mock 失败**不因此误报**；静态已能证明则 `static_only`。仅 harness 确认的前台洞**不入队 Verifier**。

| 工具 | 用途 |
| --- | --- |
| `ConfirmVuln` | 确认漏洞并校准严重度与价值分层；可回写收口后的 `poc_code` |
| `MarkFalsePositive` | 判定误报 |
| `ReturnToWorker` | 仅打回补分析债务（入口/sink/根因错了） |
| `MergeIntoVuln` | 同根因同危害并入主报告 |
| `CollectLabFingerprints` | 从靶场升级项目共享指纹 |
| `FinishLab` | 结束独立 Docker 靶场搭建轮 |
| `RunCode` | 仅局部验证审核轮：在沙箱执行 harness |
| `SearchOldVuln` | 查历史洞与本项目已提交报告 |

### 4. 互联网验证（Verifier）

可选。开启后，Reviewer 确认**前台**漏洞会入队。应用指纹按项目采集一次，所有漏洞复用。FOFA 有命中后项目内共享（`docs/fofa-targets.json`）；占位或 0 条时可改写语法最多 **3** 次。

默认每批 **10** 个、成功 **3** 个即结束。当前这批不足 3 个则保留已成功的，`FofaSearch(expand=true)` 按同一语法补搜下一轮，最多 **5** 轮（合计最多 **50** 个目标）。报告列出全部目标并标注成功 / 失败 / 未测；成功须附搜索语法、实际 URL、poc 与回显。

自动跳过、不做互联网复测：

- 任意文件删除、文件上传、DoS
- SQL 增删改 / 结构变更
- 仅 `evidence_level=harness` 确认（没有可对任意 URL 复测的 HTTP PoC）
- 后台漏洞（只测前台）

FOFA Key 配在设置页或 `VULNHUNTER_FOFA_KEY`。

| 工具 | 用途 |
| --- | --- |
| `FofaSearch` | 只读测绘；有缓存则复用；`expand=true` 翻页补搜 |
| `FinishVerifier` | 提交结论：`success` / `fail` / `no_targets` / `skipped` |

### 5. 攻击链串联

可选。挖掘完成且审核队列清空后启动一轮 Agent。已确认洞少于 2 条时跳过并标记完成。本阶段 `SearchOldVuln` **只允许**本项目已确认产出（`kind=old` 不可见）。不执行 PoC、不打靶场、不打互联网。找不到合理链也必须 `FinishAttackChain`，不要硬凑。

| 工具 | 用途 |
| --- | --- |
| `SearchOldVuln` | 仅已确认产出；默认标题+摘要，传 title/#id 看全文 |
| `SubmitAttackChain` | 提交一条链（至少 2 个已确认 `vuln_id` + steps 正文），写入 `docs/attack-chains/` |
| `FinishAttackChain` | 结束本阶段（有链或无链都必须调用） |

## 角色与工具 ACL

| 角色 | 阶段 | 可用工具（摘要） |
| --- | --- | --- |
| `recon` | 地图/鉴权 | Read/Grep/Glob/Write/shell/TodoWrite/MarkSource/FinishReconMap |
| `recon_source_ext` | 扩展名 | Read/Grep/Glob/TodoWrite/AddSourceExt |
| `recon_old_vuln` | 历史漏洞爬虫落盘 | Read/TodoWrite/SearchOldVuln/WriteOldVuln |
| `recon_old_vuln_ghsa` | 搜索补漏 | 上列 + WebSearch/SearchGHSA/SearchGitHubIssues |
| `recon_mark` | 盖章 | 仅 MarkSource/MarkWeight/MarkSkip |
| `worker` | 启发式 | 公共读写 + SearchOldVuln/SubmitVuln/AppendAffectedLocations/FinishFile/FinishRound/FinishFix |
| `fast_worker` | 快速扫描 | Read/Grep/Glob/SearchOldVuln/SubmitVuln/AppendAffectedLocations/FinishSink |
| `bypass_worker` | 绕过 | 同上，收工工具为 FinishBypass |
| `sink_triage` | Sink 筛选 | 仅 FinishSinkTriage |
| `reviewer` | 审核 | 公共读写 + SearchOldVuln/SearchGHSA/ConfirmVuln/CollectLabFingerprints/MergeIntoVuln/MarkFalsePositive/ReturnToWorker；局部验证时另注入 RunCode |
| `reviewer_lab` | 靶场搭建 | Read/Grep/Glob/Write/shell/TodoWrite/FinishLab |
| `fix` | 打回修复 | 公共读写 + SearchOldVuln/FinishFix/SubmitVuln/AppendAffectedLocations |
| `verifier` | 互联网验证 | 公共读写 + FofaSearch/FinishVerifier |
| `attack_chain` | 攻击链 | Read/Grep/TodoWrite/SearchOldVuln/SubmitAttackChain/FinishAttackChain |

## 上下文压缩

当请求估算 token 超过上下文窗口的 **85%**（设置页可配窗口，默认 128000）时主动压缩：发送 Conclude 提示词，落盘总结文档到 `docs/summaries/`，确认落盘后新开上下文，并注入总结作为初始上下文。启发式还会注入最近最多 10 轮 `workspace/rounds/` 摘要。Worker 轮次结束后系统压缩本轮并自动注入下一份尚未 `FinishFile` 的文件。

## 容错与恢复

对齐 AutoPoc：检查点落在 `workspace/checkpoints/`，暂停/进程中断后可接续原上下文。

1. **LLM 429**。休眠 90s 再试，最多 20 次；有进程级共享冷却。其它请求退避 3 次。
2. **工具调用失败**。把错误原因返回给 LLM。本地执行失败记高权重日志（`tool-exec-errors.jsonl`）。
3. **每轮失败退出前**发送 Conclude，编写总结，新一轮注入。失败原因包括：本轮超时、429 重试用尽、死循环（相同工具阈值触达 5 次）。阶段最多再试 2 次（`phase_max_resumes`）；侦察最多 8 次（`recon_max_resumes`）。
4. **无工具调用的纯文字轮**视为无效轮，立刻提醒改用工具（见看门狗）。门闩满足后系统自己结束。

各阶段默认时限（秒）：

| 阶段 | 配置 | 默认 |
| --- | --- | --- |
| Recon | `timeout_recon` | 3600 |
| Recon 盖章轮 | `timeout_recon_mark_round` | 1800 |
| Worker 一轮 | `timeout_worker_round` | 7200 |
| Reviewer 静态 | `timeout_reviewer_static` | 1800 |
| Reviewer 动态（含 Docker） | `timeout_docker + timeout_reviewer_static` | 3600 |
| Verifier | `timeout_verifier` | 1800 |
| 攻击链 | `timeout_attack_chain` | 1800 |
| Semgrep | `timeout_semgrep` | 1800 |
| Sink 筛选 | `timeout_sink_triage` | 1800 |
| Conclude | `timeout_conclude` | 300 |
| Conclude 抢救 | `timeout_conclude_rescue` | 1800 |

盖章每批文件数：`recon_mark_batch_size=150`。

## 漏洞挖掘指令与去重

### 成立性闸门（所有模式）

source→sink 可达只是候选。必须在**默认配置**或**只修改应用自身提供的配置选项**下，攻击者只凭自身权限与用户可控输入就能打出可观察有害冲击。`SubmitVuln` 必填 `config_premise`：`default`（默认配置）或 `specific`（须改应用自身配置）。**特定配置不包括**官方文档已明确警示会导致安全风险的配置；仅在此类开关下才成立的不要提交。禁止为了让洞成立而种文件、改非应用配置、组合第二个独立漏洞。已知且允许的业务能力对照 `docs/auth.md`；若仍提交须 `intended_behavior=true`。

### 赏金模式范围

接收：RCE、SSTI、反序列化、SQL 注入、XML 注入、任意文件操作（读/写/删/改/复制/解压穿越等）、能打内网的 SSRF、敏感信息泄露、文件上传、文件包含、目录遍历、认证绕过、越权、DoS、**存储型 XSS**、**有服务端机密危害的源码硬编码密钥**，以及其他确定能造成实际危害的问题。

明确丢弃（不要标 `low_impact` 入库）：CORS / 安全头、开放重定向（除非能升级为鉴权劫持）、反射 XSS / DOM XSS / Self-XSS、缺速率限制、弱随机（除非直接导致认证绕过）、配置文件 / `.env` / compose 里用户可改的口令、前端传输混淆 AES / 公开下发密钥。

SSRF 必须标明观察面：有回显（响应含目标正文）或仅响应差别（内网端口探测）。仅差别不得写成已获取云元数据凭据。

### 全量模式范围

除高危害外，也接收难以利用但仍能被请求打出差异的问题（CORS、反射 XSS、缺速率限制等），Confirm 后价值标 `low_impact`。不可利用的代码味道、需种文件才成立的路径逃逸、配置默认密码、前端混淆 AES 仍应误报。

### 自定义模式

无赏金代码硬闸门。收录与确认标准完全以项目快照的自定义提示词为准；不改变工具权限或 ACL。

### 价值分层

Reviewer 确认时二选一（另加一个流程标记）：

| `submission_tier` | 中文 |
| --- | --- |
| `cve_candidate` | 有 CVE 价值 |
| `low_impact` | 低危害难利用 |
| `duplicate_grouped` | 危害/鉴权不同的相关变体（不是并入；须复用 `root_cause_key`） |

缺动态复现不是价值分层：静态已能证明默认可利用时用 `evidence_level=static_only`，价值仍标上面两类。

### 去重

- Worker 提交前必须 `SearchOldVuln`（`kind=old` 去重未修复洞，`kind=found` 查本项目已交）。
- 同 `file_path+vuln_type` 或同 `root_cause_key`：首次调用会提醒；确认仍要单独交时再次调用并传 `confirm_not_duplicate=true`（仅本会话已提醒过一次后才接受）。
- Reviewer 同根因同危害优先 `MergeIntoVuln`，不要 Confirm 成多份。

### 严重度分数

Worker 不填严重度。Reviewer 按四维校准，不按漏洞类型映射：

| 维度 | 取值 | 分 | 怎么来的 |
| --- | --- | --- | --- |
| 可达性 | 未认证可达 | +1 | `attack_surface=frontend`（前台） |
|  | 低权限可达 | +0 | 后台 + `required_account=user` |
|  | 管理员才可达 | -1 | 后台 + `required_account=admin` |
| 影响范围 `impact` | RCE / 全库 / 完整控制 | +4 | `rce_or_full_data` |
|  | 敏感数据 / 权限提升 / 部分数据 | +2 | `sensitive_data_or_privilege` |
|  | 有限信息泄露 / 信息收集 | +1 | `limited_info` |
| 利用复杂度 `exploit_complexity` | 单请求或简单触发 | +0 | `single_request` |
|  | 多步骤利用 | +0 | `multi_step`（不加分也不扣分） |
|  | 依赖特定环境 | -2 | `specific_environment` |
| 防护状态 `defense_status` | 无有效防护 | +0 | `none` |
|  | 有防护但可绕过 | +0 | `bypassable` |
|  | 有防护且绕过需额外条件 | -1 | `conditional` |

分数：≥5 critical，3–4 high，1–2 medium，≤0 low。

## 看门狗提醒

1. **本轮没调任何工具（所有阶段）**  
   纯文字回复立刻注入提醒：改用工具继续；门闩满足后系统会自己结束。每出现一轮无工具都会提醒一次，计数累加；一旦有工具调用，连续无工具计数清零。环境轮 / Verifier / 攻击链 / Fast / Bypass / SinkTriage 有各自文案。

2. **连续 4 次「同一工具 + 同一参数」（所有阶段）**  
   判定为死循环窗口后拦截：这次不执行，返回错误让模型改参数、换工具或往下走，并重置窗口。同一轮触达该阈值 **5** 次则终止本轮。

3. **侦察落盘空闲 50 轮**  
   - `recon-old-vuln`：催 `WriteOldVuln`  
   - `recon-old-vuln-ghsa`：催补漏并 `WriteOldVuln`  
   - `recon-source-ext`：催 `AddSourceExt`  
   对应工具清零计数；`Read` / `Grep` 等不算。之后每再空闲 50 轮（100、150…）再催一次。代码地图/鉴权轮不催落盘。

4. **挖掘收工空闲 50 轮**  
   - Worker：催 `FinishFile`（标完继续分析焦点，禁止立刻 `FinishRound`）  
   - Fast Worker：催 `FinishSink`  
   - Bypass Worker：催 `FinishBypass`  
   - SinkTriage：催 `FinishSinkTriage`  
   对应工具清零，其它工具不算。之后每再空闲 50 轮再催一次。

## 框架

### 前端

Vite + React + TypeScript + Tailwind，组件基于 shadcn/ui。

- 首页：GitHub 地址或 zip 创建项目；选挖掘模式、三条挖掘路径、验证方式、Verifier、攻击链、项目模型。卡片展示阶段流程图、挖掘进度、token、漏洞计数。
- 项目详情：阶段流程图（侦察含四个子阶段；审核含环境搭建/审核；挖掘按开启路径分列）。点击阶段看 SSE 实时日志（Agent 文本 + 工具调用）。可全部暂停/续跑、重跑地图或历史漏洞、重置启发式进度、改项目配置。
- 漏洞产出：确认 / 误报 / 待审筛选，另可按前台/后台、价值分层、提交跟踪筛选；同根因分组；批量下载报告；详情含 PoC、HTTP 包、互联网验证目标、追加动态/局部验证。
- 容器页：查看/管理本机 VulnHunter 靶场容器。
- 设置页：Chat Completions Base URL / API Key / 默认模型 / 上下文窗口；多 Provider（chat/responses）与角色绑定；GitHub PAT；FOFA Key；出站代理与 Chat 代理；全局 LLM 总线程数（默认 6）；自定义审计模式提示词库；清理 X 天前的 SSE 实时日志。

挖掘 Worker 并发当前为代码内固定池（挖掘 1、修复 1），不再由设置页「Worker 并发数」调节；并发压力由全局 LLM 总线程数约束。

### 后端

Python FastAPI + SQLAlchemy + SQLite。

- 路由 `backend/app/api`，schema `schemas.py`，模型 `models.py`（已有库加列走 `_ensure_columns()`）
- 路径一律经 `services/paths.py`
- 阶段调度 `services/pipeline.py`；Agent 循环 `agent/loop.py`（压缩、检查点、429、看门狗）
- 工具 `backend/app/tools`，新增须注册并补 ACL / 门闩 / 测试
- 提示词 `backend/app/prompts`，文档模板 `templates/`
- 运行态：`data/projects/{id}`、`data/logs`、`data/app.db`

每个阶段消耗的 token（输入 / 输出 / 缓存 / 合计）记入 `phase_runs` 与 `token_usages`，前端项目卡片与阶段报告展示。

## MCP

用于靶场动态时**修正 PoC**，不是首选验证方式。源码在仓库 `tools/mcp/`（相对仓库根），不依赖外部 `D:\AI\MCP_Tools` 路径。可用 `VULNHUNTER_MCP_JAVA` / `VULNHUNTER_MCP_NODE` / `VULNHUNTER_MCP_PYTHON` 覆盖。

| 运行时 | 目录 |
| --- | --- |
| Java | `tools/mcp/java-debug` |
| Node | `tools/mcp/node-debug` |
| Python | `tools/mcp/python-debug` |

未构建时 Reviewer 只走普通动态（HTTP PoC + docker exec）。局部验证不使用 debug MCP。

## 其他

1. 每个项目工作目录隔离：`data/projects/{id}/{src,docs,workspace,vulns,env,logs}`。
2. 漏洞报告须有 HTTP 请求包（`request.http`）、CLI 参数化的 Python PoC（`poc.py`）；局部验证另存 `harness.py`。确保 Reviewer / Verifier / 人工仅凭报告即可换目标复现。
3. 文档按各自模板写：`templates/code-map.md`、`auth.md`、`old-vuln.md`、`old-vulns-index.md`、`vuln-report.md`、`round-report.md`、`search-fingerprints.md`、`summary.md`。
4. 记录每个阶段消耗的总 token（输入、输出、缓存）。
5. 不要在代码、测试、文档中写入真实 API Key、GitHub PAT、FOFA Key、CEYE token 或代理凭据。

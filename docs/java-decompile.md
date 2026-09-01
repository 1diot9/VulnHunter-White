# Java 反编译（设计决策）

本文档拍板 Recon / Worker / Reviewer 的 Java 反编译能力。实现前以此为准；变更须同步改本文与工具 ACL / 提示词。

**入口形态（已定）**：内置 Tool 收口 jadx、索引与异步；不对 Agent 暴露原始 CLI；不走 `tools/cli` + `SearchTools`。

---

## 1. 异步语义（不阻塞本轮）

### 决策

| 项 | 决定 |
| --- | --- |
| 阻塞边界 | **只保证 jadx 子进程不占用本轮 LLM 回合**：`DecompileJava` 同步返回（毫秒级），后台排队执行。 |
| Agent 循环 | **第一期不改**同回合真并行；现有 `PARALLEL_SAFE` 仍仅标记。`DecompileJava` 可标 `parallel_safe=True`（自身立刻返回），但不依赖循环并行。 |
| 完成回传 | **系统注入优先 + 查询兜底**。每轮工具结果落盘后、下一次请求模型前，若本项目有自该会话提交且刚完成的任务，注入一条 user 消息（含 `job_id`、源路径、`output_root`、状态）。Agent 也可再次调用 `DecompileJava` 查询同一路径 / `job_id`。 |
| Watchdog | **禁止空转轮询**。提示词明确：queued/running 时去做别的事，不要反复同参调用。实现上：对 `DecompileJava` 且参数仅查询且索引仍为 queued/running 的连续相同调用，在 identical 拦截时改写 redirect 文案为「任务仍在跑，请 Read/Grep 其它文件或继续地图」，**不计入** `identical_threshold_hits` 的终止额度（或单独豁免该 key），避免「合规等待」被当成死循环杀掉。 |
| Shell 硬超时 | 不适用：jadx 不走 Bash/PowerShell 的 120–180s 硬超时。 |

### 工具瞬时返回形状（约定）

```json
{
  "ok": true,
  "status": "ready | queued | running | failed | skipped",
  "job_id": "…",
  "source": "src/lib/app.jar",
  "output_root": "workspace/decompiled/<key>/",
  "hint": "任务已排队；请继续其它工作，完成后系统会注入通知，也可再用本工具查询。"
}
```

`ready` 时额外给 `primary_files`（最多约 20 条入口类路径）与 `class_count`；完整树用 `Glob`/`Grep` 在 `output_root` 下浏览。

---

## 2. 任务生命周期

### 决策

| 场景 | 决定 |
| --- | --- |
| 跨轮次 / 跨阶段 | **允许**。任务挂在**项目级**后台队列，不绑死某次 AgentLoop 的 `timeout_sec`。 |
| 跨暂停 | **继续跑**已启动的 jadx；新提交在暂停期间仍可排队（若调度器仍处理工具调用）或等续跑后再提交——实现取「暂停不杀已跑子进程」。 |
| 进程重启 | 内存队列与 jadx 子进程会丢。启动恢复 / 续跑只向反编译 sidecar **投递** resume；任务快照与待入库路径在 `data/decompile.db`，`index.jsonl` 仍作 Agent 查询回放。已 `ready` 的产物在 sidecar 于 app.db **空闲时**滴注入 `FileWeight`。 |
| 项目取消 | **取消队列中任务**；尽量 terminate 正在跑的 jadx；索引标 `cancelled`。 |
| Recon 结束时未完成 | **不阻塞**代码地图门闩 / `FinishReconMap`。未完成任务继续在后台跑；Worker / Reviewer 需要时查询索引，命中则用，未命中再补提交。 |
| `reset-progress` | **保留**反编译索引与产物（与 Semgrep 产物、侦察文档类似，属可复用工件）。 |
| 重新导入 zip / 换源 | **清空** `workspace/decompiled/` 与索引。 |
| 单任务超时 | 默认 **1800s**（可配置）；超时标 `failed`，可带 `force=true` 重试一次。 |

---

## 3. 字节码如何被发现

### 现状约束

`ingest` 将 `.class` / `.jar` / `.war` 列入 `IGNORE_FILE_SUFFIXES`，并把 `target` / `build` / `dist` 等列入 `IGNORE_DIR_NAMES`。因此普通 `Glob` / 文件权重索引**看不到**这些文件。

### 决策

| 项 | 决定 |
| --- | --- |
| 发现入口 | 新增并行安全工具 **`ListBytecode`**：在 `src/` 下枚举 `.class` / `.jar` / `.war`（及可选 `.ear`），**不受**后缀忽略限制；默认仍跳过 `IGNORE_DIR_NAMES`（含 `target`/`build`/`dist`）。 |
| 构建产物 | 默认**不碰** `target/` 等。`ListBytecode(include_build_dirs=true)` 仅 Recon 可用，且提示词写明「仅当仓内无已提交 lib、只有编译输出时才开」。 |
| 无字节码 | `ListBytecode` 空列表 → 反编译能力对本项目 **no-op**；提示词不要求强行调用 `DecompileJava`。 |
| 权重索引 | **仍不**把 `.class`/`.jar` 写入 `FileWeight`；Worker 焦点仍是源码扩展名。 |

---

## 4. Recon「重要文件」与范围

### 决策

| 项 | 决定 |
| --- | --- |
| 谁选 | **混合**：导入/Recon 开场后系统可对高置信候选**自动入队**（应用自身相关 jar / `WEB-INF/classes` 松散 class）；Recon Agent 用 `ListBytecode` + `DecompileJava` **点名补漏**。Worker / Reviewer 只做**临时补录**。 |
| 第三方依赖 | **默认拒绝**常见前缀/坐标（如 `spring-`、`tomcat-`、`jackson-`、`hibernate-`、`netty-`、`lucene-`、`log4j-`、`slf4j-`、`junit-` 等，列表配置化）。Agent 可用 `force=true` + 短 `reason` 强制提交；工具结果注明「已强制第三方」。 |
| 嵌套范围（一期） | 支持：单 `.class`、普通 `.jar`、`.war`（含 `WEB-INF/classes` 与一层 `WEB-INF/lib/*.jar` 中**非拒绝**的条目）。Spring Boot fat jar：解 `BOOT-INF/classes` + 对 `BOOT-INF/lib` 中非拒绝 jar **按需**（Agent 点名或 force）。**不做** apk/dex。 |
| 已有源码 | 若 `src/` 已存在对应 `.java`（按包路径/类名可对齐），对该 class **`skipped`（已有源码）**，不重复反编译。整 jar 提交时跳过已有类，只产出缺失类；若全部已有则整任务 `skipped`。 |
| Kotlin / Groovy | 一期接受 jadx 产出的 **Java 伪源**；报告中注明来自字节码反编译。 |

「重要」启发式（系统自动入队，可调）：

1. 路径含 `WEB-INF/lib`、`lib/`、`libs/`，且文件名/路径像应用名或与 Maven `groupId`/`artifactId` 同前缀；
2. 散落在 `WEB-INF/classes` / `BOOT-INF/classes` 下的 `.class`；
3. 排除第三方拒绝列表与测试路径。

---

## 5. Tool 契约与角色 ACL

### 5.1 工具拆分

| 工具 | 职责 |
| --- | --- |
| `ListBytecode` | 发现候选；只读；`parallel_safe`。 |
| `DecompileJava` | **提交 + 查询合一**：有索引且 ready → 直接返回路径；queued/running → 返回状态；无索引 → 入队。 |

不拆成三个 Tool，降低模型选错成本。

### 5.2 参数粒度

**整包 jar/war 允许**（Recon / Worker / Reviewer / Fix 均可），用**输入体积上限**卡住，而不是按角色禁止整包。

| 项 | 决定 |
| --- | --- |
| 整包提交 | `.jar` / `.war` 可不带 `class_name` / `package`，反编译整个归档（仍受第三方拒绝列表约束，除非 `force`）。 |
| 输入大小上限 | 默认 **80 MiB**（可配置 `decompile_max_jar_bytes`）。超限则 `ok=false` / `skipped`，提示改用 `class_name` 或 `package` 缩小范围，或拆更小的 jar。 |
| `.class` / 包级 | 始终允许；包级、单类**不**吃整包体积上限（但单次仍受产出目录上限约束）。 |
| 多路径 | Recon 一次最多约 20 条；Worker / Reviewer / Fix 补录建议一次 1～3 条。 |

| 角色 | 允许提交 |
| --- | --- |
| `recon` | `.class` / 整包 `.jar`/`.war`（≤ 上限）/ `jar`+类或包；可对第三方 `force`。 |
| `worker` / `reviewer` / `fix` | 同上（整包亦允许，同一体积上限）；意图仍是「需要时补录」，不是扫全依赖。 |
| 其它角色 | 一期**不注入**（含 `fast_worker`、`bypass_worker`、`reviewer_lab`、`verifier`、`attack_chain`）。 |

### 5.3 强制静态审核轮

超时后的「仅静态」轮：**仍允许** `ListBytecode` / `DecompileJava`（只读产物 + 后台反编译，不依赖 Shell / Docker / RunCode）。

### 5.4 与 Shell 互斥

在 `block_dangerous_shell`（或等价拦截）中禁止直接调用 **`jadx` / `cfr` / `procyon` / `fernflower`**，提示改用 `DecompileJava`。避免绕过索引与去重。

### 5.5 ACL 摘要

- `recon`：`ListBytecode`、`DecompileJava`
- `worker`、`fix`、`reviewer`：同上（均可整包，受同一 jar 体积上限）
- `PARALLEL_SAFE`：两者均可（立即返回）

---

## 6. 索引、产物与审计流水线

### 6.1 索引键

| 输入 | 主键 |
| --- | --- |
| `.class` 文件 | `sha256(文件字节)` |
| 整包 `.jar`/`.war` | `sha256(归档字节)` |
| jar 内指定类/包 | `sha256(归档) + "#" + 规范类名或包前缀` |

另存：`source_rel`、`size`、`mtime`、`jadx_version`、`status`、`output_root`、`error`。源文件字节变化或 jadx 主版本变化 → 视为新键，旧产物可留着不删（或 LRU 清理，运维项）。

### 6.2 并发与失效

- 同键第二次提交：**立刻返回**已有 `job_id` + `running`/`queued`/`ready`，不启第二个 jadx。
- 输出目录被删但索引仍 ready：查询时校验目录，缺失则自动改 `queued` 重跑。
- `failed`：默认不自动重试；Agent 显式 `force=true` 才重入队。

### 6.3 落盘

| 项 | 决定 |
| --- | --- |
| 根目录 | `workspace/decompiled/`（经 `ensure_project_dirs` 创建） |
| 索引 | `workspace/decompiled/index.jsonl`（或同目录 `index.sqlite`；一期 JSONL + 文件锁即可） |
| 产物 | `workspace/decompiled/<key_short>/…` 保持包路径 |
| Agent 写入 | **禁止** Agent `Write` 直接改索引；只能经 Tool。可用现有可写规则收紧，或工具写后设只读提示。 |
| 输入体积 | 整包 `.jar`/`.war` 默认 ≤ **80 MiB**（见 §5.2）；超限拒绝入队。 |
| 产出体积 | 单任务产出目录软上限（如 500MB）超则 `failed` 并提示缩小为 package/class；拒绝列表减少无意义第三方膨胀。 |

### 6.4 读与搜

- 默认 `Grep`/`Glob` **不**自动扫 `workspace/decompiled`（避免噪声与重复命中）。
- Agent 必须显式 `root=workspace/decompiled/...` 或对具体 `path` `Read`。
- Recon 须在 `docs/code-map.md` 中记录**已反编译**的源 jar/class 与 `output_root`（提示词约束；系统注入完成通知时可附「请写入 code-map」hint）。

### 6.5 权重与领取

Agent 通过 **`MarkBusinessJar`**（仅 recon 地图轮）点名要纳入定权的业务 jar/class；**每个** jar 反编译 `ready` 后先把 `.java` 路径写入 **`data/decompile.db` 的 pending 队列**，再由 **`vh-decompile-svc`** 在 app.db 空闲时按约 50 行一批滴注入 **`FileWeight`**（路径 `workspace/decompiled/<key>/...`）。jadx 线程、盖章 / Worker / 调度器只投递；Agent `_persist` / 领取期间不写 `file_weights`。反编译不阻塞仓库原文件盖章，已入库的反编译类可混入盖章批次。点名列表仍有 `queued`/`running`、sidecar 仍有 pending、或已 `ready` 尚未标 `ingested` 时，**不置 `recon_done`**（失败/跳过/取消的 jar 不挡门闩）。`DecompileJava` / `force=true` **不**自动入库。已有 `src/` 同源 `.java` 与内部类 `*$*.java` 机械跳过。

### 6.6 报告与证据路径

漏洞代码段须同时可追溯：

1. **逻辑路径（主）**：`src/…/foo.jar!com/example/Foo.class`（或 war 内路径）；
2. **可读副本**：`workspace/decompiled/<key>/com/example/Foo.java`。

中文报告 `### 漏洞代码`：标题/说明里写清 jar!class，代码块用反编译 `.java` 原文。  
英文 Advisory `### Vulnerable code`：同样注明 bytecode 来源 + 反编译副本路径；CVE `descriptions` 英文链路里两者都提。  
**不要**把 `workspace/decompiled/...` 伪装成上游仓库已提交源码路径。

---

## 7. 引擎与运维

| 项 | 决定 |
| --- | --- |
| 二进制 | 设置页可配 `jadx_path`；未配则 `PATH` 上的 `jadx` / `jadx.bat`。一期**不做** Docker 兜底（可二期对齐 Semgrep）。 |
| 版本 | 启动任务时记录 `jadx --version`；写入索引。 |
| 全局并发 | 进程内线程池，默认 **每主机 2** 个 jadx（上限 4），多项目共享。并发 ≥2 时预留 **1** 个槽给 Worker / Reviewer / Fix 的 `DecompileJava`（以及 recon 临时预读）；其余给 `MarkBusinessJar` 与 recon 启发式自动入队。并发为 1 时两路共用同一槽。同键仍去重，不启第二个 jadx。 |
| 资源隔离 | 独立 sidecar `vh-decompile-svc` + 专用库 `data/decompile.db`（任务快照与待入库路径）。FileWeight 仅在 app.db 空闲时小批滴注；jadx 子进程降为低于正常优先级。挖掘轮遇 `database is locked` 保留检查点重试，不自杀线程。 |
| 失败 | 混淆严重仍有部分输出 → 有 `.java` 则 `ready`（可带 `partial=true`）；零输出 → `failed`。 |
| Fallback | 一期 **仅 jadx**，不接 CFR/Procyon。 |
| Windows | 产物 I/O 走现有 `windows_long_path`。传给 jadx 子进程的 `-d` / 输入路径必须是普通盘符绝对路径，**不要**带 `\\?\`（Java 不认，会退出码 1 且零产出）。 |

---

## 8. 实现落点（供后续开发，非本轮代码）

| 区域 | 建议 |
| --- | --- |
| 服务 | [`backend/app/services/decompile_java.py`](../backend/app/services/decompile_java.py)（队列、索引、调 jadx）+ [`decompile_store.py`](../backend/app/services/decompile_store.py)（`data/decompile.db`） |
| 工具 | [`backend/app/tools/phase_decompile.py`](../backend/app/tools/phase_decompile.py) + `ROLE_ACL` / `PARALLEL_SAFE` |
| Shell 拦截 | [`backend/app/tools/sandbox.py`](../backend/app/tools/sandbox.py) |
| 循环注入 | [`backend/app/agent/loop.py`](../backend/app/agent/loop.py)（下轮模型前注入完成通知） |
| 路径 | `ensure_project_dirs` 含 `workspace/decompiled` |
| 设置 | 设置页 / `VULNHUNTER_JADX_PATH`、`decompile_max_jar_bytes` 等 |
| 提示词 | `recon.md` / `worker.md` / `reviewer.md` |
| 测试 | `backend/tests/test_decompile_java.py` |

---

## 9. 决策对照（原待定项）

| 原问题 | 结论 |
| --- | --- |
| 1.1 不阻塞哪一层 | 工具立刻返回；后台 jadx；完成靠系统注入 + 可查询；不改真并行循环 |
| 1.2 生命周期 | 跨阶段继续；不堵地图门闩 / `FinishReconMap`；点名业务 jar 未跑完或未入库前不置 `recon_done`；取消才停；reset-progress 保留；重导入清空 |
| 1.3 如何发现 | `ListBytecode`；默认不扫 target；无字节码则 no-op |
| 4 重要文件 | 系统启发式入队 + Recon 点名；默认拒第三方；一层 war/fat 嵌套；有源码则 skip |
| Tool / ACL | 两工具；各角色均可整包 jar（默认 ≤80MiB），超限改类/包；禁 Shell 直调反编译器；静态强制轮仍可用 |
| 索引与流水线 | sha256 键；`workspace/decompiled`；仅 `MarkBusinessJar` 入库 FileWeight，`DecompileJava` 不入库；盖章可混入已反编译类；Worker 与侦察共用 jadx 池（并发≥2 时预留 1 槽给 Worker）；占用时排队、立刻返回、完成注入；报告 jar!class + 反编译路径 |

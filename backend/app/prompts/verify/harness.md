## 本项目验证方式：局部验证

项目选择**局部验证**，不搭建 Docker 靶场，也不对 `target_url` 发 HTTP / 跑 `poc.py` / 使用 debug MCP。**覆盖上文「动态验证阶梯」**：

1. 先 Read 报告、`poc.py` 和源码，确认 `file_path` 与代码片段真实存在。文件不存在或代码对不上 → 误报。
2. 按**目标语言**自己设计验证。默认：抽出可疑函数或最小可编译片段，mock 数据库 / 文件系统 / 框架依赖，用多种 payload 打 sink。**仅当组件公开入口本身就吃 HTTP / WebSocket / RPC 等请求对象时**（如 `ValidateRequest`、中间件、`ServeHTTP`、吃 `HttpServletRequest` 的 Filter），做一次**同进程请求级加强验证**（见下节）；YAML / 加密 / 模板 / 反序列化等只吃字节或字符串的 API **不要**再包一层 HTTP。
3. 用 `RunCode` 在一次性沙箱里执行（Python / PHP / JS / Ruby / Go / Java / Bash 均可）。不要在本机 Bash/PowerShell 里跑 harness。**脚本自己打印的 stdout/stderr（标签、步骤、判定）须中英双语：默认英语，须提供 `--zh` 切中文**（Python `argparse`；其它语言扫 argv / `process.argv` / `os.Args`）。注释 / docstring / `--help` 仍用英语；源码片段、payload、目标回显原文不要翻译。
4. **输出必须来自运行时数据**：最后落到 stdout 的证据必须是调用抽出函数 / sink 之后的实际值（返回值、查询行、命令回显、渲染 HTML、异常原文等）。**禁止**只打印固定字符串（`VULNERABILITY CONFIRMED` / `SUCCESS` / `PASS`）；**禁止**写死成功字段（`success = True`、`{"success": true}`、`confirmed: true`）；**禁止**把预期回显写成字面量（如直接 `print("uid=0(root)")`）。判定标签可以有，但必须同时打印实际数据；成功/失败字段必须由运行结果计算。
5. **禁止**用另一种语言复述源码逻辑再标 `harness`（例如用 Python 重写 Java Controller）。跑的必须是目标语言代码，或与源码同语义的可编译片段。
6. **Java harness 默认 JDK 8**：按 Java 8 语言级别与 API 写（不要用 `var`、record、text block、`List.of`/`Map.of`、`switch` 表达式等 9+ 语法，也不要调用 JDK 9+ 才有的 API）。沙箱 `javac` 默认 `--release 8`。仅当目标源码本身明确需要更高版本（`pom.xml` / `compiler.source` 为 11/17，或抽出片段用了对应语法）时，才提高到该版本，并在源码顶部写 `// java-release: 11` 或 `// java-release: 17`。
7. **报告闸门（harness Confirm 前必做）**：Write `vulns/{id}/report.md`，在 `## 漏洞技术细节` 下补齐 `### 漏洞代码`：
   - 写明漏洞代码段对应的**仓库内完整相对路径**（如 `src/main/java/com/foo/Bar.java` 或 `app/utils/backup.py:42`），不要只写类名/方法名。
   - 粘贴**源码原文**到 fenced 代码块（与 Read 到的内容一致，可含关键前后若干行）。
   - 缺路径或缺代码段时 `ConfirmVuln(evidence_level=harness)` 会被系统拒绝。
8. 判定：
   - 沙箱跑通且默认部署下攻击者可单独打出有害冲击 → 先写好 `### 漏洞代码`，再 `ConfirmVuln(evidence_level=harness)`。把 harness 写入 `vulns/{id}/harness.py`（或对应语言文件；Confirm 可传 `harness_code`）。**不要**把 mock / 内联源码 / 同一套 TEST 矩阵写进 `poc.py`。脚本最终输出必须打印运行时实际数据，禁止写死成功字段。
   - 沙箱不可用、镜像缺失、编译失败、mock 起不来、依赖不够 → **不要误报**。静态已能证明默认可利用则 `evidence_level=static_only`（此时不强制 `### 漏洞代码`）；否则继续静态分析或说明信息不够后误报（仅当成立性本身不成立）。
   - harness 跑通并明确打不中（参数化查询、鉴权不可达、默认磁盘没有敏感对象等）→ 按成立性否决项误报。
9. 成立性门槛**不降**：source→sink 可达不够；禁止种文件/改非应用配置来让洞成立。局部验证只是动态证据来源，不是降低默认可利用标准。
10. 不要标 `dynamic` / `mcp`。无运行中的站点，不要 `CollectLabFingerprints`。
11. 沙箱默认无网。SSRF 等必须出网的类型不要指望 harness 打通，走静态判断。
12. **组件库审计**：Confirm 以 `RunCode` harness 为准；勿因缺 HTTP 靶场或没有 `poc.py -u` 而误报。纯库洞：沙箱证据只进 `harness.py`。仅当安装真实包后能 `import` 公开 API 时才另写最小 `poc.py`（不要假 `-u/--proxy`，不要抄 harness）。无 HTTP 面且无安装面时不要落盘 `poc.py`，报告写 API 调用配方即可。
13. **请求型公开 API 的加强验证**（组件库 / 混合仓的库核心；Web 应用里若 sink 就在请求校验中间件上，同样适用）。判定「组件本身接受请求」：公开 API 的参数就是 HTTP Request / 中间件 / 路由校验输入，而不是 `[]byte` / `string` / Reader。满足时必须加强，不要只拷 `deepSet` 这类内部函数：
    - 编译或 import **项目 `src/`**，调用该公开入口（如 `openapi3filter.ValidateRequest`），禁止把 sink 逐字拷进 handler 再当主证据。
    - 同一脚本内：进程内测试服务器（Go `httptest`、同进程客户端打 loopback）+ 发送攻击请求 + 打印真实状态码 / 响应 / panic 原文。优先 `httptest` / 短生命周期监听；不要绑 `0.0.0.0`，不要当成 Docker 靶场，`evidence_level` 仍为 `harness`。
    - payload **必须来自这次请求**（query / body / header），禁止 handler 内写死常量再让 `GET /` 当门铃。
    - 整模块在沙箱编不过或依赖不够 → 退回抽出函数，并在输出里写明未打到公开 API；不要因此误报。
    - 不要把 YAML / `json.Unmarshal` / 模板 `Execute` / 反序列化等无请求面 API 包进自写 HTTP；那会伪造远程攻击面。这类继续直接调公开函数并打印运行时异常或返回值。

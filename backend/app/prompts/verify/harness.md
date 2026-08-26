## 本项目验证方式：局部验证

项目选择**局部验证**，不搭建 Docker 靶场，也不对 `target_url` 发 HTTP / 跑 `poc.py` / 使用 debug MCP。**覆盖上文「动态验证阶梯」**：

1. 先 Read 报告、`poc.py` 和源码，确认 `file_path` 与代码片段真实存在。文件不存在或代码对不上 → 误报。
2. 按**目标语言**自己设计验证：抽出可疑函数或最小可编译片段，mock 数据库 / HTTP / 文件系统 / 框架依赖，用多种 payload 打 sink。
3. 用 `RunCode` 在一次性沙箱里执行（Python / PHP / JS / Ruby / Go / Java / Bash 均可）。不要在本机 Bash/PowerShell 里跑 harness。**脚本自己打印的 stdout/stderr（标签、步骤、判定）以及注释 / docstring 必须用英语**；源码片段、payload、目标回显原文不要翻译。
4. **禁止**用另一种语言复述源码逻辑再标 `harness`（例如用 Python 重写 Java Controller）。跑的必须是目标语言代码，或与源码同语义的可编译片段。
5. **报告闸门（harness Confirm 前必做）**：Write `vulns/{id}/report.md`，在 `## 漏洞技术细节` 下补齐 `### 漏洞代码`：
   - 写明漏洞代码段对应的**仓库内完整相对路径**（如 `src/main/java/com/foo/Bar.java` 或 `app/utils/backup.py:42`），不要只写类名/方法名。
   - 粘贴**源码原文**到 fenced 代码块（与 Read 到的内容一致，可含关键前后若干行）。
   - 缺路径或缺代码段时 `ConfirmVuln(evidence_level=harness)` 会被系统拒绝。
6. 判定：
   - 沙箱跑通且默认部署下攻击者可单独打出有害冲击 → 先写好 `### 漏洞代码`，再 `ConfirmVuln(evidence_level=harness)`。把 harness 写入 `vulns/{id}/harness.py`（或对应语言文件；Confirm 可传 `harness_code`）。**不要**把 mock 脚本写进 `poc.py`（`poc.py` 仍是 `-u/--url` + `--proxy` 的 HTTP 合同）。
   - 沙箱不可用、镜像缺失、编译失败、mock 起不来、依赖不够 → **不要误报**。静态已能证明默认可利用则 `evidence_level=static_only`（此时不强制 `### 漏洞代码`）；否则继续静态分析或说明信息不够后误报（仅当成立性本身不成立）。
   - harness 跑通并明确打不中（参数化查询、鉴权不可达、默认磁盘没有敏感对象等）→ 按成立性否决项误报。
7. 成立性门槛**不降**：source→sink 可达不够；禁止种文件/改非应用配置来让洞成立。局部验证只是动态证据来源，不是降低默认可利用标准。
8. 不要标 `dynamic` / `mcp`。无运行中的站点，不要 `CollectLabFingerprints`。
9. 沙箱默认无网。SSRF 等必须出网的类型不要指望 harness 打通，走静态判断。
10. **组件库审计**：Confirm 以 `RunCode` harness 为准；勿因缺 HTTP 靶场或 `poc.py` 不能 `-u` 打 URL 而误报。纯库洞可把 harness 当作主证据，`poc.py` 可为 API 调用脚本。

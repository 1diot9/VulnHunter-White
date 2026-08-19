## 本项目验证方式：局部验证

项目选择**局部验证**，不搭建 Docker 靶场，也不对 `target_url` 发 HTTP / 跑 `poc.py` / 使用 debug MCP。**覆盖上文「动态验证阶梯」**：

1. 先 Read 报告、`poc.py` 和源码，确认 `file_path` 与代码片段真实存在。文件不存在或代码对不上 → 误报。
2. 按**目标语言**自己设计验证：抽出可疑函数或最小可编译片段，mock 数据库 / HTTP / 文件系统 / 框架依赖，用多种 payload 打 sink。
3. 用 `RunCode` 在一次性沙箱里执行（Python / PHP / JS / Ruby / Go / Java / Bash 均可）。不要在本机 Bash/PowerShell 里跑 harness。
4. **禁止**用另一种语言复述源码逻辑再标 `harness`（例如用 Python 重写 Java Controller）。跑的必须是目标语言代码，或与源码同语义的可编译片段。
5. 判定：
   - 沙箱跑通且默认部署下攻击者可单独打出有害冲击 → `ConfirmVuln(evidence_level=harness)`。把 harness 写入 `vulns/{id}/harness.py`（或对应语言文件；Confirm 可传 `harness_code`）。**不要**把 mock 脚本写进 `poc.py`（`poc.py` 仍是 `-u/--url` 的 HTTP 合同）。
   - 沙箱不可用、镜像缺失、编译失败、mock 起不来、依赖不够 → **不要误报**。静态已能证明默认可利用则 `evidence_level=static_only`；否则继续静态分析或说明信息不够后误报（仅当成立性本身不成立）。
   - harness 跑通并明确打不中（参数化查询、鉴权不可达、默认磁盘没有敏感对象等）→ 按成立性否决项误报。
6. 成立性门槛**不降**：source→sink 可达不够；禁止种文件/改非应用配置来让洞成立。局部验证只是动态证据来源，不是降低默认可利用标准。
7. 不要标 `dynamic` / `mcp`。无运行中的站点，不要 `CollectLabFingerprints`。
8. 沙箱默认无网。SSRF 等必须出网的类型不要指望 harness 打通，走静态判断。

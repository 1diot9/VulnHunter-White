挖掘模式：${audit_mode_label}。${audit_mode_hint}
审计对象：${target_kind_label}。${target_kind_hint}

Worker=${worker_id} 轮次=${round_id}
当前焦点文件: src/${file_path} （权重=${weight}, has_source=${has_source}）
Source 方法: ${sources}

```
${snippet}
```

侦察文档与最近挖掘摘要已注入：不要重复分析项目结构，不要重复尝试摘要中已走过的路径。请按本轮焦点的角色分析，不要按历史摘要里的建议改方向。
注入文件是本轮焦点，不是默认 HTTP source。
- has_source=true 或权重=100：用户可控入口（HTTP / WebSocket / RPC / MQ / 回调等），正向 source→sink。
- 权重 70–90：过滤器 / 鉴权做控面审计；Service 盘点危险操作与鉴权缺口后回推 caller / 二阶数据。
- Mapper / 模板 / 危险工具：只查执行面或做文件级 sink 回推。
- DTO / 常量 / 启动类 / 死代码：薄扫有服务端机密危害的硬编码密钥与反序列化 gadget 后 FinishFile 该焦点，再 FinishRound，不要改去挖其它模块；前端传输混淆 AES 不要当洞。
FinishFile 与 FinishRound 不是一对：沿调用链读到其它文件后，确认无漏洞才 FinishFile(paths=[...])，然后继续分析本轮注入焦点，禁止立刻 FinishRound。不要因为文件不能当入口就 FinishFile。
仅当一开始注入的这份焦点文件已按角色分析完后，才 FinishFile 它（若尚未标）并 FinishRound。report 对齐 templates/round-report.md。不要只标注入文件。
从摘要接续已分析的调用链，不要重复已 FinishFile 的文件。
SearchOldVuln 的 kind=old：unpatched 来自未关闭 Issues，用于去重；patched 不要当新洞也不要做绕过。不要把框架 CVE 清单当本项目新洞。
同一根因同一危害只 SubmitVuln 一次（填 root_cause_key 与 config_premise=default|specific，报告含同根因受影响点）；pending 同根因用 AppendAffectedLocations，不要拆成多份报告。若 SubmitVuln 提示疑似重复，先复查；仍要单独交则再次调用并传 confirm_not_duplicate=true（仅提醒过后才接受）。
poc_code 必须可对任意目标复测：`python poc.py -u <url>`，必须支持 `--proxy`（空则直连；有代理时 127.0.0.1 也须强制走代理），RCE 加 `-c/--cmd` 并打印回显；不要写死靶场地址或代理。SSRF 须标明观察面：有回显（打印目标正文）或仅响应差别（通/不通对照），不要把端口探测写成已读云元数据。特定配置不含官方已警示的风险开关。SubmitVuln 须同时交中文 `report_md`（`templates/vuln-report.md`）与英文 `advisory_md`（`templates/vuln-advisory.md`，GitHub Advisory 填表稿；`## Severity / CWE` 含 CVSS 3.1 与 CVSS 4.0）。

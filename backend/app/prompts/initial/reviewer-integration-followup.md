本项目已开启局部验证。本条漏洞此前已确认（`${prior_basis}`）。请接续上面的审核轮次，在${prior_conclusion}上**追加 L3 集成验证**，不要从零重做静态分析，也不要搭建 Docker 靶场。

先 Read `vulns/${vuln_id}/report.md`、request.http、poc.py、已有 harness 脚本与 `env/env.json`。

要求：
- 报告须已有「### 局部验证」章节（L1/L2 证据）。在此基础上追加集成验证。
- 调用 `ConfirmVuln(harness_depth=integration, integration_start=..., integration_setup=...)`。
  - **integration_start**（必填，除非沙箱不可用且已写 `env/env.json` 的 `local_service_url`）：后台启动命令，须监听 `127.0.0.1:$PORT`（`$PORT` 由系统在 integration 沙箱注入），例如 `node bin/whistle.js start -p $PORT` 或 `npx w2 start -p $PORT`。
  - **integration_setup**（可选）：容器内安装依赖，多行 shell，如 `npm ci`。
- 系统会在 **integration 沙箱**（非 harness 沙箱）内：临时安装依赖 → 起 loopback 服务 → 跑 `poc.py -u http://127.0.0.1:$PORT`。**不要**在本机长期起服务或沿用宿主机全局 node/python 环境；沙箱不可用时才用 `local_service_url` fallback。
- 集成验证通过 → `evidence_level=dynamic`（动态验证），`harness_depth=integration`；Write 报告追加 `### 集成验证（动态）` 并粘贴 poc 输出。
- 集成验证失败 → 不要误报；保持原 harness 结论，说明失败原因，可修正 integration_start/setup 或 poc 后重试。
- 不要把 harness 内联/mock 抄进 `poc.py`；不要把同一份测试写进 harness 与 poc。
- 不要 MergeIntoVuln，不要打回 Worker。

漏洞 ID=${vuln_id}
${lab_note}
集成验证计划: ${debug_plan}

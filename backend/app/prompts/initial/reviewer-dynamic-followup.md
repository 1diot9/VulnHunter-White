本项目已开启动态验证。本条漏洞此前已静态确认（`static_only`）。请接续上面的审核轮次，在静态结论上追加动态验证，不要从零重做静态分析。

先 Read `vulns/${vuln_id}/report.md`、request.http、poc.py 以及 `env/env.json`、`docs/lab.md`。

要求：
- 不要再搭建 Docker 靶场（环境轮独立进行，见 docs/lab.md）。
- 按动态验证阶梯：**先跑 Worker 的 poc.py**（`python poc.py -u <target_url>`，RCE 可加 `-c/--cmd`）或对 target_url 发请求，结合 docker exec/日志/文件**观察**冲击。poc.py 只是写死地址/命令 → 先改成 CLI 参数化（Write + ConfirmVuln 传 poc_code）。**debug MCP 不是首选**：仅当 Worker 的 PoC 缺失、跑不通或复现失败，且你需要自己改写/调试 PoC 时，才 attach（runtime 为 java/nodejs/python 且调试端口可用）。
- 动态复现成功 → ConfirmVuln(`evidence_level=dynamic` 或 `mcp`)。价值分层默认沿用静态结论，仅当动态证据明显改变危害时再改 `submission_tier`。
- 环境起不来，但静态仍能证明默认部署可利用 → ConfirmVuln(`evidence_level=static_only`)，不要误报。
- 动态证明默认可利用不成立（原 PoC 无有害差异、需种文件等）→ ReturnToWorker(`false_positive=true`, reason=...)。
- 不要 MergeIntoVuln，不要为「再做一遍静态」打回 Worker。
- 有漏洞环境且项目指纹仍缺标题/hash 时才 CollectLabFingerprints。

漏洞 ID=${vuln_id}
${lab_note}
动态验证计划: ${debug_plan}

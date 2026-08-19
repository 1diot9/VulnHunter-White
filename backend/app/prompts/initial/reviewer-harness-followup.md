本项目已开启局部验证。本条漏洞此前已静态确认（`static_only`）。请接续上面的审核轮次，在静态结论上追加局部验证，不要从零重做静态分析，也不要搭建 Docker 靶场。

先 Read `vulns/${vuln_id}/report.md`、request.http、poc.py 以及源码中的可疑函数。

要求：
- 用 `RunCode` 按目标语言写 mock / harness 做局部动态验证。不要对 target_url 发请求，不要跑 `poc.py -u`，不要 debug MCP。
- 打通且成立性仍满足 → ConfirmVuln(`evidence_level=harness`)，必要时传 `harness_code`。价值分层默认沿用静态结论，仅当证据明显改变危害时再改 `submission_tier`。
- 沙箱不可用或 mock 失败 → 不要误报；静态仍能证明默认部署可利用则 ConfirmVuln(`evidence_level=static_only`)。
- 局部验证证明默认可利用不成立（打不中、需种文件等）→ ReturnToWorker(`false_positive=true`, reason=...)。
- 不要 MergeIntoVuln，不要为「再做一遍静态」打回 Worker。
- 不要 CollectLabFingerprints。不要把 harness 写进 `poc.py`。

漏洞 ID=${vuln_id}
${lab_note}
局部验证计划: ${debug_plan}

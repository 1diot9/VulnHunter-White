本项目已开启动态验证。本条漏洞此前已静态确认（`static_only`）。请接续上面的审核轮次，在静态结论上追加动态验证，不要从零重做静态分析。

先 Read `vulns/${vuln_id}/report.md`、request.http、poc.py 以及 `env/env.json`、`docs/lab.md`。

要求：
- 不要再搭建 Docker 靶场（环境轮独立进行，见 docs/lab.md）。
- 按动态验证阶梯：**先跑当前 poc.py**（`python poc.py -u <target_url>`，RCE 可加 `-c/--cmd`，需要抓包时加 `--proxy`）或对 target_url 发请求，结合 docker exec/日志/文件**观察**冲击。poc.py 写死地址/命令/代理或缺 `--proxy` → 先改成 CLI 参数化（Write + ConfirmVuln 传 poc_code）。同链 payload 跑不通由你改，不要打回 Worker。**debug MCP 不是首选**：仅当 PoC 缺失、跑不通或复现失败，且你需要自己改写/调试 PoC 时，才 attach（runtime 为 java/nodejs/python 且调试端口可用）。
- ConfirmVuln 会系统再跑一遍落盘 `poc.py -u <target_url>`；退出码非 0 则拒绝确认。靶场可用时不要 `static_only`。
- 动态复现成功 → ConfirmVuln(`evidence_level=dynamic` 或 `mcp`)。价值分层默认沿用静态结论，仅当动态证据明显改变危害时再改 `submission_tier`。
- 环境起不来（无 target_url），但静态仍能证明默认部署可利用 → ConfirmVuln(`evidence_level=static_only`)，不要误报。
- 动态证明默认可利用不成立（需种文件、换 sink 才成立等）→ MarkFalsePositive(reason=...)。同链 payload 细节问题则自己改再跑，不要误报、不要打回。
- 不要 MergeIntoVuln，不要为「再做一遍静态」或改 PoC 打回 Worker。
- 有漏洞环境且项目指纹仍缺标题/hash 时才 CollectLabFingerprints。

漏洞 ID=${vuln_id}
${lab_note}
动态验证计划: ${debug_plan}

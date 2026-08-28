本项目已开启局部验证。本条漏洞此前已确认（`${prior_basis}`）。请接续上面的审核轮次，在${prior_conclusion}上追加局部验证，不要从零重做静态分析，也不要搭建 Docker 靶场。

先 Read `vulns/${vuln_id}/report.md`、request.http、poc.py 以及源码中的可疑函数。

要求：
- 用 `RunCode` 按目标语言写 mock / harness 做局部动态验证。不要对 target_url 发请求，不要跑 `poc.py -u`，不要 debug MCP。组件公开入口本身吃 HTTP/请求对象时，须对 `src/` 公开 API 做同进程请求级加强验证（httptest 或进程内客户端），禁止只拷内部 sink；YAML/编解码等无请求面 API 不要包 HTTP。harness 输出须中英双语：默认英语，须提供 `--zh` 切中文标签/步骤/判定；注释仍用英语。stdout 必须打印运行时实际数据（返回值/查询结果/回显/渲染结果）；禁止只打印固定 SUCCESS/CONFIRMED，禁止写死 `success=True` / `{"success": true}`。Java harness 默认 JDK 8（不要用 `var`/record/text block 等 9+ 语法）；仅当目标源码需要更高版本时在文件顶部写 `// java-release: 11` 或 `// java-release: 17`。
- 打通且成立性仍满足 → 先 Write 报告补齐 `### 漏洞代码`（**完整文件路径** + 源码原文 fenced 代码块），再 ConfirmVuln(`evidence_level=harness`)，必要时传 `harness_code`。缺路径或缺代码段会被系统拒绝。价值分层默认沿用既有结论，仅当证据明显改变危害时再改 `submission_tier`。
- 沙箱不可用或 mock 失败 → 不要误报；静态仍能证明默认部署可利用则 ConfirmVuln(`evidence_level=static_only`)。
- 局部验证证明默认可利用不成立（打不中、需种文件等）→ MarkFalsePositive(reason=...)。不要为此打回 Worker。
- 不要 MergeIntoVuln，不要为「再做一遍静态」打回 Worker。
- 不要 CollectLabFingerprints。不要把 harness 的内联/mock 或同一套 TEST 矩阵写进 `poc.py`。纯库洞无 HTTP/安装面时不要为兼容性补假 `-u/--proxy`。

漏洞 ID=${vuln_id}
${lab_note}
局部验证计划: ${debug_plan}

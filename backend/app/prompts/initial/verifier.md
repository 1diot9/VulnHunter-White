挖掘模式：${audit_mode_label}。${audit_mode_hint}
Verifier 验证漏洞 ID=${vuln_id}
元数据: ${payload}
报告内 FOFA 语句: ${fofa_query}
备选检索（title/app 与 body 特征各一条，0 条就换另一条，不要在同一方向反复改）: ${fofa_alts}
项目共享 FOFA: ${fofa_shared}
请 Read vulns/${vuln_id}/report.md（及 request.http / poc.py）。复测优先 `python poc.py -u <该目标>`（RCE 可加 `-c/--cmd`；需要抓包时加 `--proxy`）。任意文件删除、DoS、SQL 增删改等会中断或篡改业务的漏洞须先 AskUser(reason=...) 询问用户，不要直接 FinishVerifier(skipped)，也不要未同意就打目标。应用指纹是项目级的（docs/app-fingerprints.json），不要重新识别。本项目 FOFA 语法有命中后冻结、结果给全部漏洞共享：已有共享命中则不要为换语法再 FofaSearch，直接按这些目标复测本条；尚无则用项目指纹 FofaSearch，title/app 与默认页 body 特征各试一条，0 条立刻换另一类，不要在同一方向反复改写，最多 3 次。完成标准是 3 个目标成功：每轮默认 10 个，凑满 3 个即 FinishVerifier(verdict=success, verified_url=实际URL, poc=对该目标发出的请求或脚本, response=该目标真实响应, fofa_query=本项目FOFA语法, targets=全部FOFA样本并标注success|fail|untested，其中至少 3 条 success)；当前这批测完仍不足 3 个则保留已成功的，FofaSearch(expand=true) 再搜下一轮 10 个新目标；最多 5 轮（合计 50 个目标）都失败或不足=fail；无样本=no_targets；无 key/网络不可用=skipped。成功必须原样粘贴 URL/PoC/响应，并附上搜索语法；targets 必须列出全部搜到的目标（成功/失败/未测），凑满 3 个成功后不要为了填未测项继续打。不要继续挖新洞。

挖掘模式：${audit_mode_label}。${audit_mode_hint}
Verifier 验证漏洞 ID=${vuln_id}
元数据: ${payload}
报告内 FOFA 语句: ${fofa_query}
项目共享 FOFA: ${fofa_shared}
请 Read vulns/${vuln_id}/report.md（及 request.http / poc.py）。任意文件删除、DoS、SQL 增删改等会中断或篡改业务的漏洞禁止互联网复测，立刻 FinishVerifier(verdict=skipped)。本项目 FOFA 只搜一次、结果给全部漏洞共享：已有共享结果则禁止再 FofaSearch，直接按这些目标复测本条；尚无则 FofaSearch 一次。任一目标成功即 FinishVerifier(verdict=success, verified_url=实际URL, poc=对该目标发出的请求或脚本, response=该目标真实响应, fofa_query=本项目FOFA语法, targets=全部FOFA样本并标注success|fail|untested)；都失败=fail；无样本=no_targets；无 key/网络不可用=skipped。成功必须原样粘贴 URL/PoC/响应，并附上搜索语法；targets 必须列出全部搜到的目标（成功/失败/未测），不要为了填未测项继续打。不要继续挖新洞。

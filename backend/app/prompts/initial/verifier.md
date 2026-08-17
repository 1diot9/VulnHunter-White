挖掘模式：${audit_mode_label}。${audit_mode_hint}
Verifier 验证漏洞 ID=${vuln_id}
元数据: ${payload}
报告内 FOFA 语句: ${fofa_query}
请 Read vulns/${vuln_id}/report.md（及 request.http / poc.py）。任意文件删除、DoS、SQL 增删改等会中断或篡改业务的漏洞禁止互联网复测，立刻 FinishVerifier(verdict=skipped)。其余用 FofaSearch 默认搜 10 个同款目标，按报告 PoC 逐个复测。任一目标成功即 FinishVerifier(verdict=success, verified_url=实际URL, poc=对该目标发出的请求或脚本, response=该目标真实响应)；都失败=fail；无样本=no_targets；无 key/网络不可用=skipped。成功三项必须原样粘贴，不要只写摘要。不要继续挖新洞。

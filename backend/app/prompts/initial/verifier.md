挖掘模式：${audit_mode_label}。${audit_mode_hint}
Verifier 验证漏洞 ID=${vuln_id}
元数据: ${payload}
报告内 FOFA 语句: ${fofa_query}
请 Read vulns/${vuln_id}/report.md（及 request.http / poc.py），用 FofaSearch 默认搜 10 个同款目标，按报告 PoC 逐个复测。任一目标成功即 FinishVerifier(verdict=success, verified_url=...)；都失败=fail；无样本=no_targets；无 key/网络不可用=skipped。不要继续挖新洞。

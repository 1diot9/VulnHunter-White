挖掘模式：${audit_mode_label}。${audit_mode_hint}

Bypass Worker=${worker_id} 轮次=${round_id}
当前注入历史漏洞 #${bypass_id}
文档: ${file_path}
标题: ${title}
CVE=${cve} CWE=${cwe} 修复状态=${fix_status} 来源=${source}

${old_vuln_doc}

从该历史漏洞文档出发，到当前源码找对应实现并尝试绕过。找不到代码即可 FinishBypass(verdict=unreachable)。文档无法落地则 incomplete。
分析结束后必须 FinishBypass（verdict 为 bypass_submitted / still_patched / unreachable / incomplete / intended）。
提交漏洞则先 SubmitVuln 再 FinishBypass(verdict=bypass_submitted, vuln_id=...)。必填 config_premise=default|specific；特定配置不含官方已警示的风险开关。poc.py 须 CLI 参数化（-u/--url；RCE 加 -c/--cmd 并打印回显）。SSRF 须标明有回显或仅响应差别，不要把端口探测写成已读云元数据。
report 可用简短中文说明绕过结论。不要分析未注入的历史漏洞。

审核漏洞 ID=${vuln_id}
元数据: ${payload}
${lab_note}
动态验证计划: ${debug_plan}
请 Read vulns/${vuln_id}/report.md 等，完成后 ConfirmVuln（须标 attack_surface=frontend|backend；后台再标 required_account=user|admin；并按审核证据填写 impact、exploit_complexity、defense_status 用于最终严重度校准）或 ReturnToWorker。

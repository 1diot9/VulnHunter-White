挖掘模式：${audit_mode_label}。${audit_mode_hint}
审核漏洞 ID=${vuln_id}
元数据: ${payload}
${lab_note}
动态验证计划: ${debug_plan}
请 Read vulns/${vuln_id}/report.md 等，确认报告含 `## 互联网资产证明`（旧报告 `## 应用搜索指纹` 视为等价）且分别给出 FOFA / X 情报社区资产测绘语句（禁止「或」关系）；「基础环境搭建」应引用 `docs/lab.md`。完成后 ConfirmVuln（须标 attack_surface=frontend|backend；后台再标 required_account=user|admin；并按审核证据填写 impact、exploit_complexity、defense_status 用于最终严重度校准；还必须填写 submission_tier、submission_reason；同一根因都要填 root_cause_key，后续变体再标 duplicate_grouped）或 ReturnToWorker。
记住双层判断：先确认默认部署下攻击者能否单独打出有害冲击（默认可利用，不是只碰到 sink），再判断有没有 CVE 价值。不可利用的路径逃逸/需种文件才成立的问题、以及项目配置里的默认密码/弱口令，直接误报；低危害难利用项标 `low_impact`，不要一律标 `cve_candidate`。不要按漏洞类型映射严重度。

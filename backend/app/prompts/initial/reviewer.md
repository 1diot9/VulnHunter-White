挖掘模式：${audit_mode_label}。${audit_mode_hint}
审核漏洞 ID=${vuln_id}
元数据: ${payload}
${lab_note}
动态验证计划: ${debug_plan}
本轮只审核漏洞，不要再搭建 Docker 靶场（环境轮已结束，见 docs/lab.md）。
请 Read vulns/${vuln_id}/report.md、request.http、poc.py。poc.py 应对任意目标可跑（`python poc.py -u <target_url>`；RCE 支持 `-c/--cmd` 并打印回显）；若写死地址/命令，Write 改成 CLI 后 ConfirmVuln 传入 poc_code，不要为此打回。确认报告含 `## 互联网资产证明`（旧报告 `## 应用搜索指纹` 视为等价）且分别给出 FOFA / X 情报社区资产测绘语句（禁止「或」关系）；「基础环境搭建」应引用 `docs/lab.md`。应用指纹是项目级的（docs/app-fingerprints.json），不要每条洞重新识别。有漏洞环境且项目指纹仍缺标题/hash 时才 CollectLabFingerprints 升级共享指纹并写回本条（apply=true 或 ConfirmVuln 传 fofa_fingerprint/x_fingerprint），不要把「待运行环境确认」留到确认后，也不要为此打回。先 SearchOldVuln kind=found：同根因同危害的 pending 兄弟用 MergeIntoVuln(absorb=[...]) 再 Confirm；当前条是重复则 MergeIntoVuln(into=主报告id) 结束会话，不要打回/误报/Write 已确认报告。完成后 ConfirmVuln（须标 attack_surface=frontend|backend；后台再标 required_account=user|admin；并按审核证据填写 impact、exploit_complexity、defense_status 用于最终严重度校准；还必须填写 submission_tier、submission_reason、root_cause_key；duplicate_grouped 仅留给危害/鉴权不同的相关变体且须原样复用已有键）或 ReturnToWorker。
记住双层判断：先确认默认部署下攻击者能否单独打出有害冲击（默认可利用，不是只碰到 sink），再判断有没有 CVE 价值。不可利用的路径逃逸/需种文件才成立的问题、以及项目配置/.env/compose 里的默认密码/弱口令，直接误报；源码常量中的硬编码密钥不要当默认密码误报。低危害难利用项标 `low_impact`，不要一律标 `cve_candidate`。不要按漏洞类型映射严重度。SSRF 必须核对观察面：有回显才能写可读元数据/内网正文；仅状态码/时延/报错差别只算内网端口探测，`impact` 用 `limited_info`，不要按凭据窃取 Confirm。

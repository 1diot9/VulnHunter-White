项目 ID=${project_id}。请开始历史漏洞会话。
可读 docs/code-map.md、docs/auth.md 了解技术栈；每确认一条立刻 WriteOldVuln（落盘不会结束本会话）。
若 docs/old-vulns 已有部分文档，SearchOldVuln 核对 kind=old 后只补缺；不要把 kind=found 写入 old-vulns。
确认无公开历史漏洞则 WriteOldVuln(no_findings=true)；检索全部完成再 WriteOldVuln(done=true)。不要改写 code-map/auth，不要标权重。

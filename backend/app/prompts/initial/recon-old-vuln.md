项目 ID=${project_id}。请开始历史漏洞 **爬虫落盘**（第一轮）。
已写入 workspace/ghsa_new.json（GHSA 新候选 ${ghsa_count} 条，GitHub Issues ${issues_count} 条；仓库 ${issues_repo}；关键词 ${keyword}${ghsa_error}）。Read 该文件后符合口径立刻 WriteOldVuln（落盘不会结束本会话）。不要读源码。
**禁止**调用 WebSearch / SearchGHSA / SearchGitHubIssues，只根据爬虫结果写文档。GHSA/公开公告标 patched；未关闭 Issue 默认 unpatched。未修复洞只来自 Issues。不要收录依赖/框架 CVE（Spring、Tomcat 等）。无关/安全政策帖不要建档。尚未分配 CVE 的 Issue 披露只要机制清楚、属于本项目即可收录。
若 docs/old-vulns 已有部分文档，SearchOldVuln 核对 kind=old 后只补缺；不要把 kind=found 写入 old-vulns。
全部核验完 WriteOldVuln(done=true, note=跳过说明)；无符合口径则 WriteOldVuln(no_findings=true)。系统随后会用 WebSearch 补漏。不要改写 code-map/auth，不要标权重。

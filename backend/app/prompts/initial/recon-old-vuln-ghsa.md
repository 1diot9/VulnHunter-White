项目 ID=${project_id}。这是历史漏洞第二轮：核验 GHSA 与未关闭 GitHub Issues 爬虫补漏。
已写入 workspace/ghsa_new.json（GHSA 新候选 ${ghsa_count} 条，GitHub Issues ${issues_count} 条；仓库 ${issues_repo}${ghsa_error}）。Read 该文件后符合口径立刻 WriteOldVuln（落盘不会结束本会话）。不要读源码。
第一轮已落盘的条目不要删除。GHSA/公开公告标 patched；未关闭 Issue 默认 unpatched。未修复洞只来自 Issues。无关/安全政策帖不要建档。尚未分配 CVE 的 Issue 披露只要机制清楚、属于本项目即可收录。
全部核验完 WriteOldVuln(done=true, note=跳过说明)；无符合口径则 WriteOldVuln(no_findings=true)。文件缺失时用 SearchGHSA / SearchGitHubIssues / WebSearch 补漏（Issues 只搜未关闭）。不要改写 code-map/auth，不要标权重。

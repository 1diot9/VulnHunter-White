项目 ID=${project_id}。这是历史漏洞第二轮：WebSearch 补漏。
可读 docs/code-map.md、docs/auth.md 确认产品短名，再用 WebSearch 补第一轮爬虫没覆盖的本项目公开 CVE/公告。不要读源码，不要 Grep。
只收集本项目自身公开 CVE/公告，标 source=websearch、fix_status=patched（可省略）。未修复洞不要在本轮搜。不要扫框架 CVE 清单，不要收录依赖/框架历史漏洞。第一轮已落盘的条目不要删除。
每确认一条立刻 WriteOldVuln（落盘不会结束本会话）。
若 docs/old-vulns 已有部分文档，SearchOldVuln 核对 kind=old 后只补缺；不要把 kind=found 写入 old-vulns。
无新的符合口径条目则 WriteOldVuln(no_findings=true)；本轮完成再 WriteOldVuln(done=true, note=跳过说明)。爬虫文件缺失时可用 SearchGHSA / SearchGitHubIssues 兜底（Issues 只搜未关闭）。不要改写 code-map/auth，不要标权重。

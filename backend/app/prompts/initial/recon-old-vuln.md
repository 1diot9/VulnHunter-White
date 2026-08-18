项目 ID=${project_id}。请开始历史漏洞 **LLM 检索**（第一轮）。
可读 docs/code-map.md、docs/auth.md 确认产品短名，再用 WebSearch。不要读源码，不要 Grep，不要调用 SearchGHSA / SearchGitHubIssues。
只收集本项目自身公开 CVE/公告，标 source=websearch、fix_status=patched（可省略）。未修复洞不要在本轮搜，留给第二轮未关闭 GitHub Issues。不要扫框架 CVE 清单。
每确认一条立刻 WriteOldVuln（落盘不会结束本会话）。
若 docs/old-vulns 已有部分文档，SearchOldVuln 核对 kind=old 后只补缺；不要把 kind=found 写入 old-vulns。
无符合口径的条目则 WriteOldVuln(no_findings=true)；本轮完成再 WriteOldVuln(done=true, keyword=产品短名, note=跳过说明)。系统随后会跑 GHSA 与 GitHub Issues 爬虫补漏。不要改写 code-map/auth，不要标权重。

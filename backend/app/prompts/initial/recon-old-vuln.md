项目 ID=${project_id}。请开始历史漏洞 **LLM 检索**（第一轮）。
可读 docs/code-map.md、docs/auth.md；先 Grep 本仓库危险 API 调用点，再 WebSearch。不要调用 SearchGHSA。
只为「本项目自身公开洞」或「源码确有调用点且版本仍可能受影响、默认部署可能打到」的组件洞 WriteOldVuln。已修复 / 未使用 / 仅传递依赖不要一条一文，结束时写进 note。
每确认一条立刻 WriteOldVuln（落盘不会结束本会话）。
若 docs/old-vulns 已有部分文档，SearchOldVuln 核对 kind=old 后只补缺；不要把 kind=found 写入 old-vulns。
无符合口径的条目则 WriteOldVuln(no_findings=true)；本轮完成再 WriteOldVuln(done=true, keyword=产品短名, note=跳过说明)。系统随后会跑 GHSA 爬虫补漏。不要改写 code-map/auth，不要标权重。

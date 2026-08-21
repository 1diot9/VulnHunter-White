---
title: 历史漏洞索引
summary: 本项目已知历史漏洞列表
complete: true
llm_complete: true
---

# 历史漏洞索引

| 标题 | 摘要 | 修复状态 | 文件 |
|------|------|----------|------|
| （暂无） | 经检索未写入历史漏洞 |  |  |

检索说明：爬虫落盘第一轮：GHSA 新候选 0 条、未关闭 GitHub Issues 0 条（仓库无 GitHub 仓库，issues.skipped=无 GitHub 仓库），关键词 memoboard（pip 生态）。SearchOldVuln 核对 docs/old-vulns 无已有 kind=old 文档。无符合口径的历史漏洞可建档，留待第二轮 WebSearch 补漏。


检索说明：MemoBoard（项目 ID=11）是故意存在漏洞的 Flask 内网备忘录靶场应用（VulnHunter 白盒审计靶场），非真实生产项目，无公开 CVE/安全公告。WebSearch 按产品短名 "MemoBoard" 检索仅返回 Flask 框架自身 CVE（框架通告，不在收录口径）与无关安全政策页面；SearchGHSA 在 pip 生态搜 MemoBoard 返回 0 条；GitHub 同名仓库均为不同项目，无安全公告。第一轮爬虫未落盘任何条目（SearchOldVuln kind=old 返回 0 条）。本轮无新的符合口径条目。

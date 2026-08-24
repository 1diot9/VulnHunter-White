项目 ID=${project_id}。审计对象：${target_kind_label}。${target_kind_hint}
这是**地图/鉴权重跑**：已有 `docs/code-map.md` 与 `docs/auth.md`，请在保留原文档的基础上对照源码复核并更新（补遗漏入口、修正鉴权/角色/权限描述，删过时内容）。
用 Write 覆盖写回这两份文档；新发现的用户可控入口立刻 MarkSource（HTTP / WebSocket / RPC / MQ / 回调，以及组件公开 API / 解析入口）。
不要 AddSourceExt，不要检索历史漏洞，不要扫全库标权重。两份都更新完毕后调用 FinishReconMap 结束本会话。

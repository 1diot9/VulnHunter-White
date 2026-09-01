项目 ID=${project_id}。代码地图与鉴权已就绪。

系统已预筛选了一批扩展名。请根据 docs/code-map.md 和仓库实际文件检查并调整扩展名（不要按固定名单照抄）：
- 有模板/映射/脚本等执行面则 AddSourceExt(exts=[...])
- 有噪音扩展名（过多且不重要）则 AddSourceExt(remove_exts=[...])
- 没有需要调整则 AddSourceExt(done=true)

扩展名筛选原则：以仓库为准，优先广覆盖；某种类型文件过多（>500个）且审计价值低时跳过。

全部确认后 AddSourceExt(done=true)。不要改写地图/鉴权，不要标权重，不要检索历史漏洞。

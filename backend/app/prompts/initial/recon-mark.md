项目 ID=${project_id}。已标记 ${marked}/${total}，本批 ${batch_count} 个。
只处理下列路径，全部 MarkSource / MarkWeight / MarkSkip 后本轮自动结束。
不要读文件全文，不要写文档，不要处理列表外的文件。
同一类文件用一次 MarkWeight(paths=[...], weight=N) 或 MarkSkip(paths=[...])。
用户可控入口（HTTP / WebSocket / RPC / MQ / 回调等）用 MarkSource（权重自动 100），不要只标 HTTP。
后台调度若只消费库内数据用 70–90；过滤器 / Service 70–90；Mapper / 模板 / 危险工具 40–60；DTO / 常量 / 启动类 10–30。

${paths}

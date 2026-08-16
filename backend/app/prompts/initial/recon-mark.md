项目 ID=${project_id}。已标记 ${marked}/${total}，本批 ${batch_count} 个。
只处理下列路径，全部 MarkWeight 或 MarkSkip 后本轮自动结束。
不要读文件全文，不要写文档，不要处理列表外的文件。
同一类文件用一次 MarkWeight(paths=[...], weight=N) 或 MarkSkip(paths=[...])。
HTTP 入口可用 MarkSource（权重自动 100）。

${paths}

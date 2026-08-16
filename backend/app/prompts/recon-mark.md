# Recon 盖章

你只处理**本轮用户消息里列出的路径**，为每个文件 `MarkWeight` 或 `MarkSkip`。标完本批后系统会自动结束本轮并注入下一批。

## 规则
- 不要读文件全文，不要 Grep/Glob/Write，不要写 code-map / auth / 历史漏洞（那些已由前面的独立会话处理）。
- 不要处理列表以外的文件。
- 同一目录或同一类文件用一次 `MarkWeight(paths=[...], weight=N)` 或 `MarkSkip(paths=[...])`。
- HTTP 入口（Controller / Router / API）用 `MarkSource`（权重自动 100），或 `MarkWeight` 100。
- 测试、生成代码、纯配置样例、前端静态资源：`MarkSkip`。
- 业务逻辑 / Service / 鉴权 / 过滤器：权重 70–90。
- 普通工具类、DTO、一般 Vue 页面：20–50。

用路径和目录名判断即可。

# Recon 盖章

你只处理**本轮用户消息里列出的路径**，为每个文件 `MarkSource`、`MarkWeight` 或 `MarkSkip`。标完本批后系统会自动结束本轮并注入下一批。

## 规则
- 不要读文件全文，不要 Grep/Glob/Write，不要写 code-map / auth / 历史漏洞（那些已由前面的独立会话处理）。
- 不要处理列表以外的文件。
- 同一目录或同一类文件用一次 `MarkWeight(paths=[...], weight=N)` 或 `MarkSkip(paths=[...])`。
- **用户可控入口（权重 100，优先 `MarkSource`）**，不要只标 HTTP：
  - HTTP：Controller / Router / API / Servlet。
  - 非 HTTP：WebSocket 处理器、RPC / Dubbo / gRPC / Hessian 接口实现、MQ / Kafka / Rabbit 消费者、接受外部 payload 的回调 / Webhook、执行器开放接口、可被对端调用的 OpenAPI 实现。没有 `@RequestMapping` 也可以是入口。
  - **组件 / 库**：对外公开包 API、SPI、插件点、配置/编解码/解析器入口、反序列化入口——调用方可控参数视为 source（见审计对象 overlay）。
  - 后台调度若只消费库内已有数据、本身不接受新的外部输入，不要标 100；用 70–90（二阶 / Service）。
- 业务逻辑 / Service：70–90。
- 鉴权 / 过滤器 / 拦截器：70–90（控面，不是入口；除非过滤器本身解析用户输入并送到危险操作）。
- Mapper XML / 模板等执行面，以及路径 / 命令 / 反序列化 / 模板 / 加密类工具：40–60。
- 普通工具类、DTO、枚举、常量、启动类、一般 Vue 页面：10–30。
- 测试、生成代码、纯配置样例、前端静态资源：`MarkSkip`。
- **混合仓**：`demo` / `sample` / `examples` / 示例 Web Controller 用 `MarkSkip` 或 10–30；库 `api` / `core` / `parser` / `codec` / `serialize` 优先高权或 `MarkSource`。

用路径和目录名判断即可。

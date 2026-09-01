项目 ID=${project_id}。审计对象：${target_kind_label}。${target_kind_hint}
源码在 src/。请开始代码地图与鉴权文档会话。
写 docs/code-map.md、docs/auth.md；用户可控入口立刻 MarkSource（HTTP / WebSocket / RPC / MQ / 回调，以及组件公开 API / 解析入口；不要只标 HTTP）。
若有字节码：ListBytecode 后点名业务 jar（MarkBusinessJar），看路径 / artifactId / 包名（如 com.landgrey）；勿点 spring/commons。松散 class 同目录有业务类则可一批 paths。全部点完 done=true；无业务覆盖则 none=true。DecompileJava 仅预读不入定权。
不要 AddSourceExt，不要检索历史漏洞，不要扫全库标权重。文档齐全且业务 jar 门闩满足后系统会结束本会话。

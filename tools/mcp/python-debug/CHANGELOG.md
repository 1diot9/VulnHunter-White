# Changelog

MCP 工具变更日志。

## 2026-05-31

### Added
- `debug_attach_tcp` — 新增直接 TCP 连接工具，用于 Docker 容器等 adapter 反向连接不可达的场景。底层调用 `DebugSessionManager.attach_tcp()`，通过 `DAPClient.connect_tcp()` 直连 debugpy 服务器的 DAP 端口，绕过 subprocess adapter 的随机端口回连机制。

## 2026-05-30

### Added
- 初始工具集发布：`debug_launch`, `debug_attach`, `debug_detach`, `debug_status`, `debug_set_breakpoint`, `debug_remove_breakpoint`, `debug_list_breakpoints`, `debug_set_function_breakpoint`, `debug_set_exception_breakpoints`, `debug_watch_sinks`, `debug_clear_exception_breakpoints`, `debug_continue`, `debug_step`, `debug_pause`, `debug_list_threads`, `debug_list_modules`, `debug_get_stack`, `debug_get_locals`, `debug_inspect_variable`, `debug_set_variable`, `debug_evaluate_expression`, `debug_get_events`, `debug_get_last_stop_event`

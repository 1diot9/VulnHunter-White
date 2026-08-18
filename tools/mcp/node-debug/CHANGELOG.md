# Changelog

All notable changes to this project will be documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/). Versioning follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- `debug_get_scope_variables` now skips module scope by default to prevent oversized responses from module-level globals
- `debug_get_scope_variables` adds `maxProperties` parameter to limit variables per scope
- `debug_get_scope_variables` adds `includeModuleScope` parameter to opt-in to module scope when needed
- `debug_get_scope_variables` shows truncation info (`truncated.shown`/`truncated.total`) when output is limited

## [1.0.0] - 2025-05-31

### Added

- MCP Server with 20 debug tools over Chrome DevTools Protocol (CDP)
- Connection management: `debug_connect`, `debug_disconnect`, `debug_status`
- Script inspection: `debug_list_scripts`, `debug_get_script_source`, `debug_search_in_scripts`
- Breakpoint management: `debug_set_breakpoint`, `debug_remove_breakpoint`, `debug_list_breakpoints`
- Execution control: `debug_pause`, `debug_resume`, `debug_step`, `debug_wait_for_pause`
- Runtime inspection: `debug_evaluate`, `debug_get_call_stack`, `debug_get_scope_variables`, `debug_get_object_properties`, `debug_get_runtime_info`
- Event system: `debug_get_events`, `debug_get_last_stop_event`
- Smart script URL matching (full URL, absolute path, partial path, bare filename)
- Internal-to-CDP breakpoint ID mapping (`bp-1`, `bp-2`, ...)
- WebSocket URL auto-discovery via `/json` endpoint
- State machine (DISCONNECTED / RUNNING / SUSPENDED) with guard checks
- Demo vulnerable app (`demo/vuln-app/`) and test suite (`test/`)

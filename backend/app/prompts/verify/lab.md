## 本项目验证方式：靶场动态

项目已开启 Docker / 人工靶场动态验证。**靶场可用时覆盖上文「环境起不来 → static_only」捷径**：

- ConfirmVuln **会由系统再执行一遍**即将落盘的 `poc.py`：`python poc.py -u <target_url>`（`--proxy` 空，直连靶场）。这是收口闸门，不是让你跳过自己观察冲击。
- 脚本必须支持 `-u/--url`。打出预期冲击退出码 **0**，否则非 0。非 0、超时、无法启动 → **拒绝确认**，漏洞保持 pending。Write 修好后再 Confirm 并传 `poc_code`，或 MarkFalsePositive。不要 ReturnToWorker 改 PoC。
- 靶场可用时不要用 `evidence_level=static_only` 跳过；跑通后标 `dynamic`（用了 debug MCP 改写/调试 PoC 后复现则 `mcp`）。
- 假就绪（容器 running 但业务 URL 不可用：登录页/门户 404、sidecar 退出、应用未起来）时调用 `RequestLabRebuild(reason=...)`，不要自己修 Docker，也不要用 `static_only` 硬过闸门。
- 靶场未就绪（无 `target_url` / 未 accepted）时才允许 `static_only`。

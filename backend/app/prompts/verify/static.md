## 本项目验证方式：仅静态

项目未开启动态验证。**覆盖上文「动态验证阶梯」**：
- 不要搭建或复用 Docker 靶场，不要 `docker exec`，不要对 `target_url` 发请求或运行 `poc.py`，不要使用 debug MCP。
- ConfirmVuln 必须 `evidence_level=static_only`。不要标 `dynamic` / `mcp`。
- 静态已能证明默认部署可利用则 Confirm；只能证明 sink 可达、默认冲击不确定则误报。
- 无运行环境：复用项目共享指纹 `docs/app-fingerprints.json`（系统已采集一次），Confirm 写入报告即可。不要编造 hash，不要为此 ReturnToWorker，也不要 `CollectLabFingerprints`，不要每条漏洞再搜指纹。

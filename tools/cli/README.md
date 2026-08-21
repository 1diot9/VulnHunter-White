# CLI 工具目录

每个**子目录**是一个独立 CLI 工具。后台会轮询扫描，用静默 Agent（最多 30 轮、带 Shell）生成描述并写入 `.vulnhunter-index.json`。Agent 日志在该子目录的 `agent.log.jsonl`。

Reviewer 可用 `SearchTools` 按关键词搜索已索引工具，得到目录路径、入口路径和描述，再用 Bash/PowerShell 按绝对路径执行。

设置页可改本目录路径，默认即仓库下的 `tools/cli`。

不要把索引元数据（`.vulnhunter-index.json`、`agent.log.jsonl`、`conclude.md`）当成工具本体。

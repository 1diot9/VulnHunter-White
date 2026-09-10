# 产出漏洞去重任务

挖掘模式：${audit_mode_label}。审计对象：${target_kind_label}。

请将下列 **${vuln_count}** 条本项目产出与侦察历史漏洞（`kind=old`）逐条对比，判断是否已经公开。优先核对下方「近期收录」的历史漏洞。

## 待查产出
```json
${catalog}
```

## 近期收录的历史漏洞（新→旧，最多 20 条）
```json
${recent_old}
```

## 路径锚点预匹配（仅供参考，须 SearchOldVuln 读全文后才能下结论）
```json
${path_hints}
```

## 要求
1. `SearchOldVuln` 只查 `kind=old`。先浏览近期收录，再按每条产出的入口/sink/类型检索。
2. 每条产出都 `RecordVulnDedup`：`known_public` / `unique` / `uncertain`。同一入口或 sink 的已公开洞标 `known_public`（默认误报）。
3. 全部完成后 `FinishVulnDedup(notes=...)`。没有历史漏洞或全部 unique 也要 Finish。

当前挖掘模式：${audit_mode_label}
${audit_mode_hint}

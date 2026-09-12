# 产出漏洞去重任务

挖掘模式：${audit_mode_label}。审计对象：${target_kind_label}。

请将下列 **${vuln_count}** 条本项目产出逐条做两件事：对照侦察历史漏洞（`kind=old`）判断是否已经公开；对照当前 `src/` 判断漏洞是否还在。优先核对下方「近期收录」的历史漏洞。

## 当前源码快照
${source_note}

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
1. 每条先 `Read` 报告（`### 漏洞代码` / 入口 / sink），再 `Read`/`Grep` 当前 `src/`（或报告中的反编译路径）核对漏洞代码是否还在。
2. `SearchOldVuln` 只查 `kind=old`。先浏览近期收录，再按每条产出的入口/sink/类型检索。没有历史漏洞文档时公开结论用 `unique` 或 `uncertain`，仍必须填 `source_status`。
3. 每条产出都 `RecordVulnDedup`：`verdict` 为 `known_public` / `unique` / `uncertain`；`source_status` 为 `present` / `fixed` / `uncertain`。已公开或最新代码已修复默认标误报；两者同时成立时按已修复。
4. 全部完成后 `FinishVulnDedup(notes=...)`。没有历史漏洞或全部 unique、或全部源码仍在，也要 Finish。

当前挖掘模式：${audit_mode_label}
${audit_mode_hint}

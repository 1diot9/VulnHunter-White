# 攻击链串联任务

挖掘与审核已结束。本项目当前有 **${confirmed_count}** 条已确认漏洞（`confirmed` / `static_only`）。

## 已确认漏洞目录（摘要）
```json
${catalog}
```

## 要求
1. 用 `SearchOldVuln` 查看候选全文（只允许本项目已确认产出；禁止历史旧漏洞）。
2. 需要时 `Read`/`Grep` 核对源码上的前置是否真能被上一步满足。先收齐候选再排序。
3. **详文最多 3 条**：只对危害最大、利用最简单的链 `SubmitAttackChain`（须 steps 正文）。
4. 其余真链用 `IndexAttackChain` 写入索引简述，或在 `FinishAttackChain(other_chains=...)` 里一次性补交。不要为同质变体再写详文。
5. 完成后 `FinishAttackChain(notes=...)`。找不到合理链也要 Finish，不要硬凑。

当前挖掘模式：${audit_mode_label}
${audit_mode_hint}

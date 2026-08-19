# 攻击链串联任务

挖掘与审核已结束。本项目当前有 **${confirmed_count}** 条已确认漏洞（`confirmed` / `static_only`）。

## 已确认漏洞目录（摘要）
```json
${catalog}
```

## 要求
1. 用 `SearchOldVuln` 查看候选全文（只允许本项目已确认产出；禁止历史旧漏洞）。
2. 需要时 `Read`/`Grep` 核对源码上的前置是否真能被上一步满足。
3. 发现真串联则 `SubmitAttackChain`；可提交多条。
4. 完成后 `FinishAttackChain(notes=...)`。找不到合理链也要 Finish，不要硬凑。

当前挖掘模式：${audit_mode_label}
${audit_mode_hint}

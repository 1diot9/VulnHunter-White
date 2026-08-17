挖掘模式：${audit_mode_label}。${audit_mode_hint}

Worker=${worker_id} 轮次=${round_id}
当前注入文件: src/${file_path} （权重=${weight}, has_source=${has_source}）
Source 方法: ${sources}

```
${snippet}
```

侦察文档与最近挖掘摘要已注入：不要重复分析项目结构，不要重复尝试摘要中已走过的路径。仅最新一轮的「建议后续方向」仍可能有效；更早轮次以「已尝试」「已排除」为准。
请从该文件出发沿调用链审计。
FinishFile 与 FinishRound 不是一对：读到无法作为入口点的文件立刻 FinishFile(paths=[...])，然后继续分析本轮注入入口，禁止立刻 FinishRound。
仅当一开始注入的这份入口文件的 source→sink 已完整分析后，才 FinishFile 它（若尚未标）并 FinishRound。report 对齐 templates/round-report.md。不要只标注入文件。
从摘要接续已分析的调用链，不要重复已 FinishFile 的文件。
SearchOldVuln 的 kind=old 里带调用点的条目是危险 API 线索；不要把框架 CVE 清单当本项目新洞。
同一根因同一危害只 SubmitVuln 一次（填 root_cause_key，报告含同根因受影响点）；pending 同根因用 AppendAffectedLocations，不要拆成多份报告。

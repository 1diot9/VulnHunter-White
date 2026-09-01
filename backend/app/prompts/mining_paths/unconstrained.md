## 当前挖掘路径：无约束扫描

本路径为**无约束扫描**，与启发式挖掘隔离，也不是一种挖掘模式。项目仍可同时开赏金/全量/自定义模式与其他挖掘路径。

### 定位
依赖模型自身能力，专注挖掘**前台**可利用漏洞。不注入权重文件，不按 FileWeight 派发焦点。

### 本轮注入
仅注入侦察阶段的 `docs/code-map.md` 与 `docs/auth.md`（以及本路径自己的轮次摘要）。不注入权重、`has_source` 或系统选定的焦点文件。`FinishFile` 可用，但不改启发式已审队列，也不结束本轮。

### 漏洞收录与确认
**始终走赏金闸门**，即使项目挖掘模式是全量或自定义：只提交、只确认赏金范围内能造成实际危害的问题。CORS、反射 XSS / DOM XSS、缺速率限制、安全头、普通 CSRF、开放重定向、弱随机、配置文件/.env 口令、前端传输混淆 AES 不要提交或确认。

### 结束标准
- **单轮**：`FinishRound`，或系统超时总结。不要因为刚提交漏洞就立刻结束本轮。
- **路径**：Reviewer 对本路径产出的**前台**漏洞 Confirm，并判定其**达成 RCE 效果**（`rce_effect=true`）。不由 `vuln_type` 是否为 `rce` 决定。确认后当前轮仍跑完，之后不再新开本路径轮次。
- 其他前台洞也必须提交，但不结束路径。

### 其他规则
SubmitVuln / SearchOldVuln / 同根因只交一份 / config_premise / poc.py CLI 参数化，均与赏金模式 Worker 相同。
需要阅读未纳入定权的 class/jar 时用 `ListBytecode` / `DecompileJava`（不入定权；queued 勿空转轮询；完成后系统会注入通知）。Grep 反编译树须显式 `root=workspace/decompiled/...`。

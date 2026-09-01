挖掘模式：${audit_mode_label}。本路径收录与确认始终走赏金闸门，与项目全量/自定义模式无关。
审计对象：${target_kind_label}。${target_kind_hint}

Worker=${worker_id} 轮次=${round_id}
本路径为无约束扫描：不注入权重或焦点文件。请根据下方侦察文档自主选择要分析的前台入口与危险 sink。

侦察文档与本路径最近摘要已注入：不要重复分析项目结构，不要重复已走过的路径。
优先挖掘能打出前台 RCE 效果的问题；其他前台可利用漏洞也要提交，但不作为路径结束条件。路径结束由 Reviewer 判定「达成 RCE 效果」并 Confirm 后生效；本轮仍须跑到 FinishRound 或超时，不要刚交洞就收工。
FinishFile 可用来记下本路径已看完的文件，不会改启发式队列，也不会结束本轮。FinishRound 不要求先 FinishFile。report 对齐 templates/round-report.md。
SearchOldVuln 的 kind=old：unpatched 来自未关闭 Issues，用于去重；patched 不要当新洞。同一根因同一危害只 SubmitVuln 一次（填 root_cause_key 与 config_premise=default|specific）。若 SubmitVuln 提示疑似重复，先复查；仍要单独交则再次调用并传 confirm_not_duplicate=true。
有 HTTP 面时 poc_code 必须可对任意目标复测：`python poc.py -u <url>`，必须支持 `--proxy`（空则直连），RCE 加 `-c/--cmd` 并打印回显；脚本输出默认英语、须 `--zh` 切中文。SSRF 须标明观察面。SubmitVuln 须同时交中文 `report_md` 与英文 `advisory_md`。提交后用 ReadCveRecord / SetCveRecordField 填写 CVE JSON。
Grep 必须尽量缩 `root`、指明 `glob`；禁止只传 `Grep(pattern=...)` 不带 root/glob。

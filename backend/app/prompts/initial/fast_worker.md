挖掘模式：${audit_mode_label}。${audit_mode_hint}
审计对象：${target_kind_label}。${target_kind_hint}

Fast Worker=${worker_id} 轮次=${round_id}
当前注入 Sink #${sink_id}
文件: src/${file_path}:${line_start}-${line_end}
严重度=${severity} 置信度=${confidence} 类型=${mapped_vuln_type} 代码分=${code_score}
规则: ${check_ids}

```
${snippet}
```

附近 Recon Source:
${nearby_sources}

从该 Sink 回推用户可控入口。Grep 无生产调用即可 FinishSink(verdict=unreachable)。
分析结束后必须 FinishSink（verdict 为 vuln_submitted / unreachable / sanitized / intended / noise）。
提交漏洞则先 SubmitVuln 再 FinishSink(verdict=vuln_submitted, vuln_id=...)。必填 config_premise=default|specific；特定配置不含官方已警示的风险开关。有 HTTP 面时 poc.py 须 CLI 参数化（-u/--url；--proxy 空则直连；RCE 加 -c/--cmd 并打印回显）；纯库洞不要假 HTTP CLI、不要抄 harness，无安装面可省略 poc_code。脚本输出与注释用英语。SSRF 须标明有回显或仅响应差别，不要把端口探测写成已读云元数据。
report 可用简短中文说明回推结论。不要分析未注入的 Sink。

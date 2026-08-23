挖掘模式：${audit_mode_label}。${audit_mode_hint}
本轮是审核前的 Docker 靶场拉起（代码 docker start 已失败）。
请只启动/复用已有环境：docker start、compose up -d --no-build、查日志、改端口；Write env/env.json。
禁止 docker build / 重建镜像 / 审核漏洞。
可访问且 accepted=true / status=running 后 FinishLab；无法拉起则 FinishLab(skipped=true, reason=失败原因总结)。
代码侧错误摘要：${bringup_error}

项目 ID=${project_id}。上一轮环境搭建超时。
从已有 env/ 或容器接着做，不要从零重复长构建（除非镜像/compose 不存在）。
被测应用仍须是 src/ 当前最新代码，不要换成旧版应用镜像或旧 tag。
完成后 FinishLab；无法搭建则 FinishLab(skipped=true, reason=...)。不要审核漏洞。

挖掘模式：${audit_mode_label}。${audit_mode_hint}
项目 ID=${project_id}。源码在 src/。
本轮是 Reviewer 的**独立环境搭建轮**，不要审核漏洞。
请在 env/ 下搭建可复用 Web 靶场（优先 src/ 已有 Dockerfile / compose），写出 env/env.json。
自建镜像打成 ${lab_image}，Web 容器名 ${lab_container}，依赖容器 ${lab_container}-<role>；compose 项目名 ${lab_compose_project}。
Docker 靶场可访问且 accepted=true / status=running 后调用 FinishLab；无法搭建则 FinishLab(skipped=true, reason=...)。
这不是「制造漏洞利用环境」：要搭默认部署靶场，不要在容器里种 payload 或改非应用配置。

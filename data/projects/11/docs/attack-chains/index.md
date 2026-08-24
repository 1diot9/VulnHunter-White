# 攻击链索引

详文只保留危害最大、利用最简单的最多 3 条；其余真链见「其他简述」。
有本地 Docker 靶场时，无用户交互的详文链会动态验证并落盘 chain 脚本。

## 详文

- **匿名 SQLi 泄露 admin 凭据 → 登录 → ping 命令注入 RCE** [仅静态]（#183, #184）→ `docs/attack-chains/匿名-SQLi-泄露-admin-凭据-登录-ping-命令注入-RCE.md`
  - 匿名用户通过未授权 SQLi 拖取 admin 明文密码，登录获取 admin 会话后利用 ping 接口命令注入实现 RCE，从匿名访问到完全控制服务器。

## 其他简述

- **存储型 XSS 劫持 admin 浏览器 → 同源 fetch 触发 ping RCE** [需用户交互，跳过动态验证]（#185, #184）
  - 匿名 POST /api/notes 注入 XSS payload（漏洞 185），admin 访问公开 /notes 页面时脚本在其浏览器执行，通过同源 fetch('/api/tools/ping?host=;cmd') 携带 admin session 自动满足鉴权（漏洞 184），实现 RCE 并外带结果；需 admin 访问 /notes 页面。

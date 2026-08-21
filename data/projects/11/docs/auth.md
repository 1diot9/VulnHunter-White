# 鉴权文档 — MemoBoard（项目 ID=11）

## 概述

MemoBoard 使用 Flask session（cookie-based）进行身份认证。认证逻辑极简，仅登录与 admin 角色检查，大部分接口无鉴权。

## 登录入口

- **路径**：`POST /api/login`
- **参数**：`username`、`password`（支持 JSON body 或 form 表单）
- **处理函数**：`app.py → api_login()`
- **验证逻辑**：调用 `board.store.find_user(username, password)`，使用参数化 SQL 查询 `users` 表
- **成功**：设置 `session["name"]` 和 `session["role"]`，返回 `{"ok": true, "name": ..., "role": ...}`
- **失败**：返回 401

## Session 机制

- **类型**：Flask 默认 cookie session（签名 cookie）
- **secret_key**：`os.urandom(32)`，每次进程启动重新生成（非硬编码密钥）
- **session 字段**：
  - `session["name"]` — 用户名
  - `session["role"]` — 角色（"user" 或 "admin"）

## 角色与权限

### 角色

| 角色 | 用户 | 说明 |
|------|------|------|
| `user` | alice、bob | 普通用户 |
| `admin` | admin | 管理员，可访问 ping 接口 |

### 种子用户

| 用户名 | 密码 | 角色 | 邮箱 |
|--------|------|------|------|
| alice | alice123 | user | alice@memoboard.lab |
| bob | bob123 | user | bob@memoboard.lab |
| admin | admin123 | admin | admin@memoboard.lab |

## 各接口鉴权情况

| 接口 | 鉴权要求 | 说明 |
|------|----------|------|
| `GET /` | 无 | 公开首页 |
| `GET /healthz` | 无 | 健康检查 |
| `GET /notes` | 无 | 公开备忘录页面 |
| `POST /api/login` | 无 | 登录入口 |
| `GET /api/me` | 需 `session["name"]` | 返回当前用户信息，未登录返回 401 |
| `GET /api/users` | **无** | 用户查询接口，无任何鉴权（SQLi 入口） |
| `GET /api/notes/<id>` | **无** | 获取单条备忘录，`X-User` header 被读取但未做属主校验（IDOR） |
| `POST /api/notes` | **无** | 创建备忘录，任何人可写（存储型 XSS 写入点） |
| `GET /api/tools/ping` | **需 admin 会话** | 检查 `session["name"]` 存在且 `session["role"] == "admin"`，否则 401/403（RCE 入口） |

## 显式允许的能力

- **admin 角色**：可访问 `GET /api/tools/ping`（运维 ping 工具）
- **已登录用户**：可访问 `GET /api/me`
- **所有访客（含匿名）**：可访问首页、健康检查、公开备忘录页、用户查询、创建备忘录、获取任意备忘录

## 鉴权缺陷

1. **`GET /api/users` 无鉴权**：匿名用户可查询用户列表，且 `name` 参数存在 SQL 注入，可拖出所有用户密码（含 admin）
2. **`GET /api/notes/<id>` 无属主校验**：`X-User` header 被读取但未用于权限判断，任何用户可读取任意 id 的备忘录（IDOR）
3. **`POST /api/notes` 无鉴权**：匿名用户可创建备忘录，body 内容未经转义在 `/notes` 页面用 `| safe` 渲染（存储型 XSS）
4. **`GET /api/tools/ping` admin 限制可被绕过**：通过 SQLi 拖取 admin 口令 → 登录获取 admin 会话 → 访问 ping 接口（攻击链）

## 攻击链

**SQLi → admin 登录 → ping RCE**

1. 匿名访问 `GET /api/users?name=' OR 1=1 --` 拖出 admin 口令
2. `POST /api/login` 用 admin 口令登录，获取 admin 会话
3. `GET /api/tools/ping?host=;id` 利用命令注入执行任意命令（RCE）

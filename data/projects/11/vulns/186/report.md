## 摘要

MemoBoard 的备忘录获取接口 `GET /api/notes/<id>` 存在 IDOR（不安全直接对象引用）漏洞。该接口读取了 `X-User` 请求头但未用于属主校验，任何用户（含匿名）可通过遍历 note_id 读取其他用户的私密备忘录，包括 bob 的薪资信息（"Confidential: bob salary review = 128000"）。

## 漏洞描述

MemoBoard 是一款基于 Flask 3.0.3 框架开发的内网备忘录看板应用。应用提供 `GET /api/notes/<int:note_id>` 接口用于获取单条备忘录。该接口的设计意图是仅允许备忘录作者读取自己的备忘录，代码中读取了 `X-User` 请求头作为当前用户身份标识，但从未将其与备忘录的 `author` 字段进行比对校验。

接口直接根据 `note_id` 查询数据库并返回结果，无任何属主校验。攻击者可通过遍历 note_id（1, 2, 3...）读取所有用户的备忘录，包括标记为机密的薪资信息。

## 漏洞危害

- **越权读取敏感数据**：攻击者可读取其他用户的私密备忘录，包括 bob 的薪资信息（"Confidential: bob salary review = 128000. Do not share."）。
- **信息泄露**：通过遍历 note_id 可获取所有备忘录内容，泄露内网敏感业务数据。

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

`GET /api/notes/<int:note_id>`（`src/app.py` 第 73-84 行）：

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

### 漏洞分析

1. 第 80 行读取 `X-User` header 赋值给 `_current`，但该变量从未被使用
2. 第 81 行直接调用 `get_note(note_id)` 按 id 查询，无属主过滤
3. 第 84 行将查询结果原样返回，包含 author、title、body 全部字段
4. `get_note`（store.py:33-39）使用参数化查询按 id 获取备忘录，无 WHERE author = ? 条件

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

### 攻击路径

1. 攻击者发送 `GET /api/notes/2`（带任意或不带 X-User header）
2. 接口返回 bob 的私密备忘录：`{"id":2,"author":"bob","title":"private-salary","body":"Confidential: bob salary review = 128000. Do not share."}`
3. 攻击者获取了本不应可见的薪资等敏感信息

## 同根因受影响点

- `src/app.py:73-84` — `api_note` 路由，读取 X-User 但未做属主校验（主报告点）
- `src/board/store.py:33-39` — `get_note` 函数，按 id 查询无属主过滤

## 复现证明

```bash
# 以 alice 身份读取 bob 的私密备忘录（note_id=2）
curl -H "X-User: alice" http://TARGET:5000/api/notes/2

# 预期响应:
# {"id":2,"author":"bob","title":"private-salary",
#  "body":"Confidential: bob salary review = 128000. Do not share."}

# 使用 PoC 脚本
python poc.py -u http://TARGET:5000
```

局部验证 harness 已通过（5/5 测试），验证了：
1. Alice 可读取 bob 的私密薪资备忘录
2. 匿名用户（无 X-User header）同样可读取
3. 空 X-User 仍可读取
4. 无论 X-User 值如何，返回结果完全相同（无属主校验）
5. 可遍历所有 note_id 枚举全部备忘录

## 修复方案

1. 在 `api_note` 中校验属主：
```python
@app.get("/api/notes/<int:note_id>")
def api_note(note_id: int):
    current = (request.headers.get("X-User") or "").strip()
    row = get_note(note_id)
    if not row:
        abort(404)
    if row["author"] != current:
        abort(403)
    return jsonify(row)
```
2. 更好的方案：使用 session 认证而非 X-User header，并在查询中加入属主过滤。

## 备注

此漏洞为独立漏洞，不依赖其他漏洞作为前提。X-User header 可被任意伪造，即使做了属主校验也应基于服务端 session 而非客户端 header。

---

## 审核标注

- 攻击面：前台
- 配置前提：默认配置
- 严重度：高危（high）
- CVSS 3.1：7.5
- 评分向量：CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
- 价值分层：有 CVE 价值（cve_candidate）
- 分层理由：Unauthenticated IDOR on a public API endpoint. Any attacker (no login required) can enumerate note IDs and read other users' private notes including confidential salary data. Clear source→sink: X-User header read but never used for ownership check, get_note queries by id only with no author filter, full row returned. Single-request exploitation, no defense. Meets CVE value threshold for unauthenticated sensitive data exposure.
- 根因合并键：idor:api_note

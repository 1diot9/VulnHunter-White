## 本轮入口

- 焦点文件：`src/app.py`（权重=100, has_source=True）
- 角色：用户可控 HTTP 入口，正向 source→sink 分析
- Source 方法：GET /api/users, GET /api/tools/ping, POST /api/notes, GET /api/notes/<id>, POST /api/login, GET /api/me, GET /notes, GET /, GET /healthz

## 本轮挖掘方向

从 `app.py` 的 HTTP 路由正向追踪用户可控输入到危险 sink。沿调用链读取了 `board/engine.py`（run_user_lookup SQLi sink、ping_host RCE sink）、`board/store.py`（参数化查询辅助函数）、`templates/notes.html`（| safe 渲染 sink）、`templates/index.html`（无危险点）、`scripts/smoke.py`（验证 4 个 sink 的冒烟测试）、`board/__init__.py`（版本号常量）。

## 已尝试

1. **SQL 注入（MB-01）**：`GET /api/users?name=` → `run_user_lookup(name)` → `f"SELECT ... WHERE name = '{name}'"`（engine.py:71）。无鉴权，字符串拼接 SQL，响应含 password 字段。已提交 vuln_id=183，root_cause_key=`sqli:run_user_lookup`，config_premise=default。

2. **命令注入 RCE（MB-02）**：`GET /api/tools/ping?host=` → `ping_host(host)` → `subprocess.getoutput(f"echo MEMO-PING {host}")`（engine.py:79）。需 admin 会话，但 admin 密码可通过 SQLi 泄露或种子数据默认凭据 admin/admin123 获取。已提交 vuln_id=184，root_cause_key=`rce:ping_host`，config_premise=default。

3. **存储型 XSS（MB-03）**：`POST /api/notes` body → `create_note` 存入 DB → `GET /notes` → `{{ n.body | safe }}`（notes.html:18）。无鉴权写入，safe 过滤器跳过转义，其他用户访问 /notes 时执行注入脚本。已提交 vuln_id=185，root_cause_key=`stored_xss:notes_template_safe`，config_premise=default。

4. **IDOR 越权读取（MB-04）**：`GET /api/notes/<id>` → X-User header 读取但未用于属主校验（app.py:80）→ `get_note(note_id)` 按 id 查询无属主过滤 → 返回任意用户备忘录（含 bob 薪资 128000）。已提交 vuln_id=186，root_cause_key=`idor:api_note`，config_premise=default。

5. **攻击链串联**：SQLi（MB-01）泄露 admin 密码 → 登录获取 admin 会话 → ping 接口命令注入 RCE（MB-02）。存储型 XSS 也可盗取 admin session cookie 替代 SQLi 获取 admin 会话。各漏洞在报告中均注明了攻击链关系。

6. **查重**：SearchOldVuln kind=old 和 kind=found 均无历史记录，4 条均为新发现。

## 已排除（后续轮不要再走）

- `board/store.py`：所有函数（find_user、list_users、list_notes、get_note、create_note）均使用参数化查询，无 SQLi。已 FinishFile。
- `board/engine.py`：除 run_user_lookup（SQLi）和 ping_host（RCE）外，init_db 和 seed_if_needed 为内部初始化函数，无用户可控输入。已 FinishFile。
- `templates/index.html`：使用 Jinja2 默认自动转义（`{{ n.title }}`、`{{ n.author }}`），无 XSS。已 FinishFile。
- `scripts/smoke.py`：测试脚本，非生产代码，无独立审计价值。已 FinishFile。
- `board/__init__.py`：仅版本号常量，无密钥或 gadget。已 FinishFile。
- `app.py` 中 `/`、`/healthz`、`/api/me`、`POST /api/login` 路由：无危险 sink，login 使用参数化查询。已 FinishFile。
- `app.secret_key = os.urandom(32)`：每次启动轮换，非硬编码密钥，不构成 hardcoded_secret 漏洞。
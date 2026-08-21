# MemoBoard — VulnHunter 演示靶场

故意存在 **4 个**漏洞的小型 Flask 内网备忘录。其中 **SQL 注入与管理员 ping RCE 可串联**，用来测攻击链阶段。

**不要部署到公网。**

## 预设漏洞

| 类型 | 入口 |
| --- | --- |
| SQL 注入 | `GET /api/users?name=`（可拖出 admin 口令） |
| RCE（ping 命令注入） | `GET /api/tools/ping?host=`（**必须先有 admin 会话**） |
| 存储型 XSS | `POST /api/notes` → `GET /notes` |
| IDOR 越权 | `GET /api/notes/<id>`（`X-User` 未做属主校验） |

预期攻击链：**SQLi 拿 admin 口令 → `POST /api/login` → ping RCE**。详见 [INTENDED_VULNS.md](INTENDED_VULNS.md)。

登录本身不是漏洞：`POST /api/login` `{"username","password"}`，会话存在 cookie 里。

## 在 VulnHunter 中导入

1. 首页上传 `vulnhunter-python-lab.zip`。
2. 赏金模式；开启发式（可再开快速扫描）。
3. **勾选攻击链串联**，以便审核结束后跑串联 Agent。
4. 验证方式按需。镜像默认 **5000**。不要开 Verifier。

## 本地运行

```bash
python -m pip install -r requirements.txt
python app.py
```

或 `docker compose up --build`。健康检查：`GET http://127.0.0.1:5000/healthz`

演示账号：`alice / alice123`，`bob / bob123`，`admin / admin123`。

```bash
python scripts/smoke.py
```

## 布局

- `app.py` — 路由、登录会话、admin-only ping
- `board/engine.py` — 拼接 SQL、ping 命令拼接
- `board/store.py` — 用户与备忘录
- `templates/notes.html` — `| safe`
- `Dockerfile` — 靶场动态复用

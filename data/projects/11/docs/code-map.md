# 代码地图 — MemoBoard（项目 ID=11）

## 概述

MemoBoard 是一个故意存在漏洞的小型 Flask 内网备忘录应用，用作 VulnHunter 白盒审计靶场。预设 4 个漏洞，其中 SQL 注入与管理员 ping RCE 可串联为攻击链。

- **语言/运行时**：Python 3.10+（Docker 镜像 python:3.12-slim）
- **Web 框架**：Flask 3.0.3（Jinja2 模板引擎内置）
- **WSGI 服务器**：gunicorn 23.0.0（Dockerfile CMD 实际用 `python app.py` 开发服务器）
- **数据库**：SQLite（标准库 `sqlite3`，文件 `data/board.db`）
- **进程执行**：`subprocess.getoutput`（ping 功能）
- **模板引擎**：Jinja2（Flask 内置），模板目录 `templates/`
- **ORM**：无，直接使用 `sqlite3` 原生 SQL

## 目录结构

```
src/
├── app.py                  # Flask 应用入口：路由、登录会话、admin-only ping
├── board/
│   ├── __init__.py          # __version__ = "0.5.0"
│   ├── engine.py            # 数据访问与危险 helper：DB 连接、建表、seed、run_user_lookup（SQLi）、ping_host（RCE）
│   └── store.py             # SQLite 辅助函数：find_user、list_users、list_notes、get_note、create_note
├── scripts/
│   └── smoke.py             # 冒烟测试脚本，验证 4 个 sink 与 SQLi→admin ping 链
├── templates/
│   ├── index.html           # 首页模板，列出备忘录
│   └── notes.html           # 公开备忘录模板，body 用 `| safe` 渲染（存储型 XSS sink）
├── static/uploads/.gitkeep  # 静态上传目录（空）
├── data/.gitkeep            # 数据目录（运行时生成 board.db）
├── requirements.txt         # flask==3.0.3, gunicorn==23.0.0
├── pyproject.toml           # 项目元数据
├── Dockerfile               # 容器构建
├── docker-compose.yml       # 端口 5000
├── README.md                # 项目说明
├── CHANGELOG.md             # 版本历史
├── SECURITY.md              # 安全策略
└── INTENDED_VULNS.md        # 预设漏洞答案表
```

## 模块划分

### app.py — 路由层（HTTP 入口）

所有 HTTP 路由均定义在此文件。Flask 应用对象 `app`，`secret_key = os.urandom(32)`（每次启动轮换）。启动时调用 `_boot()` 初始化数据库并 seed。

| 方法 | 路径 | 函数 | 鉴权 | 说明 |
|------|------|------|------|------|
| GET | `/` | `index` | 无 | 渲染 `index.html`，列出所有备忘录 |
| GET | `/healthz` | `healthz` | 无 | 健康检查 JSON |
| GET | `/notes` | `notes_page` | 无 | 渲染 `notes.html`，body 用 `\| safe` 渲染（**存储型 XSS sink**） |
| POST | `/api/login` | `api_login` | 无 | 登录入口，JSON 或 form，设置 session |
| GET | `/api/me` | `api_me` | 需 session["name"] | 返回当前会话用户信息 |
| GET | `/api/users` | `api_users` | 无 | 用户查询，`name` 参数传入 `run_user_lookup`（**SQLi sink**） |
| GET | `/api/notes/<int:note_id>` | `api_note` | 无（X-User 未校验） | 获取单条备忘录（**IDOR sink**） |
| POST | `/api/notes` | `api_create_note` | 无 | 创建备忘录，body 存入 DB（**存储型 XSS 写入点**） |
| GET | `/api/tools/ping` | `api_ping` | 需 admin 会话 | 运维 ping，`host` 传入 `ping_host`（**RCE sink**） |

### board/engine.py — 数据访问与危险 helper

- `DATA_DIR` / `DB_PATH`：数据目录与数据库路径
- `_connect()`：创建 SQLite 连接，`row_factory = sqlite3.Row`
- `init_db()`：建表（users、notes）
- `seed_if_needed()`：种子数据（alice/bob/admin 用户 + 2 条备忘录）
- `run_user_lookup(name)`：**字符串拼接 SQL**，`name` 直接插入 `WHERE name = '{name}'`（SQLi）
- `ping_host(host)`：**命令注入**，`subprocess.getoutput(f"echo MEMO-PING {host}")`（RCE）

### board/store.py — SQLite 辅助函数

- `find_user(username, password)`：参数化查询，登录验证
- `list_users()`：列出所有用户（不含 password）
- `list_notes()`：列出所有备忘录
- `get_note(note_id)`：按 id 获取备忘录（参数化）
- `create_note(author, title, body)`：插入备忘录（参数化）

### scripts/smoke.py — 冒烟测试

验证 4 个 sink 及 SQLi→admin ping 攻击链。使用 Flask test_client。

## 技术栈与关键依赖

| 依赖 | 版本 | 用途 |
|------|------|------|
| flask | 3.0.3 | Web 框架（含 Jinja2 模板引擎） |
| gunicorn | 23.0.0 | WSGI 服务器（Dockerfile 未使用，实际用 `python app.py`） |
| sqlite3 | 标准库 | 数据库 |
| subprocess | 标准库 | ping 命令执行 |

## 模板引擎 / ORM 映射

- **模板引擎**：Jinja2（Flask 内置）
  - `templates/index.html`：`{% for n in notes %}` 循环渲染备忘录列表
  - `templates/notes.html`：`{{ n.body | safe }}` — `safe` 过滤器跳过转义，是存储型 XSS 的渲染 sink
- **ORM**：无 ORM，直接使用 `sqlite3` 原生 SQL
  - 参数化查询（安全）：`find_user`、`list_users`、`list_notes`、`get_note`、`create_note`
  - 字符串拼接（不安全）：`run_user_lookup` — `f"SELECT ... WHERE name = '{name}'"`

## 非 HTTP 入口

本项目无 WebSocket、RPC、MQ 消费、回调或执行器开放接口。所有用户可控入口均为 HTTP 路由。

## 种子数据

- 用户：alice/alice123/user、bob/bob123/user、admin/admin123/admin
- 备忘录：alice 的 "welcome"、bob 的 "private-salary"（含薪资 128000）

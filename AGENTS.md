# AGENTS.md

本文件给后续在本仓库工作的 AI agent 使用。先读 `README.md`，再按本文约定修改代码。

## 项目概览

VulnHunter 是一个白盒审计 Agent 平台：导入 GitHub 仓库或源码 zip 后，按 Recon、启发式 Worker、Reviewer 流程进行漏洞挖掘与验证；可选开启 Verifier，在 Reviewer 确认前台漏洞后用 FOFA 搜索同款目标并复测。

- 后端：`backend/app`，FastAPI + SQLAlchemy + SQLite，负责项目导入、阶段调度、Agent 循环、工具注册、报告与漏洞数据。
- 前端：`frontend`，Vite + React + TypeScript + Tailwind，用于审计项目、实时日志、阶段报告、漏洞列表和设置页。
- 模板：`templates`，阶段报告和提示词相关模板。
- 运行态数据：`data/projects/{id}`、`data/logs`、`data/app.db`。除非任务明确要求，不要手工改运行态数据或提交生成文件。

## 常用命令

在 Windows 环境优先使用仓库脚本：

```bat
start.cmd
stop.cmd
scripts\run-tests.cmd
```

手动后端：

```bat
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --reload-dir app --timeout-graceful-shutdown 2 --host 127.0.0.1 --port 8000
```

手动前端：

```bat
cd frontend
npm install
npm run dev
npm run build
```

后端测试：

```bat
cd backend
.venv\Scripts\activate
pytest
```

## 后端约定

- API 路由放在 `backend/app/api`，Pydantic schema 放在 `backend/app/schemas.py`，数据库模型放在 `backend/app/models.py`。
- 使用 `SessionLocal` 时保持短生命周期，优先用 `with SessionLocal() as db:`；测试会 monkeypatch 已导入的 `SessionLocal`。
- SQLite schema 变更要更新 `models.py` 中的模型，并在 `_ensure_columns()` 里补充已有库的兼容列迁移。
- 项目路径相关逻辑优先使用 `backend/app/services/paths.py`，不要散落拼接 `data/projects/{id}`。
- 阶段调度、暂停/恢复/取消逻辑集中在 `backend/app/services/pipeline.py`；Agent 循环相关逻辑在 `backend/app/agent`。
- 项目挖掘模式（赏金模式 `bounty` / 全量模式 `full`）在创建时确定，默认赏金模式；创建后仅当项目暂停才可更改。规则与闸门在 `backend/app/audit_mode.py` 和 `backend/app/prompts/modes/`。
- 可选 Verifier（互联网验证）在创建时由用户决定，默认关闭；创建后可在项目设置中开启。开启后，Reviewer 确认前台漏洞会排队用 FOFA 搜索同款目标并按报告复测，默认 10 个、任一成功即结束。任意文件删除、DoS、SQL 增删改等会中断或篡改业务的漏洞自动跳过、不做互联网复测。FOFA Key 配在设置页或 `VULNHUNTER_FOFA_KEY`。
- 历史漏洞只收录本项目公开洞，以及本仓库确有调用点、版本仍可能受影响、默认部署可能打到的组件条目；已修复 / 未使用 / 仅传递依赖写进索引 `note`，不要一条一文。
- 工具实现放在 `backend/app/tools`，新增工具后确认会被 `register_all_tools()` 注册，并补充工具 ACL、阶段门闩或相关测试。
- 出站 HTTP、LLM、MCP 路径等配置通过 `backend/app/config.py` 的 `Settings` 管理，环境变量前缀为 `VULNHUNTER_`。
- 不要在代码、测试、文档中写入真实 API Key、GitHub PAT、FOFA Key、CEYE token 或代理凭据。

## 前端约定

- API 类型和请求封装集中在 `frontend/src/api.ts`；新增后端字段时同步更新 TypeScript 类型。
- 页面放在 `frontend/src/pages`，可复用组件放在 `frontend/src/components`，基础 UI 组件放在 `frontend/src/components/ui`。
- 优先复用现有 UI 组件、Tailwind token 和 `cn()` 工具，不为小改动引入新的样式体系。
- 保持 React 函数组件风格；涉及轮询/可见性状态时先看 `frontend/src/lib/visibilityPoll.ts` 和现有页面实现。
- 前端构建以 `npm run build` 为准；改动类型或接口契约后至少运行构建。

## 测试与验证

- 后端行为改动优先补充 `backend/tests` 下的 pytest，尤其是 API、阶段状态、工具、漏洞审核、报告读取、上下文压缩和沙箱逻辑。
- 涉及数据库、项目工作区或运行态状态时，使用现有 `tmp_env`、`project` 等 fixture，保持测试隔离。
- 前端 UI 或类型改动至少运行 `cd frontend && npm run build`。
- 跨前后端契约变更要同时验证后端 pytest 和前端 build。

## 工作边界

- 不要提交 `frontend/dist`、`frontend/node_modules`、`backend/.venv`、`.pytest_cache`、`data/logs`、`data/projects`、`data/app.db` 等生成/运行态文件，除非用户明确要求。
- 不要随意清空或重建 `data/`，其中可能包含用户审计项目和日志。
- 需要启动服务前先确认是否已有后端 8000 或前端 5173 进程在运行，避免重复启动。
- 若改动 Agent 提示词、阶段流程或漏洞判定逻辑，要保持已有中文术语一致：Recon、Worker、Reviewer、Verifier、Fix、历史漏洞、漏洞产出、审计项目、赏金模式、全量模式。

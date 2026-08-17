# VulnHunter

白盒审计 Agent：导入 GitHub / zip Web 项目，Recon ∥ Reviewer 环境搭建 → 启发式 Worker → Reviewer 审核（静态 + MCP/普通动态）；可选 Verifier 对已确认前台漏洞做 FOFA 互联网复测。

## 一键启停

双击仓库根目录：

- `start.cmd` — 启动后端（8000）+ 前端（5173）；首次会自动建 venv / `npm install`。默认不热更新，开发时加 `--reload`
- `stop.cmd` — 停止两服务（按窗口标题 + 端口）

日志：`data\logs\backend.log`、`data\logs\frontend.log`。

## 单元测试

```bash
cd backend
.venv\Scripts\activate
pip install -r requirements.txt
pytest
```

或运行 `scripts\run-tests.cmd`。覆盖：漏洞类型、看门狗、上下文压缩/429 识别、沙箱、入库索引、工具 ACL/门闩、API、环境端口重映射等。

### 代理

默认出站 HTTP（WebSearch / SearchGHSA）走 `http://127.0.0.1:10808`（可用 `.env` / `VULNHUNTER_HTTP_PROXY` 覆盖）。Chat Completions **默认直连**，不读系统代理；需要时再设 `VULNHUNTER_CHAT_PROXY`。

## 手动启动

### 后端

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --reload-dir app --timeout-graceful-shutdown 2 --host 127.0.0.1 --port 8000
```

### 前端

```bash
cd frontend
npm install
npm run dev
```

打开 http://127.0.0.1:5173 ，在「设置」配置 Chat Completions Base URL / API Key / 模型；若开启 Verifier，再配置 FOFA Key。

## 能力概览

- 凡 Web 项目均可审计（不限语言）
- v1 仅启发式挖掘；创建项目时选择赏金模式（默认）或全量模式
- 赏金模式按可利用高危害类型收口；全量模式保留低危害难利用项（CORS、反射 XSS、缺速率限制等）
- 动态验证：有 Java/Node/Python debug MCP 则优先；否则普通动态（HTTP PoC + docker exec/日志）
- 可选 Verifier：创建项目时默认关闭，也可在项目设置中开启。Reviewer 确认前台漏洞后，用 FOFA 默认搜 10 个同款目标并按报告复测，任一成功即结束。一个审计项目只搜一次 FOFA，结果给全部漏洞共享；报告会列出全部目标并标注成功 / 失败 / 未测，复现成功须附上搜索语法。任意文件删除、DoS、SQL 增删改等会中断或篡改业务的漏洞不测互联网目标
- LLM 报错对齐 AutoPoc：429 休眠续跑、超时 conclude、死循环新开、阶段最多再试 2 次
- 历史漏洞：SearchGHSA + WebSearch + SearchOldVuln；只建档项目自身洞与仍可能打到的组件调用点

## 目录

- `backend/app` — FastAPI、Agent 循环、工具、调度
- `frontend` — React + Tailwind UI
- `templates` — 文档模板
- `data/projects/{id}` — 项目隔离工作区

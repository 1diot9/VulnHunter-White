# VulnHunter-White

[中文](README.md) | **English**

Repository: [https://github.com/1diot9/VulnHunter-White](https://github.com/1diot9/VulnHunter-White)

Special thanks to [DeepAudit](https://github.com/lintsinghua/DeepAudit) and [AutoCVE](https://github.com/larlarua/AutoCVE) for many ideas, especially in early development.

LLM-based white-box vulnerability mining agent. Four mining paths (heuristic, fast-scan sink backtrace, historical-vuln bypass, unconstrained) plus Docker lab / local harness / static verify, with optional Internet reproduction and attack-chain stitching.

Import a GitHub repository or a source zip, then run a multi-role pipeline for mining, review, and optional Internet verification.

**Pipeline overview**: Mining starts after Recon (code map, auth, historical vulns, file weighting). At create time you can enable Code Intelligence (CodeGraph source graph, off by default); when on, it runs in parallel with Recon, and mining waits for both. Then heuristic / fast scan / historical-vuln bypass / unconstrained scan (at least one) → Reviewer (static by default; optional lab dynamic or local harness) → optional Verifier (FOFA) and attack-chain stitching.

**Design doc** (architecture, phase design, fault tolerance, novelty): [`docs/DESIGN.md`](docs/DESIGN.md) (Chinese).

On Windows use `start.cmd` / `stop.cmd` at the repo root; on **Linux / macOS** use `sh start.sh` / `sh stop.sh`.

**Docker distribution (optional)**: on Windows use `docker\desktop\start.cmd` (Docker Desktop + WSL2); on Linux use `sh docker/desktop/start.sh` (Docker Engine). Stop with `stop.cmd` / `stop.sh` in the same directory. See [Docker one-click start (Windows / Linux)](#docker-one-click-start-windows--linux).

## Contents

- [Features](#features)
- [Showcase](#showcase)
- [Requirements](#requirements)
  - [Required (frontend + backend)](#required-frontend--backend)
- [Build steps before first start](#build-steps-before-first-start)
  - [1. Get the source](#1-get-the-source)
  - [2. Backend Python deps](#2-backend-python-deps-startcmd--startsh-do-this-on-first-run)
  - [3. Frontend Node deps](#3-frontend-node-deps-startcmd--startsh-do-this-on-first-run)
  - [4. Local-verify sandbox image (L1/L2 harness)](#4-local-verify-sandbox-image-l1l2-harness-required-for-local-verification)
  - [5. Integration sandbox image (L3)](#5-integration-sandbox-image-l3-required-for-l3-integration-verify)
  - [6. Debug MCP](#6-debug-mcp-lab-dynamic-only-when-you-need-to-rewritedebug-pocs)
  - [7. Semgrep for fast scan](#7-semgrep-for-fast-scan)
  - [8. Optional environment variables](#8-optional-environment-variables)
- [Docker one-click start (Windows / Linux)](#docker-one-click-start-windows--linux)
- [One-click start and stop](#one-click-start-and-stop)
  - [First open: Settings](#first-open-settings)
- [Manual start](#manual-start)
  - [Backend](#backend)
  - [Frontend](#frontend)
- [Optional by feature](#optional-by-feature)
- [Common startup issues](#common-startup-issues)
- [Unit tests](#unit-tests)
- [Capability overview](#capability-overview)
- [Repository layout](#repository-layout)
- [Design document](#design-document)
- [License](#license)

## Features

VulnHunter-White:

- Three mining modes: **bounty / full / custom**
- Three audit targets: **web app / library / mixed** (`target_kind`, orthogonal to mining mode)
- Three review verification styles: **lab dynamic**, **local harness**, **static-only**
- Optional **FOFA Internet verification** and **human-in-the-loop** confirmation
- Optional **attack-chain stitching** after mining and review
- Project detail can dedupe selected findings against historical vulns and current source (already public or already fixed)
- Settings can configure an **LLM provider pool**; each project can cap token usage; **discover repos** by prompt or public GHSA
- Findings include a **findings calendar**, Chinese reports / Advisory / CVE JSON

Create-project page: start an audit from a GitHub URL or a zip upload; you can set a max token budget.

![image-20260824113345879](./assets/image-20260824113345879.png)

![image-20260827160028278](./assets/image-20260827160028278.png)

![Create project (continued)](assets/1787305131954-fd22d7db-8af2-4dff-9113-636109d3a476.png)

Project detail: SSE live logs, phase reports, runtime config. You can inject guidance while a run is in progress; each sub-phase can continue or start a new round; unconstrained scan uses stop / start.

![image-20260824113529865](./assets/image-20260824113529865.png)

![image-20260824113549690](./assets/image-20260824113549690.png)

![image-20260827160150510](./assets/image-20260827160150510.png)

Internet-verify confirmation: human gate for findings that may disrupt the target.

![Verify confirmation](assets/1787235668376-78ad9df1-71fe-44f4-bd3b-0a7d52e77349.png)

Findings page: evidence style (static / dynamic / local), privilege (frontend / backend), Internet reproduction. Reports: normal, advisory, CVE JSON. You can ask follow-up questions on a report. The calendar counts confirmed vs false-positive findings by day.

![Findings list](assets/1787235300999-a0e85751-d9ae-4b53-8d2e-2d1a51906b97.png)

![image-20260824113233175](./assets/image-20260824113233175.png)

![image-20260824113203107](./assets/image-20260824113203107.png)

Containers page: inspect containers started for dynamic reproduction.

![Containers](assets/1787235734952-1d7d6474-e228-4a30-857c-4d83e64b4b9d.png)

Settings: Chat Completions / OpenAI Responses / Anthropic Messages, custom mining prompts, log cleanup, and multiple providers as an LLM pool (mainly tested with GLM, DeepSeek, and Alibaba Bailian).

![image-20260827160330224](./assets/image-20260827160330224.png)

![Settings](assets/1787235801542-2f2bbf74-a406-4b01-9873-4ea0ca2114ef.png)

Discover-repos page: optional prompt-first GitHub search, or public GHSA filtering; official demos, sample apps, and learning projects are skipped. Already-created vs creatable are listed separately, with per-item or one-click remove. Search waits 600s by default, plus 60s for each repo beyond 5; a timeout keeps already-found repos and explains why it stopped.

## Showcase

| Application | Advisory | Type | CVSS |
| ----------------------- | ------------------------------------------------------------ | ------------ | -------- |
| udecode/plate           | [GHSA-5pmq-h882-6g62](https://github.com/udecode/plate/security/advisories/GHSA-5pmq-h882-6g62) | XML injection | 6.1      |
| udecode/plate           | [GHSA-fm23-57g4-6m2p](https://github.com/udecode/plate/security/advisories/GHSA-fm23-57g4-6m2p) | XSS          | 5.4      |
| udecode/plate           | [GHSA-qrfj-mgw8-j9c6](https://github.com/udecode/plate/security/advisories/GHSA-qrfj-mgw8-j9c6)/CVE-2026-88976 | XSS          | 6.1      |
| udecode/plate           | [GHSA-vjm2-6pxg-8vm8](https://github.com/udecode/plate/security/advisories/GHSA-vjm2-6pxg-8vm8) | XSS          | 6.1      |
| udecode/plate           | [GHSA-q8r4-6wh4-76hm](https://github.com/udecode/plate/security/advisories/GHSA-q8r4-6wh4-76hm) | RCE          | High     |
| udecode/plate           | [GHSA-6gwv-m56p-wc8m](https://github.com/udecode/plate/security/advisories/GHSA-6gwv-m56p-wc8m) | Missing auth | 6.9      |
| udecode/plate           | [GHSA-2q2r-jqh4-grp3](https://github.com/udecode/plate/security/advisories/GHSA-2q2r-jqh4-grp3) | Missing auth | 6.9      |
| udecode/plate           | [GHSA-p8g2-cf33-p28j](https://github.com/udecode/plate/security/advisories/GHSA-p8g2-cf33-p28j) | DoS          | 6.5      |
| udecode/plate           | [GHSA-r3c4-jjfg-3vvx](https://github.com/udecode/plate/security/advisories/GHSA-r3c4-jjfg-3vvx) | XSS          | 6.1      |
| filebrowser/filebrowser | GHSA-448h-jr2h-3vhp                                          | DoS          | 6.5      |
| http4s/http4s           | [GHSA-gq9p-f254-h286](https://github.com/http4s/http4s/security/advisories/GHSA-gq9p-f254-h286) | DoS          | 7.5      |
| http4s/http4s           | [GHSA-3q2f-8v8m-249p](https://github.com/http4s/http4s/security/advisories/GHSA-3q2f-8v8m-249p) | DoS          | 8.2      |
| http4s/http4s           | [GHSA-3jm4-mm2v-96qj](https://github.com/http4s/http4s/security/advisories/GHSA-3jm4-mm2v-96qj) | DoS          | 7.5      |
| http4s/http4s           | [GHSA-gw3w-mpf8-v247](https://github.com/http4s/http4s/security/advisories/GHSA-gw3w-mpf8-v247) | DoS          | 7.5      |
| http4s/http4s           | [GHSA-h2xv-5x52-7qvw](https://github.com/http4s/http4s/security/advisories/GHSA-h2xv-5x52-7qvw) | DoS          | 7.5      |
| http4s/http4s           | [GHSA-3p4m-6fv5-mjq7](https://github.com/http4s/http4s/security/advisories/GHSA-3p4m-6fv5-mjq7) | DoS          | 7.5      |
| http4s/http4s           | [GHSA-g7xf-9x49-v632](https://github.com/http4s/http4s/security/advisories/GHSA-g7xf-9x49-v632) | DoS          | 7.5      |
| getgrav/grav            | [GHSA-59qm-58v5-gvc5](https://github.com/getgrav/grav/security/advisories/GHSA-59qm-58v5-gvc5) | Sandbox escape | 7.1      |
| netty/netty             | [GHSA-q9pg-8h3j-8hvm](https://github.com/netty/netty/security/advisories/GHSA-q9pg-8h3j-8hvm) | HTTP routing bypass | 6.5      |
| YunaiV/ruoyi-vue-pro    | NCC-2026-08501                                               | XSS          | 6.9      |
| firefly-iii/firefly-iii | [GHSA-3wcx-g7jc-h9vc](https://github.com/firefly-iii/firefly-iii/security/advisories/GHSA-3wcx-g7jc-h9vc) | Privilege escalation | 7.1      |

More than ten additional findings are still in draft and unpublished; they will be added after disclosure.

Findings calendar on the findings page:

![image-20260827155754825](./assets/image-20260827155754825.png)

## Requirements

**Opening the UI and doing static review only** needs the “required” set. Lab dynamic, local verify, fast scan, Code Intelligence, Verifier, and similar extras are installed per feature — you do not need everything at once. Details after the start sections: [Optional by feature](#optional-by-feature).

### Required (frontend + backend)

| Software | Version | Notes |
| --- | --- | --- |
| OS | Windows 10 / 11, or Linux / macOS | Windows: `start.cmd`. Linux/macOS: `sh start.sh` (POSIX `sh`, no bash required) |
| Python | **3.11+** (recommend **3.12** 64-bit) | Windows must run `python` (Add to PATH, with `venv`). Unix prefers `python3`. Debian/Ubuntu also install `python3-venv` |
| Node.js | **20 LTS** (18 minimum) | Need `node` and `npm`; frontend Vite 6 wants a recent Node |
| Git | 2.x | GitHub import uses `git clone --depth 1` (Windows sets `core.longpaths` to avoid `Filename too long` on deep trees such as XWiki). Zip-only import can skip Git, but installing it is still recommended |
| Free ports | **16780**, **15173** | Backend API / frontend dev server. If taken, use `--backend-port` / `--frontend-port`, or run `stop.cmd` / `sh stop.sh` first |
| LLM API | OpenAI Chat Completions, OpenAI Responses, or Anthropic Messages | After start, fill Base URL, API Key, and model on Settings. Agents cannot run without a model |

Check in any terminal **outside** the repo before starting:

```bat
python --version
node --version
npm --version
git --version
```

On Linux / macOS use `python3 --version` for the first line. On Windows, `python` should print `3.11` or `3.12`, not the Windows Store stub `python.exe` (that opens the Store and cannot create a venv).

## Build steps before first start

`start.cmd` / `start.sh` **only** create the backend venv, run `pip install`, and `npm install` the frontend on first run. The items below are **not** automatic — do them ahead of time for the features you will use.

### 1. Get the source

```bat
git clone https://github.com/1diot9/VulnHunter-White.git
cd VulnHunter-White
```

### 2. Backend Python deps (`start.cmd` / `start.sh` do this on first run)

You can also do it once by hand to surface missing Python / pip early.

Windows:

```bat
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
cd ..
```

Linux / macOS:

```sh
cd backend
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
cd ..
```

### 3. Frontend Node deps (`start.cmd` / `start.sh` do this on first run)

```bat
cd frontend
npm install
cd ..
```

On slow networks in China, `start.cmd` / `start.sh` default backend installs to `https://pypi.tuna.tsinghua.edu.cn/simple` (override with `VULNHUNTER_PIP_INDEX_URL`; failure falls back to the default index) and frontend installs to `https://registry.npmmirror.com`. Manual:

```bat
cd frontend
npm install --registry=https://registry.npmmirror.com
```

### 4. Local-verify sandbox image (L1/L2 harness, required for “local verification”)

Used by the `RunCode` harness for **L1 (function/mock)** and **L2 (module chain)**. With Docker running, from the repo root:

```bat
scripts\build-sandbox.cmd
```

Linux / macOS: `sh scripts/build-sandbox.sh`.

Equivalent to:

```bat
docker build -t vulnhunter/sandbox:latest docker/sandbox
```

After success, `docker images` should list `vulnhunter/sandbox:latest`. The image includes Python / PHP / Node / Ruby / Go / JDK / Bash / **gcc (C)**; no rustc / g++. If the image is missing, local verify cannot start the harness sandbox and falls back to static. Rebuild after Dockerfile changes if you already have an older image.

### 5. Integration sandbox image (L3, required for L3 integration verify)

**L3 integration verify**: temporarily install deps in a container, start a loopback service on `127.0.0.1`, and run `poc.py`. On success, evidence is upgraded to **dynamic** (no Docker lab image required). Skip this image if you only use L1/L2.

With Docker running, from the repo root:

```bat
scripts\build-integration-sandbox.cmd
```

Linux / macOS: `sh scripts/build-integration-sandbox.sh`.

Equivalent to:

```bat
docker build -t vulnhunter/integration-sandbox:latest docker/integration-sandbox
```

After success, `docker images` should list `vulnhunter/integration-sandbox:latest`. If the image is missing, L3 cannot use the sandbox path. If `data/projects/{id}/env/env.json` already has a loopback `local_service_url`, it can fall back to running `poc.py` on the host (still must be `127.0.0.1` / `localhost`).

### 6. Debug MCP (lab dynamic only, when you need to rewrite/debug PoCs)

Source lives in `tools/mcp/`, paths relative to the repo root. Without a build, Reviewer still uses ordinary dynamic (current HTTP PoC + docker exec). PoCs are owned by Reviewer; attach MCP only when a PoC is missing, fails, or needs rewriting. See `tools/mcp/README.md`.

**Java** (JDK 17+, Maven 3.6+):

```bat
cd tools\mcp\java-debug
mvn package
```

This must produce `target\java-debug-mcp-0.1.0-SNAPSHOT-all.jar`. Without that jar, Java MCP is unavailable.

**Node**:

```bat
cd tools\mcp\node-debug
npm install
```

The backend launches it with `npx tsx src/index.ts` and needs npm access for `tsx`.

**Python** (install into the **backend venv**, because start scripts run the backend with that interpreter):

```bat
backend\.venv\Scripts\pip.exe install mcp debugpy
```

Linux / macOS: `backend/.venv/bin/pip install mcp debugpy`.

Or:

```bat
backend\.venv\Scripts\pip.exe install -e tools\mcp\python-debug
```

Unix: `backend/.venv/bin/pip install -e tools/mcp/python-debug`.

Override MCP dirs with `VULNHUNTER_MCP_JAVA` / `VULNHUNTER_MCP_NODE` / `VULNHUNTER_MCP_PYTHON` (relative to repo root or absolute). Do not commit build artifacts (`target/`, `node_modules/`, `dist/`).

### 7. Semgrep for fast scan

Either is enough:

- Install host `semgrep` so `semgrep --version` works; or
- Install and start Docker, then pre-pull the image (large; needs registry access):

```bat
scripts\pull-semgrep.cmd
```

Linux / macOS: `sh scripts/pull-semgrep.sh`.

Equivalent to `docker pull returntocorp/semgrep:latest`. Skipping the pre-pull is fine: the first fast scan will pull the same image.

### 8. Optional environment variables

Copy `.env.example` to the repo root or `backend/.env`. Listen ports are for `start.cmd` / `start.sh`. After Settings has saved proxy / FOFA, Settings wins; env vars are fallbacks **only if never saved**. Do not commit real keys.

```
# VULNHUNTER_ACCESS_TOKEN=
# VULNHUNTER_PORT=16780
# VULNHUNTER_FRONTEND_PORT=15173
# VULNHUNTER_HOST=127.0.0.1
VULNHUNTER_HTTP_PROXY=
VULNHUNTER_HTTPS_PROXY=
VULNHUNTER_CHAT_PROXY=
VULNHUNTER_FOFA_KEY=
GITHUB_TOKEN=
# VULNHUNTER_CODEGRAPH_PATH=
# VULNHUNTER_JADX_PATH=
```

`VULNHUNTER_ACCESS_TOKEN` is a global access token: after it is set, the frontend asks for it before showing data or calling APIs. You can also change it on Settings with the current token (Settings then wins). Unset means no gate. `OPENAI_API_KEY` can be a fallback; day-to-day, fill Settings. `VULNHUNTER_HOST` defaults to `127.0.0.1` (localhost only); LAN access uses `0.0.0.0` or `--lan` at start.

## Docker one-click start (Windows / Linux)

The app runs in a Linux container and uses host Docker via a mounted `docker.sock` to build/run local-verify sandboxes (DooD). It does **not** auto-build Docker labs for the target app; verification is off / local verify / **manual lab**. Root `start.cmd` / `start.sh` still support full lab dynamic.

Requirements:

- **Windows**: Docker Desktop installed and running (tray visible, WSL2 backend)
- **Linux**: Docker Engine + Compose v2 plugin installed and running (`sudo systemctl start docker`); the current user can run `docker version` / `docker compose` without prompts (add to the `docker` group and re-login; do not start this script with sudo)
- Disk and network: first run builds the app image and, if missing, `vulnhunter/sandbox` and `vulnhunter/integration-sandbox` (can take tens of minutes)
- Mounting the socket gives the container host Docker privileges; intended for local personal use only

**Windows** (any working directory):

```bat
docker\desktop\start.cmd
```

Stop:

```bat
docker\desktop\stop.cmd
```

**Linux**:

```sh
sh docker/desktop/start.sh
```

Stop:

```sh
sh docker/desktop/stop.sh
```

Open `http://127.0.0.1:16788` (frontend and backend on the same port; FastAPI serves the static UI).

Notes:

- Data still lives in repo-root `data/` (shared with native start). On Linux the container runs as the current uid so `data/` does not become root-owned
- A manual lab URL `http://127.0.0.1:<port>` is rewritten inside the container to `host.docker.internal` (Linux injects `host-gateway`)
- Default port **16788** (offset from native `start.cmd` / `start.sh` 16780 so both can run). Override with `VULNHUNTER_PORT`
- App image builds on amd64 / arm64. Rootless Docker tries `$XDG_RUNTIME_DIR/docker.sock`; under SELinux Enforcing the start script adds `:z` on the data volume and disables container MCS labels
- macOS Docker Desktop can try `sh docker/desktop/start.sh`; it was not a first-milestone acceptance platform

## One-click start and stop

**Windows** (double-click at repo root, or CMD):

```bat
start.cmd
```

**Linux / macOS**:

```sh
sh start.sh
```

If you `chmod +x start.sh`, `./start.sh` also works. The script is POSIX `sh`; macOS `/bin/sh` is enough — no bash required.

- Starts backend `http://127.0.0.1:16780` and frontend `http://127.0.0.1:15173` (avoids common 8000 / Vite 5173); binds localhost by default
- LAN: `start.cmd --lan` or `start.cmd --host 0.0.0.0` (Unix: `sh start.sh --lan`), or `VULNHUNTER_HOST=0.0.0.0`
- Change ports with `start.cmd --backend-port 19000 --frontend-port 19001` (Unix: `sh start.sh --backend-port 19000 --frontend-port 19001`) or `VULNHUNTER_PORT` / `VULNHUNTER_FRONTEND_PORT`
- First run creates `backend/.venv`, installs Python deps, and `npm install` in `frontend`
- No hot reload by default; use `start.cmd --reload` or `sh start.sh --reload` when editing the backend
- Stops the previous instance from this repo first. If the target port is still held by **another program**, the script errors out and does not pick a new port
- Checks that chosen ports are listening within about 45s; timeout tells you to read logs — not always a hard failure
- Unix writes PIDs to `data/run/backend.pid` and `data/run/frontend.pid`; this run’s ports go to `data/run/ports.env` for `stop`

Stop:

```bat
stop.cmd
```

```sh
sh stop.sh
```

Windows kills by window title and frees last-recorded ports (plus defaults 16780 / 15173). Linux/macOS uses PID files + ports.

Logs: `data/logs/backend-YYYY-MM-DD.log`, `data/logs/frontend-YYYY-MM-DD.log` (one file per local day; rolls over at midnight). If ports never come up, start with today's files.

After a successful start, open **http://127.0.0.1:15173**. API docs: http://127.0.0.1:16780/docs.

### First open: Settings

Without a model you cannot create and run audit projects. If a global access token is set (`.env` `VULNHUNTER_ACCESS_TOKEN` or Settings), enter it first. Then open Settings:

1. Choose **global wire API**: OpenAI **Chat Completions** (default), OpenAI **Responses**, or **Anthropic Messages**. Each provider endpoint can override; empty follows global
2. Fill **API Base URL**, **API Key**, and default **model** (you can fetch the model list first, then save)
3. Optional: GitHub PAT (private repos, higher GHSA / Issues quota)
4. For Verifier: **FOFA Key** (or `VULNHUNTER_FOFA_KEY`)
5. Optional: outbound HTTP proxy and Chat proxy; empty means direct (no default `10808`)

Save, then create an audit project.

## Manual start

Use this if the one-click scripts fail, or you want frontend and backend separate. Finish steps 2 and 3 in “Build steps before first start”; for local verify, also build the sandbox images in steps 4 and 5.

### Backend

Windows:

```bat
cd backend
.venv\Scripts\activate
uvicorn app.main:app --reload --reload-dir app --timeout-graceful-shutdown 2 --host 127.0.0.1 --port 16780
```

Linux / macOS:

```sh
cd backend
. .venv/bin/activate
uvicorn app.main:app --reload --reload-dir app --timeout-graceful-shutdown 2 --host 127.0.0.1 --port 16780
```

Keep `--timeout-graceful-shutdown 2`: SSE long-polls otherwise stall hot reload on “Waiting for connections to close”.

### Frontend

```bat
cd frontend
npm run dev
```

The dev server proxies `/api` to `127.0.0.1:16780` (override with `VULNHUNTER_PORT`); keep the backend running. To change the frontend port, set `VULNHUNTER_FRONTEND_PORT` or `npm run dev -- --port 15173 --strictPort`.

## Optional by feature

Install only what you use. For UI + static review, the [Requirements](#requirements) “required” set is enough.

| Feature | Needs | If missing |
| --- | --- | --- |
| Import a public GitHub repo | Git | Import fails |
| Private repos / higher GHSA and Issues quota | **GitHub PAT** on Settings | Public clone still works; GitHub API hits anonymous limits sooner |
| Lab dynamic verify (Reviewer builds a Docker lab and runs `poc.py`) | **Docker** running (Desktop or Linux engine) and `docker version` works | Env phase skips; cannot confirm with dynamic evidence |
| Local verify (L1/L2: harness in sandbox) | Docker + `vulnhunter/sandbox:latest` from [step 4](#4-local-verify-sandbox-image-l1l2-harness-required-for-local-verification) | Falls back to static; not treated as a false positive |
| Local L3 integration verify (loopback service + `poc.py`, then upgrade evidence to dynamic) | Docker + `vulnhunter/integration-sandbox:latest` from [step 5](#5-integration-sandbox-image-l3-required-for-l3-integration-verify) | Cannot auto-run L3; can set `local_service_url` in `env/env.json` for host fallback |
| Fast scan (Semgrep → sink backtrace) | Host `semgrep` **or** Docker + `returntocorp/semgrep:latest` (`scripts\pull-semgrep.cmd` / `sh scripts/pull-semgrep.sh`) | That path cannot run |
| Code Intelligence (call-graph queries) | Enable at project create; host `codegraph`, or Settings path / `VULNHUNTER_CODEGRAPH_PATH` | Off: no graph, no disk, mining waits only on Recon. On: build stage installs to `data/tools/codegraph`; still failing degrades to Read/Grep and does not block mining |
| Verifier (FOFA Internet retest) | **FOFA Key** on Settings (or `VULNHUNTER_FOFA_KEY`) | Verify phase skips |
| Outbound proxy (WebSearch / GitHub / FOFA) | HTTP proxy on Settings, or `VULNHUNTER_HTTP_PROXY` in `.env` | Direct; if the proxy is down it automatically falls back to direct |
| Chat proxy | Chat proxy on Settings, or `VULNHUNTER_CHAT_PROXY` | Chat is direct by default, separate from tool proxy |
| Global access token | `.env` `VULNHUNTER_ACCESS_TOKEN`, or Settings | Unset: no entry gate |
| Debug MCP when rewriting Java lab PoCs | **JDK 17+**, **Maven 3.6+**, and `mvn package` | HTTP PoC + `docker exec` still work; cannot attach a Java debugger |
| Node lab debug MCP | Node installed; `npm install` in `tools/mcp/node-debug` | Same, ordinary dynamic |
| Python lab debug MCP | `mcp` and `debugpy` in the backend venv | Same |

Docker-backed features also need:

- Docker **actually running** (Desktop tray on Windows/Mac; docker service on Linux), not merely installed. Windows usually uses the WSL2 backend.
- The current user can run `docker ps` without sudo / admin prompts.
- Disk space for harness / integration sandbox images, the Semgrep image, and per-project lab images.

Build steps: [Build steps before first start](#build-steps-before-first-start) (sandbox images, Debug MCP, Semgrep).

## Common startup issues

| Symptom | What to do |
| --- | --- |
| `python` is not recognized / Microsoft Store opens | Install 64-bit Python 3.12, add to PATH; disable the `python.exe` App Execution Alias |
| Unix: `need Python 3.11+` | Install 3.11/3.12; Debian/Ubuntu: `sudo apt install python3 python3-venv python3-pip`; macOS: `brew install python@3.12` |
| `creating backend venv` fails | Confirm `python -m venv --help` / `python3 -m venv --help`; antivirus should not lock `backend/.venv` |
| `npm` fails or is extremely slow | Switch to Node 20 LTS; use npmmirror; delete a half-installed `frontend/node_modules` and retry |
| `error: backend/frontend port … is still in use` | Another program holds the port. Change ports: `start.cmd --backend-port N --frontend-port N` |
| `warn: ports not ready` | Read `data/logs/`; often a stale process — run `stop.cmd` / `sh stop.sh` first |
| UI loads but every API fails | Backend is down, or frontend port vs Vite proxy `VULNHUNTER_PORT` mismatch |
| GitHub import fails | `git` on PATH; PAT for private repos; HTTP proxy on Settings for corporate nets. On `Filename too long`, update and retry (`core.longpaths` is already set on clone) |
| Lab / containers page says docker unavailable | Start Docker Desktop or the docker service, wait until the engine is ready, then `docker ps` |
| Docker-on-Linux: `permission denied` on docker.sock | Add the user to `docker` and re-login: `sudo usermod -aG docker $USER`; do not sudo `start.sh` |
| Docker-on-Linux: SELinux denies the mount | Use `sh docker/desktop/start.sh` (Enforcing adds `:z` and `label:disable`) |
| Local verify: harness image missing | Run `scripts\build-sandbox.cmd` or `sh scripts/build-sandbox.sh` |
| L3: integration image missing | Run `scripts\build-integration-sandbox.cmd` or `sh scripts/build-integration-sandbox.sh`; or set `local_service_url` in `env/env.json` |
| Fast scan: semgrep not found | Install host semgrep, or start Docker and run `scripts\pull-semgrep.cmd` / `sh scripts/pull-semgrep.sh` |
| Java MCP does nothing | Confirm `mvn package` produced the jar; `java -version` is 17+ |
| `/bin/sh^M: bad interpreter` or `\r: command not found` | Scripts were saved as CRLF. The repo sets `*.sh text eol=lf`; run `git add --renormalize '*.sh'` and check out again, or `sed -i 's/\r$//' start.sh stop.sh scripts/*.sh` |

## Unit tests

Windows:

```bat
cd backend
.venv\Scripts\activate
pip install -r requirements.txt
pytest
```

Or `scripts\run-tests.cmd`.

Linux / macOS:

```sh
cd backend
. .venv/bin/activate
pip install -r requirements.txt
pytest
```

Or `sh scripts/run-tests.sh`. Coverage includes vuln types, watchdog, context compression / 429 detection, sandboxes, ingest indexing, tool ACL/gates, APIs, env port remapping, and more.

## Capability overview

Phase details, tool ACL, fault tolerance, and scoring: [`docs/DESIGN.md`](docs/DESIGN.md) (Chinese).

| Area | Content |
| --- | --- |
| Audit scope | Any web project (language-agnostic) |
| Project and mining config | At create time pick bounty (default) / full / custom. Enable mining paths: heuristic (on by default; lite mode only weight-100 files), fast scan (off), historical-vuln bypass (off), unconstrained (off); at least one. Each project can pick a model or inherit Settings; optional token cap; optional pasted/uploaded Worker hint. Discover-repos can take a user prompt and search GitHub by that intent first, or fall back to public GHSA, skipping demos/learning projects; candidates can be removed one-by-one or all at once. Search waits 600s by default, plus 60s for each repo beyond 5. GitHub projects sync upstream on resume from pause (list/detail show the fetched commit on success; on failure the current snapshot is kept); zip projects are unchanged |
| Mining paths | Wait for **Recon done**; if Code Intelligence is enabled, also wait for its first build (failure degrades and continues). **Heuristic**: mine by file weight; weight 100 is a user-controlled entry (HTTP, WebSocket / RPC / MQ / callbacks, etc.); lower weights backtrace, control-plane, or thin-scan by role. **Fast scan**: Semgrep → code filter → agent triage → sink backtrace; SAST sinks, while auth / IDOR / business logic still rely on heuristic. **Historical-vuln bypass**: each round tries to bypass a patch or confirm an unpatched issue still works. **Unconstrained**: one Worker, only code map + auth injected; always bounty gates; path ends after Reviewer marks a frontend finding with RCE effect. The project is `completed` only when every enabled path has finished |
| Code Intelligence | Optional at create, off by default. When on, parallel with Recon. CodeGraph indexes `src/` only; if missing, build installs to `data/tools/codegraph`. Failure degrades to Read/Grep. Source changes mark stale; the user rebuilds. Turning it off deletes that project’s `src/.codegraph/`. Worker / Reviewer get short call-graph queries; tests can open the graph UI |
| Audit modes | Bounty keeps exploitable high-impact types (stored XSS, 1-click CSRF, hardcoded secrets with server-side impact, etc.; ordinary CSRF / frontend AES obfuscation / publicly shipped keys are dropped). Full keeps lower-impact items (CORS, reflected XSS, missing rate limits, etc.). Custom has no bounty hard gates — prompts only. Harmless/restricted file ops (read-only specific extensions or public non-sensitive dirs, harmless uploads) and unguessable object keys (UUIDs / filenames; share links, email, preview URLs do not count as obtainable) are dropped in mining and review. Settings manage named custom prompts; selecting one snapshots the text onto the project |
| Dynamic verify | Off by default at create (static review only). **Lab dynamic**: Reviewer builds a Docker lab and runs HTTP PoC (`poc.py -u`). **Local verify**: L1/L2 harness sandbox (`evidence_level=harness`; Python/PHP/JS/Ruby/Go/Java/Bash/C; Rust/C++ stay static) and L3 integration (loopback + `poc.py`, then `evidence_level=dynamic`). When a lab is available, `ConfirmVuln` re-runs the on-disk `poc.py`; non-zero exit rejects confirm. PoCs are owned by Reviewer; debug MCP only if missing/failing and rewrite is needed. HTTP-facing `poc.py` must support `-u/--url`, `--proxy` (empty = direct), and RCE `-c/--cmd`. `harness.py` and `poc.py` have separate jobs; stdout is English by default, `--zh` for Chinese |
| Internet verify | Optional Verifier, off by default, toggle in project settings. After a frontend confirm, FOFA searches same-fingerprint targets; understand the exploit from the report and PoC, prefer original `poc.py`; if there is no portable HTTP PoC, build a payload from the report (do not auto-skip); if the original fails, adapt on the same chain (default 10 per batch, stop after 3 successes, max 5 rounds / 50 hosts). Wall-clock timeout marks that item fail with no new round. Fingerprints are collected once per project. Destructive ops need human confirm |
| Attack chains | Optional, off by default; after mining is done and the review queue is empty, try multi-step exploits from confirmed findings |
| Findings dedupe | On project detail, selected “this project” vulns are checked against historical vulns and current `src/`: already public or already fixed become false positives; logs live under phase log “findings dedupe” |
| Fault tolerance and scheduling | Per-endpoint cooldown and failover, timeout Conclude, loop-break new round, phase retry up to 2 extra times. Global LLM thread cap = sum of enabled endpoint concurrencies (default 6 each); new sessions are load-balanced; the same turn prefers the same model (prefix cache) and sticks to the same endpoint when possible; overflow queues FIFO. Settings can disable an endpoint. Pause releases the slot; resume re-queues. Same endpoint defaults to ≥2s between requests (can disable); queue time is not counted in timeouts. 429 / quota exhaustion cools only that endpoint |
| Historical vulns | GHSA / GitHub Issues crawler writes files first (no WebSearch in that stage), then WebSearch fills gaps; collect only, do not read source. Public issues are `patched`; unfixed ones come from open Issues (`unpatched`) |
| Settings and ops | Manually purge SSE live logs older than X days; CLI tool dir (default `tools/cli`) for Reviewer `SearchTools` then Shell; configurable CodeGraph path |
| Progress reset | Heuristic Worker progress can be reset (findings and recon docs kept) to re-audit with another model; fast-scan sink queue and historical-bypass progress are not reset |

## Repository layout

- `backend/app` — FastAPI, agent loop, tools, scheduler
- `frontend` — React + Tailwind UI
- `templates` — document templates
- `tools/mcp` — Java / Node / Python debug MCP
- `tools/cli` — user-placed CLI tools (one directory per tool; Reviewer SearchTools)
- `docker/sandbox` — local-verify harness sandbox image (L1/L2)
- `docker/integration-sandbox` — L3 integration sandbox image
- `docker/desktop` — Docker-distribution one-click start (compose / Dockerfile / Windows `start.cmd` / Linux `start.sh`)
- `scripts` — start/stop, tests, sandbox builds, Semgrep image pull
- `data/projects/{id}` — per-project workspace (runtime; do not commit)
- `docs/DESIGN.md` — architecture and design (Chinese)

## Design document

[`docs/DESIGN.md`](docs/DESIGN.md) (Chinese) covers features and UI, white-box agent design, per-phase tools and orchestration, fault recovery, novelty (weighted queues, historical-vuln bypass, multi-layer verify, etc.), mining results and known gaps, and scoring rules.

## License

This project is licensed under the [Apache License 2.0](LICENSE).

Copyright 2026 [1diot9](https://github.com/1diot9)

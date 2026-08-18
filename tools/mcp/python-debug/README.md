# Python Debug MCP

[English](./README_EN.md)

基于 [debugpy](https://github.com/microsoft/debugpy) 和 [DAP（Debug Adapter Protocol）](https://microsoft.github.io/debug-adapter-protocol/) 的 MCP 调试服务器，为 AI Agent（Claude Code 等）提供 Python 远程调试能力。

提供 18 个 MCP 工具，支持启动、附加、交互式调试 Python 程序 —— 设置断点、单步执行、查看变量、表达式求值等完整调试功能。

## 功能特性

- **Launch 模式** — 启动任意 Python 脚本并暂停在入口处，开箱即用
- **Attach 模式** — 连接到已运行的远程 Python 进程（通过 `debugpy --listen`），支持远程调试
- **断点管理** — 行断点、条件断点、命中次数断点、日志断点（logpoint）
- **异常断点** — 捕获所有异常或仅捕获未处理异常
- **执行控制** — 继续运行、单步跳过（step over）、单步进入（step into）、单步跳出（step out）、暂停
- **状态检查** — 调用栈、局部变量、变量展开、表达式求值
- **事件系统** — 完整的事件历史记录，支持增量轮询

## 环境要求

- Python >= 3.10
- [debugpy](https://pypi.org/project/debugpy/) >= 1.8.0
- [mcp](https://pypi.org/project/mcp/) >= 1.0.0

## 安装

```bash
# 克隆仓库
git clone <repo-url>
cd python-debug-mcp

# 创建虚拟环境并安装依赖
uv venv
uv pip install -e ".[dev]"
```

## 快速开始

### 配置 Claude Code

在项目根目录的 `.mcp.json`（项目级）或 `~/.claude.json`（全局）中添加：

```json
{
  "mcpServers": {
    "python-debug-mcp": {
      "command": "python",
      "args": ["main.py"],
      "cwd": "/path/to/python-debug-mcp"
    }
  }
}
```

### Launch 模式（本地调试）

启动脚本并暂停在第一行，随后设置断点、单步调试：

```
debug_launch(program="/path/to/script.py", stop_on_entry=True)
debug_set_breakpoint(file="/path/to/script.py", line=42)
debug_continue()           # 运行到断点处
debug_get_locals()         # 查看局部变量
debug_evaluate_expression(expression="len(items)")
debug_step(kind="over")    # 单步跳过
debug_detach()             # 结束调试
```

### Attach 模式（远程调试）

首先，在目标机器上用 debugpy 启动待调试进程：

```bash
python -m debugpy --listen 127.0.0.1:5678 --wait-for-client your_app.py
```

或者在代码中嵌入 debugpy：

```python
import debugpy
debugpy.listen(("127.0.0.1", 5678))
debugpy.wait_for_client()  # 阻塞直到调试器连接
```

然后通过 MCP 工具附加调试：

```
debug_attach(host="127.0.0.1", port=5678)
debug_set_breakpoint(file="/path/to/your_app.py", line=100)
debug_continue()           # 释放程序暂停，运行到断点处
debug_get_stack()          # 查看调用栈
debug_get_locals()         # 查看局部变量
debug_detach()             # 断开连接
```

> **重要提示：** Attach 模式下，断点必须在 `debug_continue()` **之前**设置。第一次调用 `debug_continue()` 会释放 `--wait-for-client` 的暂停，程序开始执行。如果未提前设断点，程序可能直接运行结束。

## 完整调试流程示例

下面展示一个完整的调试会话流程，以内置的示例应用为例：

```
# 1. 启动程序并暂停在入口
debug_launch(program="sample_debug_target/app.py", stop_on_entry=True)

# 2. 查看当前暂停位置
debug_get_last_stop_event()
# → {"reason": "entry", "file": ".../app.py", "line": 2, "function": "<module>"}

# 3. 设置断点
debug_set_breakpoint(file="sample_debug_target/app.py", line=102)
# → {"id": "bp-1", "line": 102, "verified": true}

# 4. 运行到断点
debug_continue()
# → {"reason": "breakpoint", "file": ".../app.py", "line": 102, "function": "process_task"}

# 5. 查看调用栈
debug_get_stack()
# → [{"name": "process_task", "line": 102}, {"name": "run_pipeline", "line": 159}, ...]

# 6. 查看局部变量
debug_get_locals()
# → {"scopes": {"Locals": [{"name": "task", "value": "Task(id=8, ...)", "type": "Task"}]}}

# 7. 展开复杂变量（用 variablesReference）
debug_inspect_variable(variables_reference=10)
# → [{"name": "name", "value": "'sort_8'"}, {"name": "priority", "value": "5"}, ...]

# 8. 表达式求值
debug_evaluate_expression(expression="task.name.upper()")
# → {"result": "'SORT_8'", "type": "str"}

# 9. 单步执行
debug_step(kind="over")     # 单步跳过 → 移到下一行
debug_step(kind="into")     # 单步进入 → 进入函数内部
debug_step(kind="out")      # 单步跳出 → 返回调用方

# 10. 继续执行到下一个断点
debug_continue()

# 11. 查看事件历史
debug_get_events(limit=5)

# 12. 结束调试
debug_detach()
```

## MCP 工具参考

### 会话管理

| 工具 | 说明 | 参数 |
|------|------|------|
| `debug_launch` | 启动 Python 脚本并进入调试 | `program`, `args`, `cwd`, `python`, `stop_on_entry` |
| `debug_attach` | 附加到远程 debugpy 监听端口 | `host`, `port` |
| `debug_detach` | 断开调试会话并清理资源 | — |
| `debug_status` | 返回当前会话状态 | — |

### 断点

| 工具 | 说明 | 参数 |
|------|------|------|
| `debug_set_breakpoint` | 设置断点 | `file`, `line`, `condition`, `hit_condition`, `log_message` |
| `debug_remove_breakpoint` | 删除断点 | `breakpoint_id`（如 `"bp-1"`） |
| `debug_list_breakpoints` | 列出所有断点 | — |
| `debug_set_exception_breakpoints` | 设置异常断点 | `filters`（`"raised"` / `"uncaught"`） |
| `debug_clear_exception_breakpoints` | 清除所有异常断点 | — |

### 执行控制

| 工具 | 说明 | 参数 |
|------|------|------|
| `debug_continue` | 继续运行直到断点或退出 | `thread_id`, `wait_timeout` |
| `debug_step` | 单步执行 | `kind`（`"over"` / `"into"` / `"out"`）, `thread_id`, `wait_timeout` |
| `debug_pause` | 暂停运行中的程序 | `thread_id` |

### 状态检查

| 工具 | 说明 | 参数 |
|------|------|------|
| `debug_list_threads` | 列出所有线程 | — |
| `debug_get_stack` | 获取调用栈 | `thread_id`, `max_frames` |
| `debug_get_locals` | 获取局部变量 | `frame_index`, `thread_id` |
| `debug_inspect_variable` | 展开复杂变量（对象/列表/字典） | `variables_reference`, `max_children` |
| `debug_evaluate_expression` | 在当前帧上下文中求值表达式 | `expression`, `frame_index`, `thread_id` |

### 事件

| 工具 | 说明 | 参数 |
|------|------|------|
| `debug_get_events` | 获取调试事件历史 | `limit`, `since_id`（增量轮询） |
| `debug_get_last_stop_event` | 获取最近一次停止事件（含文件/行号/函数名） | — |

## 断点类型详解

### 行断点

最基本的断点类型，程序执行到指定行时暂停：

```
debug_set_breakpoint(file="/path/to/app.py", line=42)
```

### 条件断点

仅在条件表达式为 `True` 时触发：

```
debug_set_breakpoint(file="/path/to/app.py", line=14, condition="i == 5")
debug_set_breakpoint(file="/path/to/app.py", line=20, condition="len(items) > 100")
```

### 命中次数断点

根据命中次数触发，适合循环调试：

```
debug_set_breakpoint(file="/path/to/app.py", line=14, hit_condition="> 10")
```

### 日志断点（Logpoint）

不暂停程序，仅输出日志。`{}` 中的内容会被作为表达式求值：

```
debug_set_breakpoint(file="/path/to/app.py", line=14, log_message="item={item}, count={len(items)}")
```

### 异常断点

捕获异常时暂停，无需指定文件和行号：

```
debug_set_exception_breakpoints(filters=["raised"])           # 所有异常
debug_set_exception_breakpoints(filters=["uncaught"])          # 仅未处理异常
debug_set_exception_breakpoints(filters=["raised", "uncaught"]) # 两者都捕获
```

## 架构

```
┌──────────────┐    stdio/MCP     ┌──────────────┐
│  AI Agent    │ ◄──────────────► │  MCP Server  │
│ (Claude Code)│                  │  (server.py) │
└──────────────┘                  └──────┬───────┘
                                         │
                                  ┌──────▼───────┐
                                  │DebugSession  │
                                  │  Manager     │
                                  │(debug_session│
                                  │     .py)     │
                                  └──────┬───────┘
                                         │
                                  ┌──────▼───────┐
                          ┌───────│  DapClient   │───────┐
                          │       │(dap_client.py)│       │
                          │       └──────────────┘       │
                     subprocess                       TCP
                      (stdio)                      (socket)
                          │                              │
                   ┌──────▼───────┐             ┌───────▼──────┐
                   │   debugpy    │             │    debugpy    │
                   │   adapter    │             │   --listen    │
                   │ (Launch 模式) │             │ (Attach 模式) │
                   └──────┬───────┘             └──────────────┘
                          │
                   ┌──────▼───────┐
                   │    目标       │
                   │  Python 进程  │
                   └──────────────┘
```

### 文件说明

| 文件 | 说明 |
|------|------|
| `main.py` | 入口文件，以 stdio 传输启动 MCP 服务器 |
| `server.py` | 使用 FastMCP 定义 18 个 MCP 工具 |
| `debug_session.py` | 高层调试会话管理器（断点管理、状态机、事件系统） |
| `dap_client.py` | 底层 DAP 协议客户端（支持子进程 stdio 和 TCP 两种通信方式） |
| `sample_debug_target/app.py` | 示例应用 —— 任务处理流水线，用于测试调试功能 |
| `tests/test_integration.py` | 集成测试（26 个用例） |

### Launch vs Attach 实现差异

| | Launch 模式 | Attach 模式 |
|------|------|------|
| **连接方式** | 启动 `debugpy.adapter` 子进程，通过 stdio 通信 | 直接 TCP 连接到 debugpy 监听端口 |
| **程序启动** | 由 adapter 启动目标进程 | 目标进程已在运行 |
| **初始状态** | `stop_on_entry=True` 时暂停在第一行 | 暂停在 `--wait-for-client` 处，等待首次 `continue` |
| **configurationDone** | 在 launch 流程中立即发送 | 延迟到首次 `debug_continue()` 调用时发送 |

## 示例应用

`sample_debug_target/app.py` 是一个任务处理流水线，包含多种可调试的代码结构：

- **函数调用链** — `main()` → `run_pipeline()` → `process_task()` → `fibonacci()` / `factorial()` / `is_prime()`
- **循环处理** — 遍历任务队列逐个处理
- **类与对象** — `Task`、`TaskQueue` 数据模型
- **异常处理** — 模拟任务失败的 `ValueError`

```bash
# 直接运行
python sample_debug_target/app.py --tasks 10

# 通过 MCP 调试
debug_launch(program="sample_debug_target/app.py", args=["--tasks", "10"], stop_on_entry=True)
```

## 运行测试

```bash
# 安装开发依赖
uv pip install -e ".[dev]"

# 运行全部集成测试
pytest tests/test_integration.py -v
```

测试覆盖范围：

- **生命周期** — 启动、附加、断开
- **断点操作** — 增删查、条件断点、多断点
- **执行控制** — 继续、单步跳过/进入/跳出、运行到结束
- **状态检查** — 线程列表、调用栈、局部变量、表达式求值、变量展开
- **事件系统** — 事件记录、增量轮询
- **错误处理** — 非法状态转换、无效参数

## License

MIT

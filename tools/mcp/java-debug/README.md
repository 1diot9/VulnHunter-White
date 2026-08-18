# java-debug-mcp

`java-debug-mcp` 是一个基于 `JDI` 和官方 Java MCP SDK 的 MCP 服务，用于让 AI 连接 Java 远程调试端口，执行断点、步进和变量读取操作，以便对已知漏洞链路做动态验证。

当前版本是第一版可用骨架，重点是：
- 单目标、单会话调试
- 基于 stdio 的 MCP 服务
- 基于官方 Java MCP SDK
- attach 到 JDWP 远程 JVM
- 断点、步进、线程/堆栈/局部变量/对象查看
- 异常断点

详细设计见 [docs/java-debug-mcp-design.md](docs/java-debug-mcp-design.md)。

## 环境要求
- JDK 17 或更高版本
- Maven 3.6 或更高版本

## 构建
```powershell
mvn test
```

运行服务：
```powershell
mvn exec:java
```

服务通过标准输入输出收发 MCP JSON-RPC 消息。

打包可供 Claude Code 启动的 fat jar：
```powershell
mvn package
```

打包后会生成：
- `target\java-debug-mcp-0.1.0-SNAPSHOT-all.jar`

## 当前已实现的 MCP 工具
### 会话控制
- `debug_attach`
- `debug_detach`
- `debug_status`

### 断点控制
- `debug_set_breakpoint`
- `debug_set_method_breakpoint`
- `debug_set_breakpoints_batch`
- `debug_remove_breakpoint`
- `debug_list_breakpoints`

### 执行控制
- `debug_resume`
- `debug_step`

### 调试信息读取
- `debug_list_threads`
- `debug_get_stack`
- `debug_get_locals`
- `debug_evaluate_expression`
- `debug_inspect_object`
- `debug_get_events`
- `debug_get_last_stop_event`

### 异常断点
- `debug_enable_exception_breakpoint`
- `debug_clear_exception_breakpoint`

## Claude Code 接入
推荐通过项目根目录的 `.mcp.json` 接入。

### 1. 先打包
每次修改代码后，先重新打包：

```powershell
mvn package
```

### 2. 配置 Claude Code
项目根目录可使用如下配置：

```json
{
  "mcpServers": {
    "java-debug-mcp": {
      "command": "cmd",
      "args": [
        "/c",
        "D:\\AI\\MCP_Tools\\Java-debug-mcp\\scripts\\run-mcp.bat"
      ],
      "env": {
        "JAVA_TOOL_OPTIONS": "-Dfile.encoding=UTF-8"
      }
    }
  }
}
```

仓库里也提供了示例文件：
- [.mcp.json.example](.mcp.json.example)

### 3. 启动脚本
Claude Code 实际调用的是：
- [scripts/run-mcp.bat](scripts/run-mcp.bat)

该脚本会启动：
- `target\java-debug-mcp-0.1.0-SNAPSHOT-all.jar`

### 4. 常见错误
#### `cmd` 参数写错
必须写：

```json
"/c"
```

不能写成：

```json
"\\c"
```

#### fat jar 没重新打包
如果代码更新后没有执行 `mvn package`，Claude Code 启动的仍然是旧版本 jar。

#### 启动脚本路径不对
确保 `.mcp.json` 里的路径与你本机实际路径一致。

#### 标准输出被污染
当前版本已使用官方 Java MCP SDK，并增加了静默 `SLF4J` provider，启动时不应再输出额外日志。如果你自行修改启动脚本，不要在标准输出打印任何调试文本。

### 5. 手工验证
如果要先验证服务是否能启动，可以手工执行：

```powershell
cmd /c scripts\run-mcp.bat
```

正常现象：
- 命令不会立刻退出
- 控制台不会输出额外文本

这表示服务正在等待 MCP 客户端通过 stdio 发送初始化请求。

## 工具行为说明
### `debug_attach`
连接一个启用 JDWP 的远程 JVM。

输入字段：
- `host`
- `port`
- `timeoutMs`

### `debug_set_breakpoint`
设置断点。

支持方式：
- 传 `line` 时，按 `className + line` 设置行断点
- 传 `methodName` 时，在目标方法首个可执行位置下断
- 同时传 `line + methodName` 时，优先绑定到对应方法位置
- 可选传入 `condition`、`hitCount`、`logMessage`，分别用于条件断点、命中次数断点和 logpoint

若目标类尚未加载，则断点保持 pending，等 `ClassPrepareEvent` 后自动绑定。

### `debug_set_method_breakpoint`
设置方法入口/出口断点。

关键参数：
- `className`
- `methodName`，可选；为空时匹配该类全部方法
- `kind`，支持 `entry`、`exit`、`both`
- `suspendPolicy`
- `condition`
- `hitCount`

适合需要观察方法进入、返回或成对跟踪调用生命周期的场景。

### `debug_set_breakpoints_batch`
批量设置断点，一次提交多个断点定义。

输入格式：
- `breakpoints`：数组
- 每个元素支持 `className`、`line`、`methodName`、`suspendPolicy`

返回结果会按元素逐项给出 `status`，便于批量下发后定位失败项。

### `debug_resume`
恢复执行，并等待下一次停止事件返回，而不是立即返回成功。

### `debug_step`
对当前暂停线程或指定线程执行单步。

`kind` 支持：
- `into`
- `over`
- `out`

### `debug_get_stack`
读取暂停线程的调用栈。

### `debug_get_locals`
读取暂停帧的局部变量。若目标类缺少本地变量表，则返回参数的合成别名：
- `arg0`, `arg1`, ...
- `p0`, `p1`, ...
- `param0`, `param1`, ...

此时结果里会带 `debugInfoPresent=false`，并通过 `note` 说明当前是参数回退模式。

### `debug_evaluate_expression`
在暂停帧中执行 Java 表达式。

当前已支持：
- 字面量、字段访问、数组访问、条件表达式
- 算术/比较/逻辑运算
- 实例方法和静态方法调用
- `new` 创建对象
- `instanceof`
- 无本地变量表时通过 `argN/pN/paramN` 访问参数

并发语义：
- 同一个暂停 `threadId` 上的表达式会串行执行
- 不同暂停 `threadId` 上的表达式可以并发执行
- 为避免默认 `activeThread` 带来的歧义，建议显式传入 `threadId`

### `debug_inspect_object`
展开对象字段或数组元素。复杂对象不会递归自动展开，而是通过 `objectHandleId` 分步查看。

### `debug_get_events`
读取最近的调试事件，例如断点命中、单步停止、异常停止。

关键参数：
- `limit`：返回的最大事件数，默认 `20`
- `sinceId`：按事件 ID 增量拉取，适合轮询场景

### `debug_get_last_stop_event`
读取最近一次暂停事件，返回其中的线程和代码位置上下文，适合在 `debug_resume` 或 `debug_step` 后快速确认当前停在哪里。

## 目标 JVM 启动示例
如果你要调试本地 Java 进程，可以在启动目标程序时打开 JDWP 端口：

```powershell
java -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:5005 -jar app.jar
```

说明：
- `server=y` 表示目标 JVM 作为调试服务器监听端口
- `suspend=n` 表示启动时不等待调试器连接
- `address=*:5005` 表示监听 `5005` 端口

然后 MCP 客户端调用：
- `debug_attach(host="127.0.0.1", port=5005, timeoutMs=5000)`

## 适用场景
这个项目主要面向以下场景：
- 已知漏洞传播链，希望动态确认 source 到 sink 的真实运行路径
- 希望让 AI 在命中断点后读取调用栈和参数值
- 希望自动捕获异常传播位置，辅助判断漏洞链是否中断

## 当前限制
- 只支持一个活动调试会话
- 只支持 socket attach，不支持 launch/listen 模式
- 不支持修改变量值
- 表达式求值依赖目标类已加载；未加载类不能直接参与求值
- 若目标类既没有本地变量表，也没有可推断的字段/类型信息，则无法使用原始参数名，只能使用 `argN/pN/paramN`
- 还没有补真实 JDWP 集成测试样例

## 代码结构
- [src/main/java/com/example/javadebugmcp/Main.java](src/main/java/com/example/javadebugmcp/Main.java)：服务入口，`Main#main`
- [src/main/java/com/example/javadebugmcp/mcp/OfficialMcpServerBootstrap.java](src/main/java/com/example/javadebugmcp/mcp/OfficialMcpServerBootstrap.java)：官方 Java MCP SDK 启动与工具注册，`OfficialMcpServerBootstrap#run`、`OfficialMcpServerBootstrap#toolSpecifications`
- [src/main/java/com/example/javadebugmcp/debug/DebugSessionManager.java](src/main/java/com/example/javadebugmcp/debug/DebugSessionManager.java)：调试会话和事件循环，`DebugSessionManager#attach`、`DebugSession#pumpEvents`、`DebugSession#step`
- [src/main/java/com/example/javadebugmcp/debug/ValueFormatter.java](src/main/java/com/example/javadebugmcp/debug/ValueFormatter.java)：调试值格式化，`ValueFormatter#formatValue`
- [scripts/run-mcp.bat](scripts/run-mcp.bat)：Claude Code 的稳定启动入口

## 下一步建议
- 增加本地 JDWP 测试样例和集成测试
- 为 MCP 客户端补充请求/响应示例
- 统一错误码映射，使返回结果更适合 AI 自动决策

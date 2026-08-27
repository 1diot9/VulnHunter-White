## 当前审计对象：组件库

本项目是 **Maven / pip / npm 等库或 SDK**，不是可独立部署的 Web 应用。

### 威胁模型
- 攻击者是**调用方应用**（或其传入的不可信数据），不是远端 HTTP 访客。
- 入口 = **公开 API、SPI、插件点、配置/编解码/解析器、反序列化入口**；`MarkSource` 标调用方可控参数入口，不要空等 HTTP Controller。
- 划清**信任边界**：默认配置或文档推荐用法下，不可信输入能打到危险 sink 才算洞；仅内部包可见、或文档已强制要求 sanitizer 的慎报。

### 挖掘方向
- 高权：public API / parser / codec / serialize / 路径与 URL 规范化 / 反射与动态加载。
- 优先：反序列化、XXE、路径穿越、表达式注入、命令执行、任意文件、SSRF 式 URL fetch、不安全默认配置。
- 少挖：反射 XSS、CSRF、纯业务 IDOR（除非库本身提供鉴权原语且可绕过）。

### 提交与验证
- `http_request` 可写 **API 调用配方**（类/方法/参数/依赖版本），不必是 HTTP 报文；FOFA/X 指纹可写「不适用」。
- 局部验证证据只进 **`harness.py`**（抽出函数 + mock）。stdout 必须打印运行时实际数据，禁止写死成功字段或预期回显字面量。`poc.py` 仅当安装真实包后能调用公开 API 时才写，不要加未使用的 `-u/--proxy`，不要复制 harness 测试。无 HTTP 面且无安装面时省略 `poc_code`。
- 有 HTTP 利用面时仍写 CLI `poc.py`（`-u/--proxy`）。
- 不要为纯库强行编造站点 FOFA 语法；复现步骤写清受影响 API 与前置依赖版本。

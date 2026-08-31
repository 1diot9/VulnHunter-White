# 报告 / Advisory / CVE 格式

提交漏洞与之后在漏洞详情页改写同一份文档时，都必须遵守下列格式。不要把三种文档互相粘贴。

## 中文报告（report_md / report.md）

- 必须为中文，结构对齐 `templates/vuln-report.md`，至少包含：`## 摘要`、`## 漏洞描述`、`## 漏洞危害`、`## 漏洞厂商全称`、`## 已知受影响产品及版本`、`## 互联网资产证明`、`## 漏洞技术细节`、`## 同根因受影响点`、`## 复现证明`、`## 修复方案`、`## 备注`。
- **标题须为中文**：`SubmitVuln` 的 `title`、报告 YAML `title` 与一级标题 `# ...` 都要用中文概括漏洞（类型 + 位置/入口），不要写成 `SQL Injection in login` 这类纯英文。产品名、类名、CVE 编号可保留原文，例如 `XXOA 前台 SQL 注入`、`UserController 未授权访问`。英文标题只写在 Advisory 的 `## Title`。
- `## 互联网资产证明` 直接复用项目共享指纹 `docs/app-fingerprints.json`（侦察结束后系统已采集一次：标题/app 与默认页 HTML 的 body 特征 / 静态资源/仓库 favicon，以及互联网检索的 FOFA 语句）。不要每条漏洞重新识别，不要编造 hash；测绘语句不允许出现「或」关系。title/app 与 `body="页面特征"` 都可写，不要默认叠成过窄的 title&&app&&icon_hash。
- 「基础环境搭建」只引用 `docs/lab.md`，不要复述镜像、端口、凭据或启动命令；文档尚不存在时写「动态环境尚未落盘，见 `docs/lab.md`」。
- 漏洞描述采用两段式：第一段概述厂商/单位与产品系统，第二段概述漏洞成因与后果。SQL 注入须在危害中说明是否能获取 OS-Shell。SSRF 须在危害中写明观察面：有回显 / 仅响应差别（内网端口探测）。
- **间接消费型**（JDBC 连接池、SQL 防火墙、解析库等组件本身无直接 HTTP/RPC 入口，完整利用依赖上游业务应用传入攻击者输入）：在 **`### 触发条件`** 明确写出不能直接向组件发请求、须在上游业务中找到可利用注入点；Reviewer Confirm 时标 `exposure_mode=indirect_consumer` 并按约束降 CVSS/分层。
- 仅当挖掘路径为历史漏洞绕过时，还须在上一节全部章节基础上对齐 `templates/vuln-report-bypass.md`：在 `## 漏洞技术细节` 下**第一节**为 `### 补丁绕过简析`（原漏洞与补丁、当前绕过或未修复原因），其后依次为 `### Source → Sink`、`### 漏洞代码`、`### 完整 PoC 描述`、`### 触发条件`。不要用自由格式短文代替完整报告。绕过报告的漏洞描述第二段须说明与历史漏洞文档的关系。
- **局部验证（harness）确认**：`## 漏洞技术细节` 下必须有 `### 漏洞代码`，写明漏洞代码段对应的仓库内**完整相对路径**，并粘贴源码原文到 fenced 代码块。缺路径或缺代码段时 `ConfirmVuln(evidence_level=harness)` 会被拒绝。静态 / 靶场动态确认不强制该节。
- **`## 复现证明` 章节按验证方式填写**：
  - **局部验证（harness）**：`### 漏洞触发操作` 下填写 `#### 局部验证（harness）`，粘贴 harness 执行 stdout 关键输出（截取关键行），并在 `**为何 harness 能证明漏洞存在**` 中说明 harness 如何构造输入、调用了哪些源码函数、观察到了何种危险运行时行为（异常/返回值变化/状态篡改/敏感数据外泄等），以及该行为与源码漏洞根因的对应关系。**不要**写 PoC 的使用方法或 CLI 参数。
  - **靶场动态（dynamic/mcp）**：`### 漏洞触发操作` 下填写 `#### 动态验证（靶场 PoC）`，给出关键 HTTP 请求包（`Host` 用 `TARGET`；长字符串用占位符）和 PoC 使用方法（`python poc.py -u <目标>`，RCE 加 `-c/--cmd`），并在 `**为何 PoC 能利用该漏洞**` 中分析请求的哪个字段为攻击者可控输入、经过源码哪条链路到达 sink，以及 PoC 输出的实际结果与危害的对应关系。
  - 两类验证方式按实际选填，删去不适用的部分。

## 英文 GitHub Advisory（advisory_md / advisory.md）

- 必须为英文 GitHub Advisory 填表稿，结构对齐 `templates/vuln-advisory.md`，至少包含：`## Title`、`## Description`（`### Summary` / `### Details` / `### Vulnerable code` / `### PoC` / `### Impact`）、`## Affected products`、`## Severity / CWE`（含 **CVSS 3.1** 向量字符串；基础分与严重度标签由 ConfirmVuln 按向量自动计算，不要手填分数；不确定时留空向量由 Reviewer 填）。
- `### Vulnerable code` 须写明漏洞代码段对应的仓库内**完整相对路径**（不要只写类名/方法名），并粘贴源码原文到 fenced 代码块，与中文报告 `### 漏洞代码` 同级证据，不要省略。
- `### PoC` 须含 `http` 代码块形式的完整 HTTP 请求包；请求包内长字符串（约 80+ 字符）用描述性占位符（如 `<BASE64_PAYLOAD>`）替代。
- 不要把中文报告粘进去；Title、Description、Impact 等章节正文一律英文；章节标题保持模板英文。用户指令即使是中文，也不要把 Advisory 改成中文。Description 按 GitHub 表单可直接粘贴。

## CVE JSON（cve.json）

- 对齐 `templates/cve.json`。未知字段保持统一占位符 `VULNHUNTER_PENDING`。
- Agent 挖掘/审核轮次用 `ReadCveRecord` / `SetCveRecordField` 逐字段填写，不要 Write 整份 `cve.json`。
- CVSS 只写 `containers.cna.metrics[0].cvssV3_1.vectorString`（`CVSS:3.1/...` 基础向量）；`baseScore` / `baseSeverity` 由系统按 CVSS 3.1 计算，手填分数或 3.0/4.0 路径会被拒绝。
- `containers.cna.affected[0]` 须满足 CVE 5.2：**vendor + product**，或 **packageName + collectionURL**（如 `https://pypi.python.org`）。可与 advisory `## Affected products` 对齐。
- `containers.cna.descriptions[0].value` 必须是可供 CNA 审核的**英文详述**，不要一句话摘要，也不要把中文报告或 Advisory Markdown 章节标题粘进去。该字段**最多 4096 字符**；约 80+ 字符的长串须用 `<BASE64_PAYLOAD>` / `<JWT_TOKEN>` 等占位符，系统对超长文本会自动截断。按下面顺序写清：
  1. **产品**：厂商/单位、产品名称、受影响版本。
  2. **根因**：漏洞类型（CWE）、缺失或被绕过的控制、关键文件/函数。
  3. **漏洞链路**：入口（端点/参数/鉴权前提）→ 中间处理 → sink；写明默认部署下为何能打通。
  4. **漏洞代码**：仓库内完整相对路径（如 `src/.../File.ext` 或 `app/utils/backup.py:42`）+ 对应源码原文；不要只写类名/方法名或一句话概述。
  5. **PoC**：有 HTTP 面时写完整原始 HTTP 请求包（方法、路径、必要头、body；`Host` 用 `TARGET`）；约 80+ 字符的长串用 `<BASE64_PAYLOAD>` / `<JWT_TOKEN>` 等占位符。无 HTTP 面（组件库/公开 API）时写可复现的 API/调用链，不要留空；不要把 `harness.py` 的内联/mock 抄进 `poc.py`。无 HTTP 且无安装面时可不落盘 `poc.py`。
  6. **危害**：成功利用后攻击者能做什么；剩余控制条件如实写，不要夸大。
- `supportingMedia[0].value` 是同一内容的 HTML：段落用 `<p>`，**漏洞代码与 HTTP/API PoC 均放在 `<pre>` 中**（各用一块，不要挤进同一段纯文本）。不要只复制一句纯文本。
- `problemTypes[0].descriptions[0].description` 仍只填 CWE 弱点英文名，不是整段漏洞描述。

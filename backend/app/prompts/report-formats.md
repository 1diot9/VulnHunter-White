# 报告 / Advisory / CVE 格式

提交漏洞与之后在漏洞详情页改写同一份文档时，都必须遵守下列格式。不要把三种文档互相粘贴。

## 中文报告（report_md / report.md）

- 必须为中文，结构对齐 `templates/vuln-report.md`，至少包含：`## 摘要`、`## 漏洞描述`、`## 漏洞危害`、`## 漏洞厂商全称`、`## 已知受影响产品及版本`、`## 互联网资产证明`、`## 漏洞技术细节`、`## 同根因受影响点`、`## 复现证明`、`## 修复方案`、`## 备注`。
- `## 互联网资产证明` 直接复用项目共享指纹 `docs/app-fingerprints.json`（侦察结束后系统已采集一次：标题/app 与默认页 HTML 的 body 特征 / 静态资源/仓库 favicon，以及互联网检索的 FOFA 语句）。不要每条漏洞重新识别，不要编造 hash；测绘语句不允许出现「或」关系。title/app 与 `body="页面特征"` 都可写，不要默认叠成过窄的 title&&app&&icon_hash。
- 「基础环境搭建」只引用 `docs/lab.md`，不要复述镜像、端口、凭据或启动命令；文档尚不存在时写「动态环境尚未落盘，见 `docs/lab.md`」。
- 漏洞描述采用两段式：第一段概述厂商/单位与产品系统，第二段概述漏洞成因与后果。SQL 注入须在危害中说明是否能获取 OS-Shell。SSRF 须在危害中写明观察面：有回显 / 仅响应差别（内网端口探测）。
- 仅当挖掘路径为历史漏洞绕过时，还须在上一节全部章节基础上对齐 `templates/vuln-report-bypass.md`：在 `## 漏洞技术细节` 下**第一节**为 `### 补丁绕过简析`（原漏洞与补丁、当前绕过或未修复原因），其后依次为 `### Source → Sink`、`### 完整 PoC 描述`、`### 触发条件`。不要用自由格式短文代替完整报告。绕过报告的漏洞描述第二段须说明与历史漏洞文档的关系。

## 英文 GitHub Advisory（advisory_md / advisory.md）

- 必须为英文 GitHub Advisory 填表稿，结构对齐 `templates/vuln-advisory.md`，至少包含：`## Title`、`## Description`（`### Summary` / `### Details` / `### PoC` / `### Impact`）、`## Affected products`、`## Severity / CWE`（含 **CVSS 3.1** 与 **CVSS 4.0**：基础分、严重度标签与向量字符串；不确定时留空由 Reviewer 填）。
- `### PoC` 须含 `http` 代码块形式的完整 HTTP 请求包；请求包内长字符串（约 80+ 字符）用描述性占位符（如 `<BASE64_PAYLOAD>`）替代。
- 不要把中文报告粘进去；Title、Description、Impact 等章节正文一律英文；章节标题保持模板英文。用户指令即使是中文，也不要把 Advisory 改成中文。Description 按 GitHub 表单可直接粘贴。

## CVE JSON（cve.json）

- 对齐 `templates/cve.json`。未知字段保持统一占位符 `VULNHUNTER_PENDING`。
- Agent 挖掘/审核轮次用 `ReadCveRecord` / `SetCveRecordField` 逐字段填写，不要 Write 整份 `cve.json`。

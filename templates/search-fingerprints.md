# 互联网资产证明编写规则

漏洞报告中的“互联网资产证明”用于帮助读者在资产测绘平台定位同类应用资产。指纹应描述应用本身，而不是只描述某个漏洞入口。测绘语句不允许出现「或」关系。

## 通用原则
- 互联网检索时 title/app 与默认页 HTML 的 `body="..."` 特征是互补的两条路：各试一条，有命中即可，不要在同一方向反复改写，也不要默认把 title、app、icon_hash 用 `&&` 叠在一起。
- 报告里的测绘语句可以同时记录标题和一段稳定页面特征；真正去 FOFA 搜时拆开试，目标是圈到同款资产，不坚持某种语法。
- 避免把漏洞路径、PoC 参数、随机 token、租户数据、用户名、时间戳、一次性错误信息作为唯一指纹。
- 若使用 `icon_hash`，说明它来自 favicon 的 mmh3 hash；没有实际 hash 时不要编造数值。icon_hash 适合精确定位，不适合作为唯一检索方向。
- 指纹要可复制执行，字符串统一使用英文双引号；需要排除噪声时再加入地域、端口、协议、状态码等过滤项。
- 逻辑连接只允许 `&&` 与括号，禁止 `||` 或任何「或」关系。
- 如果当前没有项目共享指纹，写明“待运行环境确认”，并给出需要补采的字段；有 `docs/app-fingerprints.json` 时直接复用，不要每条漏洞重新识别。

## FOFA
- 基本形式：`field="value"`，精确匹配可用 `field=="value"`，排除可用 `field!="value"` 或 `!condition`。
- 逻辑连接：只用 `&&` 表示与，括号用于控制优先级；不要写 `||`。
- 常用字段：`title`、`body`、`header`、`icon_hash`、`fid`、`app`、`product`、`server`、`domain`、`host`、`port`、`protocol`、`status_code`、`cert`、`icp`。
- 检索建议：先试 `title="<应用标题>"` 或 `app="<产品名>"`，0 条再试 `body="<默认页稳定HTML特征>"`（独特 id/class、版权行、应用自己的 js/css 路径），或反过来。不要把两条路 AND 成一条再反复微调。

## X 情报社区
- 面向微步在线 X 情报中心“资产测绘”场景，基本形式同样使用 `field="value"`。
- 常用字段：`ip`、`domain`、`app`、`title`、`body`、`cert.subject`、`port`、`protocol`、`icp_name`、`cert.hash`、`dom_hash`、`html_hash`、`icon_hash`、`dns`、`plugins`。
- 推荐写法：`title="<应用标题>"` 与 `body="<稳定页面特征>"` 分开检索；确有平台 `app` 识别时可单独写 `app="<应用/组件名>"`，不要默认 `app && title && body`。
- X 情报社区更适合结合 `app`、证书、备案、DNS、插件识别等平台字段做拓线；不要直接照搬 FOFA 独有字段如 `fid`。

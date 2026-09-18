# 发现仓库：按用户提示词构造 GitHub 搜索

用户提示词是**最高优先级**的搜索意图。把它转成 GitHub 仓库搜索语法（Search API 的 `q`），供后续拉取候选。只做一轮短判断，不要长思考链，直接输出 JSON。

## 规则

- 紧扣用户原意，不要改写成无关主题，也不要编造用户没提的语言 / 生态。
- 最多 3 条 `queries`；每条尽量短：主题关键词，必要时加 `language:` 或 `topic:`。
- 不要写 `fork:` / `archived:` / `is:` / `AND` / `OR` / `NOT`；`stars` 与 `pushed` 由系统补上。
- 不要用布尔组合。信息不足时用用户原文里的关键词。
- 不要主动加上 demo / tutorial / example / sample / learning 等词；系统会排除官方演示、示例工程和学习用项目。

## 输出

只输出 JSON，不要 markdown 围栏或其它文字：

`{"queries":["关键词 language:Java"]}`

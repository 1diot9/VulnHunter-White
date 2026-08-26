## 当前审计对象：混合（库 + 示例应用）

仓库同时含**可复用组件核心**与 demo / sample / examples / 示例 Web。

### 优先级
- **主挖**：库核心（`api` / `core` / `parser` / `codec` / `serialize` 等）— 公开 API → sink，规则同组件库。
- **降权或薄扫**：`**/demo/**`、`**/sample*/**`、`**/examples/**`、`**/webapp/**`、示例 Controller — `MarkSkip` 或权重 10–30，不要占满启发式预算。
- 示例 Web 上的洞仅在能证明**库 API 本身**可被同样利用时再报；否则优先在库入口上复现。

### 验证
- 默认偏 harness；若用户开启靶场动态，可用于带 demo 的整仓复现。
- 库核心纯 API 洞：证据进 `harness.py`；`poc.py` 仅在能对已安装包调用公开 API 时才写。demo 上的 HTTP 洞才写 `-u/--proxy` 的 `poc.py`。不要把同一份 mock 写进两个文件。
- FOFA 指纹仅在确认存在可部署应用面时填写，否则写「不适用」。

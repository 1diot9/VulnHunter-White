项目 ID=${project_id}。这是历史漏洞第二轮：核验 GHSA 爬虫补漏。
已写入 workspace/ghsa_new.json（新候选 ${ghsa_count} 条${ghsa_error}）。Read 该文件，Grep 核验调用点后，符合口径的立刻 WriteOldVuln（落盘不会结束本会话）。
第一轮已落盘的条目不要删除。无关/已修复/未使用的不要建档。
全部核验完 WriteOldVuln(done=true, note=跳过说明)；无符合口径则 WriteOldVuln(no_findings=true)。不要改写 code-map/auth，不要标权重。

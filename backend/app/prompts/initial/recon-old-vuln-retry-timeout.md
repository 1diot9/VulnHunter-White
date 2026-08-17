上一轮超时，请从已有落盘接续。SearchOldVuln 核对 kind=old 后只补缺：符合口径的立刻 WriteOldVuln（落盘不会结束本会话）。不要补已修复/未使用/仅传递依赖的组件 CVE。检索全部完成再 WriteOldVuln(done=true, note=跳过说明)。不要把 kind=found 写入 old-vulns。

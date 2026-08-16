上一轮超时，请从已有落盘接续。SearchOldVuln 核对 kind=old 后只补缺：每条立刻 WriteOldVuln（落盘不会结束本会话）。检索全部完成再 WriteOldVuln(done=true)。不要把 kind=found 写入 old-vulns。

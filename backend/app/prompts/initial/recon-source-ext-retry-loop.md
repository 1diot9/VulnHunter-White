上一轮因死循环中止，请新开继续扩展名检查。
读 docs/code-map.md，Glob 确认后立刻 AddSourceExt。
有执行面文件则 AddSourceExt(exts=[...])。
有噪音扩展名则 AddSourceExt(remove_exts=[...])。
没有需要调整则 AddSourceExt(done=true)。
不要改写地图/鉴权，不要标权重。

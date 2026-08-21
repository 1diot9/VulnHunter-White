from __future__ import annotations

from pathlib import Path

from app.services.cli_tool_index import (
    INDEX_FILENAME,
    discover_tool_dirs,
    mark_index_failed,
    needs_index,
    search_cli_tools,
    write_ready_index,
)
from app.tools import ROLE_ACL, ToolContext, registry


def _ctx(project_id: int, role: str = "reviewer", **kwargs) -> ToolContext:
    return ToolContext(project_id=project_id, role=role, phase=role, **kwargs)


def _seed_tool(root: Path, name: str, *, description: str, ready: bool = True) -> Path:
    tool_dir = root / name
    tool_dir.mkdir(parents=True, exist_ok=True)
    entry = tool_dir / "run.py"
    entry.write_text("print('ok')\n", encoding="utf-8")
    if ready:
        write_ready_index(
            tool_dir,
            entry="run.py",
            entry_path=entry,
            description=description,
        )
    return tool_dir


def test_search_tools_acl(tmp_env, project):
    assert "SearchTools" in ROLE_ACL["reviewer"]
    assert "SearchTools" not in ROLE_ACL["reviewer_lab"]
    assert "SearchTools" not in ROLE_ACL["worker"]
    assert "FinishIndex" in ROLE_ACL["cli_indexer"]
    assert "Bash" in ROLE_ACL["cli_indexer"]
    names = {t["function"]["name"] for t in registry.openai_tools_for_role("reviewer")}
    assert "SearchTools" in names
    lab = {t["function"]["name"] for t in registry.openai_tools_for_role("reviewer_lab")}
    assert "SearchTools" not in lab
    blocked = registry.dispatch(_ctx(project, "worker"), "SearchTools", {"query": ""})
    assert blocked["ok"] is False
    assert "无权" in blocked["error"]


def test_search_tools_lists_and_filters(tmp_env, project):
    root = tmp_env["cli_tools"]
    _seed_tool(root, "nuclei", description="模板扫描器，nuclei -t 跑 YAML 模板")
    _seed_tool(root, "sqlmap", description="SQL 注入检测")
    pending = _seed_tool(root, "unready", description="还没索引", ready=False)
    assert needs_index(pending) is True

    listed = registry.dispatch(_ctx(project, "reviewer"), "SearchTools", {"query": ""})
    assert listed["ok"] is True
    names = {t["name"] for t in listed["tools"]}
    assert names == {"nuclei", "sqlmap"}
    nuclei = next(t for t in listed["tools"] if t["name"] == "nuclei")
    assert nuclei["entry"] == "run.py"
    assert nuclei["dir"].replace("\\", "/").endswith("/nuclei")
    assert nuclei["path"].replace("\\", "/").endswith("/nuclei/run.py")
    assert "模板扫描器" in nuclei["description"]

    filtered = registry.dispatch(_ctx(project, "reviewer"), "SearchTools", {"query": "注入"})
    assert filtered["count"] == 1
    assert filtered["tools"][0]["name"] == "sqlmap"


def test_one_subdir_is_one_tool_and_skips_hidden(tmp_env):
    root = tmp_env["cli_tools"]
    (root / "plain.txt").write_text("ignore files at root\n", encoding="utf-8")
    (root / ".hidden").mkdir()
    (root / ".hidden" / "bin").write_text("x", encoding="utf-8")
    keep = _seed_tool(root, "keep-me", description="可见工具")
    found = {p.name for p in discover_tool_dirs(root)}
    assert found == {"keep-me"}
    assert keep.is_dir()


def test_needs_index_fingerprint_and_failed_no_retry(tmp_env):
    root = tmp_env["cli_tools"]
    tool_dir = _seed_tool(root, "demo", description="先成功")
    assert needs_index(tool_dir) is False
    (tool_dir / "run.py").write_text("print('changed')\n", encoding="utf-8")
    assert needs_index(tool_dir) is True
    mark_index_failed(tool_dir, "超时未 FinishIndex")
    assert needs_index(tool_dir) is False
    (tool_dir / "extra.txt").write_text("new file\n", encoding="utf-8")
    assert needs_index(tool_dir) is True


def test_finish_index_writes_ready_record(tmp_env):
    root = tmp_env["cli_tools"]
    tool_dir = root / "mycli"
    tool_dir.mkdir()
    entry = tool_dir / "tool.cmd"
    entry.write_text("@echo help\n", encoding="utf-8")
    ctx = _ctx(
        0,
        "cli_indexer",
        workspace_root=str(tool_dir),
        silent=True,
        log_path=str(tool_dir / "agent.log.jsonl"),
    )
    out = registry.dispatch(
        ctx,
        "FinishIndex",
        {"description": "演示 CLI，tool.cmd /help", "entry": "tool.cmd"},
    )
    assert out["ok"] is True
    assert ctx.state.get("index_done") is True
    rec_path = tool_dir / INDEX_FILENAME
    assert rec_path.is_file()
    log = tool_dir / "agent.log.jsonl"
    assert log.is_file()
    listed = search_cli_tools("演示")
    assert len(listed) == 1
    assert listed[0]["entry"] == "tool.cmd"
    assert listed[0]["path"].replace("\\", "/").endswith("/mycli/tool.cmd")


def test_settings_cli_tools_dir_roundtrip(tmp_env):
    from fastapi.testclient import TestClient

    from app.main import app

    other = tmp_env["cli_tools"].parent / "other-cli"
    other.mkdir(parents=True, exist_ok=True)
    with TestClient(app) as client:
        body = client.get("/api/settings").json()
        assert "cli_tools_dir" in body
        nxt = client.put("/api/settings", json={"cli_tools_dir": str(other)}).json()
        assert Path(nxt["cli_tools_dir"]).resolve() == other.resolve()

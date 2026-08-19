from __future__ import annotations

from pathlib import Path

from app.config import ROOT_DIR, resolve_repo_path, settings
from app.services.mcp_router import mcp_root, resolve_mcp_command, reviewer_debug_plan


def test_resolve_repo_path_relative_and_absolute(tmp_path):
    rel = resolve_repo_path("tools/mcp/java-debug")
    assert rel == ROOT_DIR / "tools" / "mcp" / "java-debug"
    abs_path = tmp_path / "override"
    abs_path.mkdir()
    assert resolve_repo_path(str(abs_path)) == abs_path


def test_default_mcp_roots_live_in_repo():
    java = mcp_root("java")
    node = mcp_root("node")
    python = mcp_root("python")
    assert java == ROOT_DIR / "tools" / "mcp" / "java-debug"
    assert node == ROOT_DIR / "tools" / "mcp" / "node-debug"
    assert python == ROOT_DIR / "tools" / "mcp" / "python-debug"
    assert (java / "pom.xml").is_file()
    assert (node / "src" / "index.ts").is_file()
    assert (python / "server.py").is_file()


def test_mcp_env_override(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "mcp_java", str(tmp_path))
    assert mcp_root("java") == tmp_path


def test_resolve_mcp_commands():
    java = resolve_mcp_command("java")
    assert java is not None
    assert Path(java["cwd"]) == ROOT_DIR / "tools" / "mcp" / "java-debug"
    jar = Path(java["cwd"]) / "target" / "java-debug-mcp-0.1.0-SNAPSHOT-all.jar"
    if jar.exists():
        assert java["command"] == "java"
    else:
        assert "hint" in java

    node = resolve_mcp_command("node")
    assert node is not None
    assert node["command"] == "npx"
    assert "src/index.ts" in node["args"]

    python = resolve_mcp_command("python")
    assert python is not None
    assert python["args"][0].endswith("server.py")


def test_reviewer_debug_plan_prefers_plain_dynamic(monkeypatch):
    from app.services import mcp_router

    monkeypatch.setattr(
        mcp_router, "load_env", lambda _pid: {"target_url": "http://127.0.0.1:8080"}
    )
    monkeypatch.setattr(
        mcp_router,
        "debug_ports_for_runtime",
        lambda _env: {"runtime": "java", "mcp": "java", "port": 5005},
    )
    plan = reviewer_debug_plan(1)
    assert plan["preferred"] == "plain_dynamic"
    assert plan["mcp"] is not None
    assert "不要作为首选" in plan["mcp_when"]
    assert "先运行" in plan["plain_dynamic"]["steps"][0]

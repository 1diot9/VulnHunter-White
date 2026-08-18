"""Optional debug MCP helpers for Reviewer (stdio attach when available)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..config import resolve_repo_path, settings
from .lab import debug_ports_for_runtime, load_env


def mcp_root(kind: str) -> Path:
    if kind == "java":
        return resolve_repo_path(settings.mcp_java, fallback="tools/mcp/java-debug")
    if kind == "node":
        return resolve_repo_path(settings.mcp_node, fallback="tools/mcp/node-debug")
    if kind == "python":
        return resolve_repo_path(settings.mcp_python, fallback="tools/mcp/python-debug")
    raise ValueError(f"unknown mcp kind: {kind}")


def resolve_mcp_command(runtime_mcp: str | None) -> dict[str, Any] | None:
    if not runtime_mcp:
        return None
    if runtime_mcp == "java":
        root = mcp_root("java")
        jar = root / "target" / "java-debug-mcp-0.1.0-SNAPSHOT-all.jar"
        if jar.exists():
            return {"transport": "stdio", "command": "java", "args": ["-jar", str(jar)], "cwd": str(root)}
        return {"transport": "stdio", "hint": "build java-debug-mcp jar first (mvn package)", "cwd": str(root)}
    if runtime_mcp == "node":
        root = mcp_root("node")
        return {
            "transport": "stdio",
            "command": "npx",
            "args": ["tsx", "src/index.ts"] if (root / "src" / "index.ts").exists() else ["node", "dist/index.js"],
            "cwd": str(root),
        }
    if runtime_mcp == "python":
        root = mcp_root("python")
        server = root / "server.py"
        return {
            "transport": "stdio",
            "command": "python",
            "args": [str(server)],
            "cwd": str(root),
        }
    return None


def reviewer_debug_plan(project_id: int) -> dict[str, Any]:
    """Describe how Reviewer should dynamically verify for this project."""
    env = load_env(project_id)
    dbg = debug_ports_for_runtime(env)
    mcp = resolve_mcp_command(dbg.get("mcp"))
    plan: dict[str, Any] = {
        "target_url": env.get("target_url"),
        "runtime": dbg.get("runtime"),
        "preferred": "mcp" if mcp and mcp.get("command") else "plain_dynamic",
        "mcp": mcp,
        "debug_port": dbg.get("port"),
        "plain_dynamic": {
            "steps": [
                "对 target_url 发送报告中的 HTTP 请求或运行 vulns/{id}/poc.py -u <target_url>（RCE 可加 -c/--cmd）",
                "docker exec / 容器日志 / 文件 / 进程确认冲击",
            ]
        },
    }
    return plan

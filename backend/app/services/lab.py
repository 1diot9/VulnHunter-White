"""Lab / env helpers aligned with AutoPoc env.json concepts."""

from __future__ import annotations

import json
import shutil
import socket
import subprocess
from pathlib import Path
from typing import Any

from .paths import env_dir


def env_json_path(project_id: int) -> Path:
    return env_dir(project_id) / "env.json"


def load_env(project_id: int) -> dict[str, Any]:
    path = env_json_path(project_id)
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def save_env(project_id: int, data: dict[str, Any]) -> Path:
    path = env_json_path(project_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def docker_available() -> bool:
    return shutil.which("docker") is not None


def find_free_port(host: str = "127.0.0.1", start: int = 18000, end: int = 19000) -> int:
    for port in range(start, end):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind((host, port))
                return port
            except OSError:
                continue
    raise RuntimeError("无可用端口")


def remap_ports_if_needed(env: dict[str, Any]) -> dict[str, Any]:
    """If host_port is busy, allocate a free one and update target_url."""
    host_port = env.get("host_port")
    if not host_port:
        return env
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", int(host_port)))
        return env
    except OSError:
        new_port = find_free_port()
        env = dict(env)
        env["host_port"] = new_port
        url = env.get("target_url") or f"http://127.0.0.1:{new_port}"
        env["target_url"] = url.replace(f":{host_port}", f":{new_port}")
        env["notes"] = (env.get("notes") or "") + f"\nport remapped {host_port}->{new_port}"
        return env


def recreate_lab(project_id: int) -> dict[str, Any]:
    """Try to bring up lab from env/ compose or recorded container."""
    env = load_env(project_id)
    if not env:
        return {"ok": False, "error": "无 env.json"}
    if not docker_available():
        return {"ok": False, "error": "本机无 docker"}
    env = remap_ports_if_needed(env)
    ed = env_dir(project_id)
    compose = None
    for name in ("docker-compose.yml", "compose.yml", "docker-compose.yaml"):
        if (ed / name).exists():
            compose = ed / name
            break
    try:
        if compose:
            proc = subprocess.run(
                ["docker", "compose", "-f", str(compose), "up", "-d"],
                cwd=str(ed),
                capture_output=True,
                text=True,
                timeout=600,
            )
            if proc.returncode != 0:
                return {"ok": False, "error": proc.stderr or proc.stdout, "env": env}
            env["status"] = "running"
            save_env(project_id, env)
            return {"ok": True, "env": env, "via": "compose"}
        image = env.get("image")
        name = env.get("container_name") or f"vulnhunter-{project_id}"
        if image:
            subprocess.run(["docker", "start", name], capture_output=True, text=True, timeout=60)
            env["status"] = "running"
            save_env(project_id, env)
            return {"ok": True, "env": env, "via": "start"}
        return {"ok": False, "error": "无 compose 且无 image", "env": env}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e), "env": env}


def debug_ports_for_runtime(env: dict[str, Any]) -> dict[str, Any]:
    runtime = str(env.get("runtime") or "").lower()
    out: dict[str, Any] = {"runtime": runtime, "mcp": None}
    if runtime in ("java", "jvm"):
        out["mcp"] = "java"
        out["port"] = env.get("jdwp_host_port")
    elif runtime in ("nodejs", "node", "javascript"):
        out["mcp"] = "node"
        out["port"] = env.get("inspect_host_port")
    elif runtime == "python":
        out["mcp"] = "python"
        out["port"] = env.get("debugpy_host_port")
    return out


ENV_BUILDER_HINT = """
请在项目 `env/` 下搭建可复用的 Web 靶场（参考 AutoPoc / prompts/docker.md）：
- 优先已有镜像 / docker-compose
- 写出 env.json，字段包括：accepted, runtime, image, container_name, host_port, container_port,
  target_url, lab_state(setup|ready), credentials, status, notes
- runtime 可为任意 Web 语言；仅 java/nodejs/python 时填写 jdwp_* / inspect_* / debugpy_*
- 业务端口与调试端口分离；调试端口绑定 127.0.0.1
"""

"""Lab / env helpers aligned with AutoPoc env.json concepts."""

from __future__ import annotations

import json
import re
import shutil
import socket
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse

from .paths import docs_dir, env_dir

_LAB_PREFIX = "vulnhunter"
_LAB_IMAGE_TAG = "lab"
_LAB_ROLE_RE = re.compile(r"[^a-z0-9]+")
_MAX_NAME_SLUG = 48


def _lab_role_suffix(role: str | None) -> str:
    if not role:
        return ""
    cleaned = _LAB_ROLE_RE.sub("-", str(role).strip().lower()).strip("-")
    if not cleaned:
        return ""
    return f"-{cleaned[:32]}"


def _slug_project_name(name: str | None) -> str:
    cleaned = _LAB_ROLE_RE.sub("-", str(name or "").strip().lower()).strip("-")
    return cleaned[:_MAX_NAME_SLUG].strip("-")


def _lookup_project_name(project_id: int) -> str:
    try:
        from ..models import Project, SessionLocal

        with SessionLocal() as db:
            row = db.get(Project, int(project_id))
            return str(row.name or "") if row else ""
    except Exception:  # noqa: BLE001
        return ""


def _resolve_project_name(project_id: int, project_name: str | None) -> str:
    if project_name is not None:
        return project_name
    return _lookup_project_name(project_id)


def _legacy_lab_compose_project(project_id: int) -> str:
    return f"{_LAB_PREFIX}-{int(project_id)}"


def _lab_base_name(project_id: int, project_name: str | None = None) -> str:
    """Compose/container prefix: {project-name}-{id}, else vulnhunter-{id}."""
    slug = _slug_project_name(_resolve_project_name(project_id, project_name))
    pid = int(project_id)
    if slug:
        return f"{slug}-{pid}"
    return _legacy_lab_compose_project(pid)


def lab_compose_project(project_id: int, *, project_name: str | None = None) -> str:
    """Compose project name: {project-name}-{id}, or vulnhunter-{id} if unsanitizable."""
    return _lab_base_name(project_id, project_name)


def lab_container_name(
    project_id: int,
    role: str | None = None,
    *,
    project_name: str | None = None,
) -> str:
    """Web container {name}-{id}; sidecars {name}-{id}-{role}."""
    return f"{lab_compose_project(project_id, project_name=project_name)}{_lab_role_suffix(role)}"


def lab_image_name(
    project_id: int,
    role: str | None = None,
    *,
    project_name: str | None = None,
) -> str:
    """Image tag for images built for this lab (not official mysql/redis/…)."""
    return f"{lab_container_name(project_id, role, project_name=project_name)}:{_LAB_IMAGE_TAG}"


def lab_naming(project_id: int, *, project_name: str | None = None) -> dict[str, str]:
    pid = int(project_id)
    name = _resolve_project_name(pid, project_name)
    container = lab_container_name(pid, project_name=name)
    return {
        "project_id": str(pid),
        "lab_image": lab_image_name(pid, project_name=name),
        "lab_container": container,
        "lab_compose_project": lab_compose_project(pid, project_name=name),
    }


def env_json_path(project_id: int) -> Path:
    return env_dir(project_id) / "env.json"


def lab_doc_path(project_id: int) -> Path:
    return docs_dir(project_id) / "lab.md"


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


def lab_ready(env: dict[str, Any]) -> bool:
    status = str(env.get("status") or "").strip().lower()
    return bool(env.get("accepted") and env.get("target_url") and status == "running")


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


def lab_setup_finished(project_id: int) -> bool:
    """True after the dedicated lab round completed (success or skipped)."""
    return _truthy(load_env(project_id).get("setup_finished"))


def lab_round_complete(project_id: int, state: dict[str, Any] | None = None) -> bool:
    if state and state.get("lab_done"):
        return True
    if lab_setup_finished(project_id):
        return True
    return lab_ready(load_env(project_id))


def finish_manual_lab(project_id: int, prompt: str = "") -> dict[str, Any]:
    """Skip Docker lab and record the user-supplied environment note."""
    env = dict(load_env(project_id) or {})
    env["lab_kind"] = "manual"
    env["setup_finished"] = True
    env["accepted"] = False
    env["status"] = "manual"
    env["notes"] = prompt.strip() or "人工靶场：用户自行提供运行环境"
    save_env(project_id, env)
    write_lab_doc(project_id, env, via="manual")
    return env


def sync_manual_lab_notes(project_id: int, prompt: str) -> dict[str, Any] | None:
    """Record the user-supplied lab note without replacing a Docker env."""
    env = dict(load_env(project_id) or {})
    env["manual_notes"] = prompt.strip()
    if not env.get("status") and not env.get("setup_finished") and not prompt.strip():
        return None
    save_env(project_id, env)
    if lab_setup_finished(project_id):
        write_lab_doc(project_id, env, via=str(env.get("lab_kind") or "manual"))
    return env


def mark_lab_setup_finished(
    project_id: int,
    *,
    skipped: bool = False,
    notes: str | None = None,
    via: str | None = None,
) -> dict[str, Any]:
    env = dict(load_env(project_id) or {})
    env["setup_finished"] = True
    if skipped:
        env["accepted"] = False
        if not env.get("status"):
            env["status"] = "skipped"
    if notes:
        prev = str(env.get("notes") or "").strip()
        env["notes"] = f"{prev}\n{notes}".strip() if prev else notes
    save_env(project_id, env)
    write_lab_doc(project_id, env, via=via or ("skipped" if skipped else "lab-round"))
    return env


def _markdown_value(value: Any) -> str:
    if value is None or value == "":
        return "未记录"
    return str(value)


def _json_block(value: Any) -> str:
    if value is None or value == "":
        return "未记录"
    return "```json\n" + json.dumps(value, ensure_ascii=False, indent=2, default=str) + "\n```"


def _port_lines(env: dict[str, Any]) -> list[str]:
    pairs = [
        ("业务端口", "container_port", "host_port"),
        ("Java JDWP", "jdwp_container_port", "jdwp_host_port"),
        ("Node inspect", "inspect_container_port", "inspect_host_port"),
        ("Python debugpy", "debugpy_container_port", "debugpy_host_port"),
    ]
    lines: list[str] = []
    for label, container_key, host_key in pairs:
        container_port = env.get(container_key)
        host_port = env.get(host_key)
        if container_port or host_port:
            lines.append(
                f"- {label}：容器 `{_markdown_value(container_port)}` -> 宿主机 `{_markdown_value(host_port)}`"
            )
    return lines or ["- 未记录端口映射"]


def render_lab_doc(env: dict[str, Any], *, via: str | None = None) -> str:
    updated_at = datetime.now(timezone.utc).isoformat()
    container = env.get("container_name") or env.get("container_id")
    start_hint = f"docker start {container}" if container else "参考 env/env.json 或 env/docker-compose.yml 启动"
    compose_hint = "docker compose -f env/docker-compose.yml up -d"
    via_line = f"- 启动来源：{via}" if via else "- 启动来源：未记录"
    notes = str(env.get("notes") or "").strip() or "未记录"
    manual = str(env.get("manual_notes") or "").strip() or "未记录"
    port_lines = "\n".join(_port_lines(env))
    return f"""# 动态环境搭建

## 环境状态
- 文档更新时间：{updated_at}
- 访问地址：{_markdown_value(env.get("target_url"))}
- 运行时：{_markdown_value(env.get("runtime"))}
- lab_state：{_markdown_value(env.get("lab_state"))}
- 状态：{_markdown_value(env.get("status"))}
{via_line}

## Docker 信息
- 镜像：{_markdown_value(env.get("image"))}
- 容器名：{_markdown_value(env.get("container_name"))}
- 容器 ID：{_markdown_value(env.get("container_id"))}

## 端口映射
{port_lines}

## 复用方式
- 环境元数据：`env/env.json`
- 若存在 compose 文件：`{compose_hint}`
- 若已记录容器：`{start_hint}`

## 凭据
{_json_block(env.get("credentials"))}

## 人工靶场
{manual}

## 备注
{notes}
"""


def write_lab_doc(project_id: int, env: dict[str, Any], *, via: str | None = None) -> Path:
    path = lab_doc_path(project_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_lab_doc(env, via=via), encoding="utf-8")
    return path


def write_lab_doc_if_ready(project_id: int, env: dict[str, Any], *, via: str | None = None) -> Path | None:
    if not lab_ready(env):
        return None
    return write_lab_doc(project_id, env, via=via)


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


def _docker_run(args: list[str], *, cwd: Path | None = None, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *args],
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _container_candidates(project_id: int, env: dict[str, Any]) -> list[str]:
    candidates = [
        env.get("container_id"),
        env.get("container_name"),
        lab_container_name(project_id),
        _legacy_lab_compose_project(project_id),
    ]
    out: list[str] = []
    for item in candidates:
        if item and item not in out:
            out.append(str(item))
    return out


def _inspect_container(candidates: list[str]) -> tuple[str, dict[str, Any]] | None:
    for candidate in candidates:
        proc = _docker_run(["inspect", candidate])
        if proc.returncode != 0:
            continue
        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            continue
        if isinstance(data, list) and data and isinstance(data[0], dict):
            return candidate, data[0]
    return None


def _status_from_inspect(info: dict[str, Any]) -> str:
    state = info.get("State") if isinstance(info.get("State"), dict) else {}
    return str(state.get("Status") or "unknown")


def _container_running(info: dict[str, Any]) -> bool:
    state = info.get("State") if isinstance(info.get("State"), dict) else {}
    return bool(state.get("Running")) or _status_from_inspect(info) == "running"


def _host_port(info: dict[str, Any], container_port: Any) -> int | None:
    if not container_port:
        return None
    ports = ((info.get("NetworkSettings") or {}).get("Ports") or {}) if isinstance(info.get("NetworkSettings"), dict) else {}
    bindings = ports.get(f"{container_port}/tcp") or ports.get(f"{container_port}/udp")
    if not bindings:
        return None
    for binding in bindings:
        if not isinstance(binding, dict):
            continue
        port = binding.get("HostPort")
        if port:
            try:
                return int(port)
            except (TypeError, ValueError):
                return None
    return None


def _target_url_with_port(url: str | None, port: int) -> str:
    if not url:
        return f"http://127.0.0.1:{port}"
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return f"http://127.0.0.1:{port}"
    host = parsed.hostname or "127.0.0.1"
    if host in {"0.0.0.0", "::"}:
        host = "127.0.0.1"
    netloc = f"{host}:{port}"
    return urlunparse(parsed._replace(netloc=netloc))


def refresh_env_from_container(env: dict[str, Any], info: dict[str, Any]) -> dict[str, Any]:
    """Trust Docker inspect over stale env.json metadata for an existing lab."""
    env = dict(env)
    container_id = info.get("Id")
    if container_id:
        env["container_id"] = container_id
    name = str(info.get("Name") or "").lstrip("/")
    if name:
        env["container_name"] = name
    image = (info.get("Config") or {}).get("Image") if isinstance(info.get("Config"), dict) else None
    if image:
        env["image"] = image
    env["status"] = _status_from_inspect(info)

    for container_key, host_key in (
        ("container_port", "host_port"),
        ("jdwp_container_port", "jdwp_host_port"),
        ("inspect_container_port", "inspect_host_port"),
        ("debugpy_container_port", "debugpy_host_port"),
    ):
        port = _host_port(info, env.get(container_key))
        if port:
            env[host_key] = port
    if env.get("host_port"):
        env["target_url"] = _target_url_with_port(env.get("target_url"), int(env["host_port"]))
    return env


def recreate_lab(project_id: int) -> dict[str, Any]:
    """Try to bring up lab from env/ compose or recorded container."""
    env = load_env(project_id)
    if not env:
        return {"ok": False, "error": "无 env.json"}
    if not docker_available():
        return {"ok": False, "error": "本机无 docker"}
    ed = env_dir(project_id)
    compose = None
    for name in ("docker-compose.yml", "compose.yml", "docker-compose.yaml"):
        if (ed / name).exists():
            compose = ed / name
            break
    try:
        inspected = _inspect_container(_container_candidates(project_id, env))
        if inspected:
            identifier, info = inspected
            was_running = _container_running(info)
            if not was_running:
                proc = _docker_run(["start", identifier])
                if proc.returncode != 0:
                    env = refresh_env_from_container(env, info)
                    save_env(project_id, env)
                    return {"ok": False, "error": proc.stderr or proc.stdout or "docker start failed", "env": env}
                inspected_after_start = _inspect_container(_container_candidates(project_id, env))
                if inspected_after_start:
                    _, info = inspected_after_start
            env = refresh_env_from_container(env, info)
            save_env(project_id, env)
            via = "reuse" if was_running else "start"
            write_lab_doc_if_ready(project_id, env, via=via)
            return {"ok": True, "env": env, "via": via}

        env = remap_ports_if_needed(env)
        if compose:
            proc = _docker_run(
                ["compose", "-p", lab_compose_project(project_id), "-f", str(compose), "up", "-d"],
                cwd=ed,
                timeout=600,
            )
            if proc.returncode != 0:
                return {"ok": False, "error": proc.stderr or proc.stdout, "env": env}
            inspected = _inspect_container(_container_candidates(project_id, env))
            if inspected:
                _, info = inspected
                env = refresh_env_from_container(env, info)
            env["status"] = "running"
            save_env(project_id, env)
            write_lab_doc_if_ready(project_id, env, via="compose")
            return {"ok": True, "env": env, "via": "compose"}
        image = env.get("image")
        name = env.get("container_name") or lab_container_name(project_id)
        if image:
            proc = _docker_run(["start", name])
            if proc.returncode != 0:
                return {"ok": False, "error": proc.stderr or proc.stdout or "docker start failed", "env": env}
            inspected = _inspect_container([name])
            if inspected:
                _, info = inspected
                env = refresh_env_from_container(env, info)
            env["status"] = "running"
            save_env(project_id, env)
            write_lab_doc_if_ready(project_id, env, via="start")
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

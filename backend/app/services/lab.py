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
LAB_LABEL_KEY = "vulnhunter"
LAB_LABEL_VALUE = "1"
LAB_PROJECT_LABEL_KEY = "vulnhunter.project"
LAB_REPAIRS_DOC = "lab-repairs.md"


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
        "lab_label_args": (
            f"--label {LAB_LABEL_KEY}={LAB_LABEL_VALUE} "
            f"--label {LAB_PROJECT_LABEL_KEY}={pid}"
        ),
    }


def lab_container_labels(project_id: int) -> dict[str, str]:
    return {
        LAB_LABEL_KEY: LAB_LABEL_VALUE,
        LAB_PROJECT_LABEL_KEY: str(int(project_id)),
    }


def lab_name_prefixes(project_id: int, *, project_name: str | None = None) -> list[str]:
    """Current and legacy compose/container prefixes for one project."""
    current = lab_compose_project(project_id, project_name=project_name)
    legacy = _legacy_lab_compose_project(project_id)
    out = [current]
    if legacy not in out:
        out.append(legacy)
    return out


def name_matches_lab_prefix(name: str | None, prefix: str | None) -> bool:
    """True if name is exactly prefix or a sidecar `{prefix}-{role}`."""
    text = str(name or "").lstrip("/")
    base = str(prefix or "").strip()
    if not text or not base:
        return False
    return text == base or text.startswith(f"{base}-")


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


def lab_setup_state(project_id: int) -> tuple[bool, bool]:
    """Return (setup_finished, setup_failed) from one env.json read."""
    env = load_env(project_id)
    finished = _truthy(env.get("setup_finished"))
    failed = finished and not lab_ready(env)
    return finished, failed


def lab_setup_finished(project_id: int) -> bool:
    """True after the dedicated lab round completed (success or skipped)."""
    return lab_setup_state(project_id)[0]


def lab_setup_failed(project_id: int) -> bool:
    """True when the lab round ended without a running accepted env."""
    return lab_setup_state(project_id)[1]


def lab_bring_up_failed(project_id: int) -> bool:
    """True after review-time bring-up exhausted; subsequent reviews stay static until retry."""
    return _truthy(load_env(project_id).get("bring_up_failed"))


def lab_rebuild_requested(project_id: int) -> bool:
    """True when Reviewer handed a false-ready lab back to the setup Agent."""
    return _truthy(load_env(project_id).get("lab_rebuild_requested"))


def lab_had_docker_lab(project_id: int) -> bool:
    """True when a Docker lab was accepted at least once (metadata still present)."""
    env = load_env(project_id)
    if _truthy(env.get("lab_ever_ready")):
        return True
    if _truthy(env.get("accepted")) and (
        env.get("container_name") or env.get("container_id") or env.get("image")
    ):
        return True
    return False


def mark_lab_bring_up_failed(
    project_id: int,
    *,
    reason: str = "",
    via: str = "bring-up",
) -> dict[str, Any]:
    """Record project-level bring-up failure and clear Docker target gate for ConfirmVuln."""
    env = dict(load_env(project_id) or {})
    env["bring_up_failed"] = True
    env["setup_finished"] = True
    env["accepted"] = False
    prev_url = str(env.get("target_url") or "").strip()
    if prev_url:
        env["last_target_url"] = prev_url
    env.pop("target_url", None)
    env["status"] = "bring_up_failed"
    text = str(reason or "").strip() or "靶场拉起失败"
    prev_notes = str(env.get("notes") or "").strip()
    fail_line = f"bring_up_failed: {text}"
    env["notes"] = f"{prev_notes}\n{fail_line}".strip() if prev_notes else fail_line
    env["bring_up_fail_reason"] = text
    save_env(project_id, env)
    write_lab_doc(project_id, env, via=via)
    return env


def clear_lab_bring_up_failed(project_id: int) -> dict[str, Any]:
    env = dict(load_env(project_id) or {})
    changed = False
    for key in ("bring_up_failed", "bring_up_fail_reason"):
        if key in env:
            env.pop(key)
            changed = True
    if changed:
        save_env(project_id, env)
    return env


def reset_lab_setup_for_retry(project_id: int, user_message: str = "") -> dict[str, Any]:
    """Clear setup_finished so reviewer-lab can run again; optional user steering note."""
    env = dict(load_env(project_id) or {})
    env["setup_finished"] = False
    env["bring_up_failed"] = False
    env.pop("bring_up_fail_reason", None)
    env["user_retry_requested"] = True
    text = str(user_message or "").strip()
    if text:
        env["retry_user_message"] = text
    else:
        env.pop("retry_user_message", None)
    save_env(project_id, env)
    return env


def clear_lab_retry_flags(project_id: int) -> None:
    env = dict(load_env(project_id) or {})
    changed = False
    for key in (
        "user_retry_requested",
        "retry_user_message",
        "lab_rebuild_requested",
        "rebuild_requested_by",
    ):
        if key in env:
            env.pop(key)
            changed = True
    if changed:
        save_env(project_id, env)


def lab_repairs_path(project_id: int) -> Path:
    return docs_dir(project_id) / LAB_REPAIRS_DOC


def lab_setup_timeout_streak(project_id: int) -> int:
    try:
        return max(0, int(load_env(project_id).get("lab_setup_timeout_streak") or 0))
    except (TypeError, ValueError):
        return 0


def reset_lab_setup_timeout_streak(project_id: int) -> dict[str, Any]:
    env = dict(load_env(project_id) or {})
    if env.get("lab_setup_timeout_streak"):
        env.pop("lab_setup_timeout_streak", None)
        save_env(project_id, env)
    return env


def increment_lab_setup_timeout_streak(project_id: int) -> int:
    env = dict(load_env(project_id) or {})
    streak = lab_setup_timeout_streak(project_id) + 1
    env["lab_setup_timeout_streak"] = streak
    save_env(project_id, env)
    return streak


def lab_setup_timeouts_exhausted(project_id: int) -> bool:
    from ..config import settings

    threshold = max(1, int(getattr(settings, "lab_setup_timeouts_before_static", 2) or 2))
    return lab_setup_timeout_streak(project_id) >= threshold


def append_lab_repair_record(
    project_id: int,
    *,
    failure_reason: str,
    solution: str,
    source: str = "reviewer",
) -> Path:
    """Append one repair history entry for subsequent lab-setup initial context."""
    path = lab_repairs_path(project_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    block = (
        f"## {ts}（{source}）\n\n"
        f"### 失效原因\n{failure_reason.strip() or '未记录'}\n\n"
        f"### 解决方案\n{solution.strip() or '未记录'}\n\n"
    )
    prev = path.read_text(encoding="utf-8").strip() if path.is_file() else ""
    header = "# 靶场修复记录\n\n" if not prev else ""
    path.write_text(f"{header}{prev}\n\n{block}".strip() + "\n", encoding="utf-8")
    env = dict(load_env(project_id) or {})
    env.pop("pending_lab_repair_failure", None)
    env.pop("pending_lab_repair_write", None)
    save_env(project_id, env)
    return path


def format_lab_repairs_for_prompt(project_id: int, *, max_chars: int = 12000) -> str:
    path = lab_repairs_path(project_id)
    if not path.is_file():
        return ""
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return ""
    if len(text) > max_chars:
        text = "…\n" + text[-max_chars:]
    return (
        "## 历史靶场修复记录（docs/lab-repairs.md）\n"
        "搭建或修复时参考以往失效原因与解决方案，避免重复踩坑。\n\n"
        f"{text}\n"
    )


def handoff_lab_for_repair(
    project_id: int,
    reason: str,
    *,
    source: str = "reviewer",
) -> dict[str, Any]:
    """Reopen reviewer-lab with a fresh timeout budget (streak reset on each handoff)."""
    reset_lab_setup_timeout_streak(project_id)
    env = invalidate_lab_for_rebuild(project_id, reason)
    env["lab_repair_handoff_source"] = str(source or "reviewer").strip() or "reviewer"
    env["pending_lab_repair_failure"] = str(reason or "").strip() or "靶场不可用"
    env.pop("pending_lab_repair_write", None)
    save_env(project_id, env)
    return env


def invalidate_lab_for_rebuild(project_id: int, reason: str) -> dict[str, Any]:
    """Mark a false-ready lab as not ready and reopen the dedicated lab-setup round."""
    env = dict(load_env(project_id) or {})
    env["accepted"] = False
    env["setup_finished"] = False
    env["status"] = "needs_rebuild"
    env["lab_state"] = "setup"
    env["lab_rebuild_requested"] = True
    env["rebuild_requested_by"] = "reviewer"
    env["user_retry_requested"] = True
    env["bring_up_failed"] = False
    env.pop("bring_up_fail_reason", None)
    prev_url = str(env.get("target_url") or "").strip()
    if prev_url:
        env["last_target_url"] = prev_url
    env.pop("target_url", None)
    text = str(reason or "").strip() or "审核判定靶场假就绪"
    env["retry_user_message"] = text
    prev_notes = str(env.get("notes") or "").strip()
    line = f"reviewer_rebuild: {text}"
    env["notes"] = f"{prev_notes}\n{line}".strip() if prev_notes else line
    save_env(project_id, env)
    write_lab_doc(project_id, env, via="reviewer-rebuild")
    return env


def lab_round_complete(project_id: int, state: dict[str, Any] | None = None) -> bool:
    if state and state.get("lab_done"):
        return True
    if lab_setup_finished(project_id):
        return True
    if lab_rebuild_requested(project_id):
        # Reviewer handed back a false-ready lab: do not auto-complete on env.json
        # still looking accepted/running. The setup Agent must FinishLab.
        return False
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
    elif lab_ready(env):
        env["lab_ever_ready"] = True
        env["bring_up_failed"] = False
        env.pop("bring_up_fail_reason", None)
        env.pop("lab_rebuild_requested", None)
        env.pop("rebuild_requested_by", None)
        reset_lab_setup_timeout_streak(project_id)
        failure = str(env.get("pending_lab_repair_failure") or "").strip()
        if failure:
            env["pending_lab_repair_write"] = True
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


def _optional_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _host_port_kwargs(env: dict[str, Any]) -> dict[str, int | None]:
    return {
        "host_port": _optional_int(env.get("host_port")),
        "jdwp_host_port": _optional_int(env.get("jdwp_host_port")),
        "inspect_host_port": _optional_int(env.get("inspect_host_port")),
        "debugpy_host_port": _optional_int(env.get("debugpy_host_port")),
    }


def _apply_port_fields(
    env: dict[str, Any],
    updated: dict[str, int | None],
    *,
    changes: list[str] | None = None,
) -> dict[str, Any]:
    env = dict(env)
    old_host = _optional_int(env.get("host_port"))
    for key, value in updated.items():
        if value is not None:
            env[key] = int(value)
    new_host = _optional_int(env.get("host_port"))
    if new_host is not None:
        if old_host is not None and old_host != new_host:
            url = str(env.get("target_url") or "")
            if f":{old_host}" in url:
                env["target_url"] = url.replace(f":{old_host}", f":{new_host}")
            else:
                env["target_url"] = _target_url_with_port(env.get("target_url"), new_host)
        elif not env.get("target_url"):
            env["target_url"] = f"http://127.0.0.1:{new_host}"
        else:
            env["target_url"] = _target_url_with_port(env.get("target_url"), new_host)
    if changes:
        note = "port remapped: " + "; ".join(changes)
        prev = str(env.get("notes") or "").strip()
        env["notes"] = f"{prev}\n{note}".strip() if prev else note
    return env


def _compose_extra_ports(compose: Path | None) -> list[int]:
    if compose is None or not compose.is_file():
        return []
    try:
        from .lab_ports import extract_compose_host_ports

        return extract_compose_host_ports(compose.read_text(encoding="utf-8"))
    except OSError:
        return []


def _rewrite_compose_file(compose: Path | None, mapping: dict[int, int]) -> int:
    if not compose or not mapping or not compose.is_file():
        return 0
    from .lab_ports import rewrite_compose_host_ports

    text = compose.read_text(encoding="utf-8")
    new_text, n = rewrite_compose_host_ports(text, mapping)
    if n <= 0 or new_text == text:
        return 0
    compose.write_text(new_text, encoding="utf-8")
    return n


def remap_ports_if_needed(
    env: dict[str, Any],
    *,
    compose: Path | None = None,
    force_all: bool = False,
) -> tuple[dict[str, Any], dict[int, int], list[str]]:
    """Remap busy host ports (and optional compose extras); may rewrite compose YAML."""
    from .lab_ports import resolve_host_port_conflicts

    kwargs = _host_port_kwargs(env)
    if not any(v is not None for v in kwargs.values()) and not _compose_extra_ports(compose):
        return env, {}, []
    updated, mapping, changes = resolve_host_port_conflicts(
        **kwargs,
        extra_ports=_compose_extra_ports(compose),
        force_all=force_all,
    )
    if not mapping:
        return env, {}, []
    env = _apply_port_fields(env, updated, changes=changes)
    _rewrite_compose_file(compose, mapping)
    return env, mapping, changes


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


def _compose_file(ed: Path) -> Path | None:
    for name in ("docker-compose.yml", "compose.yml", "docker-compose.yaml"):
        if (ed / name).exists():
            return ed / name
    return None


def recreate_lab(project_id: int, *, mode: str = "full") -> dict[str, Any]:
    """Try to bring up lab from env/ compose or recorded container.

    mode:
      - ``start``: inspect + ``docker start`` only (no compose up / rebuild). Used at review open.
      - ``full``: also ``compose up -d`` or start by image name when the container is missing.
    """
    env = load_env(project_id)
    if not env:
        return {"ok": False, "error": "无 env.json", "error_class": "no_env", "need_agent": False}
    if not docker_available():
        return {"ok": False, "error": "本机无 docker", "error_class": "no_docker", "need_agent": False}
    start_only = str(mode or "full").strip().lower() == "start"
    ed = env_dir(project_id)
    compose = _compose_file(ed)
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
                    return {
                        "ok": False,
                        "error": proc.stderr or proc.stdout or "docker start failed",
                        "env": env,
                        "error_class": "start_failed",
                        "need_agent": True,
                    }
                inspected_after_start = _inspect_container(_container_candidates(project_id, env))
                if inspected_after_start:
                    _, info = inspected_after_start
            env = refresh_env_from_container(env, info)
            if lab_ready(env) or (env.get("accepted") and _container_running(info)):
                env["lab_ever_ready"] = True
                env["bring_up_failed"] = False
                env.pop("bring_up_fail_reason", None)
            save_env(project_id, env)
            via = "reuse" if was_running else "start"
            write_lab_doc_if_ready(project_id, env, via=via)
            return {"ok": True, "env": env, "via": via, "need_agent": False}

        if start_only:
            return {
                "ok": False,
                "error": "容器不存在，审核开场仅允许 docker start，不自动 compose/build",
                "env": env,
                "error_class": "missing",
                "need_agent": bool(compose),
            }

        env, _mapping, _changes = remap_ports_if_needed(env, compose=compose)
        if compose:
            proc = _docker_run(
                ["compose", "-p", lab_compose_project(project_id), "-f", str(compose), "up", "-d"],
                cwd=ed,
                timeout=600,
            )
            if proc.returncode != 0:
                return {
                    "ok": False,
                    "error": proc.stderr or proc.stdout,
                    "env": env,
                    "error_class": "compose_failed",
                    "need_agent": True,
                }
            inspected = _inspect_container(_container_candidates(project_id, env))
            if inspected:
                _, info = inspected
                env = refresh_env_from_container(env, info)
            env["status"] = "running"
            env["lab_ever_ready"] = True
            env["bring_up_failed"] = False
            env.pop("bring_up_fail_reason", None)
            save_env(project_id, env)
            write_lab_doc_if_ready(project_id, env, via="compose")
            return {"ok": True, "env": env, "via": "compose", "need_agent": False}
        image = env.get("image")
        name = env.get("container_name") or lab_container_name(project_id)
        if image:
            proc = _docker_run(["start", name])
            if proc.returncode != 0:
                return {
                    "ok": False,
                    "error": proc.stderr or proc.stdout or "docker start failed",
                    "env": env,
                    "error_class": "start_failed",
                    "need_agent": True,
                }
            inspected = _inspect_container([name])
            if inspected:
                _, info = inspected
                env = refresh_env_from_container(env, info)
            env["status"] = "running"
            env["lab_ever_ready"] = True
            env["bring_up_failed"] = False
            env.pop("bring_up_fail_reason", None)
            save_env(project_id, env)
            write_lab_doc_if_ready(project_id, env, via="start")
            return {"ok": True, "env": env, "via": "start", "need_agent": False}
        return {
            "ok": False,
            "error": "无 compose 且无 image",
            "env": env,
            "error_class": "missing",
            "need_agent": False,
        }
    except Exception as e:  # noqa: BLE001
        return {
            "ok": False,
            "error": str(e),
            "env": env,
            "error_class": "exception",
            "need_agent": False,
        }


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


def _lab_can_start(env: dict[str, Any], compose: Path | None) -> bool:
    if not env:
        return False
    if compose is not None:
        return True
    if env.get("container_id") or env.get("container_name") or env.get("image"):
        return True
    return bool(env.get("accepted"))


def _busy_port_list(env: dict[str, Any], compose: Path | None = None) -> list[int]:
    from .docker_service import docker_service

    kwargs = _host_port_kwargs(env)
    extras = _compose_extra_ports(compose)
    busy: list[int] = []
    seen: set[int] = set()
    for value in (*kwargs.values(), *extras):
        if value is None:
            continue
        port = int(value)
        if port in seen:
            continue
        seen.add(port)
        if docker_service.is_port_in_use(port):
            busy.append(port)
    return busy


def lab_status_payload(
    project_id: int,
    *,
    env: dict[str, Any] | None = None,
    ports_remapped: bool = False,
    port_changes: list[str] | None = None,
    error: str | None = None,
    ok: bool = True,
) -> dict[str, Any]:
    """Build a project-lab status dict for API responses."""
    env = dict(env if env is not None else load_env(project_id))
    ed = env_dir(project_id)
    compose = _compose_file(ed)
    status = str(env.get("status") or "").strip() or "absent"
    running = False
    if docker_available() and env:
        inspected = _inspect_container(_container_candidates(project_id, env))
        if inspected:
            _, info = inspected
            status = _status_from_inspect(info)
            running = _container_running(info)
            env = refresh_env_from_container(env, info)
    conflicts = _busy_port_list(env, compose) if env else []
    can_start = _lab_can_start(env, compose) and docker_available()
    return {
        "ok": ok,
        "has_env": bool(env),
        "can_start": can_start and not running,
        "can_stop": running,
        "status": status if env else "absent",
        "target_url": env.get("target_url"),
        "host_port": _optional_int(env.get("host_port")),
        "jdwp_host_port": _optional_int(env.get("jdwp_host_port")),
        "inspect_host_port": _optional_int(env.get("inspect_host_port")),
        "debugpy_host_port": _optional_int(env.get("debugpy_host_port")),
        "container_name": env.get("container_name"),
        "container_id": env.get("container_id"),
        "image": env.get("image"),
        "runtime": env.get("runtime"),
        "ports_remapped": bool(ports_remapped),
        "port_changes": list(port_changes or []),
        "port_conflicts": conflicts,
        "error": error,
    }


def get_lab_status(project_id: int) -> dict[str, Any]:
    return lab_status_payload(project_id)


def patch_lab_ports(
    project_id: int,
    *,
    host_port: int | None = None,
    jdwp_host_port: int | None = None,
    inspect_host_port: int | None = None,
    debugpy_host_port: int | None = None,
) -> dict[str, Any]:
    """Update env.json host ports only; compose is rewritten on next start if needed."""
    env = load_env(project_id)
    if not env:
        return lab_status_payload(project_id, ok=False, error="无 env.json")
    updated: dict[str, int | None] = {}
    if host_port is not None:
        updated["host_port"] = int(host_port)
    if jdwp_host_port is not None:
        updated["jdwp_host_port"] = int(jdwp_host_port)
    if inspect_host_port is not None:
        updated["inspect_host_port"] = int(inspect_host_port)
    if debugpy_host_port is not None:
        updated["debugpy_host_port"] = int(debugpy_host_port)
    if not updated:
        return lab_status_payload(project_id, env=env)
    env = _apply_port_fields(env, updated)
    save_env(project_id, env)
    if lab_ready(env) or env.get("accepted"):
        write_lab_doc(project_id, env, via="port-patch")
    return lab_status_payload(project_id, env=env)


def _remove_lab_containers(project_id: int, env: dict[str, Any]) -> None:
    """Force-remove primary + same-prefix containers so compose can rebind ports."""
    from .docker_service import docker_service, collect_project_refs

    refs = [r for r in collect_project_refs() if r.id == int(project_id)]
    for item in docker_service.list_containers(refs, running_only=False):
        if item.get("project_id") != int(project_id):
            continue
        try:
            docker_service.remove(item["id"], force=True)
        except Exception:  # noqa: BLE001
            pass
    for candidate in _container_candidates(project_id, env):
        proc = _docker_run(["rm", "-f", str(candidate)], timeout=60)
        _ = proc


def _compose_up_lab(project_id: int, compose: Path, ed: Path) -> subprocess.CompletedProcess[str]:
    return _docker_run(
        [
            "compose",
            "-p",
            lab_compose_project(project_id),
            "-f",
            str(compose),
            "up",
            "-d",
            "--remove-orphans",
        ],
        cwd=ed,
        timeout=600,
    )


def _user_recreate_lab(
    project_id: int,
    *,
    force_all: bool = False,
) -> dict[str, Any]:
    """Remap ports, rewrite compose, compose up (no --build). Used by one-click start."""
    from .lab_ports import looks_like_port_conflict

    env = load_env(project_id)
    if not env:
        return lab_status_payload(project_id, ok=False, error="无 env.json")
    if not docker_available():
        return lab_status_payload(project_id, env=env, ok=False, error="本机无 docker")

    ed = env_dir(project_id)
    compose = _compose_file(ed)
    all_changes: list[str] = []
    remapped = False

    env, mapping, changes = remap_ports_if_needed(env, compose=compose, force_all=force_all)
    if mapping:
        remapped = True
        all_changes.extend(changes)
        _remove_lab_containers(project_id, env)
        save_env(project_id, env)

    def _bring_up() -> tuple[bool, str]:
        if compose:
            proc = _compose_up_lab(project_id, compose, ed)
            if proc.returncode != 0:
                return False, (proc.stderr or proc.stdout or "compose up failed").strip()
            return True, ""
        name = env.get("container_name") or lab_container_name(project_id)
        image = env.get("image")
        if not image and not name:
            return False, "无 compose 且无 image/container_name"
        # Prefer recreate via compose; without compose try start by name
        proc = _docker_run(["start", str(name)])
        if proc.returncode != 0:
            return False, (proc.stderr or proc.stdout or "docker start failed").strip()
        return True, ""

    ok_up, err = _bring_up()
    if not ok_up and looks_like_port_conflict(err) and not force_all:
        env, mapping, changes = remap_ports_if_needed(env, compose=compose, force_all=True)
        if mapping:
            remapped = True
            all_changes.extend(changes)
        _remove_lab_containers(project_id, env)
        save_env(project_id, env)
        ok_up, err = _bring_up()

    if not ok_up:
        save_env(project_id, env)
        return lab_status_payload(
            project_id,
            env=env,
            ok=False,
            error=err or "启动失败",
            ports_remapped=remapped,
            port_changes=all_changes,
        )

    inspected = _inspect_container(_container_candidates(project_id, env))
    if inspected:
        _, info = inspected
        env = refresh_env_from_container(env, info)
    env["status"] = "running"
    env["accepted"] = True
    env["lab_ever_ready"] = True
    env["bring_up_failed"] = False
    env.pop("bring_up_fail_reason", None)
    save_env(project_id, env)
    write_lab_doc_if_ready(project_id, env, via="user-start")
    return lab_status_payload(
        project_id,
        env=env,
        ports_remapped=remapped,
        port_changes=all_changes,
    )


def start_lab(project_id: int, *, force_recreate: bool = False) -> dict[str, Any]:
    """One-click start: docker start when possible, else remap + compose up."""
    from .lab_ports import any_host_ports_in_use, looks_like_port_conflict

    env = load_env(project_id)
    if not env:
        return lab_status_payload(project_id, ok=False, error="无 env.json")
    if not docker_available():
        return lab_status_payload(project_id, env=env, ok=False, error="本机无 docker")

    ed = env_dir(project_id)
    compose = _compose_file(ed)
    if not _lab_can_start(env, compose):
        return lab_status_payload(
            project_id,
            env=env,
            ok=False,
            error="无可用靶场产物，请先完成环境搭建",
        )

    ports_busy = any_host_ports_in_use(
        **_host_port_kwargs(env),
        extra_ports=_compose_extra_ports(compose),
    )
    inspected = _inspect_container(_container_candidates(project_id, env))

    if force_recreate:
        return _user_recreate_lab(project_id, force_all=ports_busy)

    if inspected:
        identifier, info = inspected
        if _container_running(info):
            env = refresh_env_from_container(env, info)
            env["lab_ever_ready"] = True
            env["bring_up_failed"] = False
            env.pop("bring_up_fail_reason", None)
            save_env(project_id, env)
            write_lab_doc_if_ready(project_id, env, via="reuse")
            return lab_status_payload(project_id, env=env)

        if ports_busy:
            return _user_recreate_lab(project_id, force_all=False)

        proc = _docker_run(["start", identifier])
        if proc.returncode != 0:
            err = (proc.stderr or proc.stdout or "docker start failed").strip()
            return _user_recreate_lab(
                project_id,
                force_all=looks_like_port_conflict(err),
            )
        inspected_after = _inspect_container(_container_candidates(project_id, env))
        if inspected_after:
            _, info = inspected_after
            if _container_running(info):
                env = refresh_env_from_container(env, info)
                env["lab_ever_ready"] = True
                env["bring_up_failed"] = False
                env.pop("bring_up_fail_reason", None)
                save_env(project_id, env)
                write_lab_doc_if_ready(project_id, env, via="start")
                return lab_status_payload(project_id, env=env)
        # started but not running → recreate
        return _user_recreate_lab(project_id, force_all=False)

    # container absent
    return _user_recreate_lab(project_id, force_all=False)


def stop_lab(project_id: int, *, via: str = "user-stop") -> dict[str, Any]:
    """Stop primary lab container and project sidecars; update env.json status."""
    from .docker_service import docker_service, collect_project_refs

    env = load_env(project_id)
    if not env:
        return lab_status_payload(project_id, ok=False, error="无 env.json")
    if not docker_available():
        return lab_status_payload(project_id, env=env, ok=False, error="本机无 docker")

    refs = [r for r in collect_project_refs() if r.id == int(project_id)]
    items = docker_service.list_containers(refs, running_only=False)
    errors: list[str] = []
    stopped_any = False
    for item in items:
        if item.get("project_id") != int(project_id):
            continue
        try:
            status = docker_service.stop(item["id"])
            stopped_any = True
            _ = status
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{item.get('name') or item.get('id')}: {exc}")

    # Fallback: stop by recorded names
    if not stopped_any:
        for candidate in _container_candidates(project_id, env):
            proc = _docker_run(["stop", str(candidate)], timeout=60)
            if proc.returncode == 0:
                stopped_any = True

    inspected = _inspect_container(_container_candidates(project_id, env))
    if inspected:
        _, info = inspected
        env = refresh_env_from_container(env, info)
    else:
        env = dict(env)
        env["status"] = "exited"
    save_env(project_id, env)
    write_lab_doc(project_id, env, via=via)
    err = "; ".join(errors) if errors else None
    return lab_status_payload(project_id, env=env, ok=not errors, error=err)

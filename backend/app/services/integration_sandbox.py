"""Integration sandbox: writable container with bridge network for L3 verify."""

from __future__ import annotations

import logging
import tempfile
import threading
from pathlib import Path
from typing import Any

from ..config import settings
from .lab import LAB_LABEL_KEY, LAB_LABEL_VALUE
from .paths import data_tmp_dir

logger = logging.getLogger(__name__)

_lock = threading.Lock()
_client = None
_init_error = ""
_initialized = False

_INTEGRATION_TMPFS: dict[str, str] = {
    "/tmp": "rw,exec,nosuid,nodev,size=512m,mode=1777",
    "/home/sandbox": "rw,exec,nosuid,nodev,size=128m,mode=1777",
}


def integration_image() -> str:
    return (settings.integration_sandbox_image or "vulnhunter/integration-sandbox:latest").strip()


def _connect():
    global _client, _init_error, _initialized
    with _lock:
        if _initialized:
            return _client, _init_error
        _initialized = True
        try:
            import docker  # noqa: PLC0415
        except ImportError as exc:
            _init_error = f"未安装 docker SDK: {exc}"
            return None, _init_error
        try:
            client = docker.from_env()
            client.ping()
            _client = client
            _init_error = ""
            return _client, _init_error
        except Exception as exc:  # noqa: BLE001
            _init_error = f"{type(exc).__name__}: {exc}"
            return None, _init_error


def reset_integration_client() -> None:
    global _client, _init_error, _initialized
    with _lock:
        _client = None
        _init_error = ""
        _initialized = False


def integration_available() -> bool:
    client, _err = _connect()
    return client is not None


def integration_diagnosis() -> dict[str, Any]:
    client, err = _connect()
    image = integration_image()
    present = False
    if client is not None:
        try:
            client.images.get(image)
            present = True
        except Exception:  # noqa: BLE001
            present = False
    return {
        "available": client is not None,
        "image": image,
        "image_present": present,
        "error": err,
        "network_mode": "bridge",
    }


def _clip(text: str | bytes, limit: int = 8000) -> str:
    if isinstance(text, bytes):
        raw = text.decode("utf-8", errors="replace")
    else:
        raw = text or ""
    if len(raw) <= limit:
        return raw
    return raw[:limit] + f"\n...[truncated {len(raw) - limit} chars]"


def build_integration_script(
    *,
    setup_commands: list[str],
    start_command: str,
    poc_filename: str = "poc.py",
) -> str:
    setup_lines = "\n".join(f"  {line}" for line in setup_commands if str(line).strip())
    setup_block = ""
    if setup_lines:
        setup_block = (
            "echo '[integration] setup'\n"
            f"{setup_lines}\n"
            "SETUP_RC=$?\n"
            'if [ "$SETUP_RC" -ne 0 ]; then echo "setup failed: $SETUP_RC"; exit "$SETUP_RC"; fi\n'
        )
    return f"""#!/bin/bash
set -euo pipefail
PORT="${{INTEGRATION_PORT:-$(python3 -c 'import random; print(random.randint(25000, 45000))')}}"
export PORT
cd /workspace
{setup_block}echo "[integration] starting service on 127.0.0.1:$PORT"
{start_command} &
SVC_PID=$!
cleanup() {{
  if kill -0 "$SVC_PID" 2>/dev/null; then kill "$SVC_PID" 2>/dev/null || true; fi
}}
trap cleanup EXIT
python3 - <<'PY'
import socket, time, sys
port = int(__import__("os").environ.get("PORT", "0"))
deadline = time.time() + 90
while time.time() < deadline:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1):
            sys.exit(0)
    except OSError:
        time.sleep(0.5)
print(f"service not listening on 127.0.0.1:{{port}}", file=sys.stderr)
sys.exit(1)
PY
TARGET="http://127.0.0.1:$PORT"
echo "[integration] running poc against $TARGET"
python3 "/vuln/{poc_filename}" -u "$TARGET" --proxy ""
POC_RC=$?
exit $POC_RC
"""


def run_integration_sandbox(
    *,
    workspace_host: Path,
    poc_host: Path,
    setup_commands: list[str],
    start_command: str,
    timeout: int | None = None,
) -> dict[str, Any]:
    """Run setup + service + poc inside an integration sandbox container."""
    timeout = max(30, min(int(timeout or settings.integration_timeout_sec or 180), 600))
    diagnosis = integration_diagnosis()
    if not diagnosis["available"]:
        return {
            "ok": False,
            "error": f"Docker 不可用，无法启动 integration 沙箱。{diagnosis.get('error') or ''}".strip(),
            "runtime": "sandbox",
            "sandbox": diagnosis,
        }
    if not diagnosis["image_present"]:
        image = diagnosis["image"]
        return {
            "ok": False,
            "error": (
                f"integration 沙箱镜像 {image} 不在本机 Docker 中。"
                "请先构建：docker build -t vulnhunter/integration-sandbox:latest docker/integration-sandbox"
            ),
            "runtime": "sandbox",
            "sandbox": diagnosis,
        }
    if not workspace_host.is_dir():
        return {"ok": False, "error": f"项目 src 目录不存在: {workspace_host}", "runtime": "sandbox"}
    if not poc_host.is_file():
        return {"ok": False, "error": f"poc 文件不存在: {poc_host}", "runtime": "sandbox"}
    if not str(start_command or "").strip():
        return {"ok": False, "error": "integration 验证缺少 integration_start 启动命令", "runtime": "sandbox"}

    client, _err = _connect()
    assert client is not None
    work = tempfile.TemporaryDirectory(prefix="vh-integration-", dir=str(data_tmp_dir("integration")))
    try:
        host_dir = Path(work.name)
        script = build_integration_script(
            setup_commands=setup_commands,
            start_command=str(start_command).strip(),
            poc_filename=poc_host.name,
        )
        (host_dir / "integration_run.sh").write_text(script, encoding="utf-8")
        container = None
        try:
            container = client.containers.run(
                image=integration_image(),
                command=["bash", "/runner/integration_run.sh"],
                detach=True,
                labels={
                    LAB_LABEL_KEY: LAB_LABEL_VALUE,
                    "vulnhunter.kind": "integration-sandbox",
                },
                mem_limit=settings.sandbox_memory,
                cpu_period=100000,
                cpu_quota=int(100000 * float(settings.sandbox_cpus)),
                network_mode="bridge",
                user="1000:1000",
                read_only=False,
                cap_drop=["ALL"],
                security_opt=["no-new-privileges:true"],
                volumes={
                    str(workspace_host.resolve()): {"bind": "/workspace", "mode": "rw"},
                    str(poc_host.parent.resolve()): {"bind": "/vuln", "mode": "ro"},
                    str(host_dir.resolve()): {"bind": "/runner", "mode": "ro"},
                },
                tmpfs=dict(_INTEGRATION_TMPFS),
                working_dir="/workspace",
                environment={
                    "HOME": "/home/sandbox",
                    "TMPDIR": "/tmp",
                    "HTTP_PROXY": "",
                    "HTTPS_PROXY": "",
                    "NO_PROXY": "*",
                },
            )
            result = container.wait(timeout=timeout)
            stdout = _clip(container.logs(stdout=True, stderr=False) or b"")
            stderr = _clip(container.logs(stdout=False, stderr=True) or b"", limit=4000)
            exit_code = int(result.get("StatusCode") or 0)
            ok = exit_code == 0
            out: dict[str, Any] = {
                "ok": ok,
                "exit_code": exit_code,
                "stdout": stdout,
                "stderr": stderr,
                "runtime": "sandbox",
                "sandbox": diagnosis,
            }
            if not ok:
                out["error"] = (
                    f"integration 沙箱验证未通过（退出码 {exit_code}）。"
                    "请检查 integration_setup / integration_start 与 poc.py。"
                )
            return out
        except Exception as exc:  # noqa: BLE001
            name = type(exc).__name__
            if container is not None:
                try:
                    container.kill()
                except Exception:  # noqa: BLE001
                    pass
            if "timeout" in name.lower() or "Timeout" in name:
                return {
                    "ok": False,
                    "error": f"integration 沙箱执行超时（{timeout}s）",
                    "stdout": "",
                    "stderr": "",
                    "exit_code": -1,
                    "runtime": "sandbox",
                    "sandbox": diagnosis,
                }
            logger.warning("integration sandbox failed: %s", exc)
            return {
                "ok": False,
                "error": f"integration 沙箱执行失败: {exc}",
                "stdout": "",
                "stderr": "",
                "exit_code": -1,
                "runtime": "sandbox",
                "sandbox": diagnosis,
            }
        finally:
            if container is not None:
                try:
                    container.remove(force=True)
                except Exception:  # noqa: BLE001
                    pass
    finally:
        try:
            work.cleanup()
        except OSError:
            pass

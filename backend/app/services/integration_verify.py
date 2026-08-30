"""L3 integration verify: sandbox service + loopback poc, with host fallback."""

from __future__ import annotations

import logging
from typing import Any

from ..config import settings
from ..harness_depth import INTEGRATION_RUNTIME_HOST_FALLBACK, INTEGRATION_RUNTIME_SANDBOX
from .integration_sandbox import integration_available, run_integration_sandbox
from .lab import load_env
from .loopback_url import extract_loopback_urls, is_loopback_url, loopback_url_error
from .paths import project_root, src_dir, vuln_dir
from .poc_run import POC_RUN_FAIL_HINT, execute_poc_text
from .poc_script import poc_lab_run_block_reason, poc_path, read_poc_code

logger = logging.getLogger(__name__)


def resolve_integration_target_url(project_id: int) -> str | None:
    """Loopback URL for host fallback: env.local_service_url or manual notes."""
    env = load_env(project_id)
    direct = str(env.get("local_service_url") or "").strip()
    if is_loopback_url(direct):
        return direct
    for key in ("manual_notes", "notes"):
        for url in extract_loopback_urls(str(env.get(key) or "")):
            return url
    return None


def _parse_setup_commands(raw: Any) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, list):
        return [str(x).strip() for x in raw if str(x).strip()]
    text = str(raw).strip()
    if not text:
        return []
    return [line.strip() for line in text.splitlines() if line.strip()]


def run_integration_verify(
    project_id: int,
    vuln_id: int,
    poc_code: str,
    *,
    setup_commands: list[str] | None = None,
    start_command: str = "",
    allow_host_fallback: bool = True,
    timeout: int | None = None,
) -> dict[str, Any]:
    """Run L3 integration verify. Prefer sandbox; optional host loopback fallback."""
    blocked = poc_lab_run_block_reason(poc_code)
    if blocked:
        return {"ok": False, "error": blocked, "hint": POC_RUN_FAIL_HINT}

    setup = list(setup_commands or [])
    start = str(start_command or "").strip()
    vdir = vuln_dir(project_id, int(vuln_id))
    vdir.mkdir(parents=True, exist_ok=True)
    poc_file = poc_path(project_id, int(vuln_id))
    poc_file.write_text(poc_code, encoding="utf-8")

    if integration_available() and start:
        sandbox_out = run_integration_sandbox(
            workspace_host=src_dir(project_id),
            poc_host=poc_file,
            setup_commands=setup,
            start_command=start,
            timeout=timeout,
        )
        if sandbox_out.get("ok"):
            sandbox_out["runtime"] = INTEGRATION_RUNTIME_SANDBOX
            sandbox_out["target_url"] = "http://127.0.0.1:<sandbox>"
            return sandbox_out
        if not allow_host_fallback:
            return sandbox_out

    if not allow_host_fallback:
        return {
            "ok": False,
            "error": "integration 沙箱不可用且未启用本机 fallback",
            "runtime": INTEGRATION_RUNTIME_SANDBOX,
        }

    target = resolve_integration_target_url(project_id)
    if not target:
        err = (
            "integration 沙箱未跑通且无 loopback local_service_url。"
            "请在 env/env.json 写入 local_service_url（127.0.0.1），"
            "或提供 integration_start 让沙箱起服务。"
        )
        if integration_available() and not start:
            err = "integration 验证须提供 integration_start 启动命令，或配置 local_service_url。"
        return {"ok": False, "error": err, "runtime": INTEGRATION_RUNTIME_HOST_FALLBACK}
    url_err = loopback_url_error(target)
    if url_err:
        return {"ok": False, "error": url_err, "runtime": INTEGRATION_RUNTIME_HOST_FALLBACK}

    logger.info(
        "integration host fallback project=%s vuln=%s target=%s",
        project_id,
        vuln_id,
        target,
    )
    host_out = execute_poc_text(
        poc_code,
        target_url=target,
        cwd=project_root(project_id),
        timeout=timeout or settings.integration_timeout_sec,
        project_id=project_id,
    )
    host_out["runtime"] = INTEGRATION_RUNTIME_HOST_FALLBACK
    return host_out


def verify_landed_integration(
    project_id: int,
    vuln_id: int,
    poc_code: str,
    *,
    setup_commands: list[str] | None = None,
    start_command: str = "",
) -> dict[str, Any]:
    landed = str(poc_code or "").strip() or (read_poc_code(project_id, int(vuln_id)) or "")
    if not landed:
        return {"ok": False, "error": "integration 验证需要 poc.py"}
    return run_integration_verify(
        project_id,
        int(vuln_id),
        landed,
        setup_commands=setup_commands,
        start_command=start_command,
    )

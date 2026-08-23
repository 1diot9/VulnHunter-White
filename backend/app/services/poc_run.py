"""Execute a landed poc.py against the current lab / manual target."""

from __future__ import annotations

import logging
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from .asset_proof import lab_target_urls
from .lab import load_env
from .paths import project_root
from .poc_script import poc_lab_run_block_reason

logger = logging.getLogger(__name__)

POC_RUN_TIMEOUT = 90
POC_RUN_MAX_OUTPUT = 8000
_PROXY_ENV_KEYS = frozenset({"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"})

POC_RUN_FAIL_HINT = (
    "打出预期冲击须退出码 0。Write 修好 poc.py 后再次 ConfirmVuln 并传 poc_code；"
    "默认可利用不成立则 MarkFalsePositive。不要 ReturnToWorker 改 PoC。"
)


def resolve_lab_target_url(project_id: int) -> str | None:
    """Prefer a running Docker lab URL; else the first manual/lab URL. Skip stale Docker URLs after bring-up failure."""
    from .lab import lab_bring_up_failed, lab_ready, load_env

    env = load_env(project_id)
    if lab_ready(env) and not lab_bring_up_failed(project_id):
        target = str((env or {}).get("target_url") or "").strip()
        if target:
            return target
    urls = lab_target_urls(project_id)
    return urls[0] if urls else None


def _clean_env() -> dict[str, str]:
    env = os.environ.copy()
    for key in list(env):
        if key.upper() in _PROXY_ENV_KEYS:
            env.pop(key, None)
    env["PYTHONUNBUFFERED"] = "1"
    return env


def _clip(text: str, limit: int = POC_RUN_MAX_OUTPUT) -> str:
    raw = text or ""
    if len(raw) <= limit:
        return raw
    return raw[:limit] + f"\n...[truncated {len(raw) - limit} chars]"


def execute_poc_file(
    script: Path,
    *,
    target_url: str,
    cwd: Path | None = None,
    timeout: int = POC_RUN_TIMEOUT,
) -> dict[str, Any]:
    """Run `python poc.py -u <target_url>` with empty --proxy (direct to lab)."""
    cmd = [sys.executable, "-u", str(script), "-u", target_url, "--proxy", ""]
    workdir = str(cwd or script.parent)
    try:
        proc = subprocess.run(
            cmd,
            cwd=workdir,
            capture_output=True,
            timeout=max(1, int(timeout)),
            check=False,
            env=_clean_env(),
        )
    except subprocess.TimeoutExpired as exc:
        stdout = _clip((exc.stdout or b"").decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else str(exc.stdout or ""))
        stderr = _clip((exc.stderr or b"").decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else str(exc.stderr or ""))
        return {
            "ok": False,
            "timed_out": True,
            "exit_code": None,
            "target_url": target_url,
            "stdout": stdout,
            "stderr": stderr or f"poc.py 超过 {timeout}s 未结束",
            "error": f"poc.py 对 {target_url} 执行超时（{timeout}s）",
            "hint": POC_RUN_FAIL_HINT,
        }
    except OSError as exc:
        return {
            "ok": False,
            "timed_out": False,
            "exit_code": None,
            "target_url": target_url,
            "stdout": "",
            "stderr": str(exc),
            "error": f"无法启动 poc.py: {exc}",
            "hint": POC_RUN_FAIL_HINT,
        }
    stdout = _clip(proc.stdout.decode("utf-8", errors="replace"))
    stderr = _clip(proc.stderr.decode("utf-8", errors="replace"))
    ok = proc.returncode == 0
    out: dict[str, Any] = {
        "ok": ok,
        "timed_out": False,
        "exit_code": int(proc.returncode),
        "target_url": target_url,
        "stdout": stdout,
        "stderr": stderr,
    }
    if not ok:
        out["error"] = (
            f"落盘 poc.py 对 {target_url} 未打出冲击（退出码 {proc.returncode}）。"
            "脚本须在利用成功时退出 0，失败时非 0。"
        )
        out["hint"] = POC_RUN_FAIL_HINT
    return out


def execute_poc_text(
    code: str,
    *,
    target_url: str,
    cwd: Path,
    timeout: int = POC_RUN_TIMEOUT,
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="vulnhunter-poc-") as tmp:
        path = Path(tmp) / "poc.py"
        path.write_text(code, encoding="utf-8")
        return execute_poc_file(path, target_url=target_url, cwd=cwd, timeout=timeout)


def verify_landed_poc(
    project_id: int,
    vuln_id: int,
    poc_code: str,
    *,
    timeout: int = POC_RUN_TIMEOUT,
) -> dict[str, Any]:
    """Shape-check then run the PoC that ConfirmVuln is about to persist."""
    blocked = poc_lab_run_block_reason(poc_code)
    if blocked:
        return {"ok": False, "error": blocked, "hint": POC_RUN_FAIL_HINT}
    target = resolve_lab_target_url(project_id)
    if not target:
        return {"ok": False, "error": "无 target_url", "skipped": True}
    logger.info("running landed poc.py project=%s vuln=%s target=%s", project_id, vuln_id, target)
    return execute_poc_text(
        poc_code,
        target_url=target,
        cwd=project_root(project_id),
        timeout=timeout,
    )

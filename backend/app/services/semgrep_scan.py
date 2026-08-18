"""Run Semgrep against a project src tree (host binary or Docker)."""

from __future__ import annotations

import json
import shutil
import subprocess
from json import JSONDecoder
from pathlib import Path
from typing import Any

from ..config import settings
from .paths import src_dir, workspace_dir

DEFAULT_CONFIGS = ("p/security-audit", "p/owasp-top-ten")
EXT_PACKS = {
    ".java": "p/java",
    ".py": "p/python",
    ".js": "p/javascript",
    ".jsx": "p/javascript",
    ".ts": "p/typescript",
    ".tsx": "p/typescript",
    ".go": "p/go",
    ".php": "p/php",
    ".rb": "p/ruby",
}
SEMGREP_IMAGE = "returntocorp/semgrep:latest"


class SemgrepUnavailable(RuntimeError):
    """Neither host semgrep nor docker is available."""


def language_configs(extensions: list[str]) -> list[str]:
    configs = list(DEFAULT_CONFIGS)
    seen = set(configs)
    for ext in extensions:
        pack = EXT_PACKS.get(str(ext or "").lower())
        if pack and pack not in seen:
            configs.append(pack)
            seen.add(pack)
    return configs


def resolve_semgrep_command() -> tuple[str, list[str]]:
    host = shutil.which("semgrep")
    if host:
        return "host", [host]
    if shutil.which("docker"):
        return "docker", ["docker"]
    raise SemgrepUnavailable("未找到 semgrep 或 docker，无法运行快速扫描")


def _extract_json(text: str) -> dict[str, Any]:
    raw = str(text or "").strip()
    if not raw:
        return {}
    decoder = JSONDecoder()
    for marker in ('{"version"', '{"paths"', '{"results"', '{"errors"'):
        start = raw.find(marker)
        while start >= 0:
            try:
                payload, _end = decoder.raw_decode(raw[start:])
            except json.JSONDecodeError:
                start = raw.find(marker, start + 1)
                continue
            if isinstance(payload, dict):
                return payload
            start = raw.find(marker, start + 1)
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def run_semgrep_scan(
    project_id: int,
    *,
    configs: list[str] | None = None,
    timeout_sec: int | None = None,
) -> dict[str, Any]:
    src = src_dir(project_id)
    if not src.is_dir():
        raise FileNotFoundError(f"源码目录不存在: {src}")
    kind, prefix = resolve_semgrep_command()
    scan_configs = [c for c in (configs or []) if str(c).strip()]
    if not scan_configs:
        scan_configs = list(DEFAULT_CONFIGS)
    timeout = max(60, int(timeout_sec or settings.timeout_semgrep))
    out_path = workspace_dir(project_id) / "semgrep.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        out_path.unlink()
    except FileNotFoundError:
        pass
    args: list[str] = []
    if kind == "docker":
        args = [
            *prefix,
            "run",
            "--rm",
            "-v",
            f"{src.resolve()}:/src",
            "-v",
            f"{out_path.parent.resolve()}:/out",
            "-w",
            "/src",
            SEMGREP_IMAGE,
            "semgrep",
            "scan",
        ]
        json_out = "/out/semgrep.json"
    else:
        args = [*prefix, "scan"]
        json_out = str(out_path)
    for cfg in scan_configs:
        args.extend(["--config", cfg])
    args.extend(["--json", "--metrics=off", "--oss-only", "-o", json_out, "."])
    proc = subprocess.run(
        args,
        cwd=str(src if kind == "host" else Path.cwd()),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )
    payload: dict[str, Any] = {}
    if out_path.is_file():
        payload = _extract_json(out_path.read_text(encoding="utf-8", errors="replace"))
    if not payload:
        payload = _extract_json(proc.stdout or "")
    if not payload:
        payload = _extract_json(proc.stderr or "")
    results = payload.get("results") if isinstance(payload.get("results"), list) else []
    if proc.returncode not in (0, 1) or (proc.returncode == 1 and not results):
        err = (proc.stderr or proc.stdout or f"semgrep exit {proc.returncode}").strip()
        raise RuntimeError(err[:2000])
    payload["results"] = results
    out_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    payload["_artifact"] = "workspace/semgrep.json"
    payload["_runner"] = kind
    payload["_returncode"] = proc.returncode
    return payload

"""PoC script conventions: CLI-parameterized, reusable against arbitrary targets."""

from __future__ import annotations

import re
from pathlib import Path

from .paths import vuln_dir

_URL_FLAG_RE = re.compile(r"""(?:--url\b|["']-u["'])""")
_HTTP_HINT_RE = re.compile(
    r"requests\.|httpx\.|urllib|aiohttp|http\.client",
    re.I,
)

POC_CLI_ERROR = (
    "poc_code 必须用 argparse 接收目标（-u/--url），不要写死地址；"
    "RCE 另须支持 -c/--cmd，有回显须打印命令输出。"
)


def poc_cli_block_reason(poc_code: str | None) -> str | None:
    """Reject HTTP-looking PoCs that hardcode the target instead of taking -u/--url."""
    text = poc_code or ""
    if not text.strip() or not _HTTP_HINT_RE.search(text):
        return None
    lower = text.lower()
    if _URL_FLAG_RE.search(text) or ("add_argument" in lower and "url" in lower):
        return None
    return POC_CLI_ERROR


def poc_path(project_id: int, vuln_id: int) -> Path:
    return vuln_dir(project_id, vuln_id) / "poc.py"


def write_poc_code(project_id: int, vuln_id: int, poc_code: str) -> Path:
    path = poc_path(project_id, vuln_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(poc_code, encoding="utf-8")
    return path


_HARNESS_NAMES = {
    "python": "harness.py",
    "python3": "harness.py",
    "py": "harness.py",
    "php": "harness.php",
    "javascript": "harness.js",
    "js": "harness.js",
    "node": "harness.js",
    "ruby": "harness.rb",
    "rb": "harness.rb",
    "go": "harness.go",
    "golang": "harness.go",
    "java": "Harness.java",
    "bash": "harness.sh",
    "sh": "harness.sh",
    "shell": "harness.sh",
}


def harness_filename(language: str | None = None) -> str:
    key = (language or "python").strip().lower()
    return _HARNESS_NAMES.get(key, "harness.py")


def harness_path(project_id: int, vuln_id: int, *, language: str | None = None) -> Path:
    return vuln_dir(project_id, vuln_id) / harness_filename(language)


def write_harness_code(
    project_id: int,
    vuln_id: int,
    harness_code: str,
    *,
    language: str | None = None,
) -> Path:
    path = harness_path(project_id, vuln_id, language=language)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(harness_code, encoding="utf-8")
    return path


def read_poc_code(project_id: int, vuln_id: int, fallback: str | None = None) -> str | None:
    path = poc_path(project_id, vuln_id)
    if path.is_file():
        return path.read_text(encoding="utf-8", errors="ignore")
    return fallback

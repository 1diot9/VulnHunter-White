"""PoC script conventions: CLI-parameterized, reusable against arbitrary targets."""

from __future__ import annotations

import re
from pathlib import Path

from .paths import vuln_dir

_URL_FLAG_RE = re.compile(r"""(?:--url\b|["']-u["'])""")
_PROXY_FLAG_RE = re.compile(r"""(?:--proxy\b)""")
_FORCE_LOCAL_PROXY_RE = re.compile(
    r"proxy_bypass|should_bypass_proxies|never_bypass|trust_env",
    re.I,
)
_SSL_HANDLING_RE = re.compile(
    r"check_hostname|CERT_NONE|verify\s*=\s*False|--strict-ssl|HTTPSHandler\s*\(\s*context\s*=",
    re.I,
)
_HTTP_HINT_RE = re.compile(
    r"requests\.|httpx\.|urllib|aiohttp|http\.client",
    re.I,
)

POC_CLI_ERROR = (
    "poc_code 必须用 argparse 接收目标（-u/--url）和 HTTP 代理（--proxy，空则直连），"
    "不要写死地址或代理；有 --proxy 时 127.0.0.1/localhost 也必须强制走代理"
    "（覆盖 urllib.request.proxy_bypass，勿让本机地址旁路）；"
    "HTTPS 须默认跳过证书校验并在 https:// 目标打印告警（--strict-ssl 可选恢复校验）；"
    "RCE 另须支持 -c/--cmd，有回显须打印命令输出；脚本自身打印与注释须用英语。"
)

POC_LAB_RUN_ERROR = (
    "靶场动态确认时 poc.py 必须可独立运行，并用 argparse 接收 -u/--url；"
    "ConfirmVuln 会执行 python poc.py -u <target_url>，打出预期冲击须退出码 0。"
)


def _has_url_flag(text: str) -> bool:
    lower = text.lower()
    return bool(_URL_FLAG_RE.search(text) or ("add_argument" in lower and "url" in lower))


def _has_proxy_flag(text: str) -> bool:
    return bool(_PROXY_FLAG_RE.search(text))


def poc_cli_block_reason(poc_code: str | None, *, target_kind: str | None = None) -> str | None:
    """Reject HTTP-looking PoCs that omit -u/--url, --proxy, or localhost force-proxy.

    For library/mixed component audits, library-style PoCs (no HTTP client) are allowed
    without forcing -u/--url; HTTP-shaped scripts still follow the web CLI contract.
    """
    from ..target_kind import is_component_target

    text = poc_code or ""
    if not text.strip():
        return None
    if is_component_target(target_kind) and not _HTTP_HINT_RE.search(text):
        return None
    if not _HTTP_HINT_RE.search(text):
        return None
    if (
        _has_url_flag(text)
        and _has_proxy_flag(text)
        and _FORCE_LOCAL_PROXY_RE.search(text)
        and _SSL_HANDLING_RE.search(text)
    ):
        return None
    if is_component_target(target_kind):
        # Component audits may ship API-call PoCs that import requests only for
        # optional demos; do not force full HTTP CLI when kind is library/mixed.
        return None
    return POC_CLI_ERROR


def poc_lab_run_block_reason(poc_code: str | None) -> str | None:
    """Reject PoCs that cannot be executed against a lab target_url."""
    text = poc_code or ""
    if not text.strip():
        return POC_LAB_RUN_ERROR
    if not _has_url_flag(text):
        return POC_LAB_RUN_ERROR
    return poc_cli_block_reason(text)


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

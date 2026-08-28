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
_ZH_FLAG_RE = re.compile(r"""(?:--zh\b)""")
_HTTP_HINT_RE = re.compile(
    r"requests\.|httpx\.|urllib|aiohttp|http\.client",
    re.I,
)
_HTTP_REQUEST_RE = re.compile(
    r"(?im)^\s*(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|CONNECT|TRACE)\s+\S+"
    r"|^\s*HTTP/\d"
)
_HARNESS_SHAPED_RE = re.compile(
    r"(?is)("
    r"inlined\s+(?:from|verbatim)"
    r"|sandbox\s+(?:lacks|has no)"
    r"|extracts the exact vulnerable"
    r"|exact copy of the vulnerable"
    r"|_MOCK_"
    r"|mock _load"
    r"|don't depend on host files"
    r"|不要依赖宿主机"
    r")"
)

POC_CLI_ERROR = (
    "poc_code 必须用 argparse 接收目标（-u/--url）和 HTTP 代理（--proxy，空则直连），"
    "不要写死地址或代理；有 --proxy 时 127.0.0.1/localhost 也必须强制走代理"
    "（覆盖 urllib.request.proxy_bypass，勿让本机地址旁路）；"
    "HTTPS 须默认跳过证书校验并在 https:// 目标打印告警（--strict-ssl 可选恢复校验）；"
    "RCE 另须支持 -c/--cmd，有回显须打印命令输出；"
    "脚本输出须中英双语：默认英语，须提供 --zh 切换中文标签/状态/告警/判定；"
    "注释、docstring、--help 仍用英语。"
)

POC_I18N_ERROR = (
    "脚本 stdout/stderr 标签、状态、告警、判定须中英双语：默认英语，必须提供 --zh 切换中文；"
    "注释、docstring、argparse --help 仍用英语；目标回显原文不要翻译。"
)

POC_LAB_RUN_ERROR = (
    "靶场动态确认时 poc.py 必须可独立运行，并用 argparse 接收 -u/--url；"
    "ConfirmVuln 会执行 python poc.py -u <target_url>，打出预期冲击须退出码 0。"
)

POC_HARNESS_SHAPE_ERROR = (
    "poc.py 不能写成沙箱 harness：不要内联源码、不要 mock 依赖、不要复制 harness 测试矩阵。"
    "局部验证证据只写入 harness.py（RunCode）。"
    "poc.py 仅在能对已安装包做最小公开 API 复现、或对任意 HTTP origin 复测时才写。"
)

LIBRARY_POC_FAKE_HTTP_CLI_ERROR = (
    "纯库洞 poc.py 不要加未使用的 -u/--url 或 --proxy。"
    "有 HTTP 利用面才写完整 HTTP CLI（-u/--url、--proxy、本机强制走代理、HTTPS 证书处理）；"
    "否则 poc.py 必须 import 已安装的真实包并调用公开 API，不要把 harness 的内联/mock 测试抄进去。"
    "没有安装面也没有 HTTP 面时不要交 poc.py，报告与 http_request 写 API 调用配方即可。"
)

POC_CODE_TOOL_DESCRIPTION = (
    "有 HTTP 利用面时必填：argparse -u/--url 为目标 origin；"
    "必须 --proxy（空则直连）并接到全部 HTTP 请求；有代理时 127.0.0.1/localhost 也必须强制走代理；"
    "RCE 须 -c/--cmd 且有回显时打印命令输出。不要写死地址或代理。"
    "SSRF 有回显须打印目标正文，仅差别则打印通/不通对照。"
    "脚本输出须中英双语：默认英语，必须 --zh 切换中文标签/状态/告警/判定；"
    "注释、--help 仍用英语；目标回显原文不要翻译。"
    "纯库洞：不要交未使用的 -u/--proxy，不要把 harness 内联/mock 抄进 poc.py。"
    "仅当安装真实包后能 import 公开 API 并打出冲击时才写 poc.py；"
    "无 HTTP 面且无安装面时留空，http_request 写 API 调用配方。局部验证证据只进 harness.py。"
)


def _has_url_flag(text: str) -> bool:
    lower = text.lower()
    return bool(_URL_FLAG_RE.search(text) or ("add_argument" in lower and "url" in lower))


def _has_proxy_flag(text: str) -> bool:
    return bool(_PROXY_FLAG_RE.search(text))


def _has_zh_flag(text: str) -> bool:
    return bool(_ZH_FLAG_RE.search(text))


def looks_like_http_request(text: str | None) -> bool:
    """True when http_request looks like a raw HTTP message rather than an API recipe."""
    return bool(_HTTP_REQUEST_RE.search(text or ""))


def looks_like_http_poc(text: str | None) -> bool:
    return bool(_HTTP_HINT_RE.search(text or ""))


def poc_required_for_submit(
    *,
    target_kind: str | None,
    http_request: str = "",
    poc_code: str = "",
) -> bool:
    """Web always needs a poc_code draft. Component audits need one only with an HTTP surface."""
    from ..target_kind import is_component_target

    if looks_like_http_request(http_request) or looks_like_http_poc(poc_code):
        return True
    return not is_component_target(target_kind)


def poc_cli_block_reason(poc_code: str | None, *, target_kind: str | None = None) -> str | None:
    """Reject HTTP PoCs that omit the web CLI contract, dummy library CLIs, and harness copies.

    Empty poc_code is allowed here; SubmitVuln decides whether the field is required.
    HTTP-shaped scripts (including library/mixed with an HTTP client) follow the web CLI
    contract (including --zh). Pure library API scripts must import the real package —
    no unused -u/--proxy and no inlined/mocked harness copies; argparse scripts still
    need --zh for bilingual stdout.
    """
    from ..target_kind import is_component_target

    text = poc_code or ""
    if not text.strip():
        return None
    if _HARNESS_SHAPED_RE.search(text):
        return POC_HARNESS_SHAPE_ERROR
    http = bool(_HTTP_HINT_RE.search(text))
    component = is_component_target(target_kind)
    if component and not http:
        if _URL_FLAG_RE.search(text) or _PROXY_FLAG_RE.search(text):
            return LIBRARY_POC_FAKE_HTTP_CLI_ERROR
        if "add_argument" in text.lower() and not _has_zh_flag(text):
            return POC_I18N_ERROR
        return None
    if not http:
        return None
    if not (
        _has_url_flag(text)
        and _has_proxy_flag(text)
        and _FORCE_LOCAL_PROXY_RE.search(text)
        and _SSL_HANDLING_RE.search(text)
    ):
        return POC_CLI_ERROR
    if not _has_zh_flag(text):
        return POC_I18N_ERROR
    return None


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


_HARNESS_EXT_LANG = {
    ".py": "python",
    ".php": "php",
    ".js": "javascript",
    ".rb": "ruby",
    ".go": "go",
    ".java": "java",
    ".sh": "bash",
}


def find_harness_path(project_id: int, vuln_id: int) -> Path | None:
    seen: set[str] = set()
    for name in _HARNESS_NAMES.values():
        if name in seen:
            continue
        seen.add(name)
        path = vuln_dir(project_id, vuln_id) / name
        if path.is_file():
            return path
    return None


def harness_language_from_path(path: Path) -> str:
    return _HARNESS_EXT_LANG.get(path.suffix.lower(), "python")


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

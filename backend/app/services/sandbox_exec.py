"""One-shot sibling Docker sandbox for local (harness) verification."""

from __future__ import annotations

import logging
import re
import tempfile
import threading
from pathlib import Path
from typing import Any

from ..config import settings
from .lab import LAB_LABEL_KEY, LAB_LABEL_VALUE
from .paths import data_tmp_dir

logger = logging.getLogger(__name__)

_JAVA_PUBLIC_CLASS_RE = re.compile(
    r"(?:^|\n)\s*public\s+(?:final\s+|abstract\s+)*class\s+(\w+)",
    re.MULTILINE,
)
_JAVA_ANY_CLASS_RE = re.compile(
    r"(?:^|\n)\s*(?:public\s+|final\s+|abstract\s+|strictfp\s+)*class\s+(\w+)",
    re.MULTILINE,
)
_JAVA_RELEASE_RE = re.compile(
    r"(?im)^\s*(?://|/\*)\s*java-release\s*:\s*(\d+)\b"
)
_JAVA_RELEASE_DEFAULT = 8
_JAVA_RELEASE_MAX = 17
_SANDBOX_LANGUAGES = "python / php / javascript / ruby / go / java / bash / c"
_UNSUPPORTED_LANGUAGES = frozenset(
    {
        "rust",
        "rs",
        "cpp",
        "cc",
        "cxx",
        "c++",
        "csharp",
        "cs",
        "kotlin",
        "kt",
        "scala",
        "swift",
    }
)
UNSUPPORTED_LANGUAGE_ERROR = (
    "不支持的 language：沙箱镜像不含该语言的编译器（Rust / C++ 等，没有 rustc / g++）。"
    f"可选: {_SANDBOX_LANGUAGES}。"
    "C 用 language=c（gcc + glibc）。"
    "不要用另一种语言复述源码再标 harness。"
    "静态已能证明默认可利用则 ConfirmVuln(evidence_level=static_only)；"
    "不要据此误报，也不要反复 RunCode 探测 rustc。"
)

# Docker tmpfs defaults to noexec. Go (and any compiled harness) writes a
# binary under /tmp or $HOME and execs it; without exec that is EACCES.
# /workspace is a host bind mount (on Windows often also noexec), so compile
# output must stay on these tmpfs mounts.
_SANDBOX_TMPFS: dict[str, str] = {
    "/tmp": "rw,exec,nosuid,nodev,size=256m,mode=1777",
    "/home/sandbox": "rw,exec,nosuid,nodev,size=64m,mode=1777",
}

_GO_BUILD_AND_RUN = "go build -o /tmp/harness main.go && /tmp/harness"
_C_BUILD_AND_RUN = "gcc -O0 -o /tmp/harness run.c && /tmp/harness"

_LANG_FILES: dict[str, tuple[str, str]] = {
    "python": ("run.py", "python3 run.py"),
    "python3": ("run.py", "python3 run.py"),
    "py": ("run.py", "python3 run.py"),
    "php": ("run.php", "php run.php"),
    "javascript": ("run.js", "node run.js"),
    "js": ("run.js", "node run.js"),
    "node": ("run.js", "node run.js"),
    "ruby": ("run.rb", "ruby run.rb"),
    "rb": ("run.rb", "ruby run.rb"),
    "go": ("main.go", _GO_BUILD_AND_RUN),
    "golang": ("main.go", _GO_BUILD_AND_RUN),
    "c": ("run.c", _C_BUILD_AND_RUN),
    "bash": ("run.sh", "bash run.sh"),
    "sh": ("run.sh", "bash run.sh"),
    "shell": ("run.sh", "bash run.sh"),
}

_lock = threading.Lock()
_client = None
_init_error = ""
_initialized = False


def sandbox_image() -> str:
    return (settings.sandbox_image or "vulnhunter/sandbox:latest").strip()


def _connect() -> tuple[Any, str]:
    global _client, _init_error, _initialized
    with _lock:
        if _initialized:
            return _client, _init_error
        _initialized = True
        try:
            import docker  # noqa: PLC0415
        except ImportError as exc:
            _init_error = f"未安装 docker SDK: {exc}"
            logger.warning("sandbox docker SDK missing: %s", exc)
            return None, _init_error
        try:
            client = docker.from_env()
            client.ping()
            _client = client
            _init_error = ""
            logger.info("sandbox docker client ready")
            return _client, _init_error
        except Exception as exc:  # noqa: BLE001
            _init_error = f"{type(exc).__name__}: {exc}"
            logger.warning("sandbox docker unavailable: %s", exc)
            return None, _init_error


def reset_sandbox_client() -> None:
    """Test helper."""
    global _client, _init_error, _initialized
    with _lock:
        _client = None
        _init_error = ""
        _initialized = False


def sandbox_available() -> bool:
    client, _err = _connect()
    return client is not None


def sandbox_diagnosis() -> dict[str, Any]:
    client, err = _connect()
    image = sandbox_image()
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
        "network_mode": "none",
    }


def _java_release(code: str) -> int:
    match = _JAVA_RELEASE_RE.search(code or "")
    if not match:
        return _JAVA_RELEASE_DEFAULT
    try:
        n = int(match.group(1))
    except ValueError:
        return _JAVA_RELEASE_DEFAULT
    if n < _JAVA_RELEASE_DEFAULT or n > _JAVA_RELEASE_MAX:
        return _JAVA_RELEASE_DEFAULT
    return n


def normalize_harness_newlines(code: str) -> str:
    """Host (Windows) CRLF breaks bash in the Linux sandbox."""
    return (code or "").replace("\r\n", "\n").replace("\r", "\n")


def _strip_java_comments(code: str) -> str:
    """Drop // and /* */ so class-name matching ignores javadoc like 'class is' / '@class'."""
    out: list[str] = []
    i = 0
    n = len(code)
    in_str = False
    quote = ""
    while i < n:
        ch = code[i]
        if in_str:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(code[i + 1])
                i += 2
                continue
            if ch == quote:
                in_str = False
            i += 1
            continue
        if ch in {'"', "'"}:
            in_str = True
            quote = ch
            out.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < n:
            nxt = code[i + 1]
            if nxt == "/":
                i += 2
                while i < n and code[i] != "\n":
                    i += 1
                continue
            if nxt == "*":
                i += 2
                while i + 1 < n and not (code[i] == "*" and code[i + 1] == "/"):
                    if code[i] == "\n":
                        out.append("\n")
                    i += 1
                i = min(n, i + 2)
                continue
        out.append(ch)
        i += 1
    return "".join(out)


def java_class_name(code: str) -> str:
    stripped = _strip_java_comments(code or "")
    match = _JAVA_PUBLIC_CLASS_RE.search(stripped)
    if match:
        return match.group(1)
    match = _JAVA_ANY_CLASS_RE.search(stripped)
    if match:
        return match.group(1)
    return "Main"


def _java_run_spec(code: str) -> tuple[str, str]:
    name = java_class_name(code)
    release = _java_release(code)
    return (
        f"{name}.java",
        (
            f"javac --release {release} -encoding UTF-8 {name}.java"
            f" && java -Dfile.encoding=UTF-8 {name}"
        ),
    )


def _sandbox_environment(description: str) -> dict[str, str]:
    return {
        "HTTP_PROXY": "",
        "HTTPS_PROXY": "",
        "http_proxy": "",
        "https_proxy": "",
        "NO_PROXY": "*",
        "no_proxy": "*",
        "HOME": "/home/sandbox",
        "TMPDIR": "/tmp",
        "GOTMPDIR": "/tmp",
        "GOCACHE": "/tmp/go-cache",
        "GOPATH": "/tmp/go",
        "GOPROXY": "off",
        "GOSUMDB": "off",
        "CGO_ENABLED": "0",
        "GOTOOLCHAIN": "local",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "JAVA_TOOL_OPTIONS": "-Dfile.encoding=UTF-8",
        "VULNHUNTER_HARNESS": (description or "")[:200],
    }


def prepare_run(language: str, code: str) -> tuple[str, str]:
    lang = (language or "python").strip().lower()
    if lang in _UNSUPPORTED_LANGUAGES:
        raise ValueError(UNSUPPORTED_LANGUAGE_ERROR)
    if lang in ("java",):
        return _java_run_spec(code)
    spec = _LANG_FILES.get(lang)
    if not spec:
        raise ValueError(
            f"不支持的 language={language!r}，可选: {_SANDBOX_LANGUAGES}。"
            "静态已能证明默认可利用则 ConfirmVuln(evidence_level=static_only)；不要据此误报。"
        )
    return spec


def execute_harness(
    code: str,
    *,
    language: str = "python",
    timeout: int = 60,
    description: str = "",
) -> dict[str, Any]:
    """Run LLM-written harness in a one-shot sibling container. Never executes on the host."""
    from .runcode_feedback import annotate_run_code_result

    return annotate_run_code_result(
        _execute_harness_raw(code, language=language, timeout=timeout, description=description),
        language=language,
        code=code,
    )


def _execute_harness_raw(
    code: str,
    *,
    language: str = "python",
    timeout: int = 60,
    description: str = "",
) -> dict[str, Any]:
    timeout = max(5, min(int(timeout or 60), 180))
    code = normalize_harness_newlines(code)
    try:
        filename, command = prepare_run(language, code)
    except ValueError as exc:
        return {
            "ok": False,
            "error": str(exc),
            "stdout": "",
            "stderr": "",
            "exit_code": -1,
            "sandbox": sandbox_diagnosis(),
        }
    diagnosis = sandbox_diagnosis()
    if not diagnosis["available"]:
        return {
            "ok": False,
            "error": (
                "Docker 不可用，局部验证无法启动沙箱。"
                f" {diagnosis.get('error') or ''}".rstrip()
                + " 请确认本机 Docker 正在运行。不要因此判误报，改为 static_only 或继续静态审核。"
            ),
            "stdout": "",
            "stderr": "",
            "exit_code": -1,
            "sandbox": diagnosis,
        }
    if not diagnosis["image_present"]:
        image = diagnosis["image"]
        return {
            "ok": False,
            "error": (
                f"沙箱镜像 {image} 不在本机 Docker 中。"
                "请先构建：docker build -t vulnhunter/sandbox:latest docker/sandbox"
                "（Windows 可用 scripts\\build-sandbox.cmd）。"
                "不要因此判误报，改为 static_only 或继续静态审核。"
            ),
            "stdout": "",
            "stderr": "",
            "exit_code": -1,
            "sandbox": diagnosis,
        }

    client, _err = _connect()
    assert client is not None
    work = tempfile.TemporaryDirectory(prefix="vh-sandbox-", dir=str(data_tmp_dir("sandbox")))
    try:
        host_dir = Path(work.name)
        (host_dir / filename).write_text(code, encoding="utf-8")
        host_bind = str(host_dir)
        container = None
        try:
            container = client.containers.run(
                image=sandbox_image(),
                command=["sh", "-c", command],
                detach=True,
                labels={
                    LAB_LABEL_KEY: LAB_LABEL_VALUE,
                    "vulnhunter.kind": "sandbox",
                },
                mem_limit=settings.sandbox_memory,
                cpu_period=100000,
                cpu_quota=int(100000 * float(settings.sandbox_cpus)),
                network_mode="none",
                user="1000:1000",
                read_only=True,
                cap_drop=["ALL"],
                security_opt=["no-new-privileges:true"],
                volumes={host_bind: {"bind": "/workspace", "mode": "rw"}},
                tmpfs=dict(_SANDBOX_TMPFS),
                working_dir="/workspace",
                environment=_sandbox_environment(description),
            )
            result = container.wait(timeout=timeout)
            stdout = container.logs(stdout=True, stderr=False) or b""
            stderr = container.logs(stdout=False, stderr=True) or b""
            exit_code = int(result.get("StatusCode") or 0)
            return {
                "ok": exit_code == 0,
                "stdout": _clip(stdout),
                "stderr": _clip(stderr, limit=4000),
                "exit_code": exit_code,
                "error": None if exit_code == 0 else f"退出码 {exit_code}",
                "sandbox": {**diagnosis, "timeout_sec": timeout, "file": filename},
            }
        except Exception as exc:  # noqa: BLE001
            name = type(exc).__name__
            if "timeout" in name.lower() or "Timeout" in name:
                if container is not None:
                    try:
                        container.kill()
                    except Exception:  # noqa: BLE001
                        pass
                return {
                    "ok": False,
                    "error": f"沙箱执行超时（{timeout}s）。不要因此判误报。",
                    "stdout": "",
                    "stderr": "",
                    "exit_code": -1,
                    "sandbox": diagnosis,
                }
            logger.warning("sandbox run failed: %s", exc)
            return {
                "ok": False,
                "error": (
                    f"沙箱执行失败: {exc}。"
                    "不要因此判误报，改为 static_only 或调整 harness 后重试。"
                ),
                "stdout": "",
                "stderr": "",
                "exit_code": -1,
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


def _clip(raw: bytes | str, *, limit: int = 12000) -> str:
    if isinstance(raw, bytes):
        text = raw.decode("utf-8", errors="replace")
    else:
        text = raw or ""
    text = text.replace("\x00", "")
    if len(text) <= limit:
        return text
    return text[:limit].rstrip() + "\n…(truncated)"


def harness_debug_plan() -> dict[str, Any]:
    diagnosis = sandbox_diagnosis()
    return {
        "enabled": True,
        "preferred": "harness",
        "sandbox": diagnosis,
        "steps": [
            "Read 报告与源码，确认文件和代码片段真实存在",
            "按目标语言设计 mock / harness，用 RunCode 在沙箱执行（Python/PHP/JS/Ruby/Go/Java/Bash/C）。C 用 gcc（language=c）；无 rustc / g++，Rust/C++ 不要探测编译器，静态已能证明则 static_only。Java 默认 JDK 8 且 javac -encoding UTF-8，更高版本须在源码顶部写 // java-release: 11 或 // java-release: 17",
            "公开入口本身吃 HTTP/请求对象时，对 src/ 该 API 做同进程请求级加强验证（httptest/进程内客户端），禁止只拷内部 sink；无请求面 API 不要包 HTTP",
            "mock 失败或沙箱不可用不要判误报；静态已能证明默认可利用则 static_only",
            "打通后先 Write 报告「### 漏洞代码」（完整文件路径 + 源码原文），再 ConfirmVuln(evidence_level=harness)；脚本写入 harness.py；stdout 必须打印运行时实际数据，禁止写死成功字段；输出默认英语、--zh 切中文；不要把同一份 mock 写进 poc.py",
        ],
    }

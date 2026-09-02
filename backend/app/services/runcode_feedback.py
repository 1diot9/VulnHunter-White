"""Structured RunCode / sandbox failure classification for Reviewer harness loops."""

from __future__ import annotations

import re
from typing import Any

FAILURE_SANDBOX = "sandbox_unavailable"
FAILURE_IMAGE = "image_missing"
FAILURE_UNSUPPORTED = "unsupported_language"
FAILURE_INVALID = "invalid_harness"
FAILURE_TIMEOUT = "timeout"
FAILURE_MISSING = "missing_dependency"
FAILURE_COMPILE = "compile_error"
FAILURE_RUNTIME = "runtime_error"
FAILURE_EXIT = "nonzero_exit"

_JAVA_PACKAGE = re.compile(r"error:\s*package\s+([\w.]+)\s+does not exist")
_JAVA_SYMBOL = re.compile(
    r"error:\s*cannot find symbol\s*(?:\r?\n[^\n]*symbol:\s*(?:class|variable|method)\s+(\S+))?",
    re.IGNORECASE,
)
_JAVA_SYMBOL_INLINE = re.compile(r"cannot find symbol:\s*(?:class|variable|method)\s+(\S+)", re.I)
_PY_MODULE = re.compile(r"ModuleNotFoundError:\s*No module named ['\"]([^'\"]+)['\"]")
_PY_IMPORT = re.compile(r"ImportError:\s*(?:cannot import name ['\"]([^'\"]+)['\"]|No module named ['\"]([^'\"]+)['\"])")
_GO_IMPORT = re.compile(r"cannot find package \"([^\"]+)\"")
_GO_UNDEF = re.compile(r"undefined:\s+(\S+)")
_JS_MODULE = re.compile(r"Cannot find module ['\"]([^'\"]+)['\"]")
_JAVA_RELEASE_HINT = re.compile(
    r"\b(?:var|record|text blocks?|switch expressions?|List\.of|Map\.of)\b"
    r"|error:\s*(?:illegal start of (?:type|expression)|')",
    re.I,
)
_JAVA_RELEASE_RE = re.compile(r"(?im)^\s*(?://|/\*)\s*java-release\s*:\s*(\d+)\b")


def _code_java_release(code: str) -> int:
    match = _JAVA_RELEASE_RE.search(code or "")
    if not match:
        return 8
    try:
        n = int(match.group(1))
    except ValueError:
        return 8
    return n if 8 <= n <= 17 else 8


def note_runcode_result(
    state: dict[str, Any],
    result: dict[str, Any] | None,
    *,
    threshold: int,
) -> bool:
    """Update consecutive-fail streak. True when the loop should park and AskUser."""
    if not isinstance(result, dict) or result.get("ok") is not False:
        state["runcode_fail_streak"] = 0
        return False
    n = int(state.get("runcode_fail_streak") or 0) + 1
    state["runcode_fail_streak"] = n
    state["runcode_last_failure"] = {
        "failure_class": result.get("failure_class"),
        "error": result.get("error"),
        "hint": result.get("hint"),
        "missing": list(result.get("missing") or []),
        "signals": list(result.get("signals") or []),
        "exit_code": result.get("exit_code"),
        "java_release": result.get("java_release"),
    }
    limit = max(1, int(threshold or 3))
    return n >= limit


def annotate_run_code_result(
    result: dict[str, Any],
    *,
    language: str = "",
    code: str = "",
) -> dict[str, Any]:
    """Attach failure_class / missing / signals / hint. Success is left mostly as-is."""
    out = dict(result or {})
    if out.get("ok") is True:
        out.setdefault("failure_class", None)
        out.setdefault("signals", [])
        out.setdefault("missing", [])
        return out
    error = str(out.get("error") or "")
    stderr = str(out.get("stderr") or "")
    stdout = str(out.get("stdout") or "")
    blob = "\n".join(p for p in (error, stderr, stdout) if p)
    lang = (language or str(out.get("language") or "")).strip().lower()
    failure, missing, signals = _classify(blob, error=error, language=lang, code=code)
    out["failure_class"] = failure
    out["missing"] = missing
    out["signals"] = signals
    if lang in ("java",) or _JAVA_RELEASE_RE.search(code or ""):
        out.setdefault("java_release", _code_java_release(code or ""))
    hint = _hint_for(failure, missing=missing, language=lang, java_release=out.get("java_release"))
    if hint:
        out["hint"] = hint
    return out


def _classify(
    blob: str,
    *,
    error: str,
    language: str,
    code: str,
) -> tuple[str, list[str], list[str]]:
    err_l = (error or "").lower()
    if "docker 不可用" in err_l or "docker unavailable" in err_l or "未安装 docker" in err_l:
        return FAILURE_SANDBOX, [], ["docker_unavailable"]
    if "沙箱镜像" in error and "不在本机" in error:
        return FAILURE_IMAGE, [], ["image_missing"]
    if "不支持的 language" in error:
        return FAILURE_UNSUPPORTED, [], ["unsupported_language"]
    if "超时" in error or "timeout" in err_l:
        return FAILURE_TIMEOUT, [], ["timeout"]
    if "禁止只打印" in error or "必须来自运行时" in error:
        return FAILURE_INVALID, [], ["canned_output"]

    missing: list[str] = []
    signals: list[str] = []
    for m in _JAVA_PACKAGE.finditer(blob):
        missing.append(m.group(1))
        signals.append("package_missing")
    for m in _JAVA_SYMBOL.finditer(blob):
        if m.group(1):
            missing.append(m.group(1))
        signals.append("cannot_find_symbol")
    for m in _JAVA_SYMBOL_INLINE.finditer(blob):
        missing.append(m.group(1))
        signals.append("cannot_find_symbol")
    for m in _PY_MODULE.finditer(blob):
        missing.append(m.group(1))
        signals.append("module_not_found")
    for m in _PY_IMPORT.finditer(blob):
        name = m.group(1) or m.group(2)
        if name:
            missing.append(name)
        signals.append("import_error")
    for m in _GO_IMPORT.finditer(blob):
        missing.append(m.group(1))
        signals.append("go_package_missing")
    for m in _GO_UNDEF.finditer(blob):
        missing.append(m.group(1))
        signals.append("go_undefined")
    for m in _JS_MODULE.finditer(blob):
        missing.append(m.group(1))
        signals.append("node_module_missing")

    missing = list(dict.fromkeys(missing))
    signals = list(dict.fromkeys(signals))

    if missing or "package_missing" in signals or "cannot_find_symbol" in signals:
        return FAILURE_MISSING, missing, signals or ["missing_dependency"]
    if re.search(r"\berror:\s", blob) or "javac" in blob.lower() or "go build" in blob.lower():
        extra = list(signals)
        if language == "java" and _JAVA_RELEASE_HINT.search(blob + "\n" + (code or "")):
            extra.append("java_language_level")
        return FAILURE_COMPILE, missing, extra or ["compile_error"]
    if re.search(
        r"Traceback \(most recent call last\)|Exception in thread|Error:\s|panic:",
        blob,
    ):
        return FAILURE_RUNTIME, missing, signals or ["runtime_error"]
    if "退出码" in error:
        return FAILURE_EXIT, missing, signals or ["nonzero_exit"]
    return FAILURE_EXIT, missing, signals or ["run_failed"]


def _hint_for(
    failure: str,
    *,
    missing: list[str],
    language: str,
    java_release: Any = None,
) -> str:
    miss = "、".join(missing[:6]) if missing else ""
    if failure == FAILURE_SANDBOX:
        return (
            "Docker 不可用，局部验证沙箱没起来。"
            "不要因此误报。静态已能证明默认可利用则 ConfirmVuln(evidence_level=static_only)。"
        )
    if failure == FAILURE_IMAGE:
        return (
            "沙箱镜像不在本机。不要因此误报。"
            "静态已能证明则 static_only；否则等镜像可用后再 RunCode。"
        )
    if failure == FAILURE_TIMEOUT:
        return "沙箱超时。缩小 harness、去掉死循环后再跑；不要因此误报。"
    if failure == FAILURE_INVALID:
        return (
            "harness 最终输出必须打印运行时实际数据，禁止写死 SUCCESS / success=true。"
            "改打印 sink 返回值、异常原文或查询结果后再 RunCode。"
        )
    if failure == FAILURE_MISSING:
        extra = f"缺：{miss}。" if miss else ""
        if language == "java":
            return (
                f"编译缺符号或包。{extra}"
                "改为 mock 该依赖，或降到抽出函数级 harness，不要为了编过而拷一整模块。"
                "不要因此误报。"
            )
        return f"缺依赖或符号。{extra}改 mock / 内联最小替代后再跑。不要因此误报。"
    if failure == FAILURE_COMPILE:
        if language == "java":
            rel = java_release or 8
            return (
                f"javac 失败（当前 java-release={rel}）。"
                "Java harness 默认 JDK 8：不要用 var/record/text block/List.of。"
                "仅当目标源码需要更高版本时在文件顶部写 // java-release: 11 或 // java-release: 17。"
                "不要因此误报。"
            )
        return "编译失败。按 stderr 修语法或导入后再 RunCode。不要因此误报。"
    if failure == FAILURE_RUNTIME:
        return (
            "harness 已编译但运行期异常。打印异常原文作为证据，"
            "区分「防护生效」与「mock 写错」。不要把 mock 失败当误报。"
        )
    return "RunCode 未成功。按 failure_class / stderr 修正后重试；沙箱或 mock 问题不要误报。"

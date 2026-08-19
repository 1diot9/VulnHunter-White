"""Common tools: Read, Grep, Glob, Write, Bash, PowerShell, TodoWrite, WebSearch, SearchOldVuln."""

from __future__ import annotations

import fnmatch
import json
import os
import re
import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Callable

import yaml

from ..config import settings
from ..services.ghsa_service import search_advisories
from ..services.fingerprint_search import web_search_results
from ..services.github_issues import search_github_issues
from ..services.http_client import http_client
from ..services.ingest import IGNORE_DIR_NAMES
from ..services.lab import write_lab_doc_if_ready
from ..services.paths import env_dir, old_vulns_dir, project_root, src_dir, vuln_dir
from . import ToolSpec, registry
from .sandbox import SandboxError, assert_readable, assert_writable, block_dangerous_shell, is_src_path

_SHELL_TIMEOUT_DEFAULT = 120
_SHELL_TIMEOUT_MAX = 180
_SHELL_OUTPUT_MAX_BYTES = 256 * 1024
_SHELL_STDOUT_KEEP = 8000
_SHELL_STDERR_KEEP = 4000
_PS_UTF8_PREFIX = (
    "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false); "
    "$OutputEncoding = [Console]::OutputEncoding; "
)


def decode_shell_bytes(data: bytes | bytearray) -> str:
    """Decode captured shell output. Prefer UTF-8, then Windows GBK/OEM."""
    raw = bytes(data)
    if not raw:
        return ""
    if raw.startswith(b"\xef\xbb\xbf"):
        try:
            return raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            pass
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        pass
    for enc in ("gbk", "cp936", "mbcs"):
        try:
            return raw.decode(enc)
        except (LookupError, UnicodeDecodeError):
            continue
    return raw.decode("utf-8", errors="replace")


def local_fail(error: str, *, traceback_text: str | None = None, **extra: Any) -> dict[str, Any]:
    """Mark a tool failure as local execution (not model call error)."""
    out: dict[str, Any] = {"ok": False, "error": error, "error_class": "local"}
    if traceback_text:
        out["traceback"] = traceback_text[-2000:]
    out.update(extra)
    return out


def call_fail(error: str, **extra: Any) -> dict[str, Any]:
    out: dict[str, Any] = {"ok": False, "error": error, "error_class": "call"}
    out.update(extra)
    return out


_READ_DEFAULT_LIMIT = 400
_READ_MAX_LIMIT = 2000
_READ_SOFT_MAX_CHARS = 40000
_READ_PAGE_MAX_BYTES = 40 * 1024
_READ_MIN_BYTES = 1024


def _optional_int(args: dict[str, Any], key: str) -> int | None:
    if key not in args or args[key] is None or args[key] == "":
        return None
    try:
        return int(args[key])
    except (TypeError, ValueError):
        return None


def _format_read_lines(lines: list[str], start_line: int) -> str:
    if not lines:
        return ""
    last = start_line + len(lines) - 1
    width = max(5, len(str(max(last, 1))))
    out: list[str] = []
    for i, line in enumerate(lines):
        out.append(f"{start_line + i:>{width}}|{line.rstrip('\r\n')}")
    return "\n".join(out)


def _fit_lines(lines: list[str], start_line: int, max_bytes: int) -> list[str]:
    """Drop trailing lines until numbered output fits max_bytes. Keep at least one line."""
    if not lines:
        return []
    chunk = list(lines)
    while chunk:
        encoded = _format_read_lines(chunk, start_line).encode("utf-8")
        if len(encoded) <= max_bytes or len(chunk) == 1:
            return chunk
        chunk.pop()
    return []


def read_text_window(
    text: str,
    *,
    offset: int | None = None,
    limit: int | None = None,
    max_bytes: int,
    default_limit: int = _READ_DEFAULT_LIMIT,
    soft_max_chars: int = _READ_SOFT_MAX_CHARS,
) -> dict[str, Any]:
    """Slice a file into a numbered line window. Metadata is meant to precede content."""
    lines = text.splitlines(keepends=True)
    total = len(lines)
    if offset is None or offset == 0:
        start = 0
    elif offset < 0:
        start = max(0, total + offset)
    else:
        start = min(total, offset - 1)

    remaining = lines[start:]
    if limit is not None:
        want = max(0, limit)
    elif len("".join(remaining)) <= soft_max_chars:
        want = len(remaining)
    else:
        want = default_limit
    want = min(want, _READ_MAX_LIMIT)

    # Cap each Read page so a full window + hint stays in the newest intact results.
    budget = min(max_bytes, _READ_PAGE_MAX_BYTES)
    window = _fit_lines(remaining[:want], start + 1, budget)
    read_n = len(window)
    truncated = (start + read_n) < total
    start_line = start + 1 if total else 0
    end_line = start + read_n if read_n else (start if total else 0)
    next_offset = start + read_n + 1 if truncated else None
    hint = None
    if truncated:
        shown_from = start + 1
        shown_to = start + read_n
        hint = (
            f"未读完：共 {total} 行，本次 {shown_from}-{shown_to}。"
            f"请再调用 Read(path=..., offset={next_offset}, limit={default_limit})，不要增大 max_bytes。"
        )
    elif total and start >= total:
        hint = f"offset 超出文件末尾（共 {total} 行）。"
        start_line = total + 1
        end_line = total

    out: dict[str, Any] = {
        "truncated": truncated,
        "start_line": start_line,
        "end_line": end_line,
        "total_lines": total,
    }
    if next_offset is not None:
        out["next_offset"] = next_offset
    if hint:
        out["hint"] = hint
    out["content"] = _format_read_lines(window, start + 1 if window else 1)
    return out


def _is_old_vuln_collect_role(ctx) -> bool:
    role = str(getattr(ctx, "role", "") or "").replace("_", "-").strip().lower()
    phase = str(getattr(ctx, "phase", "") or "").replace("_", "-").strip().lower()
    return role.endswith("old-vuln") or role.endswith("old-vuln-ghsa") or phase.endswith("old-vuln") or phase.endswith("old-vuln-ghsa")


def _read_handler(ctx, args: dict[str, Any]) -> dict[str, Any]:
    paths = args.get("paths") or args.get("path")
    if isinstance(paths, str):
        paths = [paths]
    if not paths:
        return call_fail("缺少 path/paths")
    raw_max = _optional_int(args, "max_bytes")
    cap = settings.file_inject_max_bytes
    max_bytes = cap if raw_max is None else max(_READ_MIN_BYTES, min(raw_max, cap))
    offset = _optional_int(args, "offset")
    limit = _optional_int(args, "limit")
    results = []
    local_errors = 0
    for p in paths:
        try:
            target = assert_readable(ctx.project_id, p)
            if _is_old_vuln_collect_role(ctx) and is_src_path(ctx.project_id, target):
                results.append({"path": p, "error": "历史漏洞阶段只收集，禁止读源码"})
                local_errors += 1
                continue
            if not target.exists():
                results.append({"path": p, "error": "文件不存在"})
                local_errors += 1
                continue
            if target.is_dir():
                results.append({"path": p, "error": "是目录，请用 Glob"})
                continue
            size = target.stat().st_size
            text = target.read_text(encoding="utf-8", errors="replace")
            window = read_text_window(text, offset=offset, limit=limit, max_bytes=max_bytes)
            # Paging fields before content so callers see next_offset/hint without scanning the body.
            ordered: dict[str, Any] = {
                "path": p,
                "size": size,
                "truncated": window["truncated"],
                "start_line": window["start_line"],
                "end_line": window["end_line"],
                "total_lines": window["total_lines"],
            }
            if "next_offset" in window:
                ordered["next_offset"] = window["next_offset"]
            if "hint" in window:
                ordered["hint"] = window["hint"]
            ordered["content"] = window["content"]
            results.append(ordered)
        except SandboxError as e:
            results.append({"path": p, "error": str(e)})
            local_errors += 1
        except OSError as e:
            results.append({"path": p, "error": str(e)})
            local_errors += 1
    if local_errors and not any("content" in r for r in results):
        return local_fail("; ".join(r.get("error", "") for r in results if r.get("error")), files=results)
    return {"ok": True, "files": results}


def _write_handler(ctx, args: dict[str, Any]) -> dict[str, Any]:
    path = args.get("path")
    content = args.get("content")
    if not path:
        return call_fail("缺少 path")
    if content is None:
        return call_fail("缺少 content")
    try:
        target = assert_writable(ctx.project_id, path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(str(content), encoding="utf-8")
        out = {"ok": True, "path": path, "bytes": len(str(content).encode("utf-8"))}
        if target.resolve() == (env_dir(ctx.project_id) / "env.json").resolve():
            try:
                env = json.loads(str(content))
            except json.JSONDecodeError:
                env = None
            if isinstance(env, dict):
                doc = write_lab_doc_if_ready(ctx.project_id, env, via="manual")
                if doc:
                    out["lab_doc_path"] = doc.relative_to(project_root(ctx.project_id)).as_posix()
        return out
    except SandboxError as e:
        return local_fail(str(e))
    except OSError as e:
        return local_fail(str(e))


def _ignored_dir(name: str) -> bool:
    return name in IGNORE_DIR_NAMES or (name.startswith(".") and name not in (".", ".."))


def _iter_files(root: Path, name_glob: str = "*"):
    """Walk files under root, pruning node_modules/target and other ignore dirs."""
    if root.is_file():
        if fnmatch.fnmatch(root.name, name_glob):
            yield root
        return
    if not root.exists():
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not _ignored_dir(d)]
        for fn in filenames:
            if fnmatch.fnmatch(fn, name_glob):
                yield Path(dirpath) / fn


def _glob_to_regex(pattern: str) -> re.Pattern[str]:
    pat = pattern.replace("\\", "/").lstrip("/")
    out: list[str] = []
    i = 0
    while i < len(pat):
        if pat.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pat.startswith("**", i):
            out.append(".*")
            i += 2
        elif pat[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pat[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pat[i]))
            i += 1
    return re.compile("^" + "".join(out) + "$")


def _glob_handler(ctx, args: dict[str, Any]) -> dict[str, Any]:
    pattern = args.get("pattern") or "**/*"
    root_rel = args.get("root") or "src"
    try:
        if root_rel == "src" or root_rel.startswith("src"):
            root = src_dir(ctx.project_id)
        else:
            root = assert_readable(ctx.project_id, root_rel)
            if root.is_file():
                root = root.parent
    except SandboxError as e:
        return local_fail(str(e))
    pat = str(pattern).replace("\\", "/")
    recursive = "**" in pat or "/" in pat
    rx = _glob_to_regex(pat) if recursive else None
    matches = []
    if recursive:
        files = _iter_files(root)
    elif root.is_dir():
        files = (p for p in root.iterdir() if p.is_file())
    else:
        files = []
    for p in files:
        if recursive:
            try:
                rel_to_root = p.relative_to(root).as_posix()
            except ValueError:
                rel_to_root = p.name
            if rx is None or not (rx.match(rel_to_root) or rx.match(p.name)):
                continue
        elif not fnmatch.fnmatch(p.name, pat):
            continue
        try:
            assert_readable(ctx.project_id, str(p))
        except SandboxError:
            continue
        try:
            rel = str(p.relative_to(project_root(ctx.project_id))).replace("\\", "/")
        except ValueError:
            rel = str(p)
        matches.append(rel)
        if len(matches) >= int(args.get("limit") or 200):
            break
    return {"ok": True, "matches": matches, "count": len(matches)}


def _grep_handler(ctx, args: dict[str, Any]) -> dict[str, Any]:
    pattern = args.get("pattern")
    if not pattern:
        return call_fail("缺少 pattern")
    root_rel = args.get("root") or "src"
    glob_pat = args.get("glob") or "*"
    case_insensitive = bool(args.get("i") or args.get("ignore_case"))
    try:
        flags = re.I if case_insensitive else 0
        rx = re.compile(pattern, flags)
    except re.error as e:
        return call_fail(f"正则无效: {e}")
    try:
        root = src_dir(ctx.project_id) if root_rel.startswith("src") else assert_readable(ctx.project_id, root_rel)
        files = list(_iter_files(root, glob_pat))
    except SandboxError as e:
        return local_fail(str(e))

    hits = []
    for fp in files:
        try:
            assert_readable(ctx.project_id, str(fp))
        except SandboxError:
            continue
        try:
            text = fp.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if rx.search(line):
                try:
                    rel = str(fp.relative_to(project_root(ctx.project_id))).replace("\\", "/")
                except ValueError:
                    rel = str(fp)
                hits.append({"path": rel, "line": i, "text": line[:500]})
                if len(hits) >= int(args.get("limit") or 100):
                    return {"ok": True, "hits": hits, "truncated": True}
    return {"ok": True, "hits": hits, "truncated": False}


def _kill_process_tree(proc: subprocess.Popen) -> None:
    if proc.pid is None or proc.poll() is not None:
        return
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
            capture_output=True,
            timeout=8,
            check=False,
        )
    else:
        try:
            import signal

            os.killpg(proc.pid, signal.SIGKILL)
        except OSError:
            proc.kill()
    try:
        proc.wait(timeout=3)
    except Exception:  # noqa: BLE001
        try:
            proc.kill()
        except OSError:
            pass


def _run_shell_limited(
    cmd: list[str],
    *,
    cwd: str,
    timeout: int,
    max_bytes: int,
    cancel_requested: Callable[[], bool] | None = None,
) -> tuple[int, str, str, str | None]:
    """Run a command with wall-clock timeout, output cap, and process-tree kill."""
    popen_kwargs: dict[str, Any] = {
        "cwd": cwd,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "stdin": subprocess.DEVNULL,
    }
    if os.name != "nt":
        popen_kwargs["start_new_session"] = True
    proc = subprocess.Popen(cmd, **popen_kwargs)
    out_buf = bytearray()
    err_buf = bytearray()
    lock = threading.Lock()
    aborted: list[str] = []

    def _reader(stream, buf: bytearray) -> None:
        try:
            while True:
                chunk = stream.read(4096)
                if not chunk:
                    break
                with lock:
                    if aborted:
                        break
                    used = len(out_buf) + len(err_buf)
                    room = max_bytes - used
                    if room <= 0:
                        aborted.append("output_limit")
                        break
                    buf.extend(chunk[:room])
                    if len(chunk) > room:
                        aborted.append("output_limit")
                        break
        except Exception:  # noqa: BLE001
            pass

    t_out = threading.Thread(target=_reader, args=(proc.stdout, out_buf), daemon=True)
    t_err = threading.Thread(target=_reader, args=(proc.stderr, err_buf), daemon=True)
    t_out.start()
    t_err.start()
    deadline = time.monotonic() + max(1, timeout)
    rc: int | None = None
    try:
        while True:
            if aborted:
                _kill_process_tree(proc)
                rc = proc.poll()
                break
            rc = proc.poll()
            if rc is not None:
                break
            if cancel_requested and cancel_requested():
                aborted.append("cancelled")
                _kill_process_tree(proc)
                break
            if time.monotonic() >= deadline:
                aborted.append("timeout")
                _kill_process_tree(proc)
                break
            time.sleep(0.05)
        t_out.join(timeout=2)
        t_err.join(timeout=2)
    finally:
        if proc.poll() is None:
            _kill_process_tree(proc)
        for stream in (proc.stdout, proc.stderr):
            if stream:
                try:
                    stream.close()
                except OSError:
                    pass

    return (
        rc if rc is not None else -1,
        decode_shell_bytes(out_buf),
        decode_shell_bytes(err_buf),
        (aborted[0] if aborted else None),
    )


def _shell_handler(ctx, args: dict[str, Any], shell: str) -> dict[str, Any]:
    command = args.get("command")
    if not command:
        return call_fail("缺少 command")
    try:
        block_dangerous_shell(command, ctx.project_id)
    except SandboxError as e:
        return local_fail(str(e))
    cwd = project_root(ctx.project_id)
    try:
        timeout = int(args.get("timeout") or _SHELL_TIMEOUT_DEFAULT)
    except (TypeError, ValueError):
        timeout = _SHELL_TIMEOUT_DEFAULT
    timeout = max(1, min(timeout, _SHELL_TIMEOUT_MAX))
    if shell == "powershell":
        exe = shutil.which("powershell") or shutil.which("pwsh") or "powershell"
        cmd = [exe, "-NoProfile", "-NonInteractive", "-Command", _PS_UTF8_PREFIX + command]
    elif Path("/bin/bash").exists():
        cmd = ["/bin/bash", "-lc", command]
    elif shutil.which("bash"):
        cmd = [shutil.which("bash") or "bash", "-lc", command]
    else:
        cmd = ["cmd", "/c", command]
    try:
        rc, stdout, stderr, abort = _run_shell_limited(
            cmd,
            cwd=str(cwd),
            timeout=timeout,
            max_bytes=_SHELL_OUTPUT_MAX_BYTES,
            cancel_requested=getattr(ctx, "cancel_requested", None),
        )
    except FileNotFoundError as e:
        return local_fail(f"shell 不可用: {e}")
    out = (stdout or "")[-_SHELL_STDOUT_KEEP:]
    err = (stderr or "")[-_SHELL_STDERR_KEEP:]
    if abort == "timeout":
        return local_fail(f"命令超时 ({timeout}s)", exit_code=-1, stdout=out, stderr=err)
    if abort == "cancelled":
        return local_fail("命令已取消", exit_code=-1, stdout=out, stderr=err)
    if abort == "output_limit":
        return local_fail(
            f"输出超过 {_SHELL_OUTPUT_MAX_BYTES} 字节，已终止。请缩小范围，避开 node_modules/target 等目录",
            exit_code=-1,
            stdout=out,
            stderr=err,
            truncated=True,
        )
    if rc == 0:
        return {
            "ok": True,
            "exit_code": rc,
            "stdout": out,
            "stderr": err,
            "error": None,
        }
    return local_fail(
        err or f"exit {rc}",
        exit_code=rc,
        stdout=out,
        stderr=err,
    )


_todo_file_locks: dict[str, threading.Lock] = {}
_todo_file_locks_guard = threading.Lock()


def _todo_slug(value: str | None, fallback: str) -> str:
    raw = (value or "").strip() or fallback
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", raw).strip("-._")
    return (slug[:80] or fallback)


def todo_relpath(ctx) -> str:
    """Per-agent todo file so recon/worker/reviewer/fix do not clobber each other."""
    role = (getattr(ctx, "role", None) or getattr(ctx, "phase", None) or "agent").strip().lower() or "agent"
    if role == "recon":
        return "workspace/todos-recon.json"
    if role in ("recon_old_vuln", "recon-old-vuln"):
        return "workspace/todos-recon-old-vuln.json"
    if role in ("recon_old_vuln_ghsa", "recon-old-vuln-ghsa"):
        return "workspace/todos-recon-old-vuln-ghsa.json"
    if role in ("recon_source_ext", "recon-source-ext"):
        return "workspace/todos-recon-source-ext.json"
    if role == "worker":
        return f"workspace/todos-worker-{_todo_slug(getattr(ctx, 'worker_id', None), 'default')}.json"
    if role == "reviewer":
        vid = getattr(ctx, "vuln_id", None)
        return f"workspace/todos-reviewer-{_todo_slug(str(vid) if vid is not None else None, 'current')}.json"
    if role in ("reviewer_lab", "reviewer-lab"):
        return "workspace/todos-reviewer-lab.json"
    if role == "verifier":
        vid = getattr(ctx, "vuln_id", None)
        return f"workspace/todos-verifier-{_todo_slug(str(vid) if vid is not None else None, 'current')}.json"
    if role == "fix":
        vid = getattr(ctx, "vuln_id", None)
        return f"workspace/todos-fix-{_todo_slug(str(vid) if vid is not None else None, 'current')}.json"
    return f"workspace/todos-{_todo_slug(role, 'agent')}.json"


def _todo_lock_for(path: Path) -> threading.Lock:
    key = str(path)
    with _todo_file_locks_guard:
        lock = _todo_file_locks.get(key)
        if lock is None:
            lock = threading.Lock()
            _todo_file_locks[key] = lock
        return lock


def _todo_handler(ctx, args: dict[str, Any]) -> dict[str, Any]:
    todos = args.get("todos")
    if not isinstance(todos, list):
        return {"ok": False, "error": "todos 必须是数组"}
    ctx.state["todos"] = todos
    rel = todo_relpath(ctx)
    path = assert_writable(ctx.project_id, rel)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(todos, ensure_ascii=False, indent=2)
    with _todo_lock_for(path):
        path.write_text(payload, encoding="utf-8")
    return {"ok": True, "count": len(todos), "path": rel}


def _websearch_handler(ctx, args: dict[str, Any]) -> dict[str, Any]:
    query = (args.get("query") or args.get("search_term") or "").strip()
    if not query:
        return {"ok": False, "error": "缺少 query"}
    return web_search_results(query)


def _search_ghsa_handler(ctx, args: dict[str, Any]) -> dict[str, Any]:
    return search_advisories(
        query=args.get("query"),
        ecosystem=args.get("ecosystem"),
        package=args.get("package"),
        per_page=int(args.get("per_page") or 20),
    )


def _search_github_issues_handler(ctx, args: dict[str, Any]) -> dict[str, Any]:
    per_page = args.get("per_page") or 20
    try:
        per_page_i = int(per_page)
    except (TypeError, ValueError):
        per_page_i = 20
    return search_github_issues(
        repo=args.get("repo"),
        query=args.get("query"),
        project_id=ctx.project_id,
        per_page=per_page_i,
    )


def _parse_frontmatter(text: str) -> tuple[dict[str, Any], str]:
    if not text.startswith("---"):
        return {}, text
    parts = text.split("---", 2)
    if len(parts) < 3:
        return {}, text
    try:
        meta = yaml.safe_load(parts[1]) or {}
    except Exception:  # noqa: BLE001
        meta = {}
    if not isinstance(meta, dict):
        meta = {}
    return meta, parts[2].lstrip("\n")


KIND_OLD = "old"
KIND_FOUND = "found"
KIND_LABELS = {
    KIND_OLD: "侦察旧漏洞",
    KIND_FOUND: "本项目已提交",
}
FIX_STATUS_PATCHED = "patched"
FIX_STATUS_UNPATCHED = "unpatched"
FIX_STATUS_VALUES = (FIX_STATUS_PATCHED, FIX_STATUS_UNPATCHED)
FIX_STATUS_LABELS = {
    FIX_STATUS_PATCHED: "已修复",
    FIX_STATUS_UNPATCHED: "未修复",
}
OLD_VULN_SOURCE_ISSUE = "github_issue"
OLD_VULN_SOURCE_GHSA = "ghsa"
OLD_VULN_SOURCE_WEB = "websearch"
_OLD_VULN_SOURCE_ALIASES = {
    "github_issue": OLD_VULN_SOURCE_ISSUE,
    "issue": OLD_VULN_SOURCE_ISSUE,
    "issues": OLD_VULN_SOURCE_ISSUE,
    "ghsa": OLD_VULN_SOURCE_GHSA,
    "advisory": OLD_VULN_SOURCE_GHSA,
    "websearch": OLD_VULN_SOURCE_WEB,
    "web": OLD_VULN_SOURCE_WEB,
}
_FIX_STATUS_ALIASES = {
    "patched": FIX_STATUS_PATCHED,
    "fixed": FIX_STATUS_PATCHED,
    "repaired": FIX_STATUS_PATCHED,
    "已修复": FIX_STATUS_PATCHED,
    "unpatched": FIX_STATUS_UNPATCHED,
    "unfixed": FIX_STATUS_UNPATCHED,
    "open": FIX_STATUS_UNPATCHED,
    "未修复": FIX_STATUS_UNPATCHED,
}


def _kind_label(kind: str) -> str:
    return KIND_LABELS.get(kind, kind)


def _normalize_fix_status(raw: Any) -> str | None:
    text = str(raw or "").strip()
    if not text:
        return None
    mapped = _FIX_STATUS_ALIASES.get(text) or _FIX_STATUS_ALIASES.get(text.lower())
    return mapped if mapped in FIX_STATUS_VALUES else None


def _normalize_old_vuln_source(raw: Any) -> str | None:
    text = str(raw or "").strip().lower().replace("-", "_")
    if not text:
        return None
    return _OLD_VULN_SOURCE_ALIASES.get(text)


def _default_fix_status(source: str | None) -> str:
    if source == OLD_VULN_SOURCE_ISSUE:
        return FIX_STATUS_UNPATCHED
    return FIX_STATUS_PATCHED


def _fix_status_label(status: str | None) -> str:
    if not status:
        return "未标注"
    return FIX_STATUS_LABELS.get(status, "未标注")


def _public_doc(entry: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {
        "title": entry["title"],
        "summary": entry["summary"],
        "file": entry["file"],
        "kind": entry["kind"],
        "kind_label": _kind_label(entry["kind"]),
    }
    if entry.get("kind") == KIND_OLD:
        fix_status = _normalize_fix_status(entry.get("fix_status"))
        if fix_status:
            out["fix_status"] = fix_status
            out["fix_status_label"] = entry.get("fix_status_label") or _fix_status_label(fix_status)
    if entry.get("kind") == KIND_FOUND:
        for key in (
            "vuln_id",
            "status",
            "file_path",
            "vuln_type",
            "cwe",
            "submission_tier",
            "root_cause_key",
            "merged_into_id",
        ):
            if key in entry:
                out[key] = entry[key]
        if entry.get("status") == "merged" and entry.get("merged_into_id"):
            out["merged_note"] = f"已并入 #{entry['merged_into_id']}"
    return out


def _full_doc(entry: dict[str, Any]) -> dict[str, Any]:
    out = _public_doc(entry)
    out["ok"] = True
    out["matched"] = True
    out["content"] = entry.get("content") or ""
    out["meta"] = entry.get("meta") or {}
    return out


def _search_blob(entry: dict[str, Any]) -> str:
    parts = [
        entry.get("title") or "",
        entry.get("summary") or "",
        entry.get("content") or "",
        entry.get("file") or "",
        entry.get("file_path") or "",
        entry.get("vuln_type") or "",
        entry.get("cwe") or "",
        entry.get("status") or "",
        entry.get("fix_status") or "",
        entry.get("fix_status_label") or "",
        entry.get("submission_tier") or "",
        entry.get("root_cause_key") or "",
        str(entry.get("merged_into_id") or ""),
        entry.get("merged_note") or "",
    ]
    return "\n".join(str(p) for p in parts).lower()


def _exact_title_match(entry: dict[str, Any], title: str) -> bool:
    if entry["title"] == title:
        return True
    if entry.get("kind") == KIND_OLD and Path(entry["file"]).stem == title:
        return True
    vid = entry.get("vuln_id")
    if vid is None:
        return False
    return title in {str(vid), f"#{vid}", f"vulns/{vid}", f"vulns/{vid}/report.md"}


def _old_vuln_entries(project_id: int) -> list[dict[str, Any]]:
    old_dir = old_vulns_dir(project_id)
    old_dir.mkdir(parents=True, exist_ok=True)
    entries: list[dict[str, Any]] = []
    for fp in sorted(old_dir.glob("*.md")):
        if fp.name == "index.md":
            continue
        text = fp.read_text(encoding="utf-8", errors="ignore")
        meta, body = _parse_frontmatter(text)
        fix_status = _normalize_fix_status(meta.get("fix_status"))
        entries.append(
            {
                "kind": KIND_OLD,
                "title": str(meta.get("title") or fp.stem),
                "summary": str(meta.get("summary") or ""),
                "file": fp.name,
                "content": body,
                "meta": meta,
                "fix_status": fix_status or "",
                "fix_status_label": _fix_status_label(fix_status),
            }
        )
    return entries


def _found_vuln_entries(ctx) -> list[dict[str, Any]]:
    # Import at call time so tests can rebind models.SessionLocal.
    from ..models import SessionLocal, Vuln

    skip_id = int(ctx.vuln_id) if ctx.vuln_id is not None else None
    entries: list[dict[str, Any]] = []
    with SessionLocal() as db:
        rows = (
            db.query(Vuln)
            .filter(Vuln.project_id == ctx.project_id)
            .order_by(Vuln.id.asc())
            .all()
        )
        for vuln in rows:
            if skip_id is not None and vuln.id == skip_id:
                continue
            report_rel = vuln.report_path or f"vulns/{vuln.id}/report.md"
            report_path = vuln_dir(ctx.project_id, vuln.id) / "report.md"
            text = ""
            if report_path.is_file():
                text = report_path.read_text(encoding="utf-8", errors="ignore")
            meta, body = _parse_frontmatter(text) if text else ({}, "")
            summary = str(meta.get("summary") or "").strip()
            if not summary:
                loc = f"{vuln.file_path or ''}:{vuln.line_no or ''}".strip(":")
                bits = [vuln.vuln_type or "", vuln.cwe or "", loc, (vuln.source_sink or "")[:160]]
                summary = " | ".join(b for b in bits if b)
            if vuln.status == "merged" and vuln.merged_into_id:
                summary = f"[已并入 #{vuln.merged_into_id}] {summary}".strip()
            entries.append(
                {
                    "kind": KIND_FOUND,
                    "title": vuln.title,
                    "summary": summary,
                    "file": report_rel,
                    "content": body or text,
                    "meta": meta,
                    "vuln_id": vuln.id,
                    "status": vuln.status,
                    "file_path": vuln.file_path,
                    "vuln_type": vuln.vuln_type,
                    "cwe": vuln.cwe,
                    "submission_tier": vuln.submission_tier,
                    "root_cause_key": vuln.root_cause_key,
                    "merged_into_id": vuln.merged_into_id,
                }
            )
    return entries


def _search_old_vuln_handler(ctx, args: dict[str, Any]) -> dict[str, Any]:
    title = (args.get("title") or "").strip()
    query = (args.get("query") or "").strip().lower()
    entries = _old_vuln_entries(ctx.project_id) + _found_vuln_entries(ctx)
    if title:
        for e in entries:
            if _exact_title_match(e, title):
                return _full_doc(e)
        q = title.lower()
        suggestions = []
        for e in entries:
            blob = f"{e['title']}\n{e['file']}\n{e['summary']}".lower()
            if q in blob or e["title"].lower() in q:
                suggestions.append(_public_doc(e))
        return {
            "ok": True,
            "matched": False,
            "query_title": title,
            "suggestions": suggestions[:8],
            "hint": "未精确命中标题，请用 suggestions 里的 title 再查，或改用 query 模糊搜索。kind=old 为侦察旧漏洞，kind=found 为本项目已提交。",
        }
    docs = []
    for e in entries:
        if query and query not in _search_blob(e):
            continue
        docs.append(_public_doc(e))
    return {"ok": True, "docs": docs, "count": len(docs)}


def register_common_tools() -> None:
    registry.register(
        ToolSpec(
            name="Read",
            description=(
                "读取项目内一个或多个文件（禁止直接读 docs/old-vulns）。"
                "返回内容带行号前缀（N|）。大文件按行分页：offset 为起始行号（从 1 计，负数从末尾倒数），"
                "limit 为本次行数（默认 400）。若 truncated=true，必须用返回的 next_offset 再读，"
                "不要增大 max_bytes（有硬顶，无法一次读完整文件）。"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "paths": {"type": "array", "items": {"type": "string"}},
                    "offset": {
                        "type": "integer",
                        "description": "起始行号，从 1 计；负数表示从末尾倒数。省略则从第 1 行开始。",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "本次读取行数。省略时小文件一次返回，大文件默认 400 行。",
                    },
                    "max_bytes": {
                        "type": "integer",
                        "description": "单次字节上限，有硬顶。完整读取请用 offset/limit 分页，不要靠增大此值。",
                    },
                },
            },
            handler=_read_handler,
            parallel_safe=True,
        )
    )
    registry.register(
        ToolSpec(
            name="Write",
            description="写入 workspace/docs/vulns/env 下的文件（不可写 docs/old-vulns，请用 WriteOldVuln 逐条落盘）",
            parameters={
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "content": {"type": "string"},
                },
                "required": ["path", "content"],
            },
            handler=_write_handler,
        )
    )
    registry.register(
        ToolSpec(
            name="Glob",
            description="按 glob 模式列出文件（自动跳过 node_modules/target/dist/build 等）",
            parameters={
                "type": "object",
                "properties": {
                    "pattern": {"type": "string"},
                    "root": {"type": "string"},
                    "limit": {"type": "integer"},
                },
            },
            handler=_glob_handler,
            parallel_safe=True,
        )
    )
    registry.register(
        ToolSpec(
            name="Grep",
            description="在源码中搜索正则（自动跳过 node_modules/target/dist/build 等）",
            parameters={
                "type": "object",
                "properties": {
                    "pattern": {"type": "string"},
                    "root": {"type": "string"},
                    "glob": {"type": "string"},
                    "i": {"type": "boolean"},
                    "limit": {"type": "integer"},
                },
                "required": ["pattern"],
            },
            handler=_grep_handler,
            parallel_safe=True,
        )
    )
    registry.register(
        ToolSpec(
            name="Bash",
            description=(
                "在项目工作区执行 shell（沙箱限制）。禁止 ls -R、find、tree、Get-ChildItem -Recurse "
                "等递归全库列举；Where-Object/-Exclude 不会跳过 node_modules/target。目录请用 Glob 或只列一层。"
                "timeout 单位是秒，默认 120，最多 180；curl/docker/网络请求必须加自身超时参数。"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "command": {"type": "string"},
                    "timeout": {"type": "integer"},
                },
                "required": ["command"],
            },
            handler=lambda ctx, args: _shell_handler(ctx, args, "bash"),
        )
    )
    registry.register(
        ToolSpec(
            name="PowerShell",
            description=(
                "在项目工作区执行 PowerShell（沙箱限制）。禁止 Get-ChildItem -Recurse/-Depth、ls -R、find、tree "
                "等递归全库列举；Where-Object/-Exclude 不会跳过 node_modules/target。目录请用 Glob 或只列一层。"
                "不要使用 bash heredoc（<< EOF）；多行脚本用 here-string @'...'@ 或先 Write 到 workspace 再执行。"
                "timeout 单位是秒，默认 120，最多 180；curl/docker/网络请求必须加自身超时参数。"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "command": {"type": "string"},
                    "timeout": {"type": "integer"},
                },
                "required": ["command"],
            },
            handler=lambda ctx, args: _shell_handler(ctx, args, "powershell"),
        )
    )
    registry.register(
        ToolSpec(
            name="TodoWrite",
            description="维护本阶段自己的运行时待办（按 recon / 历史漏洞 / worker / reviewer / verifier / fix 分文件，不会覆盖其他阶段）",
            parameters={
                "type": "object",
                "properties": {
                    "todos": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "id": {"type": "string"},
                                "content": {"type": "string"},
                                "status": {"type": "string"},
                            },
                        },
                    }
                },
                "required": ["todos"],
            },
            handler=_todo_handler,
        )
    )
    registry.register(
        ToolSpec(
            name="WebSearch",
            description="网络搜索本项目已公开的历史漏洞（CVE/公告）。仅历史漏洞第二轮（搜索补漏）使用；第一轮爬虫落盘禁止调用。本轮只收集，不要读源码；命中标 fix_status=patched。未修复洞只来自未关闭 GitHub Issues。符合口径立刻 WriteOldVuln；落盘不会结束本会话。",
            parameters={
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "search_term": {"type": "string"},
                },
            },
            handler=_websearch_handler,
            parallel_safe=True,
        )
    )
    registry.register(
        ToolSpec(
            name="SearchGHSA",
            description="查询 GitHub Advisories（可按 ecosystem/package/query）。历史漏洞爬虫落盘轮不要用；搜索补漏轮在公开公告不足时作兜底。命中按已修复历史洞落盘（fix_status=patched），不要读源码判断是否已修。",
            parameters={
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "ecosystem": {"type": "string"},
                    "package": {"type": "string"},
                    "per_page": {"type": "integer"},
                },
            },
            handler=_search_ghsa_handler,
            parallel_safe=True,
        )
    )
    registry.register(
        ToolSpec(
            name="SearchGitHubIssues",
            description=(
                "搜索本仓库未关闭的 GitHub Issues（自动加 is:open）。"
                "仅用于未修复洞：未关闭即默认 unpatched。历史漏洞爬虫落盘轮不要用；搜索补漏轮在爬虫结果不足时再搜。"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "额外关键词，如 CVE、RCE、未授权；与 repo:owner/name is:issue is:open 组合",
                    },
                    "repo": {
                        "type": "string",
                        "description": "可选 owner/repo；省略则用项目 GitHub 身份",
                    },
                    "per_page": {"type": "integer"},
                },
            },
            handler=_search_github_issues_handler,
            parallel_safe=True,
        )
    )
    registry.register(
        ToolSpec(
            name="SearchOldVuln",
            description=(
                "搜索本项目漏洞库：侦察阶段历史漏洞（kind=old，含已修复 patched 与未修复 unpatched）"
                "与本项目已提交报告（kind=found）。默认返回标题与摘要；kind=old 带 fix_status；kind=found 会带上 submission_tier、root_cause_key。"
                "传入 title 可看全文。提交前查重；Reviewer 标 duplicate_grouped 时必须原样复用已有 root_cause_key。"
                "kind=found 含 merged_into_id：已并入条目勿再交相同受影响点。"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "title": {"type": "string"},
                },
            },
            handler=_search_old_vuln_handler,
            parallel_safe=True,
        )
    )


register_common_tools()

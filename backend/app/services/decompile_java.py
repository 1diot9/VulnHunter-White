"""Java bytecode decompilation via jadx (async queue + on-disk index)."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import threading
import time
import uuid
import zipfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from ..config import settings
from .ingest import IGNORE_DIR_NAMES, is_test_path
from .paths import (
    force_rmtree,
    project_root,
    src_dir,
    strip_windows_long_path,
    windows_long_path,
    workspace_dir,
)

BYTECODE_SUFFIXES = frozenset({".class", ".jar", ".war", ".ear"})

THIRD_PARTY_PREFIXES = (
    "spring-",
    "tomcat-",
    "jackson-",
    "hibernate-",
    "netty-",
    "lucene-",
    "log4j-",
    "slf4j-",
    "logback-",
    "junit-",
    "mockito-",
    "byte-buddy",
    "objenesis",
    "commons-io-",
    "commons-lang",
    "commons-codec",
    "commons-collections",
    "commons-logging",
    "guava-",
    "gson-",
    "okhttp",
    "okio-",
    "reactor-",
    "kotlin-stdlib",
    "kotlin-reflect",
    "groovy-",
    "aspectj",
    "micrometer-",
    "swagger-",
    "mybatis-",
    "druid-",
    "fastjson-",
    "hutool-",
    "snakeyaml",
    "validation-api",
    "jakarta.",
    "javax.",
    "org.apache.",
    "org.springframework.",
)

_INDEX_NAME = "index.jsonl"
_STATUS_READY = "ready"
_STATUS_QUEUED = "queued"
_STATUS_RUNNING = "running"
_STATUS_FAILED = "failed"
_STATUS_SKIPPED = "skipped"
_STATUS_CANCELLED = "cancelled"

_lock = threading.RLock()
_jobs: dict[str, "DecompileJob"] = {}
_key_to_job: dict[str, str] = {}  # index_key -> job_id
_project_cancel: dict[int, threading.Event] = {}
_executor: ThreadPoolExecutor | None = None
# Optional test hook: (cmd, cwd, timeout) -> CompletedProcess-like
_run_jadx_hook: Callable[..., Any] | None = None


@dataclass
class DecompileJob:
    job_id: str
    project_id: int
    index_key: str
    source_rel: str
    source_abs: Path
    output_rel: str
    output_abs: Path
    class_name: str = ""
    package: str = ""
    status: str = _STATUS_QUEUED
    error: str = ""
    jadx_version: str = ""
    forced_third_party: bool = False
    partial: bool = False
    class_count: int = 0
    primary_files: list[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    finished_at: float | None = None
    proc: subprocess.Popen[Any] | None = None


def decompiled_root(project_id: int) -> Path:
    path = workspace_dir(project_id) / "decompiled"
    path.mkdir(parents=True, exist_ok=True)
    return path


def index_file(project_id: int) -> Path:
    return decompiled_root(project_id) / _INDEX_NAME


def clear_decompiled(project_id: int) -> None:
    """Wipe artifacts after re-import."""
    cancel_project_jobs(project_id)
    root = workspace_dir(project_id) / "decompiled"
    if root.exists():
        force_rmtree(root)
    decompiled_root(project_id)


def cancel_project_jobs(project_id: int) -> None:
    with _lock:
        ev = _project_cancel.setdefault(project_id, threading.Event())
        ev.set()
        for job in list(_jobs.values()):
            if job.project_id != project_id:
                continue
            if job.status in (_STATUS_QUEUED, _STATUS_RUNNING):
                job.status = _STATUS_CANCELLED
                job.error = "项目已取消"
                job.finished_at = time.time()
                if job.proc and job.proc.poll() is None:
                    try:
                        job.proc.terminate()
                    except OSError:
                        pass
                _persist_entry(job)
        # Allow future work after a fresh resume/import creates a new event
        _project_cancel[project_id] = threading.Event()


def _project_cancelled(project_id: int) -> bool:
    with _lock:
        ev = _project_cancel.get(project_id)
        return bool(ev and ev.is_set())


def resolve_jadx_binary(path_override: str | None = None) -> str | None:
    """Optional form override → Settings DB path → env/settings → PATH."""
    configured = (path_override or "").strip()
    if not configured:
        try:
            from ..models import AppSettings, SessionLocal

            with SessionLocal() as db:
                row = db.query(AppSettings).first()
                if row is not None:
                    configured = (getattr(row, "jadx_path", None) or "").strip()
        except Exception:  # noqa: BLE001
            configured = ""
    if not configured:
        configured = (getattr(settings, "jadx_path", None) or "").strip()
    if configured:
        p = Path(configured)
        if p.is_file():
            return str(p.resolve())
        which = shutil.which(configured)
        if which:
            return which
        # Absolute/relative path that does not exist — do not silently fall back to PATH
        if path_override is not None and (path_override or "").strip():
            return None
        if Path(configured).is_absolute() or "/" in configured or "\\" in configured:
            return None
    for name in ("jadx", "jadx.bat", "jadx.cmd"):
        found = shutil.which(name)
        if found:
            return found
    return None


def probe_jadx(path: str | None = None) -> dict[str, Any]:
    """Connectivity check for settings page (does not require saving)."""
    started = time.perf_counter()
    override = None if path is None else str(path)
    # Distinguish "use form empty → saved/PATH" vs "form sent empty string"
    binary = resolve_jadx_binary(override if override is not None else None)
    if path is not None and (path or "").strip() and binary is None:
        return {
            "ok": False,
            "error": f"找不到 jadx：{(path or '').strip()}",
            "path": (path or "").strip(),
            "version": "",
            "latency_ms": int((time.perf_counter() - started) * 1000),
        }
    if not binary:
        return {
            "ok": False,
            "error": "未找到 jadx；请填写绝对路径，或安装到 PATH（jadx / jadx.bat）",
            "path": "",
            "version": "",
            "latency_ms": int((time.perf_counter() - started) * 1000),
        }
    version = jadx_version_string(binary)
    latency = int((time.perf_counter() - started) * 1000)
    if not version or version == "unknown":
        # binary exists but --version failed
        return {
            "ok": False,
            "error": f"已解析到 {binary}，但 jadx --version 失败",
            "path": binary,
            "version": "",
            "latency_ms": latency,
        }
    return {
        "ok": True,
        "path": binary,
        "version": version,
        "latency_ms": latency,
        "error": None,
    }


def jadx_version_string(binary: str | None = None) -> str:
    bin_path = binary or resolve_jadx_binary()
    if not bin_path:
        return ""
    try:
        proc = subprocess.run(
            [bin_path, "--version"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        text = (proc.stdout or proc.stderr or "").strip().splitlines()
        return text[0].strip() if text else "unknown"
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with windows_long_path(path).open("rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _key_short(index_key: str) -> str:
    base = index_key.split("#", 1)[0]
    return base[:16]


def make_index_key(source_abs: Path, *, class_name: str = "", package: str = "") -> str:
    digest = _sha256_file(source_abs)
    cn = (class_name or "").strip().replace("/", ".").lstrip(".")
    pkg = (package or "").strip().replace("/", ".").strip(".")
    if cn:
        return f"{digest}#{cn}"
    if pkg:
        return f"{digest}#pkg:{pkg}"
    return digest


def is_third_party_name(name: str) -> bool:
    leaf = Path(str(name or "")).name.lower()
    if not leaf:
        return False
    for prefix in THIRD_PARTY_PREFIXES:
        if leaf.startswith(prefix.lower()):
            return True
    return False


def _existing_java_rels(project_id: int) -> set[str]:
    """Relative posix paths under src/ ending in .java (lowercase)."""
    root = src_dir(project_id)
    out: set[str] = set()
    if not root.is_dir():
        return out
    walk_root = windows_long_path(root)
    for dirpath, dirnames, filenames in os.walk(walk_root):
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIR_NAMES and not d.startswith(".")]
        for fn in filenames:
            if not fn.lower().endswith(".java"):
                continue
            full = strip_windows_long_path(Path(dirpath) / fn)
            try:
                rel = full.relative_to(root).as_posix().lower()
            except ValueError:
                continue
            out.add(rel)
    return out


def _class_to_java_rel(class_name: str) -> str:
    cn = class_name.strip().replace(".", "/").replace("\\", "/")
    if cn.endswith(".class"):
        cn = cn[: -len(".class")]
    # strip nested $ for existence check against outer class file
    outer = cn.split("$", 1)[0]
    return f"{outer}.java".lower()


def source_java_exists(project_id: int, class_name: str, *, cache: set[str] | None = None) -> bool:
    rel = _class_to_java_rel(class_name)
    if not rel.endswith(".java"):
        return False
    known = cache if cache is not None else _existing_java_rels(project_id)
    if rel in known:
        return True
    # also match .../com/foo/Bar.java anywhere
    leaf = Path(rel).name
    return any(p.endswith("/" + leaf) or p == leaf for p in known)


def list_bytecode(
    project_id: int,
    *,
    include_build_dirs: bool = False,
    limit: int = 200,
) -> list[dict[str, Any]]:
    root = src_dir(project_id)
    if not root.is_dir():
        return []
    results: list[dict[str, Any]] = []
    walk_root = windows_long_path(root)
    for dirpath, dirnames, filenames in os.walk(walk_root):
        if include_build_dirs:
            dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        else:
            dirnames[:] = [d for d in dirnames if d not in IGNORE_DIR_NAMES and not d.startswith(".")]
        for fn in filenames:
            suf = Path(fn).suffix.lower()
            if suf not in BYTECODE_SUFFIXES:
                continue
            full = strip_windows_long_path(Path(dirpath) / fn)
            try:
                rel = full.relative_to(root).as_posix()
            except ValueError:
                continue
            if is_test_path(rel):
                continue
            try:
                size = full.stat().st_size
            except OSError:
                size = 0
            results.append(
                {
                    "path": f"src/{rel}",
                    "size": size,
                    "suffix": suf,
                    "third_party_likely": is_third_party_name(fn),
                }
            )
            if len(results) >= max(1, limit):
                return results
    results.sort(key=lambda x: (x["third_party_likely"], -int(x["size"]), x["path"]))
    return results


def _load_index(project_id: int) -> dict[str, dict[str, Any]]:
    path = index_file(project_id)
    out: dict[str, dict[str, Any]] = {}
    if not path.is_file():
        return out
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return out
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict) and row.get("index_key"):
            out[str(row["index_key"])] = row
    return out


def _rewrite_index(project_id: int, entries: dict[str, dict[str, Any]]) -> None:
    path = index_file(project_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    lines = [json.dumps(entries[k], ensure_ascii=False) for k in sorted(entries)]
    tmp.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    tmp.replace(path)


def _persist_entry(job: DecompileJob) -> None:
    with _lock:
        entries = _load_index(job.project_id)
        entries[job.index_key] = {
            "index_key": job.index_key,
            "job_id": job.job_id,
            "source": job.source_rel,
            "output_root": job.output_rel,
            "status": job.status,
            "error": job.error,
            "jadx_version": job.jadx_version,
            "class_name": job.class_name,
            "package": job.package,
            "forced_third_party": job.forced_third_party,
            "partial": job.partial,
            "class_count": job.class_count,
            "primary_files": job.primary_files[:20],
            "finished_at": job.finished_at,
        }
        _rewrite_index(job.project_id, entries)


def _entry_to_result(entry: dict[str, Any], *, hint: str = "") -> dict[str, Any]:
    status = str(entry.get("status") or "")
    out: dict[str, Any] = {
        "ok": status not in (_STATUS_FAILED, _STATUS_CANCELLED),
        "status": status,
        "job_id": entry.get("job_id"),
        "source": entry.get("source"),
        "output_root": entry.get("output_root"),
        "index_key": entry.get("index_key"),
    }
    if entry.get("error"):
        out["error"] = entry["error"]
    if status == _STATUS_READY:
        out["ok"] = True
        out["class_count"] = int(entry.get("class_count") or 0)
        out["primary_files"] = list(entry.get("primary_files") or [])[:20]
        out["partial"] = bool(entry.get("partial"))
        out["hint"] = hint or "反编译完成；用 Read/Grep 时请显式指定 root=output_root。"
    elif status in (_STATUS_QUEUED, _STATUS_RUNNING):
        out["ok"] = True
        out["hint"] = hint or (
            "任务已排队或正在运行；请继续其它工作，完成后系统会注入通知，也可再用本工具查询。"
        )
    elif status == _STATUS_SKIPPED:
        out["ok"] = True
        out["hint"] = hint or (entry.get("error") or "已跳过")
    else:
        out["ok"] = False
        out["hint"] = hint or "反编译失败；可 force=true 重试或缩小为 class/package。"
    if entry.get("forced_third_party"):
        out["forced_third_party"] = True
    return out


def _job_to_result(job: DecompileJob) -> dict[str, Any]:
    return _entry_to_result(
        {
            "index_key": job.index_key,
            "job_id": job.job_id,
            "source": job.source_rel,
            "output_root": job.output_rel,
            "status": job.status,
            "error": job.error,
            "class_count": job.class_count,
            "primary_files": job.primary_files,
            "partial": job.partial,
            "forced_third_party": job.forced_third_party,
        }
    )


def _normalize_source_rel(project_id: int, raw: str) -> tuple[str, Path]:
    text = (raw or "").replace("\\", "/").strip().lstrip("/")
    if text.startswith("src/"):
        rel_under = text[4:]
    elif text == "src":
        raise ValueError("请指定具体 .class/.jar/.war 路径")
    else:
        rel_under = text
    if ".." in Path(rel_under).parts:
        raise ValueError("路径不允许包含 ..")
    abs_path = (src_dir(project_id) / rel_under).resolve()
    src_root = src_dir(project_id).resolve()
    try:
        abs_path.relative_to(src_root)
    except ValueError as e:
        raise ValueError(f"路径越界: {raw}") from e
    if not abs_path.is_file():
        raise ValueError(f"文件不存在: src/{rel_under}")
    suf = abs_path.suffix.lower()
    if suf not in BYTECODE_SUFFIXES:
        raise ValueError(f"仅支持 {', '.join(sorted(BYTECODE_SUFFIXES))}，收到 {suf or '(无后缀)'}")
    return f"src/{rel_under.replace(chr(92), '/')}", abs_path


def _max_jar_bytes() -> int:
    return max(1, int(getattr(settings, "decompile_max_jar_bytes", 80 * 1024 * 1024) or 80 * 1024 * 1024))


def _max_output_bytes() -> int:
    return max(1, int(getattr(settings, "decompile_max_output_bytes", 500 * 1024 * 1024) or 500 * 1024 * 1024))


def _job_timeout() -> int:
    return max(60, int(getattr(settings, "decompile_timeout_sec", 1800) or 1800))


def _pool() -> ThreadPoolExecutor:
    global _executor
    with _lock:
        if _executor is None:
            workers = max(1, min(4, int(getattr(settings, "decompile_concurrency", 2) or 2)))
            _executor = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="vh-jadx")
        return _executor


def _scan_output(output_abs: Path, project_id: int) -> tuple[int, list[str], bool]:
    if not output_abs.is_dir():
        return 0, [], False
    java_files: list[str] = []
    total_size = 0
    root = project_root(project_id)
    for dirpath, _dns, filenames in os.walk(windows_long_path(output_abs)):
        for fn in filenames:
            full = strip_windows_long_path(Path(dirpath) / fn)
            try:
                total_size += full.stat().st_size
            except OSError:
                pass
            if not fn.lower().endswith(".java"):
                continue
            try:
                rel = full.relative_to(root).as_posix()
            except ValueError:
                rel = str(full)
            java_files.append(rel)
    java_files.sort()
    primary = java_files[:20]
    partial = total_size > _max_output_bytes()
    return len(java_files), primary, partial


def _dir_size(path: Path) -> int:
    total = 0
    if not path.is_dir():
        return 0
    for dirpath, _dns, filenames in os.walk(windows_long_path(path)):
        for fn in filenames:
            try:
                total += (Path(dirpath) / fn).stat().st_size
            except OSError:
                pass
    return total


def _filter_input_for_scope(
    source_abs: Path,
    work_dir: Path,
    *,
    class_name: str,
    package: str,
    project_id: int,
) -> Path | None:
    """Copy scoped class(es) into work_dir; return path to feed jadx. None = use whole archive."""
    cn = (class_name or "").strip().replace(".", "/")
    pkg = (package or "").strip().replace(".", "/").strip("/")
    if not cn and not pkg:
        # whole archive — still skip classes that already have source when jar
        if source_abs.suffix.lower() == ".class":
            return None
        return _copy_jar_missing_only(source_abs, work_dir, project_id)
    work_dir.mkdir(parents=True, exist_ok=True)
    if source_abs.suffix.lower() == ".class":
        dest = work_dir / source_abs.name
        shutil.copy2(windows_long_path(source_abs), windows_long_path(dest))
        return dest

    extracted = 0
    with zipfile.ZipFile(windows_long_path(source_abs), "r") as zf:
        for name in zf.namelist():
            if not name.lower().endswith(".class") or name.endswith("/"):
                continue
            norm = name.replace("\\", "/")
            if cn:
                target = cn if cn.endswith(".class") else f"{cn}.class"
                # allow nested classes Foo$1 when class_name is Foo
                base = target[: -len(".class")] if target.endswith(".class") else target
                if not (norm == target or norm.endswith("/" + target) or norm.rsplit("/", 1)[-1].startswith(base.split("/")[-1] + "$")):
                    # also exact FQCN path
                    if norm != target and not norm.endswith("/" + target):
                        leaf = norm.rsplit("/", 1)[-1]
                        want_leaf = target.rsplit("/", 1)[-1]
                        if leaf != want_leaf and not leaf.startswith(want_leaf.replace(".class", "") + "$"):
                            continue
            elif pkg:
                if not (norm.startswith(pkg + "/") or norm.startswith(pkg + "\\")):
                    continue
            # skip if source exists
            fqcn = norm[: -len(".class")].replace("/", ".")
            if source_java_exists(project_id, fqcn):
                continue
            dest = work_dir / Path(norm)
            dest.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(name) as src, dest.open("wb") as dst:
                shutil.copyfileobj(src, dst)
            extracted += 1
    if extracted == 0:
        return work_dir  # empty marker
    return work_dir


def _copy_jar_missing_only(source_abs: Path, work_dir: Path, project_id: int) -> Path | None:
    """Extract only .class entries without matching src .java; None if nothing to do / use original if none exist."""
    try:
        names = []
        with zipfile.ZipFile(windows_long_path(source_abs), "r") as zf:
            names = [n for n in zf.namelist() if n.lower().endswith(".class") and not n.endswith("/")]
    except zipfile.BadZipFile:
        return None
    if not names:
        return None
    cache = _existing_java_rels(project_id)
    missing = []
    for name in names:
        fqcn = name[: -len(".class")].replace("/", ".").replace("\\", ".")
        if not source_java_exists(project_id, fqcn, cache=cache):
            missing.append(name)
    if not missing:
        return work_dir  # empty — all have source
    if len(missing) == len(names):
        return None  # use original jar
    work_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(windows_long_path(source_abs), "r") as zf:
        for name in missing:
            dest = work_dir / Path(name.replace("\\", "/"))
            dest.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(name) as src, dest.open("wb") as dst:
                shutil.copyfileobj(src, dst)
    return work_dir


def _run_jadx(cmd: list[str], *, timeout: int, job: DecompileJob) -> subprocess.CompletedProcess[str]:
    if _run_jadx_hook is not None:
        return _run_jadx_hook(cmd, timeout=timeout, job=job)
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    job.proc = proc
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate(timeout=30)
        return subprocess.CompletedProcess(cmd, -1, stdout or "", (stderr or "") + "\n超时")
    return subprocess.CompletedProcess(cmd, proc.returncode, stdout or "", stderr or "")


def _execute_job(job_id: str) -> None:
    with _lock:
        job = _jobs.get(job_id)
        if job is None or job.status == _STATUS_CANCELLED:
            return
        job.status = _STATUS_RUNNING
        _persist_entry(job)

    if _project_cancelled(job.project_id):
        job.status = _STATUS_CANCELLED
        job.error = "项目已取消"
        job.finished_at = time.time()
        _persist_entry(job)
        return

    binary = resolve_jadx_binary()
    if not binary:
        job.status = _STATUS_FAILED
        job.error = "未找到 jadx；请在设置页配置 jadx_path 或安装到 PATH"
        job.finished_at = time.time()
        _persist_entry(job)
        return

    job.jadx_version = jadx_version_string(binary)
    out_abs = windows_long_path(job.output_abs)
    if out_abs.exists():
        force_rmtree(Path(out_abs))
    out_abs.mkdir(parents=True, exist_ok=True)

    staging = decompiled_root(job.project_id) / ".staging" / job.job_id
    if staging.exists():
        force_rmtree(staging)
    staging.mkdir(parents=True, exist_ok=True)

    try:
        feed = _filter_input_for_scope(
            job.source_abs,
            staging / "in",
            class_name=job.class_name,
            package=job.package,
            project_id=job.project_id,
        )
        if feed is not None and feed.is_dir():
            # empty dir means all skipped
            has_class = any(p.suffix.lower() == ".class" for p in feed.rglob("*") if p.is_file())
            if not has_class:
                job.status = _STATUS_SKIPPED
                job.error = "对应源码已存在于 src/，无需反编译"
                job.finished_at = time.time()
                _persist_entry(job)
                return
            input_path = feed
        elif feed is not None and feed.is_file():
            input_path = feed
        else:
            input_path = job.source_abs

        # Single .class with existing source
        if job.source_abs.suffix.lower() == ".class" and not job.class_name and not job.package:
            # derive FQCN from path under typical package roots
            rel = job.source_rel
            if rel.startswith("src/"):
                rel = rel[4:]
            fqcn = rel[: -len(".class")].replace("/", ".") if rel.lower().endswith(".class") else ""
            # strip WEB-INF/classes / BOOT-INF/classes prefix
            for prefix in ("WEB-INF/classes/", "BOOT-INF/classes/", "classes/"):
                low = rel.replace("\\", "/")
                if low.upper().startswith(prefix.upper()) or low.startswith(prefix):
                    # find case-insensitive
                    pass
            norm = rel.replace("\\", "/")
            for prefix in ("WEB-INF/classes/", "BOOT-INF/classes/", "classes/"):
                idx = norm.lower().find(prefix.lower())
                if idx >= 0:
                    fqcn = norm[idx + len(prefix) : -len(".class")].replace("/", ".")
                    break
            if fqcn and source_java_exists(job.project_id, fqcn):
                job.status = _STATUS_SKIPPED
                job.error = "对应源码已存在于 src/，无需反编译"
                job.finished_at = time.time()
                _persist_entry(job)
                return

        cmd = [
            binary,
            "--quiet",
            "-d",
            str(out_abs),
            str(windows_long_path(input_path)),
        ]
        # Prefer only class filters when jadx supports --include-class; keep simple for portability
        timeout = _job_timeout()
        completed = _run_jadx(cmd, timeout=timeout, job=job)
        if _project_cancelled(job.project_id):
            job.status = _STATUS_CANCELLED
            job.error = "项目已取消"
            job.finished_at = time.time()
            _persist_entry(job)
            return

        count, primary, oversized = _scan_output(job.output_abs, job.project_id)
        job.class_count = count
        job.primary_files = primary
        if oversized or _dir_size(job.output_abs) > _max_output_bytes():
            job.partial = True
            job.status = _STATUS_FAILED
            job.error = (
                f"产出超过上限 ({_max_output_bytes()} bytes)；请改用 class_name / package 缩小范围"
            )
            force_rmtree(job.output_abs)
            job.finished_at = time.time()
            _persist_entry(job)
            return

        if count == 0:
            err = (completed.stderr or completed.stdout or "").strip()[:500]
            job.status = _STATUS_FAILED
            job.error = err or f"jadx 退出码 {completed.returncode}，无 .java 产出"
            job.finished_at = time.time()
            _persist_entry(job)
            return

        job.partial = completed.returncode != 0
        job.status = _STATUS_READY
        job.finished_at = time.time()
        _persist_entry(job)
    except Exception as e:  # noqa: BLE001
        job.status = _STATUS_FAILED
        job.error = str(e)[:800]
        job.finished_at = time.time()
        _persist_entry(job)
    finally:
        if staging.exists():
            force_rmtree(staging)
        job.proc = None


def get_job_status(project_id: int, *, job_id: str = "", index_key: str = "", source: str = "") -> dict[str, Any] | None:
    with _lock:
        job: DecompileJob | None = None
        if job_id and job_id in _jobs and _jobs[job_id].project_id == project_id:
            job = _jobs[job_id]
        elif index_key and index_key in _key_to_job:
            jid = _key_to_job[index_key]
            job = _jobs.get(jid)
        if job is not None:
            return _job_to_result(job)
    entries = _load_index(project_id)
    if index_key and index_key in entries:
        return _entry_to_result(entries[index_key])
    if job_id:
        for e in entries.values():
            if e.get("job_id") == job_id:
                return _entry_to_result(e)
    if source:
        for e in entries.values():
            if e.get("source") == source or e.get("source") == source.replace("\\", "/"):
                # prefer ready
                if e.get("status") == _STATUS_READY:
                    return _entry_to_result(e)
        for e in entries.values():
            if e.get("source") == source or e.get("source") == source.replace("\\", "/"):
                return _entry_to_result(e)
    return None


def submit_decompile(
    project_id: int,
    source: str,
    *,
    class_name: str = "",
    package: str = "",
    force: bool = False,
    reason: str = "",
) -> dict[str, Any]:
    try:
        source_rel, source_abs = _normalize_source_rel(project_id, source)
    except ValueError as e:
        return {"ok": False, "status": _STATUS_FAILED, "error": str(e), "error_class": "call"}

    suf = source_abs.suffix.lower()
    whole_archive = suf in {".jar", ".war", ".ear"} and not (class_name or "").strip() and not (package or "").strip()
    if whole_archive:
        try:
            size = source_abs.stat().st_size
        except OSError as e:
            return {"ok": False, "status": _STATUS_FAILED, "error": str(e), "error_class": "local"}
        limit = _max_jar_bytes()
        if size > limit:
            return {
                "ok": False,
                "status": _STATUS_SKIPPED,
                "source": source_rel,
                "error": (
                    f"整包大小 {size} 字节超过上限 {limit} 字节；"
                    "请传 class_name 或 package 缩小范围，或换更小的 jar"
                ),
                "hint": "超限未入队",
                "error_class": "call",
            }

    third = is_third_party_name(source_abs.name)
    if third and not force:
        return {
            "ok": False,
            "status": _STATUS_SKIPPED,
            "source": source_rel,
            "error": "疑似第三方依赖，默认拒绝；确认需要时传 force=true 与简短 reason",
            "third_party_likely": True,
            "error_class": "call",
        }

    index_key = make_index_key(source_abs, class_name=class_name, package=package)

    with _lock:
        # live job?
        existing_id = _key_to_job.get(index_key)
        if existing_id and existing_id in _jobs:
            job = _jobs[existing_id]
            if job.status in (_STATUS_QUEUED, _STATUS_RUNNING, _STATUS_READY) and not force:
                return _job_to_result(job)
            if job.status == _STATUS_FAILED and not force:
                return _job_to_result(job)

        entries = _load_index(project_id)
        if index_key in entries and not force:
            entry = entries[index_key]
            st = entry.get("status")
            out_rel = str(entry.get("output_root") or "")
            out_abs = project_root(project_id) / out_rel if out_rel else None
            if st == _STATUS_READY and out_abs and out_abs.is_dir() and any(out_abs.rglob("*.java")):
                return _entry_to_result(entry)
            if st == _STATUS_READY and (not out_abs or not out_abs.is_dir()):
                pass  # re-queue below
            elif st in (_STATUS_QUEUED, _STATUS_RUNNING):
                return _entry_to_result(entry)
            elif st == _STATUS_SKIPPED and not force:
                return _entry_to_result(entry)
            elif st == _STATUS_FAILED and not force:
                return _entry_to_result(entry)

        job_id = uuid.uuid4().hex[:12]
        out_rel = f"workspace/decompiled/{_key_short(index_key)}"
        if class_name:
            safe = re.sub(r"[^\w.-]+", "_", class_name)[:80]
            out_rel = f"{out_rel}_{safe}"
        elif package:
            safe = re.sub(r"[^\w.-]+", "_", package)[:80]
            out_rel = f"{out_rel}_pkg_{safe}"
        out_abs = project_root(project_id) / out_rel

        job = DecompileJob(
            job_id=job_id,
            project_id=project_id,
            index_key=index_key,
            source_rel=source_rel,
            source_abs=source_abs,
            output_rel=out_rel.replace("\\", "/"),
            output_abs=out_abs,
            class_name=(class_name or "").strip(),
            package=(package or "").strip(),
            status=_STATUS_QUEUED,
            forced_third_party=bool(third and force),
        )
        if third and force and reason:
            job.error = f"force: {reason[:200]}"
        _jobs[job_id] = job
        _key_to_job[index_key] = job_id
        _persist_entry(job)
        _pool().submit(_execute_job, job_id)
        return _job_to_result(job)


def job_statuses_for_ids(project_id: int, job_ids: list[str]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for jid in job_ids:
        st = get_job_status(project_id, job_id=jid)
        if st:
            out.append(st)
    return out


def take_finished_notices(project_id: int, watched: list[str], already: set[str]) -> list[dict[str, Any]]:
    """Return newly finished (ready/failed/skipped/cancelled) jobs for injection."""
    notices: list[dict[str, Any]] = []
    for jid in watched:
        if jid in already:
            continue
        st = get_job_status(project_id, job_id=jid)
        if not st:
            continue
        if st.get("status") in (_STATUS_READY, _STATUS_FAILED, _STATUS_SKIPPED, _STATUS_CANCELLED):
            notices.append(st)
    return notices


def is_pending_decompile_query(arguments: dict[str, Any], project_id: int) -> bool:
    """True when identical DecompileJava poll would still see queued/running."""
    job_id = str(arguments.get("job_id") or "").strip()
    source = str(arguments.get("path") or arguments.get("source") or "").strip()
    class_name = str(arguments.get("class_name") or "").strip()
    package = str(arguments.get("package") or "").strip()
    st = None
    if job_id:
        st = get_job_status(project_id, job_id=job_id)
    elif source:
        try:
            source_rel, source_abs = _normalize_source_rel(project_id, source)
            key = make_index_key(source_abs, class_name=class_name, package=package)
            st = get_job_status(project_id, index_key=key, source=source_rel)
        except ValueError:
            return False
    if not st:
        return False
    return st.get("status") in (_STATUS_QUEUED, _STATUS_RUNNING)


def enqueue_heuristic_candidates(project_id: int, *, limit: int = 8) -> list[dict[str, Any]]:
    """Auto-queue high-confidence app jars/classes (Recon start helper)."""
    items = list_bytecode(project_id, include_build_dirs=False, limit=200)
    queued: list[dict[str, Any]] = []
    for item in items:
        if item.get("third_party_likely"):
            continue
        path = str(item.get("path") or "")
        low = path.lower()
        interesting = any(
            p in low
            for p in (
                "/web-inf/lib/",
                "/web-inf/classes/",
                "/boot-inf/classes/",
                "/lib/",
                "/libs/",
            )
        ) or low.endswith(".class")
        if not interesting and not low.endswith((".jar", ".war")):
            continue
        if low.endswith((".jar", ".war")) and int(item.get("size") or 0) > _max_jar_bytes():
            continue
        # Prefer jars in lib paths or loose classes
        if low.endswith((".jar", ".war")) and not any(
            p in low for p in ("/web-inf/lib/", "/lib/", "/libs/")
        ):
            # still allow non-third-party jar at repo root-ish
            if path.count("/") > 4:
                continue
        result = submit_decompile(project_id, path)
        queued.append(result)
        if len(queued) >= limit:
            break
    return queued


def format_completion_inject(notices: list[dict[str, Any]]) -> str:
    lines = ["【系统】Java 反编译任务有更新（请继续其它工作；Recon 请把路径记入 docs/code-map.md）："]
    for n in notices:
        lines.append(
            f"- job_id={n.get('job_id')} status={n.get('status')} source={n.get('source')} "
            f"output_root={n.get('output_root')}"
            + (f" error={n.get('error')}" if n.get("error") else "")
        )
        if n.get("status") == _STATUS_READY and n.get("primary_files"):
            lines.append(f"  primary_files: {', '.join(n['primary_files'][:5])}")
    lines.append("完整树请 Glob/Grep，并显式传 root=上述 output_root。")
    return "\n".join(lines)

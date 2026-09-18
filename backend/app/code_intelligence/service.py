"""Project-level Code Intelligence index lifecycle (CodeGraph + Jar Analyzer)."""

from __future__ import annotations

import hashlib
import json
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..config import settings
from ..models import Project, SessionLocal, utcnow
from ..services.ingest import IGNORE_DIR_NAMES
from ..services.live_log import live_log
from ..services.paths import code_intel_dir, force_rmtree, src_dir, strip_windows_long_path
from .cli import cli_version, ensure_codegraph, find_codegraph, popen_ui, stream_codegraph, ui_subcommand

CODE_INTEL_PHASE = "code_intel"
STATUSES = ("pending", "building", "ready", "degraded", "stale", "skipped")
BACKEND_CODEGRAPH = "codegraph"
BACKEND_JAR = "jar_analyzer"
VALID_BACKENDS = frozenset({BACKEND_CODEGRAPH, BACKEND_JAR})
_STALE_CHECK_SEC = 30.0
_last_stale_check: dict[int, float] = {}
_ui_lock = threading.Lock()
_ui_procs: dict[int, Any] = {}
_ui_urls: dict[str, str] = {}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _meta_path(project_id: int) -> Path:
    return code_intel_dir(project_id) / "metadata.json"


def _index_dir(project_id: int) -> Path:
    return src_dir(project_id) / ".codegraph"


def jars_index_dir(project_id: int) -> Path:
    path = code_intel_dir(project_id) / "jars"
    path.mkdir(parents=True, exist_ok=True)
    return path


def read_metadata(project_id: int) -> dict[str, Any]:
    path = _meta_path(project_id)
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def write_metadata(project_id: int, payload: dict[str, Any]) -> None:
    path = _meta_path(project_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    current = read_metadata(project_id)
    current.update(payload)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(current, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)


def requested_backends(project_id: int) -> list[str]:
    meta = read_metadata(project_id)
    raw = meta.get("requested_backends")
    if not isinstance(raw, list):
        return []
    out: list[str] = []
    for item in raw:
        name = str(item or "").strip()
        if name in VALID_BACKENDS and name not in out:
            out.append(name)
    return out


def code_intel_choice_ready(project_id: int) -> bool:
    """True when map Agent has named at least one backend (or CI is off)."""
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        if not proj or not bool(getattr(proj, "code_intel_enabled", False)):
            return True
    return bool(requested_backends(project_id))


def source_fingerprint(project_id: int) -> str:
    """Hash of source files under src/ (size + mtime). Skips .codegraph and ignore dirs."""
    root = src_dir(project_id)
    if not root.is_dir():
        return hashlib.sha256(b"").hexdigest()
    skip = set(IGNORE_DIR_NAMES) | {".codegraph"}
    lines: list[str] = []
    for dirpath, dirnames, filenames in os_walk_sorted(root):
        dirnames[:] = [d for d in sorted(dirnames) if d not in skip and d != "." and d != ".."]
        rel_dir = Path(dirpath).relative_to(root).as_posix()
        for name in sorted(filenames):
            if name.startswith("."):
                continue
            rel = name if rel_dir in (".", "") else f"{rel_dir}/{name}"
            path = Path(dirpath) / name
            try:
                st = path.stat()
            except OSError:
                continue
            lines.append(f"{rel}\0{st.st_size}\0{int(st.st_mtime_ns)}")
    blob = "\n".join(lines).encode("utf-8", errors="replace")
    return hashlib.sha256(blob).hexdigest()


def os_walk_sorted(root: Path):
    import os

    return os.walk(root)


def is_code_intel_enabled(proj: Project | None) -> bool:
    return bool(proj and getattr(proj, "code_intel_enabled", False))


def code_intel_ready_for_mining(proj: Project | None) -> bool:
    """True when mining may start with respect to Code Intelligence."""
    if not proj:
        return False
    if not is_code_intel_enabled(proj):
        return True
    return bool(getattr(proj, "code_intel_done", False))


def create_fields(*, enabled: bool) -> dict[str, Any]:
    if enabled:
        return {
            "code_intel_enabled": True,
            "code_intel_status": "pending",
            "code_intel_done": False,
            "code_intel_error": None,
        }
    return {
        "code_intel_enabled": False,
        "code_intel_status": "skipped",
        "code_intel_done": False,
        "code_intel_error": None,
    }


def mark_skipped(project_id: int) -> None:
    _set_project_fields(
        project_id,
        code_intel_enabled=False,
        code_intel_status="skipped",
        code_intel_done=False,
        code_intel_error=None,
    )
    purge_index(project_id)


def purge_index(project_id: int) -> None:
    """Delete src/.codegraph and jar analyzer DBs when Code Intelligence is off."""
    force_rmtree(_index_dir(project_id))
    force_rmtree(jars_index_dir(project_id))
    write_metadata(
        project_id,
        {
            "status": "skipped",
            "purged_at": _now_iso(),
            "index_dir": "src/.codegraph",
            "requested_backends": [],
            "backends": {},
        },
    )
    _log(project_id, "已关闭代码库并删除索引，释放磁盘")


def code_intel_settled(project_id: int) -> bool:
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        return code_intel_ready_for_mining(proj)


def _set_project_fields(project_id: int, **fields: Any) -> None:
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        if not proj:
            return
        for key, value in fields.items():
            setattr(proj, key, value)
        proj.updated_at = utcnow()
        db.commit()


def status_payload(project_id: int) -> dict[str, Any]:
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        if not proj:
            return {
                "status": "pending",
                "enabled": False,
                "done": False,
                "error": "",
                "source_hash": "",
                "version": "",
                "stale": False,
                "backends": [],
            }
        status = (getattr(proj, "code_intel_status", None) or "pending").strip() or "pending"
        enabled = bool(getattr(proj, "code_intel_enabled", False))
        return {
            "status": status,
            "enabled": enabled,
            "done": bool(getattr(proj, "code_intel_done", False)),
            "error": (getattr(proj, "code_intel_error", None) or "").strip(),
            "source_hash": (getattr(proj, "code_intel_source_hash", None) or "").strip(),
            "version": (getattr(proj, "code_intel_version", None) or "").strip(),
            "stale": status == "stale",
            "backends": requested_backends(project_id),
        }


def metadata_payload(project_id: int) -> dict[str, Any]:
    meta = read_metadata(project_id)
    payload = status_payload(project_id)
    backends = requested_backends(project_id)
    if len(backends) == 1:
        payload["backend"] = backends[0]
    elif backends:
        payload["backend"] = "+".join(backends)
    else:
        payload["backend"] = str(meta.get("backend") or "")
    payload["index_dir"] = str(meta.get("index_dir") or "src/.codegraph")
    payload["created_at"] = str(meta.get("created_at") or "")
    payload["backend_status"] = meta.get("backends") if isinstance(meta.get("backends"), dict) else {}
    return payload


def _log(project_id: int, text: str) -> None:
    live_log.system(project_id, text, phase=CODE_INTEL_PHASE, role="code_intel")


def _backend_status_map(project_id: int) -> dict[str, Any]:
    meta = read_metadata(project_id)
    raw = meta.get("backends")
    return dict(raw) if isinstance(raw, dict) else {}


def _set_backend_status(project_id: int, backend: str, **fields: Any) -> None:
    backends = _backend_status_map(project_id)
    row = dict(backends.get(backend) or {}) if isinstance(backends.get(backend), dict) else {}
    row.update(fields)
    backends[backend] = row
    write_metadata(project_id, {"backends": backends})


def mark_code_intel(
    project_id: int,
    *,
    codegraph: bool = False,
    jar_analyzer: bool = False,
) -> dict[str, Any]:
    """Recon Agent names which backends to build. At least one must be true."""
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        if not proj:
            return {"ok": False, "error": "项目不存在"}
        if not bool(getattr(proj, "code_intel_enabled", False)):
            return {"ok": False, "error": "本项目未开启代码库；不要调用 MarkCodeIntel"}
    want_cg = bool(codegraph)
    want_ja = bool(jar_analyzer)
    if not want_cg and not want_ja:
        return {
            "ok": False,
            "error": "至少选择一个后端：codegraph=true 和/或 jar_analyzer=true",
        }
    backends: list[str] = []
    if want_cg:
        backends.append(BACKEND_CODEGRAPH)
    if want_ja:
        backends.append(BACKEND_JAR)
    status_map: dict[str, Any] = {}
    for name in backends:
        status_map[name] = {"status": "pending", "error": ""}
    write_metadata(
        project_id,
        {
            "requested_backends": backends,
            "backends": status_map,
            "status": "pending",
            "chosen_at": _now_iso(),
            "created_at": read_metadata(project_id).get("created_at") or _now_iso(),
        },
    )
    _set_project_fields(
        project_id,
        code_intel_status="pending",
        code_intel_done=False,
        code_intel_error=None,
    )
    _log(project_id, f"侦察已点名代码库后端: {', '.join(backends)}")
    from ..services.pipeline import request_code_intel_after_choice

    try:
        request_code_intel_after_choice(project_id)
    except Exception as exc:  # noqa: BLE001
        return {
            "ok": True,
            "backends": backends,
            "hint": f"已记录点名，但启动构建失败: {exc}",
        }
    return {
        "ok": True,
        "backends": backends,
        "hint": (
            "已开始构建所选后端。"
            + (" jar_analyzer 会等 MarkBusinessJar(done/none) 后再对点名业务 jar 建图。" if want_ja else "")
            + " 地图门闩已满足代码库点名条件；业务 jar 门闩仍按 MarkBusinessJar。"
        ),
    }


def mark_stale_if_source_changed(project_id: int, *, force: bool = False) -> bool:
    """If src/ changed after a ready codegraph index, mark stale. Does not rebuild."""
    now = time.time()
    last = _last_stale_check.get(project_id, 0.0)
    if not force and now - last < _STALE_CHECK_SEC:
        return False
    _last_stale_check[project_id] = now
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        if not proj:
            return False
        if not bool(getattr(proj, "code_intel_enabled", False)):
            return False
        status = (getattr(proj, "code_intel_status", None) or "").strip()
        if status not in ("ready", "stale"):
            return False
        stored = (getattr(proj, "code_intel_source_hash", None) or "").strip()
    req = requested_backends(project_id)
    if BACKEND_CODEGRAPH not in req:
        return False
    if not stored:
        return False
    current = source_fingerprint(project_id)
    if current == stored:
        if status == "stale":
            _set_project_fields(project_id, code_intel_status="ready", code_intel_error=None)
            write_metadata(project_id, {"status": "ready"})
        return False
    if status != "stale":
        _set_project_fields(project_id, code_intel_status="stale")
        write_metadata(project_id, {"status": "stale", "source_hash": stored})
        _set_backend_status(project_id, BACKEND_CODEGRAPH, status="stale")
        _log(project_id, "检测到 src/ 文件变化，CodeGraph 索引已过期。不会自动重建，请点击重建。")
    return True


def _wait_business_jars_closed(project_id: int, cancel: threading.Event | None, log) -> dict[str, Any]:
    """Block until MarkBusinessJar done/none, then return business jar state."""
    from ..services.decompile_java import load_business_jar_state

    while True:
        if cancel is not None and cancel.is_set():
            return {"cancelled": True}
        state = load_business_jar_state(project_id)
        if state.get("complete") or state.get("none"):
            return state
        log("Jar Analyzer 等待 MarkBusinessJar(done/none) 闭合业务 jar 名单…")
        time.sleep(3.0)


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _build_codegraph(project_id: int, *, force: bool, cancel: threading.Event | None, log) -> str:
    src = src_dir(project_id)
    src.mkdir(parents=True, exist_ok=True)
    _set_backend_status(project_id, BACKEND_CODEGRAPH, status="building", error="")
    log("开始构建 CodeGraph（仅 src/ 源码）" if not force else "开始重建 CodeGraph（仅 src/ 源码）")
    try:
        binary = ensure_codegraph(log=log)
    except Exception as exc:  # noqa: BLE001
        _set_backend_status(project_id, BACKEND_CODEGRAPH, status="degraded", error=str(exc)[:2000])
        return "degraded"
    if binary is None:
        msg = "未找到 CodeGraph，自动安装失败"
        _set_backend_status(project_id, BACKEND_CODEGRAPH, status="degraded", error=msg)
        return "degraded"
    version = cli_version(binary)
    timeout = int(getattr(settings, "timeout_codegraph_index", 1800) or 1800)
    if (_index_dir(project_id) / "codegraph.db").is_file():
        args = ["index", "--force"]
    else:
        args = ["init", "--yes"]
    try:
        code = stream_codegraph(
            args,
            cwd=src,
            timeout=timeout,
            log=log,
            binary=binary,
            cancel=cancel,
        )
    except FileNotFoundError as exc:
        _set_backend_status(project_id, BACKEND_CODEGRAPH, status="degraded", error=str(exc)[:2000])
        return "degraded"
    except Exception as exc:  # noqa: BLE001
        _set_backend_status(project_id, BACKEND_CODEGRAPH, status="degraded", error=str(exc)[:2000])
        return "degraded"
    if cancel is not None and cancel.is_set():
        return "cancelled"
    if code != 0:
        msg = f"CodeGraph 退出码 {code}"
        _set_backend_status(project_id, BACKEND_CODEGRAPH, status="degraded", error=msg)
        return "degraded"
    db_path = _index_dir(project_id) / "codegraph.db"
    if not db_path.is_file():
        msg = "构建结束但未生成 src/.codegraph/codegraph.db"
        _set_backend_status(project_id, BACKEND_CODEGRAPH, status="degraded", error=msg)
        return "degraded"
    fingerprint = source_fingerprint(project_id)
    _set_backend_status(
        project_id,
        BACKEND_CODEGRAPH,
        status="ready",
        error="",
        version=version,
        source_hash=fingerprint,
    )
    log(f"CodeGraph 就绪（{version or 'unknown'}）")
    return "ready"


def _resolve_jar_input(project_id: int, source_rel: str) -> Path | None:
    from ..services.paths import project_root

    rel = source_rel.replace("\\", "/").lstrip("/")
    abs_path = (src_dir(project_id) / rel).resolve()
    try:
        abs_path.relative_to(src_dir(project_id).resolve())
    except ValueError:
        return None
    if not abs_path.exists():
        # also try project-relative
        alt = (project_root(project_id) / rel).resolve()
        if alt.is_file() or alt.is_dir():
            abs_path = alt
        else:
            return None
    if abs_path.is_file() and abs_path.suffix.lower() in {".jar", ".war", ".ear"}:
        return abs_path
    if abs_path.is_file() and abs_path.suffix.lower() == ".class":
        return abs_path.parent
    if abs_path.is_dir():
        return abs_path
    return None


def _build_jar_analyzer(project_id: int, *, force: bool, cancel: threading.Event | None, log) -> str:
    from ..services.decompile_java import load_business_jar_state
    from .jar_cli import ensure_jar_analyzer, engine_version, run_jar_analyzer

    _set_backend_status(project_id, BACKEND_JAR, status="building", error="")
    log("开始构建 Jar Analyzer（仅 MarkBusinessJar 点名的业务 jar）")
    state = _wait_business_jars_closed(project_id, cancel, log)
    if state.get("cancelled"):
        return "cancelled"
    if state.get("none") and not (state.get("paths") or []):
        msg = "未点名业务 jar（MarkBusinessJar none=true），Jar Analyzer 已降级"
        _set_backend_status(project_id, BACKEND_JAR, status="degraded", error=msg)
        log(msg)
        return "degraded"
    paths = [str(p) for p in (state.get("paths") or []) if str(p).strip()]
    if not paths:
        msg = "业务 jar 名单为空，Jar Analyzer 已降级"
        _set_backend_status(project_id, BACKEND_JAR, status="degraded", error=msg)
        log(msg)
        return "degraded"

    try:
        engine = ensure_jar_analyzer(log=log)
    except Exception as exc:  # noqa: BLE001
        _set_backend_status(project_id, BACKEND_JAR, status="degraded", error=str(exc)[:2000])
        return "degraded"
    if engine is None:
        msg = "未找到 jar-analyzer-engine，自动安装失败"
        _set_backend_status(project_id, BACKEND_JAR, status="degraded", error=msg)
        return "degraded"

    max_bytes = int(getattr(settings, "decompile_max_jar_bytes", 80 * 1024 * 1024) or (80 * 1024 * 1024))
    timeout = int(getattr(settings, "timeout_jar_analyzer_index", 1800) or 1800)
    version = engine_version(engine)
    ready_artifacts: list[dict[str, Any]] = []
    errors: list[str] = []

    for source_rel in paths:
        if cancel is not None and cancel.is_set():
            return "cancelled"
        jar_path = _resolve_jar_input(project_id, source_rel)
        if jar_path is None:
            errors.append(f"{source_rel}: 路径不存在")
            continue
        try:
            size = jar_path.stat().st_size if jar_path.is_file() else 0
        except OSError:
            size = 0
        if jar_path.is_file() and size > max_bytes:
            errors.append(f"{source_rel}: 超过体积上限 {max_bytes} 字节")
            continue
        digest = _sha256_file(jar_path) if jar_path.is_file() else hashlib.sha256(source_rel.encode()).hexdigest()
        out_dir = jars_index_dir(project_id) / digest
        db_file = out_dir / "jar-analyzer.db"
        if db_file.is_file() and not force:
            ready_artifacts.append({"source": source_rel, "digest": digest, "db": str(db_file)})
            log(f"复用已有 Jar Analyzer 图: {source_rel}")
            continue
        out_dir.mkdir(parents=True, exist_ok=True)
        # Clean previous db for rebuild
        if force and db_file.is_file():
            try:
                db_file.unlink()
            except OSError:
                pass
        log(f"Jar Analyzer 分析 {source_rel} → jars/{digest[:12]}…")
        try:
            code = run_jar_analyzer(
                jar_path,
                cwd=out_dir,
                timeout=timeout,
                log=log,
                engine=engine,
                cancel=cancel,
            )
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{source_rel}: {exc}")
            continue
        if cancel is not None and cancel.is_set():
            return "cancelled"
        if code != 0 or not db_file.is_file():
            # Engine may write jar-analyzer.db in cwd; also check alternate names
            alt = list(out_dir.glob("*.db"))
            if alt and not db_file.is_file():
                try:
                    alt[0].replace(db_file)
                except OSError:
                    pass
        if not db_file.is_file():
            errors.append(f"{source_rel}: 未生成 jar-analyzer.db（exit={code}）")
            continue
        meta = {
            "source": source_rel,
            "digest": digest,
            "version": version,
            "built_at": _now_iso(),
        }
        (out_dir / "meta.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
        ready_artifacts.append({"source": source_rel, "digest": digest, "db": "jar-analyzer.db"})

    if not ready_artifacts:
        msg = "；".join(errors) if errors else "没有成功的 Jar Analyzer 图"
        _set_backend_status(project_id, BACKEND_JAR, status="degraded", error=msg[:2000])
        log(f"Jar Analyzer 降级: {msg}")
        return "degraded"

    note = ""
    if errors:
        note = "；部分失败: " + "；".join(errors)[:800]
    _set_backend_status(
        project_id,
        BACKEND_JAR,
        status="ready",
        error=note,
        version=version,
        artifacts=ready_artifacts,
    )
    log(f"Jar Analyzer 就绪（{len(ready_artifacts)} 个产物，engine {version or 'unknown'}）{note}")
    return "ready"


def run_build(
    project_id: int,
    *,
    force: bool = False,
    cancel: threading.Event | None = None,
) -> str:
    """Build or rebuild requested backends. Returns aggregate status (ready|degraded|pending|cancelled)."""
    backends = requested_backends(project_id)
    if not backends:
        _log(project_id, "代码库尚未点名后端（MarkCodeIntel），等待侦察地图 Agent")
        _set_project_fields(project_id, code_intel_status="pending", code_intel_done=False)
        write_metadata(project_id, {"status": "pending"})
        return "pending"

    src = src_dir(project_id)
    src.mkdir(parents=True, exist_ok=True)
    _set_project_fields(project_id, code_intel_status="building", code_intel_error=None)
    write_metadata(
        project_id,
        {
            "status": "building",
            "created_at": read_metadata(project_id).get("created_at") or _now_iso(),
            "index_dir": "src/.codegraph",
        },
    )
    try:
        live_log.begin_session(project_id, CODE_INTEL_PHASE, if_used=True)
    except Exception:  # noqa: BLE001
        pass
    _log(
        project_id,
        f"{'重建' if force else '构建'}代码数据库：{', '.join(backends)}",
    )

    def log_line(text: str) -> None:
        if text.strip():
            _log(project_id, text[:2000])

    results: dict[str, str] = {}
    if BACKEND_CODEGRAPH in backends:
        results[BACKEND_CODEGRAPH] = _build_codegraph(project_id, force=force, cancel=cancel, log=log_line)
        if results[BACKEND_CODEGRAPH] == "cancelled":
            return "cancelled"
    if BACKEND_JAR in backends:
        results[BACKEND_JAR] = _build_jar_analyzer(project_id, force=force, cancel=cancel, log=log_line)
        if results[BACKEND_JAR] == "cancelled":
            return "cancelled"

    # Aggregate: done when every requested backend finished (ready or degraded)
    statuses = [results.get(b, "degraded") for b in backends]
    if any(s == "cancelled" for s in statuses):
        return "cancelled"
    any_ready = any(s == "ready" for s in statuses)
    all_degraded = all(s == "degraded" for s in statuses)
    errors = []
    for name, st in results.items():
        if st == "degraded":
            row = _backend_status_map(project_id).get(name) or {}
            err = str((row if isinstance(row, dict) else {}).get("error") or "")
            if err:
                errors.append(f"{name}: {err}")
    cg_hash = ""
    cg_ver = ""
    cg_row = _backend_status_map(project_id).get(BACKEND_CODEGRAPH) or {}
    if isinstance(cg_row, dict):
        cg_hash = str(cg_row.get("source_hash") or "")
        cg_ver = str(cg_row.get("version") or "")

    if all_degraded:
        msg = "；".join(errors) if errors else "全部后端构建失败"
        _set_project_fields(
            project_id,
            code_intel_status="degraded",
            code_intel_done=True,
            code_intel_error=msg[:2000],
            code_intel_source_hash=cg_hash or None,
            code_intel_version=cg_ver or None,
        )
        write_metadata(project_id, {"status": "degraded", "error": msg[:2000]})
        live_log.error(project_id, f"代码库构建失败，已降级继续审计: {msg}", phase=CODE_INTEL_PHASE)
        return "degraded"

    # Mix of ready/degraded still counts as done for mining
    final = "ready" if any_ready else "degraded"
    err_msg = "；".join(errors) if errors else None
    _set_project_fields(
        project_id,
        code_intel_status=final,
        code_intel_done=True,
        code_intel_error=err_msg,
        code_intel_source_hash=cg_hash or None,
        code_intel_version=cg_ver or None,
    )
    write_metadata(
        project_id,
        {
            "status": final,
            "error": err_msg or "",
            "source_hash": cg_hash,
            "version": cg_ver,
            "backend": "+".join(backends),
        },
    )
    _log(project_id, f"代码数据库就绪（backends={','.join(backends)}，aggregate={final}）")
    if BACKEND_CODEGRAPH in backends and results.get(BACKEND_CODEGRAPH) == "ready":
        _log(project_id, "测试可用：在本阶段点击「打开图浏览器」查看源码调用关系")
    return final


def _degrade(project_id: int, error: str) -> str:
    msg = (error or "构建失败").strip()[:2000]
    _set_project_fields(
        project_id,
        code_intel_status="degraded",
        code_intel_done=True,
        code_intel_error=msg,
    )
    write_metadata(project_id, {"status": "degraded", "error": msg})
    live_log.error(project_id, f"代码库构建失败，已降级继续审计: {msg}", phase=CODE_INTEL_PHASE)
    return "degraded"


def request_rebuild(project_id: int) -> dict[str, Any]:
    from ..services.pipeline import request_code_intel_rebuild

    return request_code_intel_rebuild(project_id)


def _cli_lacks_ui(text: str) -> bool:
    lowered = (text or "").lower()
    return "unknown command" in lowered and ("'ui'" in lowered or '"ui"' in lowered or " ui" in lowered or "'web'" in lowered)


def request_ui(project_id: int) -> dict[str, Any]:
    """Open a graph viewer for testers (CodeGraph only)."""
    from ..services.runtime import is_docker_runtime

    payload = status_payload(project_id)
    if payload["status"] not in ("ready", "stale"):
        return {"ok": False, "error": "代码库尚未就绪，无法打开图浏览器"}
    if BACKEND_CODEGRAPH not in requested_backends(project_id) and not (_index_dir(project_id) / "codegraph.db").is_file():
        return {"ok": False, "error": "未构建 CodeGraph；Jar Analyzer 图请用查询工具或 SQLite 查看"}
    if is_docker_runtime():
        _log(project_id, "Docker 版改用内置调用图浏览（容器内 127.0.0.1 浏览器不可达）")
        return {"ok": True, "builtin": True, "url": ""}
    binary = find_codegraph()
    if binary is None:
        return {"ok": False, "error": "未找到 codegraph CLI"}
    command = ui_subcommand(binary)
    if not command:
        _log(project_id, "当前 CodeGraph 不含 ui 命令，改用内置调用图浏览")
        return {"ok": True, "builtin": True, "url": ""}
    src = src_dir(project_id)
    with _ui_lock:
        proc = _ui_procs.get(project_id)
        if proc is not None and proc.poll() is None and _ui_urls.get(project_id):
            return {"ok": True, "url": _ui_urls[project_id], "reused": True, "builtin": False}
        try:
            proc = popen_ui(src, binary=binary, command=command)
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error": str(exc)}
        url = "http://127.0.0.1:4747"
        deadline = time.time() + 8
        assert proc.stdout is not None
        buf = ""
        while time.time() < deadline:
            if proc.poll() is not None:
                rest = proc.stdout.read() or ""
                text = (buf + rest).strip()
                if _cli_lacks_ui(text):
                    _log(project_id, "CodeGraph 不支持 ui 命令，改用内置调用图浏览")
                    return {"ok": True, "builtin": True, "url": ""}
                return {"ok": False, "error": text[:800] or "图浏览器进程已退出"}
            line = proc.stdout.readline()
            if not line:
                time.sleep(0.05)
                continue
            buf += line
            for token in line.replace("'", " ").split():
                if token.startswith("http://127.0.0.1:") or token.startswith("http://localhost:"):
                    url = token.rstrip(".,)")
                    break
            if "127.0.0.1" in line or "localhost" in line:
                break
        _ui_procs[project_id] = proc
        _ui_urls[project_id] = url
    _log(project_id, f"图浏览器已在本机启动: {url}（仅 127.0.0.1，供测试查看）")
    return {"ok": True, "url": url, "reused": False, "builtin": False}


def reset_runtime_state() -> None:
    _last_stale_check.clear()
    with _ui_lock:
        for proc in _ui_procs.values():
            try:
                if proc.poll() is None:
                    proc.terminate()
            except Exception:  # noqa: BLE001
                pass
        _ui_procs.clear()
        _ui_urls.clear()


def index_ready(project_id: int) -> bool:
    """True when CodeGraph DB is ready (source graph)."""
    status = status_payload(project_id)["status"]
    return status in ("ready", "stale") and (_index_dir(project_id) / "codegraph.db").is_file()


def codegraph_index_ready(project_id: int) -> bool:
    return index_ready(project_id)


def src_root(project_id: int) -> Path:
    return strip_windows_long_path(src_dir(project_id))

"""Locate, install, and invoke jar-analyzer-engine."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ..config import ROOT_DIR, settings
from ..services.paths import PROJECTS_DIR

GITHUB_REPO = "jar-analyzer/jar-analyzer-engine"
LATEST_RELEASE_URL = f"https://github.com/{GITHUB_REPO}/releases/latest"
RELEASE_API_URL = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"

LogFn = Callable[[str], None]


def jar_analyzer_install_dir() -> Path:
    path = PROJECTS_DIR.parent / "tools" / "jar-analyzer"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _settings_engine_path() -> str:
    try:
        from ..models import AppSettings, SessionLocal

        with SessionLocal() as db:
            row = db.query(AppSettings).first()
            stored = (getattr(row, "jar_analyzer_path", None) or "").strip() if row else ""
        if stored:
            return stored
    except Exception:  # noqa: BLE001
        pass
    env = (os.environ.get("VULNHUNTER_JAR_ANALYZER_PATH") or "").strip()
    if env:
        return env
    return (getattr(settings, "jar_analyzer_path", None) or "").strip()


def _bundled_engines() -> list[Path]:
    root = jar_analyzer_install_dir()
    found: list[Path] = []
    for folder in (root / "current", root):
        if not folder.is_dir():
            continue
        for path in sorted(folder.glob("jar-analyzer-engine*.jar"), reverse=True):
            if path.is_file():
                found.append(path)
        plain = folder / "jar-analyzer-engine.jar"
        if plain.is_file():
            found.append(plain)
    return found


def find_jar_analyzer(explicit: str | None = None) -> Path | None:
    raw = (explicit or "").strip() or _settings_engine_path()
    if raw:
        path = Path(raw)
        if not path.is_absolute():
            path = (ROOT_DIR / path).resolve()
        if path.is_file() and path.suffix.lower() == ".jar":
            return path
        if path.is_dir():
            for name in ("jar-analyzer-engine.jar",):
                cand = path / name
                if cand.is_file():
                    return cand
            hits = sorted(path.glob("jar-analyzer-engine*.jar"), reverse=True)
            if hits:
                return hits[0]
    bundled = _bundled_engines()
    if bundled:
        return bundled[0]
    return None


def find_java() -> Path | None:
    mcp = (os.environ.get("VULNHUNTER_MCP_JAVA") or "").strip()
    if mcp:
        p = Path(mcp)
        if p.is_file():
            return p
    java_home = (os.environ.get("JAVA_HOME") or "").strip()
    if java_home:
        for name in ("java.exe", "java"):
            cand = Path(java_home) / "bin" / name
            if cand.is_file():
                return cand
    for name in ("java", "java.exe"):
        hit = shutil.which(name)
        if hit:
            return Path(hit)
    return None


def _subprocess_kwargs() -> dict[str, Any]:
    kwargs: dict[str, Any] = {}
    if os.name == "nt":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    return kwargs


def _proxy_env() -> dict[str, str]:
    env = os.environ.copy()
    try:
        from ..services.http_client import proxy_url

        proxy = (proxy_url() or "").strip()
    except Exception:  # noqa: BLE001
        proxy = (getattr(settings, "http_proxy", None) or "").strip()
    if proxy:
        env.setdefault("HTTP_PROXY", proxy)
        env.setdefault("HTTPS_PROXY", proxy)
        env.setdefault("http_proxy", proxy)
        env.setdefault("https_proxy", proxy)
    return env


def run_jar_analyzer(
    jar_path: Path,
    *,
    cwd: Path,
    timeout: int | None = None,
    log: LogFn | None = None,
    engine: Path | None = None,
    java: Path | None = None,
    fix_class: bool = True,
    inner_jars: bool = True,
    cancel=None,
) -> int:
    """Run engine against one jar/war/dir. Writes jar-analyzer.db under cwd. Returns exit code."""
    exe = engine or find_jar_analyzer()
    if exe is None:
        raise FileNotFoundError("未找到 jar-analyzer-engine")
    java_bin = java or find_java()
    if java_bin is None:
        raise FileNotFoundError("未找到 java；请安装 JDK 或设置 JAVA_HOME / VULNHUNTER_MCP_JAVA")
    cwd.mkdir(parents=True, exist_ok=True)
    args = [str(java_bin), "-jar", str(exe), "--jar", str(jar_path)]
    if fix_class:
        args.append("--fix-class")
    if inner_jars:
        args.append("--inner-jars")
    if log:
        log("$ " + " ".join(args))
    proc = subprocess.Popen(
        args,
        cwd=str(cwd),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=_proxy_env(),
        **_subprocess_kwargs(),
    )
    deadline = None if timeout is None else time.time() + max(1, timeout)
    try:
        assert proc.stdout is not None
        while True:
            if cancel is not None and cancel.is_set():
                proc.terminate()
                try:
                    proc.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    proc.kill()
                if log:
                    log("已取消 Jar Analyzer 进程")
                return 130
            if deadline is not None and time.time() >= deadline:
                proc.terminate()
                try:
                    proc.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    proc.kill()
                if log:
                    log(f"Jar Analyzer 超时（{timeout}s），已终止")
                return 124
            line = proc.stdout.readline()
            if line:
                if log:
                    log(line.rstrip("\n")[:2000])
                continue
            if proc.poll() is not None:
                rest = proc.stdout.read()
                if rest and log:
                    for chunk in rest.splitlines():
                        log(chunk[:2000])
                return int(proc.returncode or 0)
            time.sleep(0.05)
    finally:
        if proc.poll() is None:
            proc.kill()


def _resolve_latest_asset(timeout: int) -> tuple[str, str]:
    """Return (tag, download_url) for the latest release fat jar."""
    from ..services.http_client import http_client

    headers = {"User-Agent": "VulnHunter-jar-analyzer-install"}
    with http_client(timeout=timeout) as client:
        resp = client.get(LATEST_RELEASE_URL, headers=headers, follow_redirects=True)
        resp.raise_for_status()
        path = str(resp.url)
        tag = ""
        if "/tag/" in path:
            tag = path.rstrip("/").rsplit("/tag/", 1)[-1].strip()
        api = client.get(RELEASE_API_URL, headers=headers)
        api.raise_for_status()
        payload = api.json() or {}
        if not tag:
            tag = str(payload.get("tag_name") or "").strip()
        if not tag:
            raise RuntimeError("无法解析 jar-analyzer-engine 最新版本")
        assets = payload.get("assets") or []
        url = ""
        name = ""
        for asset in assets:
            aname = str(asset.get("name") or "")
            if aname.endswith(".jar") and "jar-analyzer-engine" in aname:
                url = str(asset.get("browser_download_url") or "")
                name = aname
                break
        if not url:
            # Fallback naming convention used by releases
            name = f"jar-analyzer-engine-{tag.lstrip('v')}.jar"
            url = f"https://github.com/{GITHUB_REPO}/releases/download/{tag}/{name}"
        return tag, url


def install_jar_analyzer(*, log: LogFn | None = None) -> Path | None:
    dest_root = jar_analyzer_install_dir()
    dest_root.mkdir(parents=True, exist_ok=True)
    timeout = int(getattr(settings, "timeout_jar_analyzer_install", 300) or 300)
    if log:
        log(f"未检测到 jar-analyzer-engine，开始安装到 {dest_root}")
    try:
        from ..services.http_client import http_client

        tag, url = _resolve_latest_asset(min(60, timeout))
        if log:
            log(f"下载 {url}")
        tmp_dir = dest_root / ".download-tmp"
        if tmp_dir.exists():
            shutil.rmtree(tmp_dir)
        tmp_dir.mkdir(parents=True, exist_ok=True)
        asset_name = url.rstrip("/").rsplit("/", 1)[-1] or "jar-analyzer-engine.jar"
        archive = tmp_dir / asset_name
        headers = {"User-Agent": "VulnHunter-jar-analyzer-install"}
        with http_client(timeout=timeout) as client:
            with client.stream("GET", url, headers=headers) as resp:
                resp.raise_for_status()
                with archive.open("wb") as fh:
                    for chunk in resp.iter_bytes():
                        if chunk:
                            fh.write(chunk)
        current = dest_root / "current"
        if current.exists():
            shutil.rmtree(current)
        current.mkdir(parents=True, exist_ok=True)
        target = current / "jar-analyzer-engine.jar"
        shutil.move(str(archive), str(target))
        meta = current / "VERSION"
        meta.write_text(tag + "\n", encoding="utf-8")
        shutil.rmtree(tmp_dir, ignore_errors=True)
    except Exception as exc:  # noqa: BLE001
        if log:
            log(f"安装 jar-analyzer-engine 失败: {exc}")
        return None
    found = find_jar_analyzer()
    if found and log:
        log(f"已安装 jar-analyzer-engine: {found}")
    elif log:
        log("安装结束但未找到 jar-analyzer-engine.jar")
    return found


def ensure_jar_analyzer(*, log: LogFn | None = None) -> Path | None:
    found = find_jar_analyzer()
    if found:
        return found
    return install_jar_analyzer(log=log)


def engine_version(engine: Path | None = None) -> str:
    path = engine or find_jar_analyzer()
    if path is None:
        return ""
    # Prefer VERSION file next to bundled jar
    for parent in (path.parent, path.parent.parent):
        ver_file = parent / "VERSION"
        if ver_file.is_file():
            try:
                return ver_file.read_text(encoding="utf-8").strip().splitlines()[0].strip()
            except OSError:
                pass
    match = re.search(r"jar-analyzer-engine-([0-9][\w.\-]*)\.jar$", path.name, re.I)
    if match:
        return match.group(1)
    return path.name


def probe_jar_analyzer(explicit: str | None = None) -> dict[str, Any]:
    started = time.perf_counter()
    path = find_jar_analyzer(explicit)
    java = find_java()
    if path is None:
        return {
            "ok": False,
            "path": (explicit or "").strip(),
            "version": "",
            "error": "未找到 jar-analyzer-engine",
            "java": str(java) if java else "",
        }
    if java is None:
        return {
            "ok": False,
            "path": str(path),
            "version": engine_version(path),
            "latency_ms": int((time.perf_counter() - started) * 1000),
            "error": "未找到 java；请安装 JDK 或设置 JAVA_HOME",
            "java": "",
        }
    # Engine has no --version; presence of jar + java is enough for settings probe.
    return {
        "ok": True,
        "path": str(path),
        "version": engine_version(path),
        "latency_ms": int((time.perf_counter() - started) * 1000),
        "error": None,
        "java": str(java),
    }

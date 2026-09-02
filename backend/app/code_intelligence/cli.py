"""Locate, install, and invoke the CodeGraph CLI."""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ..config import ROOT_DIR, settings
from ..services.paths import codegraph_install_dir

GITHUB_REPO = "colbymchenry/codegraph"
LATEST_RELEASE_URL = f"https://github.com/{GITHUB_REPO}/releases/latest"
RELEASE_API_URL = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"

LogFn = Callable[[str], None]


def _settings_cli_path() -> str:
    try:
        from ..models import AppSettings, SessionLocal

        with SessionLocal() as db:
            row = db.query(AppSettings).first()
            stored = (getattr(row, "codegraph_path", None) or "").strip() if row else ""
        if stored:
            return stored
    except Exception:  # noqa: BLE001
        pass
    return (getattr(settings, "codegraph_path", None) or "").strip()


def _bundled_binaries() -> list[Path]:
    root = codegraph_install_dir()
    names = ("codegraph.cmd", "codegraph.exe", "codegraph.bat", "codegraph")
    candidates = [
        root / "current" / "bin",
        root / "bin",
    ]
    current = root / "current"
    if current.is_symlink() or current.is_dir():
        candidates.append(current / "bin")
    versions = root / "versions"
    if versions.is_dir():
        for child in sorted(versions.iterdir(), reverse=True):
            candidates.append(child / "bin")
    found: list[Path] = []
    for folder in candidates:
        for name in names:
            path = folder / name
            if path.is_file():
                found.append(path)
    return found


def _which_codegraph() -> Path | None:
    for name in ("codegraph", "codegraph.cmd", "codegraph.exe", "codegraph.bat"):
        hit = shutil.which(name)
        if hit:
            return Path(hit)
    return None


def find_codegraph(explicit: str | None = None) -> Path | None:
    """Resolve a runnable CodeGraph binary. None if not installed."""
    raw = (explicit or "").strip() or _settings_cli_path()
    if raw:
        path = Path(raw)
        if not path.is_absolute():
            path = (ROOT_DIR / path).resolve()
        if path.is_file():
            return path
        if path.is_dir():
            for name in ("codegraph.cmd", "codegraph.exe", "codegraph", "codegraph.bat"):
                cand = path / name
                if cand.is_file():
                    return cand
                nested = path / "bin" / name
                if nested.is_file():
                    return nested
        which_hit = shutil.which(raw)
        if which_hit:
            return Path(which_hit)
    bundled = _bundled_binaries()
    if bundled:
        return bundled[0]
    return _which_codegraph()


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
    env["CODEGRAPH_NO_DAEMON"] = "1"
    env.setdefault("CODEGRAPH_TELEMETRY", "0")
    return env


def run_codegraph(
    args: list[str],
    *,
    cwd: Path | None = None,
    timeout: int | None = None,
    log: LogFn | None = None,
    extra_env: dict[str, str] | None = None,
    binary: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    exe = binary or find_codegraph()
    if exe is None:
        raise FileNotFoundError("未找到 codegraph CLI")
    env = _proxy_env()
    if extra_env:
        env.update(extra_env)
    cmd = [str(exe), *args]
    if log:
        log("$ " + " ".join(cmd))
    return subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        env=env,
        **_subprocess_kwargs(),
    )


def stream_codegraph(
    args: list[str],
    *,
    cwd: Path | None = None,
    timeout: int | None = None,
    log: LogFn | None = None,
    extra_env: dict[str, str] | None = None,
    binary: Path | None = None,
    cancel: threading.Event | None = None,
) -> int:
    """Run CodeGraph and stream combined output. Returns exit code."""
    exe = binary or find_codegraph()
    if exe is None:
        raise FileNotFoundError("未找到 codegraph CLI")
    env = _proxy_env()
    if extra_env:
        env.update(extra_env)
    cmd = [str(exe), *args]
    if log:
        log("$ " + " ".join(cmd))
    proc = subprocess.Popen(
        cmd,
        cwd=str(cwd) if cwd else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
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
                    log("已取消 CodeGraph 进程")
                return 130
            if deadline is not None and time.time() >= deadline:
                proc.terminate()
                try:
                    proc.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    proc.kill()
                if log:
                    log(f"CodeGraph 超时（{timeout}s），已终止")
                return 124
            line = proc.stdout.readline()
            if line:
                if log:
                    log(line.rstrip("\n"))
                continue
            if proc.poll() is not None:
                rest = proc.stdout.read()
                if rest and log:
                    for chunk in rest.splitlines():
                        log(chunk)
                return int(proc.returncode or 0)
            time.sleep(0.05)
    finally:
        if proc.poll() is None:
            proc.kill()


def release_target() -> str:
    """GitHub asset triple, e.g. win32-x64 / linux-arm64."""
    if os.name == "nt" or sys.platform.startswith(("win", "cygwin")):
        os_name = "win32"
    elif sys.platform == "darwin":
        os_name = "darwin"
    else:
        os_name = "linux"
    machine = platform.machine().lower()
    arch = "arm64" if machine in ("arm64", "aarch64") else "x64"
    return f"{os_name}-{arch}"


def _flatten_extracted(dest: Path, target: str) -> None:
    inner = dest / f"codegraph-{target}"
    if not inner.is_dir():
        children = [p for p in dest.iterdir() if p.name not in {".", ".."}]
        if len(children) == 1 and children[0].is_dir():
            inner = children[0]
        else:
            return
    for child in list(inner.iterdir()):
        out = dest / child.name
        if out.exists():
            if out.is_dir():
                shutil.rmtree(out)
            else:
                out.unlink()
        shutil.move(str(child), str(out))
    shutil.rmtree(inner, ignore_errors=True)


def extract_bundle(archive: Path, dest: Path, target: str) -> None:
    """Unpack a CodeGraph release archive into dest and flatten the top folder."""
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True, exist_ok=True)
    name = archive.name.lower()
    if name.endswith(".zip"):
        import zipfile

        with zipfile.ZipFile(archive) as zf:
            zf.extractall(dest)
    else:
        import tarfile

        with tarfile.open(archive) as tf:
            try:
                tf.extractall(dest, filter="data")
            except TypeError:
                tf.extractall(dest)
    _flatten_extracted(dest, target)


def _resolve_latest_tag(timeout: int) -> str:
    from ..services.http_client import http_client

    headers = {"User-Agent": "VulnHunter-codegraph-install"}
    with http_client(timeout=timeout) as client:
        resp = client.get(LATEST_RELEASE_URL, headers=headers)
        resp.raise_for_status()
        path = str(resp.url)
        if "/tag/" in path:
            tag = path.rstrip("/").rsplit("/tag/", 1)[-1].strip()
            if tag:
                return tag if tag.startswith("v") else f"v{tag}"
        api = client.get(RELEASE_API_URL, headers=headers)
        api.raise_for_status()
        tag = str((api.json() or {}).get("tag_name") or "").strip()
    if not tag:
        raise RuntimeError("无法解析 CodeGraph 最新版本")
    return tag if tag.startswith("v") else f"v{tag}"


def install_codegraph(*, log: LogFn | None = None) -> Path | None:
    """Download the official bundle into data/tools/codegraph. Does not modify PATH."""
    dest_root = codegraph_install_dir()
    dest_root.mkdir(parents=True, exist_ok=True)
    timeout = int(getattr(settings, "timeout_codegraph_install", 300) or 300)
    target = release_target()
    if log:
        log(f"未检测到 CodeGraph，开始安装到 {dest_root}（{target}）")
    try:
        from ..services.http_client import http_client

        tag = _resolve_latest_tag(min(60, timeout))
        asset = f"codegraph-{target}.zip" if os.name == "nt" else f"codegraph-{target}.tar.gz"
        url = f"https://github.com/{GITHUB_REPO}/releases/download/{tag}/{asset}"
        if log:
            log(f"下载 {url}")
        tmp_dir = dest_root / ".download-tmp"
        if tmp_dir.exists():
            shutil.rmtree(tmp_dir)
        tmp_dir.mkdir(parents=True, exist_ok=True)
        archive = tmp_dir / asset
        headers = {"User-Agent": "VulnHunter-codegraph-install"}
        with http_client(timeout=timeout) as client:
            with client.stream("GET", url, headers=headers) as resp:
                resp.raise_for_status()
                with archive.open("wb") as fh:
                    for chunk in resp.iter_bytes():
                        if chunk:
                            fh.write(chunk)
        current = dest_root / "current"
        extract_bundle(archive, current, target)
        shutil.rmtree(tmp_dir, ignore_errors=True)
    except Exception as exc:  # noqa: BLE001
        if log:
            log(f"安装 CodeGraph 失败: {exc}")
        return None
    found = find_codegraph()
    if found:
        if log:
            log(f"已安装 CodeGraph: {found}")
        try:
            run_codegraph(["telemetry", "off"], timeout=20, binary=found, log=log)
        except Exception as exc:  # noqa: BLE001
            if log:
                log(f"关闭遥测失败（可忽略）: {exc}")
    elif log:
        log("安装结束但未找到 codegraph 可执行文件")
    return found


def ensure_codegraph(*, log: LogFn | None = None) -> Path | None:
    found = find_codegraph()
    if found:
        return found
    return install_codegraph(log=log)


def probe_codegraph(explicit: str | None = None) -> dict[str, Any]:
    started = time.perf_counter()
    path = find_codegraph(explicit)
    if path is None:
        return {"ok": False, "path": (explicit or "").strip(), "version": "", "error": "未找到 codegraph"}
    try:
        proc = run_codegraph(["version"], timeout=20, binary=path)
    except Exception as exc:  # noqa: BLE001
        return {
            "ok": False,
            "path": str(path),
            "version": "",
            "latency_ms": int((time.perf_counter() - started) * 1000),
            "error": str(exc),
        }
    version = ((proc.stdout or "") + (proc.stderr or "")).strip().splitlines()
    ver = version[0].strip() if version else ""
    if proc.returncode != 0:
        return {
            "ok": False,
            "path": str(path),
            "version": ver,
            "latency_ms": int((time.perf_counter() - started) * 1000),
            "error": (proc.stderr or proc.stdout or f"exit {proc.returncode}").strip()[:500],
        }
    return {
        "ok": True,
        "path": str(path),
        "version": ver,
        "latency_ms": int((time.perf_counter() - started) * 1000),
        "error": None,
    }


def cli_version(binary: Path | None = None) -> str:
    try:
        proc = run_codegraph(["version"], timeout=20, binary=binary)
    except Exception:  # noqa: BLE001
        return ""
    text = ((proc.stdout or "") + (proc.stderr or "")).strip()
    return text.splitlines()[0].strip() if text else ""


def popen_ui(src: Path, *, binary: Path | None = None, extra_env: dict[str, str] | None = None) -> subprocess.Popen[str]:
    exe = binary or find_codegraph()
    if exe is None:
        raise FileNotFoundError("未找到 codegraph CLI")
    env = _proxy_env()
    if extra_env:
        env.update(extra_env)
    return subprocess.Popen(
        [str(exe), "ui", "--no-open"],
        cwd=str(src),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        **_subprocess_kwargs(),
    )


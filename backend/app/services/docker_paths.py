"""Rewrite container-local paths to host paths for Docker edition DooD binds.

Sibling sandbox / Semgrep containers run on the host engine. Bind sources must
be paths the *engine* understands (Windows ``D:\\...\\data\\...``, Desktop's
``/run/desktop/mnt/host/...``, or a Linux ``/home/.../data``), not the path
inside the app container.
"""

from __future__ import annotations

import logging
import os
import threading
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse

logger = logging.getLogger(__name__)

_lock = threading.Lock()
_host_data: str | None = None
_resolved = False

# App container always sees project data under these prefixes (compose mounts
# host data at /data and entrypoint symlinks /app/data -> /data).
_CONTAINER_DATA_PREFIXES = ("/data", "/app/data")


def reset_docker_paths() -> None:
    """Test helper."""
    global _host_data, _resolved
    with _lock:
        _host_data = None
        _resolved = False


def _normalize_prefix(raw: str) -> str:
    text = (raw or "").strip().rstrip("/\\")
    return text


def _env_host_data() -> str:
    return _normalize_prefix(os.environ.get("VULNHUNTER_HOST_DATA") or "")


def _inspect_self_data_source() -> str:
    """Read the host Source for the /data (or /app/data) mount of this container."""
    try:
        import docker  # noqa: PLC0415
    except ImportError:
        return ""
    hostname = (os.environ.get("HOSTNAME") or "").strip()
    if not hostname:
        return ""
    try:
        client = docker.from_env()
        client.ping()
        info = client.api.inspect_container(hostname)
    except Exception as exc:  # noqa: BLE001
        logger.info("docker path inspect failed: %s", exc)
        return ""
    mounts = info.get("Mounts") or []
    preferred = ("/data", "/app/data")
    for dest in preferred:
        for mount in mounts:
            if str(mount.get("Destination") or "").rstrip("/") != dest:
                continue
            source = _normalize_prefix(str(mount.get("Source") or ""))
            if source:
                return source
    return ""


def host_data_root() -> str:
    """Absolute host path that backs container /data. Empty when not in Docker or unknown."""
    global _host_data, _resolved
    with _lock:
        if _resolved:
            return _host_data or ""
        _resolved = True
        from .runtime import is_docker_runtime

        if not is_docker_runtime():
            _host_data = ""
            return ""
        source = _inspect_self_data_source() or _env_host_data()
        _host_data = source
        if source:
            logger.info("docker host data root: %s", source)
        else:
            logger.warning(
                "docker host data root unknown; set VULNHUNTER_HOST_DATA "
                "(start.cmd / start.sh sets this). Sibling bind mounts may fail."
            )
        return _host_data or ""


def _as_posix_under_data(path: Path | str) -> str | None:
    """Return path relative to a container data prefix, using forward slashes."""
    raw = os.fspath(path)
    # Drop Windows long-path prefix if somehow present.
    if raw.startswith("\\\\?\\"):
        raw = raw[4:]
    text = raw.replace("\\", "/")
    for prefix in _CONTAINER_DATA_PREFIXES:
        if text == prefix:
            return ""
        if text.startswith(prefix + "/"):
            return text[len(prefix) + 1 :]
    return None


def ensure_sandbox_bind_readable(path: Path | str) -> None:
    """Relax modes so sandbox uid 1000 can traverse Docker edition bind mounts.

    ``tempfile.TemporaryDirectory`` defaults to ``0700``. When the app runs as
    root (Docker edition), sibling containers with ``user=1000:1000`` cannot
    open ``/workspace`` (Permission denied). Host-native runs as the same uid
    are unaffected by a world-readable temp tree.
    """
    root = Path(path)
    try:
        if root.is_dir():
            root.chmod(0o755)
        elif root.is_file():
            root.chmod(0o644)
            return
        else:
            return
    except OSError:
        return
    try:
        for child in root.rglob("*"):
            try:
                if child.is_dir():
                    child.chmod(0o755)
                elif child.is_file():
                    child.chmod(0o644)
            except OSError:
                continue
    except OSError:
        return


def to_host_bind_path(path: Path | str) -> str:
    """Map a container-local path under /data to the host bind source string.

    Outside Docker runtime, returns the absolute path unchanged.
    """
    from .runtime import is_docker_runtime

    if not is_docker_runtime():
        return str(Path(path).resolve())

    # Prefer the literal container path (posix). On a Windows *dev host* running
    # tests with VULNHUNTER_RUNTIME=docker, Path("/data").resolve() becomes
    # ``D:\\data\\...`` and would miss the prefix match.
    raw = os.fspath(path).replace("\\", "/")
    if raw.startswith("\\\\?\\"):
        raw = raw[4:].replace("\\", "/")
    rel = _as_posix_under_data(raw)
    if rel is None:
        try:
            resolved = Path(path).resolve()
        except OSError:
            return raw
        rel = _as_posix_under_data(resolved)
        if rel is None:
            return str(resolved)

    root = host_data_root()
    if not root:
        return raw if raw.startswith("/") else str(Path(path).resolve())

    # Prefer native separators when root looks like a Windows path.
    if "\\" in root or (len(root) >= 2 and root[1] == ":"):
        joined = root.rstrip("\\/") + ("\\" + rel.replace("/", "\\") if rel else "")
        return joined
    joined = root.rstrip("/") + ("/" + rel if rel else "")
    return joined


def rewrite_loopback_url(url: str, *, host: str = "host.docker.internal") -> str:
    """Rewrite 127.0.0.1 / localhost in a URL to reach the host from the container.

    No-op outside Docker runtime, or when the hostname is already non-loopback.
    """
    from .runtime import is_docker_runtime

    text = (url or "").strip()
    if not text or not is_docker_runtime():
        return text
    try:
        parsed = urlparse(text)
    except Exception:  # noqa: BLE001
        return text
    hostname = (parsed.hostname or "").lower()
    if hostname not in {"127.0.0.1", "localhost", "::1"}:
        return text
    # Preserve brackets for IPv6 was not needed; we replace with a hostname.
    netloc = parsed.netloc
    # netloc may be "127.0.0.1:8080" or "localhost:8080" or user@host:port
    userinfo = ""
    hostport = netloc
    if "@" in netloc:
        userinfo, hostport = netloc.rsplit("@", 1)
        userinfo = userinfo + "@"
    if hostport.startswith("["):
        # [::1]:port
        if "]:" in hostport:
            port = hostport.split("]:", 1)[1]
            hostport = f"{host}:{port}"
        else:
            hostport = host
    elif ":" in hostport:
        _old, port = hostport.rsplit(":", 1)
        if port.isdigit():
            hostport = f"{host}:{port}"
        else:
            hostport = host
    else:
        hostport = host
    return urlunparse(parsed._replace(netloc=userinfo + hostport))


def rewrite_loopback_urls(urls: list[str], *, host: str = "host.docker.internal") -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for item in urls:
        rewritten = rewrite_loopback_url(item, host=host)
        if rewritten and rewritten not in seen:
            seen.add(rewritten)
            out.append(rewritten)
    return out


def diagnosis() -> dict[str, Any]:
    from .runtime import is_docker_runtime

    return {
        "docker_runtime": is_docker_runtime(),
        "host_data": host_data_root(),
        "env_host_data": _env_host_data(),
    }

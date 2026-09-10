"""Detect Docker Desktop edition runtime and related feature gates."""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path


@lru_cache(maxsize=1)
def is_docker_runtime() -> bool:
    """True when running the Docker Desktop distribution (not host start.cmd)."""
    raw = (os.environ.get("VULNHUNTER_RUNTIME") or "").strip().lower()
    if raw in {"docker", "desktop", "1", "true", "yes"}:
        return True
    if raw in {"host", "local", "0", "false", "no"}:
        return False
    return Path("/.dockerenv").is_file()


def docker_lab_build_enabled() -> bool:
    """Auto Docker lab (reviewer-lab / build app image) is host-only."""
    return not is_docker_runtime()


def runtime_payload() -> dict[str, bool | str]:
    docker = is_docker_runtime()
    return {
        "runtime": "docker" if docker else "host",
        "docker_lab_build_enabled": not docker,
        "manual_lab_allowed": True,
    }


def reset_runtime_cache() -> None:
    """Test helper."""
    is_docker_runtime.cache_clear()

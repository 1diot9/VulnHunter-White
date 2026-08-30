"""Loopback-only PoC execution helpers for L3 integration verify."""

from __future__ import annotations

import re
from urllib.parse import urlparse

_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "[::1]"})


def is_loopback_url(url: str) -> bool:
    raw = str(url or "").strip()
    if not raw:
        return False
    try:
        parsed = urlparse(raw)
    except ValueError:
        return False
    if parsed.scheme not in ("http", "https"):
        return False
    host = (parsed.hostname or "").strip().lower()
    if not host:
        return False
    return host in _LOOPBACK_HOSTS


def loopback_url_error(url: str) -> str | None:
    if is_loopback_url(url):
        return None
    return (
        f"integration 验证仅允许 loopback 目标（127.0.0.1 / localhost / ::1），"
        f"收到: {url!r}"
    )


def extract_loopback_urls(text: str) -> list[str]:
    found: list[str] = []
    for match in re.finditer(r"https?://[^\s\"'<>]+", text or ""):
        url = match.group(0).rstrip(").,;]")
        if is_loopback_url(url) and url not in found:
            found.append(url)
    return found

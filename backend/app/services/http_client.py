"""Shared httpx client with optional proxy."""

from __future__ import annotations

import httpx

from ..config import settings


def _row_proxy(field: str) -> str | None:
    """None = never saved (fall back); '' = explicit direct."""
    try:
        from ..models import AppSettings, SessionLocal

        with SessionLocal() as db:
            row = db.query(AppSettings).first()
            if row is None:
                return None
            if getattr(row, field, None) is None:
                return None
            return str(getattr(row, field) or "").strip()
    except Exception:  # noqa: BLE001
        return None


def proxy_url() -> str | None:
    stored = _row_proxy("http_proxy")
    if stored is not None:
        return stored or None
    proxy = (settings.https_proxy or settings.http_proxy or "").strip()
    return proxy or None


def chat_proxy_url() -> str | None:
    stored = _row_proxy("chat_proxy")
    if stored is not None:
        return stored or None
    return (settings.chat_proxy or "").strip() or None


def chat_http_timeout(remaining: float, est_tokens: int = 0) -> httpx.Timeout:
    """Split connect/read; scale read with remaining budget and prompt size."""
    connect = float(settings.chat_connect_timeout)
    read_min = float(settings.chat_read_timeout_min)
    read_max = float(settings.chat_read_timeout_max)
    scaled = 120.0 + max(0, int(est_tokens)) / 80.0
    read = min(read_max, max(read_min, scaled))
    budget = max(30.0, float(remaining) - 5.0)
    read = min(read, budget)
    return httpx.Timeout(connect=connect, read=read, write=60.0, pool=30.0)


def http_client(timeout: float | httpx.Timeout = 30.0) -> httpx.Client:
    kwargs: dict = {"timeout": timeout, "follow_redirects": True, "trust_env": False}
    p = proxy_url()
    if p:
        kwargs["proxy"] = p
    return httpx.Client(**kwargs)


def chat_http_client(timeout: float | httpx.Timeout = 30.0) -> httpx.Client:
    """Chat Completions: direct by default; ignores OS/system proxy.

    Set Settings.chat_proxy or VULNHUNTER_CHAT_PROXY only when Chat must use a proxy.
    """
    kwargs: dict = {"timeout": timeout, "follow_redirects": True, "trust_env": False}
    proxy = chat_proxy_url()
    if proxy:
        kwargs["proxy"] = proxy
    return httpx.Client(**kwargs)

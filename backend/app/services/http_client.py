"""Shared httpx client with optional local proxy."""

from __future__ import annotations

import os

import httpx

from ..config import settings


def proxy_url() -> str | None:
    for key in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY"):
        val = (os.environ.get(key) or "").strip()
        if val:
            return val
    proxy = (settings.https_proxy or settings.http_proxy or "").strip()
    return proxy or None


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
    kwargs: dict = {"timeout": timeout, "follow_redirects": True}
    p = proxy_url()
    if p:
        kwargs["proxy"] = p
    return httpx.Client(**kwargs)


def chat_http_client(timeout: float | httpx.Timeout = 30.0) -> httpx.Client:
    """Chat Completions: direct by default; ignores env/system proxy.

    Set VULNHUNTER_CHAT_PROXY only when Chat must go through an explicit proxy.
    """
    kwargs: dict = {"timeout": timeout, "follow_redirects": True, "trust_env": False}
    proxy = (settings.chat_proxy or "").strip()
    if proxy:
        kwargs["proxy"] = proxy
    return httpx.Client(**kwargs)

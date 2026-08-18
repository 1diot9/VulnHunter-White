"""Shared httpx client with optional proxy and direct fallback."""

from __future__ import annotations

import logging
import socket
import threading
import time
from typing import Any
from urllib.parse import urlparse

import httpx

from ..config import settings

logger = logging.getLogger(__name__)

# After a proxy fails, skip it for a while so later calls go direct immediately.
_PROXY_SKIP_SEC = 30.0
_PROXY_OK_SEC = 30.0
_PROXY_TCP_TIMEOUT = 1.5
_DEFAULT_PROXY_PORTS = {
    "http": 80,
    "https": 443,
    "socks4": 1080,
    "socks5": 1080,
    "socks5h": 1080,
}
_skip_lock = threading.Lock()
_proxy_skip_until: dict[str, float] = {}
_proxy_ok_until: dict[str, float] = {}


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


def is_proxy_unavailable(exc: BaseException) -> bool:
    """True when the proxy itself cannot be used (not a slow/failed origin)."""
    if isinstance(exc, httpx.ProxyError):
        return True
    if isinstance(exc, (httpx.ConnectError, httpx.ConnectTimeout)):
        return True
    return False


def reset_proxy_skip() -> None:
    with _skip_lock:
        _proxy_skip_until.clear()
        _proxy_ok_until.clear()


def proxy_is_skipped(proxy: str) -> bool:
    key = (proxy or "").strip()
    if not key:
        return False
    with _skip_lock:
        until = _proxy_skip_until.get(key, 0.0)
        return time.monotonic() < until


def _proxy_recently_ok(proxy: str) -> bool:
    key = (proxy or "").strip()
    if not key:
        return False
    with _skip_lock:
        return time.monotonic() < _proxy_ok_until.get(key, 0.0)


def _mark_proxy_skipped(proxy: str) -> None:
    key = (proxy or "").strip()
    if not key:
        return
    with _skip_lock:
        _proxy_skip_until[key] = time.monotonic() + _PROXY_SKIP_SEC
        _proxy_ok_until.pop(key, None)


def _mark_proxy_ok(proxy: str) -> None:
    key = (proxy or "").strip()
    if not key:
        return
    with _skip_lock:
        _proxy_ok_until[key] = time.monotonic() + _PROXY_OK_SEC
        _proxy_skip_until.pop(key, None)


def proxy_tcp_reachable(proxy: str, timeout: float = _PROXY_TCP_TIMEOUT) -> bool:
    parsed = urlparse((proxy or "").strip())
    host = parsed.hostname
    if not host:
        return False
    scheme = (parsed.scheme or "http").lower()
    port = parsed.port or _DEFAULT_PROXY_PORTS.get(scheme, 8080)
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except OSError:
        return False


def _copy_request(request: httpx.Request) -> httpx.Request:
    try:
        content = request.content
    except Exception:  # noqa: BLE001
        return request
    return httpx.Request(
        request.method,
        request.url,
        headers=request.headers,
        content=content,
        extensions=dict(request.extensions or {}),
    )


class FallbackClient(httpx.Client):
    """httpx client that retries without proxy when the proxy is unreachable."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        raw = kwargs.get("proxy")
        self._configured_proxy = str(raw).strip() if raw else None
        self._direct: httpx.Client | None = None
        super().__init__(*args, **kwargs)

    def _direct_client(self) -> httpx.Client:
        if self._direct is None or self._direct.is_closed:
            self._direct = httpx.Client(
                timeout=self.timeout,
                follow_redirects=self.follow_redirects,
                trust_env=False,
            )
        return self._direct

    def send(self, request: httpx.Request, *args: Any, **kwargs: Any) -> httpx.Response:
        proxy = self._configured_proxy
        if proxy and proxy_is_skipped(proxy):
            return self._direct_client().send(request, *args, **kwargs)
        if proxy and not _proxy_recently_ok(proxy) and not proxy_tcp_reachable(proxy):
            _mark_proxy_skipped(proxy)
            logger.warning("proxy %s not reachable; falling back to direct", proxy)
            return self._direct_client().send(request, *args, **kwargs)
        try:
            response = super().send(request, *args, **kwargs)
        except Exception as exc:
            if not proxy or not is_proxy_unavailable(exc):
                raise
            _mark_proxy_skipped(proxy)
            logger.warning("proxy %s unavailable (%s); falling back to direct", proxy, exc)
            retry = _copy_request(request)
            try:
                return self._direct_client().send(retry, *args, **kwargs)
            except Exception as direct_exc:
                raise direct_exc from exc
        if proxy:
            _mark_proxy_ok(proxy)
        return response

    def close(self) -> None:
        extra = self._direct
        self._direct = None
        if extra is not None and not extra.is_closed:
            extra.close()
        super().close()


def _make_client(timeout: float | httpx.Timeout, proxy: str | None) -> httpx.Client:
    kwargs: dict = {"timeout": timeout, "follow_redirects": True, "trust_env": False}
    if proxy:
        kwargs["proxy"] = proxy
        return FallbackClient(**kwargs)
    return httpx.Client(**kwargs)


def http_client(timeout: float | httpx.Timeout = 30.0) -> httpx.Client:
    return _make_client(timeout, proxy_url())


def chat_http_client(timeout: float | httpx.Timeout = 30.0) -> httpx.Client:
    """Chat Completions: direct by default; ignores OS/system proxy.

    Set Settings.chat_proxy or VULNHUNTER_CHAT_PROXY only when Chat must use a proxy.
    If that proxy cannot be reached, the request is retried without a proxy.
    """
    return _make_client(timeout, chat_proxy_url())

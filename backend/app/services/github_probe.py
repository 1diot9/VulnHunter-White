"""Ping GitHub API for settings UI (network / proxy / optional PAT)."""

from __future__ import annotations

import json
import os
import time

import httpx

from ..models import AppSettings, SessionLocal
from ..schemas import GithubProbeIn, GithubTestOut
from .http_client import proxy_url

GITHUB_API = "https://api.github.com"
_PROBE_TIMEOUT = 15.0


def probe_http_client(timeout: float = _PROBE_TIMEOUT, proxy: str | None = None) -> httpx.Client:
    kwargs: dict = {"timeout": timeout, "follow_redirects": True, "trust_env": False}
    if proxy:
        kwargs["proxy"] = proxy
    return httpx.Client(**kwargs)


def _saved_github_pat() -> str:
    with SessionLocal() as db:
        row = db.query(AppSettings).first()
        if row and (row.github_pat or "").strip():
            return row.github_pat.strip()
    return (os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or "").strip()


def _resolve_pat(body: GithubProbeIn) -> str:
    form = (body.github_pat or "").strip()
    if form:
        return form
    return _saved_github_pat()


def _resolve_proxy(body: GithubProbeIn) -> str | None:
    if "http_proxy" in body.model_fields_set:
        return (body.http_proxy or "").strip() or None
    return proxy_url()


def _short_error(text: str, limit: int = 300) -> str:
    t = " ".join((text or "").split())
    if len(t) > limit:
        return t[: limit - 1] + "…"
    return t


def _github_message(data: object, fallback: str) -> str:
    if isinstance(data, dict):
        msg = str(data.get("message") or "").strip()
        if msg:
            return _short_error(msg)
    return fallback


def _int_header(resp: httpx.Response, name: str) -> int | None:
    raw = resp.headers.get(name)
    if raw is None or raw == "":
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def _rate_from_payload(data: object) -> tuple[int | None, int | None]:
    if not isinstance(data, dict):
        return None, None
    resources = data.get("resources")
    core = resources.get("core") if isinstance(resources, dict) else None
    if not isinstance(core, dict):
        core = data.get("rate") if isinstance(data.get("rate"), dict) else None
    if not isinstance(core, dict):
        return None, None
    limit = core.get("limit")
    remaining = core.get("remaining")
    try:
        limit_i = int(limit) if limit is not None and limit != "" else None
    except (TypeError, ValueError):
        limit_i = None
    try:
        remaining_i = int(remaining) if remaining is not None and remaining != "" else None
    except (TypeError, ValueError):
        remaining_i = None
    return limit_i, remaining_i


def _transport_error(exc: Exception) -> str:
    if isinstance(exc, httpx.TimeoutException):
        return "请求超时，请检查出站代理或网络"
    if isinstance(exc, httpx.ConnectError):
        return "无法连接 GitHub API，请检查出站代理与网络"
    if isinstance(exc, httpx.ProxyError):
        return "出站代理无法连接 GitHub，请检查代理地址"
    return _short_error(str(exc) or exc.__class__.__name__)


def _http_error(status: int, message: str, *, authenticated: bool) -> str:
    if status == 401:
        return "GitHub PAT 无效，请检查令牌" if authenticated else "GitHub 未授权（HTTP 401）"
    if status == 403:
        lowered = message.lower()
        if "rate limit" in lowered or "额度" in message:
            return f"GitHub 额度已用尽: {_short_error(message)}"
        return f"GitHub 拒绝访问 (HTTP 403): {_short_error(message)}" if message else "GitHub 拒绝访问 (HTTP 403)"
    if message:
        return f"HTTP {status}: {_short_error(message)}"
    return f"HTTP {status}"


def test_connectivity(body: GithubProbeIn) -> GithubTestOut:
    """Ping api.github.com using form PAT/proxy, else saved/env values."""
    token = _resolve_pat(body)
    proxy = _resolve_proxy(body)
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "VulnHunter",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
        url = f"{GITHUB_API}/user"
    else:
        url = f"{GITHUB_API}/rate_limit"

    started = time.perf_counter()
    try:
        with probe_http_client(timeout=_PROBE_TIMEOUT, proxy=proxy) as client:
            resp = client.get(url, headers=headers)
            try:
                data = resp.json()
            except (ValueError, json.JSONDecodeError):
                data = None
    except Exception as e:  # noqa: BLE001
        return GithubTestOut(ok=False, error=_transport_error(e))

    latency = int((time.perf_counter() - started) * 1000)
    limit = _int_header(resp, "x-ratelimit-limit")
    remaining = _int_header(resp, "x-ratelimit-remaining")
    if limit is None or remaining is None:
        body_limit, body_remaining = _rate_from_payload(data)
        if limit is None:
            limit = body_limit
        if remaining is None:
            remaining = body_remaining

    if resp.status_code >= 400:
        fallback = resp.text if data is None else ""
        message = _github_message(data, _short_error(fallback, 160) or f"HTTP {resp.status_code}")
        return GithubTestOut(
            ok=False,
            latency_ms=latency,
            authenticated=bool(token),
            rate_limit=limit,
            rate_remaining=remaining,
            error=_http_error(resp.status_code, message, authenticated=bool(token)),
        )

    login = ""
    if token:
        if not isinstance(data, dict) or not str(data.get("login") or "").strip():
            return GithubTestOut(
                ok=False,
                latency_ms=latency,
                authenticated=True,
                rate_limit=limit,
                rate_remaining=remaining,
                error="GitHub 返回格式异常，未拿到登录名",
            )
        login = str(data.get("login") or "").strip()
    elif not isinstance(data, dict):
        return GithubTestOut(
            ok=False,
            latency_ms=latency,
            error="GitHub 返回非 JSON，请确认出站代理未劫持 api.github.com",
        )

    return GithubTestOut(
        ok=True,
        latency_ms=latency,
        authenticated=bool(token),
        login=login,
        rate_limit=limit,
        rate_remaining=remaining,
    )

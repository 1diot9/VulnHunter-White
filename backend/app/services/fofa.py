"""FOFA search/all client (aligned with AutoHunter-fork)."""

from __future__ import annotations

import base64
import os
import time
from typing import Any
from urllib.parse import urlparse

import httpx

from ..config import settings
from ..models import AppSettings, SessionLocal
from ..schemas import FofaProbeIn, FofaTestOut
from .http_client import http_client

FOFA_DEFAULT_BASE = "https://fofa.info"
FOFA_DEFAULT_SIZE = 10
FOFA_MAX_PAGES = 5
FOFA_MAX_TARGETS = FOFA_DEFAULT_SIZE * FOFA_MAX_PAGES
FOFA_MAX_SIZE = 30
FOFA_FIELDS = "host,ip,port,title,domain,org,protocol"
_DEFAULT_HOSTS = {"fofa.info", "api.fofa.info"}
_ACCOUNT_ERROR_MARKERS = (
    "820000",
    "820001",
    "-700",
    "账号无效",
    "账号已过期",
    "账号过期",
    "无效的fofa",
    "无效的 fofa",
    "f点不足",
    "f币不足",
    "余额不足",
    "配额",
    "权限不足",
    "没有权限",
    "会员",
    "account invalid",
    "invalid key",
    "expired",
    "insufficient",
    "quota",
    "permission",
    "unauthorized",
    "forbidden",
)


class FofaError(Exception):
    def __init__(self, message: str, account_error: bool = False):
        super().__init__(message)
        self.account_error = account_error


def _is_account_error(errmsg: str) -> bool:
    text = str(errmsg or "").lower()
    return any(m in text for m in _ACCOUNT_ERROR_MARKERS)


def _qbase64(query: str) -> str:
    return base64.b64encode(query.encode("utf-8")).decode("ascii")


def _extra_allowed_hosts() -> set[str]:
    raw = (
        os.environ.get("VULNHUNTER_FOFA_ALLOWED_HOSTS")
        or os.environ.get("FOFA_ALLOWED_HOSTS")
        or ""
    )
    return {h.strip().lower() for h in raw.split(",") if h.strip()}


def assert_safe_fofa_base(base_url: str) -> str:
    """Reject non-FOFA hosts so a crafted base_url cannot exfiltrate the key."""
    base = (base_url or FOFA_DEFAULT_BASE).strip() or FOFA_DEFAULT_BASE
    parsed = urlparse(base if "://" in base else f"https://{base}")
    if parsed.scheme not in ("http", "https"):
        raise FofaError(f"FOFA base_url 协议不被允许: {parsed.scheme or 'empty'}")
    host = (parsed.hostname or "").strip().lower()
    if not host:
        raise FofaError("FOFA base_url 缺少 host")
    allowed = _DEFAULT_HOSTS | _extra_allowed_hosts()
    if host not in allowed:
        raise FofaError(f"FOFA base_url 不被允许：{host}")
    return f"{parsed.scheme}://{parsed.netloc}".rstrip("/")


def resolve_fofa_key() -> str:
    with SessionLocal() as db:
        row = db.query(AppSettings).first()
        if row and (getattr(row, "fofa_key", None) or "").strip():
            return str(row.fofa_key).strip()
    return (
        (settings.fofa_key or "").strip()
        or (os.environ.get("FOFA_KEY") or "").strip()
    )


def resolve_fofa_base_url() -> str:
    with SessionLocal() as db:
        row = db.query(AppSettings).first()
        if row and (getattr(row, "fofa_base_url", None) or "").strip():
            return str(row.fofa_base_url).strip()
    return (settings.fofa_base_url or "").strip() or FOFA_DEFAULT_BASE


def clamp_size(size: Any, *, default: int = FOFA_DEFAULT_SIZE) -> int:
    try:
        n = int(size)
    except (TypeError, ValueError):
        n = default
    if n <= 0:
        n = default
    return max(1, min(n, FOFA_MAX_SIZE))


def _cell(row: list[Any], i: int) -> str:
    if len(row) <= i or row[i] is None:
        return ""
    return str(row[i])


def clamp_page(page: Any, *, default: int = 1) -> int:
    try:
        n = int(page)
    except (TypeError, ValueError):
        n = default
    if n <= 0:
        n = default
    return n


def search(
    query: str,
    *,
    size: int = FOFA_DEFAULT_SIZE,
    page: int = 1,
    key: str | None = None,
    base_url: str | None = None,
) -> dict[str, Any]:
    """Call FOFA search/all. Returns a tool-friendly dict; never includes the key."""
    q = (query or "").strip()
    if not q:
        return {
            "ok": False,
            "error": "query 不能为空",
            "error_class": "call",
            "guidance": '传 FOFA 语法。title/app 与 body="页面特征" 各试一条，有命中即可。',
        }
    api_key = (key if key is not None else resolve_fofa_key()).strip()
    if not api_key:
        return {
            "ok": False,
            "error": "未配置 FOFA key",
            "error_class": "call",
            "guidance": "在设置页填写 FOFA Key，或设置环境变量 VULNHUNTER_FOFA_KEY。没有 key 时 FinishVerifier(verdict=skipped)。",
        }
    safe_size = clamp_size(size)
    safe_page = clamp_page(page)
    try:
        base = assert_safe_fofa_base(base_url if base_url is not None else resolve_fofa_base_url())
    except FofaError as e:
        return {"ok": False, "error": str(e), "error_class": "call", "account_error": e.account_error}
    params = {
        "key": api_key,
        "qbase64": _qbase64(q),
        "fields": FOFA_FIELDS,
        "page": str(safe_page),
        "size": str(safe_size),
        "full": "false",
    }
    try:
        with http_client(timeout=30.0) as client:
            resp = client.get(f"{base}/api/v1/search/all", params=params)
            try:
                data = resp.json()
            except Exception:
                return {
                    "ok": False,
                    "error": f"FOFA 返回非 JSON (HTTP {resp.status_code}): {resp.text[:200]}",
                    "error_class": "local",
                }
    except httpx.HTTPError as e:
        return {
            "ok": False,
            "error": f"FOFA 请求失败: {type(e).__name__}: {e}",
            "error_class": "local",
            "guidance": "网络不可用时 FinishVerifier(verdict=skipped)，不要空转。",
        }
    if not isinstance(data, dict):
        return {"ok": False, "error": "FOFA 返回格式异常", "error_class": "local"}
    if data.get("error"):
        errmsg = str(data.get("errmsg") or "FOFA 错误")
        account = _is_account_error(errmsg)
        return {
            "ok": False,
            "error": f"FOFA 错误: {errmsg}"[:300],
            "error_class": "call",
            "account_error": account,
            "guidance": (
                "账号/配额问题请检查 FOFA Key，然后 FinishVerifier(verdict=skipped)。"
                if account
                else "改写更精确的 FOFA 语法后重试；仍失败则 FinishVerifier(verdict=no_targets)。"
            ),
        }
    sample: list[dict[str, str]] = []
    for row in (data.get("results") or [])[:safe_size]:
        if isinstance(row, list):
            sample.append(
                {
                    "host": _cell(row, 0),
                    "ip": _cell(row, 1),
                    "port": _cell(row, 2),
                    "title": _cell(row, 3)[:120],
                    "domain": _cell(row, 4),
                    "org": _cell(row, 5),
                    "protocol": _cell(row, 6),
                }
            )
        elif isinstance(row, dict):
            sample.append(
                {
                    "host": str(row.get("host") or ""),
                    "ip": str(row.get("ip") or ""),
                    "port": str(row.get("port") or ""),
                    "title": str(row.get("title") or "")[:120],
                    "domain": str(row.get("domain") or ""),
                    "org": str(row.get("org") or ""),
                    "protocol": str(row.get("protocol") or ""),
                }
            )
    return {
        "ok": True,
        "query": q,
        "page": safe_page,
        "size": int(data.get("size") or 0),
        "returned": len(sample),
        "sample": sample,
        "guidance": (
            f"每页最多 {FOFA_DEFAULT_SIZE} 条。首批按报告复测，凑满 3 个成功即 "
            "FinishVerifier(verdict=success, verified_url=..., poc=..., response=..., "
            "fofa_query=本次语法, targets=全部样本)。"
            "targets 里已测标 success/fail，达 3 个成功后其余标 untested；"
            f"当前这批测完仍不足 3 个则保留成功的，FofaSearch(expand=true) 再搜下一页"
            f"（最多 {FOFA_MAX_PAGES} 轮 / {FOFA_MAX_TARGETS} 个目标）。"
        ),
    }


def _short_error(text: str, limit: int = 300) -> str:
    t = " ".join((text or "").split())
    if len(t) > limit:
        return t[: limit - 1] + "…"
    return t


def _f_points(data: dict[str, Any]) -> int | None:
    """FOFA 控制台的「F点」是 fofa_point；fcoin 是旧币，会员账号经常为 0。"""
    for key in ("fofa_point", "fofa_points", "fcoin"):
        raw = data.get(key)
        if raw is None or raw == "":
            continue
        try:
            return int(raw)
        except (TypeError, ValueError):
            continue
    return None


def test_connectivity(body: FofaProbeIn) -> FofaTestOut:
    """Ping FOFA /api/v1/info/my using the form key, else the saved/env key."""
    form_key = (body.key or "").strip()
    api_key = form_key or resolve_fofa_key()
    if not api_key:
        return FofaTestOut(ok=False, error="未配置 FOFA Key，请先填写或保存")
    try:
        base = assert_safe_fofa_base((body.base_url or "").strip() or resolve_fofa_base_url())
    except FofaError as e:
        return FofaTestOut(ok=False, error=str(e), account_error=e.account_error)
    started = time.perf_counter()
    try:
        with http_client(timeout=15.0) as client:
            resp = client.get(f"{base}/api/v1/info/my", params={"key": api_key})
            try:
                data = resp.json()
            except Exception:
                latency = int((time.perf_counter() - started) * 1000)
                return FofaTestOut(
                    ok=False,
                    latency_ms=latency,
                    error=f"FOFA 返回非 JSON (HTTP {resp.status_code}): {_short_error(resp.text, 160)}",
                )
    except httpx.TimeoutException:
        return FofaTestOut(ok=False, error="请求超时，请检查 FOFA Base URL、代理或网络")
    except httpx.ConnectError:
        return FofaTestOut(ok=False, error="无法连接 FOFA，请检查 Base URL 与代理")
    except httpx.HTTPError as e:
        return FofaTestOut(ok=False, error=f"FOFA 请求失败: {type(e).__name__}: {e}")
    latency = int((time.perf_counter() - started) * 1000)
    if not isinstance(data, dict):
        return FofaTestOut(ok=False, latency_ms=latency, error="FOFA 返回格式异常")
    if resp.status_code >= 400 or data.get("error"):
        errmsg = str(data.get("errmsg") or data.get("message") or f"HTTP {resp.status_code}")
        account = _is_account_error(errmsg)
        return FofaTestOut(
            ok=False,
            latency_ms=latency,
            error=_short_error(f"FOFA 错误: {errmsg}"),
            account_error=account,
        )
    username = str(data.get("username") or "").strip()
    fcoin = _f_points(data)
    isvip = data.get("isvip")
    if isvip is not None:
        isvip = bool(isvip)
    return FofaTestOut(
        ok=True,
        latency_ms=latency,
        username=username,
        fcoin=fcoin,
        isvip=isvip,
    )

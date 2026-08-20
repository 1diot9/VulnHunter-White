"""Search public web pages for FOFA / X-intel application fingerprints."""

from __future__ import annotations

import html as html_lib
import re
import threading
import time
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

import httpx

from .http_client import http_client

_FOFA_FIELDS = (
    "title",
    "body",
    "header",
    "icon_hash",
    "fid",
    "app",
    "product",
    "server",
    "cert",
    "icp",
)
_CLAUSE_RE = re.compile(
    r"\b(" + "|".join(_FOFA_FIELDS) + r')\s*(?:==|=)\s*"([^"]{2,160})"',
    re.IGNORECASE,
)
_ICON_BARE_RE = re.compile(
    r"\bicon_hash\s*(?:==|=)\s*(-?\d{5,12})\b",
    re.IGNORECASE,
)
_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")
_RESULT_A_RE = re.compile(
    r'<a[^>]*class="[^"]*result__a[^"]*"[^>]*href="([^"]+)"[^>]*>(.*?)</a>',
    re.IGNORECASE | re.DOTALL,
)
_SNIPPET_RE = re.compile(
    r'class="[^"]*result__snippet[^"]*"[^>]*>(.*?)</(?:a|td|div|span)>',
    re.IGNORECASE | re.DOTALL,
)
_BING_A_RE = re.compile(
    r'<h2[^>]*>\s*<a[^>]+href="([^"]+)"[^>]*>(.*?)</a>',
    re.IGNORECASE | re.DOTALL,
)
_BING_CAP_RE = re.compile(
    r'class="b_caption"[^>]*>(.*?)</div>',
    re.IGNORECASE | re.DOTALL,
)
_SEARCH_UA = "VulnHunterWebSearch/1.0"
_BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
)
# DuckDuckGo is often DNS-poisoned / unreachable in CN; fail fast then fall back.
_DDG_TIMEOUT = httpx.Timeout(connect=5.0, read=8.0, write=8.0, pool=5.0)
_WEB_TIMEOUT = httpx.Timeout(connect=8.0, read=12.0, write=8.0, pool=5.0)
_NVD_CACHE_TTL = 300.0
_nvd_lock = threading.Lock()
_nvd_cache: dict[str, tuple[float, list[dict[str, str]]]] = {}
_GENERIC_WEB_NAMES = frozenset(
    {
        "login",
        "index",
        "home",
        "web",
        "app",
        "admin",
        "demo",
        "test",
        "untitled",
        "welcome",
    }
)


def _clean_text(raw: str, *, limit: int = 400) -> str:
    text = html_lib.unescape(_TAG_RE.sub(" ", raw or ""))
    text = _WS_RE.sub(" ", text).strip()
    return text[:limit].strip()


def _quote(value: str) -> str:
    return str(value or "").replace("\\", "\\\\").replace('"', '\\"')


def parse_fingerprint_clauses(text: str) -> list[str]:
    """Extract FOFA-like field=\"value\" clauses from blog/search snippets."""
    found: list[str] = []
    seen: set[str] = set()
    blob = text or ""
    for field, value in _CLAUSE_RE.findall(blob):
        value = _clean_text(value, limit=120)
        if not value:
            continue
        clause = f'{field.lower()}="{_quote(value)}"'
        key = clause.lower()
        if key not in seen:
            seen.add(key)
            found.append(clause)
    for raw in _ICON_BARE_RE.findall(blob):
        clause = f'icon_hash="{raw}"'
        if clause.lower() not in seen:
            seen.add(clause.lower())
            found.append(clause)
    return found


def _unwrap_ddg_url(url: str) -> str:
    raw = (url or "").strip()
    if not raw:
        return ""
    parsed = urlparse(raw)
    if "duckduckgo.com" in (parsed.netloc or "").lower() and parsed.path.startswith("/l"):
        qs = parse_qs(parsed.query)
        target = (qs.get("uddg") or [""])[0]
        if target:
            return unquote(target)
    return raw


def _ddg_instant(query: str) -> list[dict[str, str]]:
    with http_client(timeout=_DDG_TIMEOUT) as client:
        resp = client.get(
            "https://api.duckduckgo.com/",
            params={"q": query, "format": "json", "no_html": 1, "skip_disambig": 1},
            headers={"User-Agent": _SEARCH_UA},
        )
        resp.raise_for_status()
        raw = (resp.text or "").strip()
        if not raw:
            return []
        try:
            data = resp.json()
        except Exception:  # noqa: BLE001
            return []
    if not isinstance(data, dict):
        return []
    out: list[dict[str, str]] = []
    if data.get("AbstractText"):
        out.append(
            {
                "title": str(data.get("Heading") or query)[:120],
                "snippet": str(data.get("AbstractText") or ""),
                "url": str(data.get("AbstractURL") or ""),
            }
        )
    for topic in (data.get("RelatedTopics") or [])[:8]:
        if not isinstance(topic, dict):
            continue
        if topic.get("Text"):
            out.append(
                {
                    "title": str(topic.get("Text") or "")[:80],
                    "snippet": str(topic.get("Text") or ""),
                    "url": str(topic.get("FirstURL") or ""),
                }
            )
            continue
        for nested in (topic.get("Topics") or [])[:3]:
            if isinstance(nested, dict) and nested.get("Text"):
                out.append(
                    {
                        "title": str(nested.get("Text") or "")[:80],
                        "snippet": str(nested.get("Text") or ""),
                        "url": str(nested.get("FirstURL") or ""),
                    }
                )
    return out[:10]


def _ddg_html(query: str) -> list[dict[str, str]]:
    with http_client(timeout=_DDG_TIMEOUT) as client:
        resp = client.get(
            "https://html.duckduckgo.com/html/",
            params={"q": query},
            headers={"User-Agent": _SEARCH_UA},
        )
        resp.raise_for_status()
        html = resp.text or ""
    out: list[dict[str, str]] = []
    snippets = [_clean_text(m, limit=280) for m in _SNIPPET_RE.findall(html)]
    for idx, match in enumerate(_RESULT_A_RE.findall(html)):
        href, title_html = match
        title = _clean_text(title_html, limit=120)
        snippet = snippets[idx] if idx < len(snippets) else ""
        out.append({"title": title, "snippet": snippet, "url": _unwrap_ddg_url(href)})
        if len(out) >= 8:
            break
    if not out and snippets:
        for snippet in snippets[:8]:
            out.append({"title": query, "snippet": snippet, "url": ""})
    return out


def _nvd_keyword(query: str) -> list[dict[str, str]]:
    key = query.lower()
    now = time.monotonic()
    with _nvd_lock:
        cached = _nvd_cache.get(key)
        if cached and now - cached[0] < _NVD_CACHE_TTL:
            return list(cached[1])
    with http_client(timeout=_WEB_TIMEOUT) as client:
        resp = client.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": query[:200], "resultsPerPage": 10},
            headers={"User-Agent": _SEARCH_UA},
        )
        resp.raise_for_status()
        data = resp.json()
    if not isinstance(data, dict):
        return []
    out: list[dict[str, str]] = []
    for row in data.get("vulnerabilities") or []:
        if not isinstance(row, dict):
            continue
        cve = row.get("cve") if isinstance(row.get("cve"), dict) else {}
        cid = str(cve.get("id") or "").strip()
        if not cid:
            continue
        descs = cve.get("descriptions") if isinstance(cve.get("descriptions"), list) else []
        snippet = ""
        for desc in descs:
            if isinstance(desc, dict) and desc.get("lang") == "en" and desc.get("value"):
                snippet = str(desc["value"])
                break
        if not snippet:
            for desc in descs:
                if isinstance(desc, dict) and desc.get("value"):
                    snippet = str(desc["value"])
                    break
        out.append(
            {
                "title": cid,
                "snippet": snippet[:400],
                "url": f"https://nvd.nist.gov/vuln/detail/{cid}",
            }
        )
        if len(out) >= 10:
            break
    with _nvd_lock:
        _nvd_cache[key] = (time.monotonic(), list(out))
    return out


def _bing_html(query: str) -> list[dict[str, str]]:
    with http_client(timeout=_WEB_TIMEOUT) as client:
        resp = client.get(
            "https://www.bing.com/search",
            params={"q": query},
            headers={"User-Agent": _BROWSER_UA},
        )
        resp.raise_for_status()
        html = resp.text or ""
    captions = [_clean_text(m, limit=280) for m in _BING_CAP_RE.findall(html)]
    out: list[dict[str, str]] = []
    for idx, match in enumerate(_BING_A_RE.findall(html)):
        href, title_html = match
        url = html_lib.unescape(href or "").strip()
        if not url.startswith("http"):
            continue
        title = _clean_text(title_html, limit=120)
        if not title:
            continue
        snippet = captions[idx] if idx < len(captions) else ""
        out.append({"title": title, "snippet": snippet, "url": url})
        if len(out) >= 8:
            break
    return out


def _merge_results(dest: list[dict[str, str]], extra: list[dict[str, str]]) -> None:
    seen = {item.get("url") or item.get("snippet") for item in dest}
    for item in extra:
        key = item.get("url") or item.get("snippet")
        if key and key in seen:
            continue
        dest.append(item)
        if key:
            seen.add(key)


def _ddg_unreachable(exc: BaseException) -> bool:
    return isinstance(exc, (httpx.ConnectError, httpx.ConnectTimeout, httpx.TimeoutException))


def web_search_results(query: str) -> dict[str, Any]:
    """Search the public web; never raises. Uses the settings outbound proxy.

    DuckDuckGo Instant Answer is tried first (short timeout). If DDG is
    unreachable, skip its HTML endpoint and fall back to NVD then Bing.
    """
    q = " ".join(str(query or "").split()).strip()
    if not q:
        return {"ok": False, "error": "缺少 query", "results": []}
    results: list[dict[str, str]] = []
    notes: list[str] = []
    skip_ddg_html = False
    try:
        results.extend(_ddg_instant(q))
    except Exception as exc:  # noqa: BLE001
        notes.append(f"即时摘要不可用: {type(exc).__name__}")
        skip_ddg_html = _ddg_unreachable(exc)
    if len(results) < 3 and not skip_ddg_html:
        try:
            _merge_results(results, _ddg_html(q))
        except Exception as exc:  # noqa: BLE001
            notes.append(f"网页搜索不可用: {type(exc).__name__}")
    if len(results) < 3:
        try:
            _merge_results(results, _nvd_keyword(q))
        except Exception as exc:  # noqa: BLE001
            notes.append(f"NVD 不可用: {type(exc).__name__}")
    if len(results) < 3:
        try:
            _merge_results(results, _bing_html(q))
        except Exception as exc:  # noqa: BLE001
            notes.append(f"Bing 不可用: {type(exc).__name__}")
    return {
        "ok": True,
        "query": q,
        "results": results[:10],
        "note": "；".join(notes),
    }


def _pick_clauses(clauses: list[str]) -> list[str]:
    """Keep one title-family clause and one body clause; do not stack title&&app&&product."""
    by_field: dict[str, str] = {}
    for clause in clauses:
        field = clause.split("=", 1)[0].strip().lower()
        if field not in by_field:
            by_field[field] = clause
    ordered: list[str] = []
    title_clause = by_field.get("title") or by_field.get("app") or by_field.get("product")
    if title_clause:
        ordered.append(title_clause)
    if by_field.get("body") and by_field["body"] not in ordered:
        ordered.append(by_field["body"])
    elif by_field.get("icon_hash") and by_field["icon_hash"] not in ordered:
        ordered.append(by_field["icon_hash"])
    return ordered[:2]


def _join_query(parts: list[str]) -> str:
    seen: list[str] = []
    for part in parts:
        if part and part not in seen:
            seen.append(part)
    return " && ".join(seen)


def _x_from_fofa_parts(parts: list[str]) -> str:
    x_parts: list[str] = []
    for part in parts:
        field = part.split("=", 1)[0].strip().lower()
        if field == "fid":
            continue
        if field == "header":
            continue
        x_parts.append(part)
        if field == "title" and not any(p.startswith("app=") for p in x_parts):
            value = part.split("=", 1)[1].strip()
            x_parts.append(f"app={value}")
    return _join_query(x_parts[:3])


def search_app_fingerprints(query: str) -> dict[str, Any]:
    """Look up published FOFA / X fingerprints for a product or vendor name."""
    product = " ".join(str(query or "").split()).strip()
    if not product or product.lower() in _GENERIC_WEB_NAMES:
        return {"ok": False, "error": "缺少可用的产品/厂商关键词", "query": product}
    searches = [
        f'{product} FOFA',
        f'{product} body= 指纹',
        f'{product} title= 指纹',
    ]
    hits: list[dict[str, str]] = []
    clauses: list[str] = []
    notes: list[str] = []
    for term in searches:
        found = web_search_results(term)
        if found.get("note"):
            notes.append(str(found["note"]))
        for item in found.get("results") or []:
            blob = " ".join(str(item.get(k) or "") for k in ("title", "snippet", "url"))
            parsed = parse_fingerprint_clauses(blob)
            if parsed or item.get("snippet"):
                row = dict(item)
                if parsed:
                    row["clauses"] = parsed
                hits.append(row)
            clauses.extend(parsed)
        if len(clauses) >= 6:
            break
    picked = _pick_clauses(clauses)
    fofa = _join_query(picked)
    return {
        "ok": True,
        "query": product,
        "searches": searches,
        "results": hits[:8],
        "clauses": picked,
        "fofa": fofa,
        "x": _x_from_fofa_parts(picked),
        "note": "；".join(n for n in notes if n),
        "guidance": (
            "用检索到的稳定测绘语句补全报告「互联网资产证明」。"
            "title/app 与默认页 HTML 的 body 特征各是一条可用检索，有命中即可；"
            "不要叠 title&&app&&icon_hash；不要把漏洞路径当唯一指纹，不要编造 hash；语法禁止「或」/||。"
            "可将 fofa / x 传入 ConfirmVuln 或 apply=true 写回报告。"
        ),
    }

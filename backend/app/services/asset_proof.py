"""Collect FOFA / X-intel fingerprints: lab, source, or web — stored once per project."""

from __future__ import annotations

import base64
import html as html_lib
import json
import os
import re
import threading
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from ..models import Project, SessionLocal
from .ingest import IGNORE_DIR_NAMES
from .lab import load_env
from .paths import app_fingerprints_path, docs_dir, src_dir, vuln_dir
from .report import (
    extract_asset_queries,
    fingerprint_query_error,
    is_placeholder_query,
    replace_search_fingerprint_section,
    write_search_fingerprint_section,
)

_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_ICON_LINK_RE = re.compile(
    r"<link\b[^>]*rel=['\"][^'\"]*icon[^'\"]*['\"][^>]*>",
    re.IGNORECASE,
)
_HREF_RE = re.compile(r"""href\s*=\s*['"]([^'"]+)['"]""", re.IGNORECASE)
_GENERATOR_RE = re.compile(
    r"""<meta\b[^>]*name=['"](?:generator|application-name)['"][^>]*>""",
    re.IGNORECASE,
)
_META_CONTENT_RE = re.compile(r"""content\s*=\s*['"]([^'"]+)['"]""", re.IGNORECASE)
_CHARSET_HEADER_RE = re.compile(r"charset\s*=\s*([\w-]+)", re.IGNORECASE)
_CHARSET_META_RE = re.compile(br"charset=['\"]?([\w-]+)", re.IGNORECASE)
_COPYRIGHT_RE = re.compile(
    r"(?:copyright|&copy;|©|版权所有|CopyRight)\s*[:：]?\s*([^\n<]{2,80})",
    re.IGNORECASE,
)
_STATIC_PATH_RE = re.compile(
    r"""(?:src|href)\s*=\s*['"]([^'"]+\.(?:css|js)(?:\?[^'"]*)?)['"]""",
    re.IGNORECASE,
)
_GENERIC_TITLES = frozenset(
    {
        "login",
        "log in",
        "sign in",
        "welcome",
        "index",
        "home",
        "untitled",
        "登录",
        "登陆",
        "欢迎",
        "首页",
        "主页",
        "后台",
        "管理",
        "管理系统",
        "管理后台",
        "用户登录",
        "系统登录",
    }
)
_GENERIC_SERVERS = frozenset(
    {
        "nginx",
        "apache",
        "apache-coyote/1.1",
        "microsoft-iis/10.0",
        "microsoft-iis/8.5",
        "openresty",
        "caddy",
        "cloudflare",
        "litespeed",
    }
)
_GENERIC_ASSETS = (
    "jquery",
    "bootstrap",
    "vue",
    "react",
    "angular",
    "element-ui",
    "element-plus",
    "antd",
    "layui",
    "font-awesome",
    "normalize",
)
_IMAGE_MAGIC = (
    b"\x00\x00\x01\x00",  # ICO
    b"\x89PNG",
    b"GIF87a",
    b"GIF89a",
    b"\xff\xd8\xff",  # JPEG
    b"RIFF",  # WEBP container
)
_HTML_SUFFIXES = {
    ".html",
    ".htm",
    ".jsp",
    ".jspx",
    ".vue",
    ".tsx",
    ".jsx",
    ".ftl",
    ".vm",
    ".cshtml",
    ".erb",
    ".hbs",
    ".njk",
    ".phtml",
    ".asp",
    ".aspx",
}
_ICON_NAMES = frozenset({"favicon.ico", "favicon.png", "favicon.gif", "favicon.jpg", "logo.ico"})
_MAX_SOURCE_FILES = 400
_MAX_SOURCE_BYTES = 256_000
_ORIGIN_RANK = {"lab": 3, "source": 2, "web": 1, "manual": 1, "": 0}
_CLAUSE_FIELD_RE = re.compile(
    r'\b(title|body|header|icon_hash|app|product)\s*=\s*"([^"]{1,160})"',
    re.IGNORECASE,
)
_fingerprint_locks: dict[int, threading.Lock] = {}
_fingerprint_locks_guard = threading.Lock()


def murmurhash3_32(data: bytes, seed: int = 0) -> int:
    """x86_32 MurmurHash3; signed 32-bit like Python mmh3.hash()."""
    c1 = 0xCC9E2D51
    c2 = 0x1B873593
    length = len(data)
    h = seed & 0xFFFFFFFF
    nblocks = length // 4
    for i in range(nblocks):
        k = int.from_bytes(data[i * 4 : i * 4 + 4], "little")
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
        h = ((h << 13) | (h >> 19)) & 0xFFFFFFFF
        h = (h * 5 + 0xE6546B64) & 0xFFFFFFFF
    tail = data[nblocks * 4 :]
    k = 0
    if len(tail) >= 3:
        k ^= tail[2] << 16
    if len(tail) >= 2:
        k ^= tail[1] << 8
    if len(tail) >= 1:
        k ^= tail[0]
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
    h ^= length
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & 0xFFFFFFFF
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & 0xFFFFFFFF
    h ^= h >> 16
    if h >= 0x80000000:
        return h - 0x100000000
    return h


def fofa_icon_hash(content: bytes) -> str:
    encoded = base64.encodebytes(content)
    return str(murmurhash3_32(encoded))


def fetch_bytes(url: str, *, timeout: float = 8.0) -> tuple[int, dict[str, str], bytes, str]:
    """GET a lab URL without proxy / TLS verify (local labs often self-signed)."""
    with httpx.Client(
        timeout=timeout,
        follow_redirects=True,
        verify=False,
        trust_env=False,
    ) as client:
        response = client.get(url)
        headers = {str(k).lower(): str(v) for k, v in response.headers.items()}
        return int(response.status_code), headers, bytes(response.content or b""), str(response.url)


def _extract_urls(text: str) -> list[str]:
    found: list[str] = []
    for raw in _URL_RE.findall(text or ""):
        cleaned = raw.rstrip(").,;]")
        if cleaned not in found:
            found.append(cleaned)
    return found


def lab_target_urls(project_id: int) -> list[str]:
    urls: list[str] = []
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        if proj:
            urls.extend(_extract_urls(str(proj.manual_lab_prompt or "")))
    env = load_env(project_id)
    target = str(env.get("target_url") or "").strip()
    if target:
        urls.append(target)
    notes = str(env.get("notes") or "")
    urls.extend(_extract_urls(notes))
    urls.extend(_extract_urls(str(env.get("manual_notes") or "")))
    unique: list[str] = []
    for item in urls:
        if item not in unique:
            unique.append(item)
    return unique


def has_lab_target(project_id: int) -> bool:
    return bool(lab_target_urls(project_id))


def _same_origin(left: str, right: str) -> bool:
    a, b = urlparse(left), urlparse(right)
    if not a.netloc or not b.netloc:
        return False
    return a.scheme == b.scheme and a.hostname == b.hostname and (a.port or _default_port(a.scheme)) == (
        b.port or _default_port(b.scheme)
    )


def _default_port(scheme: str) -> int | None:
    if scheme == "http":
        return 80
    if scheme == "https":
        return 443
    return None


def resolve_collect_url(project_id: int, url: str | None = None, path: str | None = None) -> str | None:
    allowed = lab_target_urls(project_id)
    if not allowed:
        return None
    chosen = (url or "").strip() or allowed[0]
    if (url or "").strip() and not any(_same_origin(chosen, item) for item in allowed):
        return None
    extra = (path or "").strip()
    if extra:
        chosen = urljoin(chosen.rstrip("/") + "/", extra.lstrip("/"))
    return chosen


def _decode_html(content: bytes, content_type: str = "") -> str:
    charset = ""
    header_match = _CHARSET_HEADER_RE.search(content_type or "")
    if header_match:
        charset = header_match.group(1)
    if not charset:
        meta = _CHARSET_META_RE.search(content[:4000])
        if meta:
            charset = meta.group(1).decode("ascii", errors="ignore")
    for enc in (charset, "utf-8", "gbk", "gb18030"):
        if not enc:
            continue
        try:
            return content.decode(enc)
        except (LookupError, UnicodeDecodeError):
            continue
    return content.decode("utf-8", errors="replace")


def _clean_text(raw: str, *, limit: int = 80) -> str:
    text = html_lib.unescape(re.sub(r"\s+", " ", raw or "")).strip()
    return text[:limit].strip()


def _is_generic_title(title: str) -> bool:
    folded = re.sub(r"\s+", " ", title or "").strip().lower()
    return not folded or folded in _GENERIC_TITLES or len(folded) < 4


def _is_generic_asset(path: str) -> bool:
    lowered = path.lower()
    return any(token in lowered for token in _GENERIC_ASSETS)


def _looks_like_image(content: bytes, content_type: str = "") -> bool:
    if not content or len(content) < 16:
        return False
    ctype = (content_type or "").lower()
    if "html" in ctype or "json" in ctype or "text/plain" in ctype:
        return False
    if ctype.startswith("image/") or "icon" in ctype:
        return True
    return any(content.startswith(magic) for magic in _IMAGE_MAGIC)


def _quote(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _header_fingerprint(headers: dict[str, str]) -> str:
    server = (headers.get("server") or "").strip()
    if server and server.lower() not in _GENERIC_SERVERS:
        return server
    powered = (headers.get("x-powered-by") or "").strip()
    if powered and powered.lower() not in {"php", "asp.net", "express"}:
        return powered
    return ""


def _cookie_names(headers: dict[str, str]) -> list[str]:
    raw = headers.get("set-cookie") or ""
    names: list[str] = []
    for part in raw.split(","):
        name = part.split("=", 1)[0].strip()
        if name and name.lower() not in {"path", "expires", "max-age", "domain", "secure", "httponly", "samesite"}:
            if name not in names and not name.lower().startswith(("jsessionid", "phpsessid", "sessionid")):
                names.append(name)
    return names[:4]


def _body_markers(html: str, title: str) -> list[str]:
    markers: list[str] = []
    for match in _COPYRIGHT_RE.finditer(html):
        value = _clean_text(match.group(0), limit=60)
        if value and value not in markers:
            markers.append(value)
    generator = ""
    for tag in _GENERATOR_RE.findall(html):
        content = _META_CONTENT_RE.search(tag)
        if content:
            generator = _clean_text(content.group(1), limit=60)
            break
    if generator:
        markers.append(generator)
    if title and not _is_generic_title(title):
        snippet = _clean_text(title, limit=40)
        if snippet and snippet not in markers:
            markers.append(snippet)
    return markers[:3]


def _static_paths(html: str) -> list[str]:
    paths: list[str] = []
    for raw in _STATIC_PATH_RE.findall(html or ""):
        path = raw.split("?", 1)[0]
        if _is_generic_asset(path):
            continue
        if path not in paths:
            paths.append(path)
        if len(paths) >= 3:
            break
    return paths


def _icon_urls(base_url: str, html: str) -> list[str]:
    urls: list[str] = []
    for tag in _ICON_LINK_RE.findall(html or ""):
        href = _HREF_RE.search(tag)
        if href:
            urls.append(urljoin(base_url, href.group(1)))
    urls.append(urljoin(base_url, "/favicon.ico"))
    unique: list[str] = []
    for item in urls:
        if item not in unique:
            unique.append(item)
    return unique


def _join_query(parts: list[str]) -> str:
    seen: list[str] = []
    for part in parts:
        if part and part not in seen:
            seen.append(part)
        if len(seen) >= 3:
            break
    return " && ".join(seen)


def suggest_queries(
    *,
    title: str = "",
    body_markers: list[str] | None = None,
    static_paths: list[str] | None = None,
    header: str = "",
    icon_hash: str = "",
) -> tuple[str, str]:
    fofa_parts: list[str] = []
    x_parts: list[str] = []
    if title and not _is_generic_title(title):
        quoted = _quote(title)
        fofa_parts.append(f'title="{quoted}"')
        x_parts.append(f'title="{quoted}"')
        x_parts.append(f'app="{quoted}"')
    if icon_hash:
        fofa_parts.append(f'icon_hash="{_quote(icon_hash)}"')
        x_parts.append(f'icon_hash="{_quote(icon_hash)}"')
    for marker in body_markers or []:
        if marker and marker != title:
            quoted = _quote(marker)
            fofa_parts.append(f'body="{quoted}"')
            x_parts.append(f'body="{quoted}"')
            break
    for path in static_paths or []:
        token = path.split("?")[0]
        if token:
            quoted = _quote(token)
            fofa_parts.append(f'body="{quoted}"')
            x_parts.append(f'body="{quoted}"')
            break
    if header:
        fofa_parts.append(f'header="{_quote(header)}"')
    return _join_query(fofa_parts), _join_query(x_parts)


def _fingerprint_lock(project_id: int) -> threading.Lock:
    with _fingerprint_locks_guard:
        lock = _fingerprint_locks.get(int(project_id))
        if lock is None:
            lock = threading.Lock()
            _fingerprint_locks[int(project_id)] = lock
        return lock


def fingerprints_usable(cache: dict[str, Any] | None) -> bool:
    if not cache:
        return False
    return not is_placeholder_query(cache.get("fofa"))


def load_project_fingerprints(project_id: int) -> dict[str, Any] | None:
    path = app_fingerprints_path(project_id)
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, TypeError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def save_project_fingerprints(project_id: int, payload: dict[str, Any]) -> dict[str, Any]:
    fofa = " ".join(str(payload.get("fofa") or "").split()).strip()
    x_query = " ".join(str(payload.get("x") or "").split()).strip()
    data = {
        "fofa": fofa,
        "x": x_query,
        "origin": str(payload.get("origin") or "").strip(),
        "product": str(payload.get("product") or "").strip(),
        "title": str(payload.get("title") or "").strip(),
        "icon_hash": str(payload.get("icon_hash") or "").strip(),
        "body_markers": list(payload.get("body_markers") or []),
        "static_paths": list(payload.get("static_paths") or []),
        "collected": True,
        "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    path = app_fingerprints_path(project_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return data


def _origin_rank(origin: str) -> int:
    primary = str(origin or "").split("+", 1)[0]
    return _ORIGIN_RANK.get(primary, 0)


def project_product_hints(project_id: int, extra: list[str] | None = None) -> list[str]:
    """Product/vendor names for one-time web fingerprint search."""
    from .old_vuln_crawl import default_product_keyword, load_crawl_spec

    hints: list[str] = []
    spec = load_crawl_spec(project_id)
    for raw in (spec.get("keyword"), default_product_keyword(project_id)):
        text = " ".join(str(raw or "").split()).strip()
        if text and text not in hints:
            hints.append(text)
    code_map = docs_dir(project_id) / "code-map.md"
    if code_map.is_file():
        try:
            body = code_map.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            body = ""
        for line in body.splitlines():
            if line.startswith("# "):
                title = line[2:].strip()
                if title and title not in hints:
                    hints.append(title)
                break
    for item in extra or []:
        text = " ".join(str(item or "").split()).strip()
        if text and text not in hints:
            hints.append(text)
    return hints


def _clauses_to_parts(query: str) -> dict[str, Any]:
    title = ""
    icon_hash = ""
    markers: list[str] = []
    paths: list[str] = []
    for field, value in _CLAUSE_FIELD_RE.findall(query or ""):
        key = field.lower()
        if key == "title" and not title:
            title = value
        elif key == "icon_hash" and not icon_hash:
            icon_hash = value
        elif key in {"body", "app", "product"} and value not in markers:
            token = value.split("?")[0]
            if token.startswith("/") or "." in token.rsplit("/", 1)[-1]:
                if token not in paths:
                    paths.append(token)
            elif value != title:
                markers.append(value)
    return {
        "title": title,
        "icon_hash": icon_hash,
        "body_markers": markers,
        "static_paths": paths,
    }


def _merge_fingerprint_payloads(*items: dict[str, Any]) -> dict[str, Any]:
    title = ""
    icon_hash = ""
    header = ""
    markers: list[str] = []
    paths: list[str] = []
    origins: list[str] = []
    product = ""
    fallback_fofa = ""
    fallback_x = ""
    for item in items:
        if not item:
            continue
        origin = str(item.get("origin") or "").strip()
        if origin and origin not in origins:
            origins.append(origin)
        if not product:
            product = str(item.get("product") or item.get("query") or "").strip()
        if not title and item.get("title") and not _is_generic_title(str(item.get("title") or "")):
            title = str(item["title"])
        if not icon_hash and item.get("icon_hash"):
            icon_hash = str(item["icon_hash"])
        if not header and item.get("header"):
            header = str(item["header"])
        for marker in item.get("body_markers") or []:
            if marker and marker not in markers:
                markers.append(str(marker))
        for path in item.get("static_paths") or []:
            if path and path not in paths:
                paths.append(str(path))
        parsed = _clauses_to_parts(str(item.get("fofa") or ""))
        if not title and parsed["title"] and not _is_generic_title(parsed["title"]):
            title = parsed["title"]
        if not icon_hash and parsed["icon_hash"]:
            icon_hash = parsed["icon_hash"]
        for marker in parsed["body_markers"]:
            if marker not in markers:
                markers.append(marker)
        for path in parsed["static_paths"]:
            if path not in paths:
                paths.append(path)
        if not fallback_fofa and item.get("fofa") and not is_placeholder_query(item.get("fofa")):
            fallback_fofa = str(item["fofa"])
            fallback_x = str(item.get("x") or "")
    fofa, x_query = suggest_queries(
        title=title,
        body_markers=markers,
        static_paths=paths,
        header=header,
        icon_hash=icon_hash,
    )
    if not fofa:
        fofa, x_query = fallback_fofa, fallback_x
    return {
        "ok": bool(fofa),
        "fofa": fofa,
        "x": x_query,
        "origin": "+".join(origins) if origins else "",
        "product": product,
        "title": title,
        "icon_hash": icon_hash,
        "body_markers": markers[:4],
        "static_paths": paths[:4],
    }


def collect_source_fingerprints(project_id: int) -> dict[str, Any]:
    """Extract title / copyright / static paths / repo favicon hash from src/ (no HTTP)."""
    root = src_dir(project_id)
    titles: list[str] = []
    markers: list[str] = []
    static_paths: list[str] = []
    icon_hash = ""
    icon_rel = ""
    html_seen = 0
    if root.is_dir():
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [name for name in dirnames if name not in IGNORE_DIR_NAMES]
            for name in filenames:
                full = Path(dirpath) / name
                lowered = name.lower()
                suffix = full.suffix.lower()
                if lowered in _ICON_NAMES and not icon_hash:
                    try:
                        data = full.read_bytes()
                    except OSError:
                        data = b""
                    if _looks_like_image(data):
                        icon_hash = fofa_icon_hash(data)
                        try:
                            icon_rel = str(full.relative_to(root)).replace("\\", "/")
                        except ValueError:
                            icon_rel = name
                if suffix not in _HTML_SUFFIXES:
                    continue
                html_seen += 1
                if html_seen > _MAX_SOURCE_FILES:
                    continue
                try:
                    raw = full.read_bytes()[:_MAX_SOURCE_BYTES]
                except OSError:
                    continue
                html = _decode_html(raw)
                match = _TITLE_RE.search(html)
                title = _clean_text(match.group(1) if match else "", limit=80)
                if title and not _is_generic_title(title):
                    titles.append(title)
                for marker in _body_markers(html, title):
                    if marker not in markers:
                        markers.append(marker)
                for path in _static_paths(html):
                    if path not in static_paths:
                        static_paths.append(path)
    title = ""
    if titles:
        counted = Counter(titles)
        title = sorted(counted.items(), key=lambda kv: (-kv[1], -len(kv[0]), kv[0]))[0][0]
    fofa, x_query = suggest_queries(
        title=title,
        body_markers=markers,
        static_paths=static_paths,
        icon_hash=icon_hash,
    )
    return {
        "ok": bool(fofa),
        "origin": "source",
        "title": title,
        "icon_hash": icon_hash,
        "icon_path": icon_rel,
        "body_markers": markers[:4],
        "static_paths": static_paths[:4],
        "fofa": fofa,
        "x": x_query,
        "files_scanned": html_seen,
        "guidance": "源码指纹已采集；写入项目共享 docs/app-fingerprints.json 后，各漏洞报告直接复用。",
    }


def ensure_project_fingerprints(project_id: int, *, force: bool = False) -> dict[str, Any]:
    """Collect application fingerprints once per project (source + web). Later callers reuse the cache."""
    from .fingerprint_search import search_app_fingerprints

    with _fingerprint_lock(project_id):
        cached = load_project_fingerprints(project_id)
        if not force and cached and cached.get("collected"):
            return cached
        source = collect_source_fingerprints(project_id)
        extras = [str(source.get("title") or "")]
        hints = project_product_hints(project_id, extras)
        web: dict[str, Any] = {}
        product = ""
        for hint in hints:
            found = search_app_fingerprints(hint)
            if found.get("ok") and (found.get("fofa") or found.get("clauses")):
                found["origin"] = "web"
                found["product"] = hint
                web = found
                product = hint
                break
        merged = _merge_fingerprint_payloads(source, web)
        if product:
            merged["product"] = product
        elif hints:
            merged["product"] = hints[0]
        if not merged.get("origin"):
            merged["origin"] = "source" if source.get("ok") else ("web" if web else "")
        merged["collected"] = True
        return save_project_fingerprints(project_id, merged)


def overlay_project_fingerprints(text: str, project_id: int) -> str:
    """Replace a report's asset-proof section with the project-wide fingerprint."""
    cache = load_project_fingerprints(project_id)
    if not fingerprints_usable(cache):
        return text
    return replace_search_fingerprint_section(
        text or "",
        fofa=cache.get("fofa"),
        x=cache.get("x"),
    )


def upgrade_project_fingerprints(
    project_id: int,
    payload: dict[str, Any],
    *,
    origin: str,
) -> dict[str, Any]:
    """Write a better fingerprint (lab/manual) over a weaker cache."""
    incoming = dict(payload)
    incoming["origin"] = origin
    incoming["ok"] = True
    with _fingerprint_lock(project_id):
        cached = load_project_fingerprints(project_id)
        if fingerprints_usable(cached) and _origin_rank(str(cached.get("origin") or "")) >= _origin_rank(origin):
            if origin != "lab":
                return cached
            if str(cached.get("origin") or "").startswith("lab"):
                return cached
        if fingerprints_usable(incoming):
            incoming["origin"] = origin
            return save_project_fingerprints(project_id, incoming)
        merged = _merge_fingerprint_payloads(incoming, cached or {})
        merged["origin"] = origin
        return save_project_fingerprints(project_id, merged)


def collect_lab_fingerprints(
    project_id: int,
    *,
    url: str | None = None,
    path: str | None = None,
) -> dict[str, Any]:
    allowed = lab_target_urls(project_id)
    if not allowed:
        return {
            "ok": False,
            "error": "当前没有可访问的漏洞环境（env.json target_url 或人工靶场地址）",
        }
    requested = (url or "").strip()
    if requested and not any(_same_origin(requested, item) for item in allowed):
        return {
            "ok": False,
            "error": "url 必须与 env.json target_url 或人工靶场说明中的地址同 origin",
        }
    target = resolve_collect_url(project_id, url, path)
    if not target:
        return {
            "ok": False,
            "error": "当前没有可访问的漏洞环境（env.json target_url 或人工靶场地址）",
        }
    try:
        status, headers, content, final_url = fetch_bytes(target)
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"访问漏洞环境失败: {exc}", "target_url": target}

    html = _decode_html(content, headers.get("content-type", ""))
    title_match = _TITLE_RE.search(html)
    title = _clean_text(title_match.group(1) if title_match else "", limit=80)
    header = _header_fingerprint(headers)
    markers = _body_markers(html, title)
    static_paths = _static_paths(html)
    icon_hash = ""
    icon_url = ""
    for candidate in _icon_urls(final_url or target, html):
        try:
            icon_status, icon_headers, icon_body, _ = fetch_bytes(candidate)
        except Exception:  # noqa: BLE001
            continue
        if icon_status >= 400 or not _looks_like_image(icon_body, icon_headers.get("content-type", "")):
            continue
        icon_url = candidate
        icon_hash = fofa_icon_hash(icon_body)
        break

    fofa, x_query = suggest_queries(
        title=title,
        body_markers=markers,
        static_paths=static_paths,
        header=header,
        icon_hash=icon_hash,
    )
    return {
        "ok": True,
        "target_url": target,
        "final_url": final_url,
        "status_code": status,
        "title": title,
        "header": header,
        "cookie_names": _cookie_names(headers),
        "body_markers": markers,
        "static_paths": static_paths,
        "icon_url": icon_url,
        "icon_hash": icon_hash,
        "fofa": fofa,
        "x": x_query,
        "guidance": (
            "已采集运行环境指纹。这是项目级应用指纹，写入 docs/app-fingerprints.json 后所有漏洞复用；"
            "不要把漏洞路径、PoC 参数或一次性业务数据当作唯一指纹。"
        ),
    }


def apply_asset_proof(
    project_id: int,
    vuln_id: int,
    *,
    fofa: object = None,
    x: object = None,
) -> dict[str, Any]:
    fofa_query = " ".join(str(fofa or "").split()).strip()
    x_query = " ".join(str(x or "").split()).strip()
    if fofa_query:
        err = fingerprint_query_error(fofa_query, label="FOFA ")
        if err:
            return {"ok": False, "error": err}
    if x_query:
        err = fingerprint_query_error(x_query, label="X 情报社区 ")
        if err:
            return {"ok": False, "error": err}
    if not fofa_query and not x_query:
        return {"ok": False, "error": "缺少可写入的测绘语句"}
    path = vuln_dir(project_id, int(vuln_id)) / "report.md"
    current_fofa, current_x = extract_asset_queries(path.read_text(encoding="utf-8", errors="ignore") if path.exists() else "")
    write_search_fingerprint_section(
        path,
        fofa=fofa_query or current_fofa,
        x=x_query or current_x,
    )
    return {
        "ok": True,
        "path": f"vulns/{int(vuln_id)}/report.md",
        "fofa": fofa_query or current_fofa,
        "x": x_query or current_x,
    }


def maybe_enrich_asset_proof(
    project_id: int,
    vuln_id: int,
    *,
    fofa: object = None,
    x: object = None,
) -> dict[str, Any]:
    """Fill this report from the project-wide fingerprint; collect/upgrade at most once."""
    fofa_arg = " ".join(str(fofa or "").split()).strip()
    x_arg = " ".join(str(x or "").split()).strip()
    for label, value in (("FOFA ", fofa_arg), ("X 情报社区 ", x_arg)):
        if value:
            err = fingerprint_query_error(value, label=label)
            if err:
                return {"ok": False, "error": err}
    path = vuln_dir(project_id, int(vuln_id)) / "report.md"
    current_fofa, current_x = extract_asset_queries(
        path.read_text(encoding="utf-8", errors="ignore") if path.exists() else ""
    )
    chosen_fofa = fofa_arg or current_fofa
    chosen_x = x_arg or current_x
    collected: dict[str, Any] | None = None
    from_lab = False
    if fofa_arg and not is_placeholder_query(fofa_arg):
        upgrade_project_fingerprints(
            project_id,
            {"fofa": fofa_arg, "x": x_arg or chosen_x, "ok": True},
            origin="manual",
        )
    elif not is_placeholder_query(current_fofa) and not fingerprints_usable(load_project_fingerprints(project_id)):
        upgrade_project_fingerprints(
            project_id,
            {"fofa": current_fofa, "x": current_x, "ok": True},
            origin="manual",
        )
    cache = ensure_project_fingerprints(project_id)
    if (
        has_lab_target(project_id)
        and not str(cache.get("origin") or "").startswith("lab")
        and is_placeholder_query(chosen_fofa)
    ):
        collected = collect_lab_fingerprints(project_id)
        if collected.get("ok") and collected.get("fofa"):
            cache = upgrade_project_fingerprints(project_id, collected, origin="lab")
            from_lab = True
    cache = load_project_fingerprints(project_id) or cache
    if fingerprints_usable(cache) and not fofa_arg:
        chosen_fofa = str(cache.get("fofa") or chosen_fofa)
        if not x_arg:
            chosen_x = str(cache.get("x") or chosen_x)
    changed = bool(fofa_arg or x_arg) or chosen_fofa != current_fofa or chosen_x != current_x
    if not changed:
        return {"ok": True, "updated": False, "fofa": current_fofa, "x": current_x}
    if is_placeholder_query(chosen_fofa) and is_placeholder_query(chosen_x) and not (fofa_arg or x_arg):
        return {
            "ok": True,
            "updated": False,
            "fofa": current_fofa,
            "x": current_x,
            "collect_error": (collected or {}).get("error"),
        }
    applied = apply_asset_proof(project_id, vuln_id, fofa=chosen_fofa, x=chosen_x)
    if not applied.get("ok"):
        return applied
    return {
        "ok": True,
        "updated": True,
        "fofa": applied["fofa"],
        "x": applied["x"],
        "from_lab": from_lab,
        "from_project": fingerprints_usable(cache),
    }

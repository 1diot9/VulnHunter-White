"""GitHub Advisories: SearchGHSA lookup + historical-vuln GHSA crawler (AutoPoc-aligned)."""

from __future__ import annotations

import json
import os
import re
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx

from ..models import AppSettings, SessionLocal
from .http_client import http_client

GHSA_ADVISORIES = "https://api.github.com/advisories"
REPO_ADVISORIES = "https://api.github.com/repos/{repo}/security-advisories"
DEFAULT_ECOSYSTEMS = ("maven", "npm", "pip", "composer")
DEFAULT_SINCE_DAYS = 365 * 3
_RATE_LIMIT_UNAUTH = 60
_RATE_LIMIT_AUTH = 5000
_RATE_LIMIT_MAX_RETRIES = 8
_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.I)
_GHSA_RE = re.compile(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", re.I)

ECOSYSTEM_HINTS = {
    "java": "maven",
    "maven": "maven",
    "npm": "npm",
    "node": "npm",
    "nodejs": "npm",
    "python": "pip",
    "pip": "pip",
    "php": "composer",
    "composer": "composer",
    "go": "go",
    "ruby": "rubygems",
    "nuget": "nuget",
    "dotnet": "nuget",
}


def _token() -> str:
    with SessionLocal() as db:
        row = db.query(AppSettings).first()
        if row and (row.github_pat or "").strip():
            return row.github_pat.strip()
    return (os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or "").strip()


def _has_github_token() -> bool:
    return bool(_token())


def _default_primary_limit() -> int:
    return _RATE_LIMIT_AUTH if _has_github_token() else _RATE_LIMIT_UNAUTH


def _github_headers() -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "VulnHunter",
    }
    token = _token()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


class _GitHubRateLimiter:
    """Pace to GitHub rate limits; wait out 429 / remaining=0.

    Core REST uses a 3600s window (default). Search API uses a 60s window.
    """

    def __init__(self, *, window_seconds: float = 3600.0) -> None:
        limit = _default_primary_limit()
        self._window = float(window_seconds) if window_seconds > 0 else 3600.0
        self._limit = limit
        self._remaining: int | None = None
        self._reset_epoch: float | None = None
        self._min_interval = self._window / max(1, limit)
        self._next_allowed_at = 0.0

    def wait_before_request(self) -> None:
        now = time.monotonic()
        delay = self._next_allowed_at - now
        if delay > 0:
            time.sleep(delay)

    def observe(self, response: httpx.Response) -> None:
        headers = response.headers
        limit_raw = headers.get("x-ratelimit-limit")
        remaining_raw = headers.get("x-ratelimit-remaining")
        reset_raw = headers.get("x-ratelimit-reset")
        if limit_raw and limit_raw.isdigit():
            self._limit = max(1, int(limit_raw))
            self._min_interval = self._window / self._limit
        if remaining_raw is not None and remaining_raw.isdigit():
            self._remaining = int(remaining_raw)
        if reset_raw and reset_raw.isdigit():
            self._reset_epoch = float(reset_raw)

        interval = self._min_interval
        if (
            self._remaining is not None
            and self._reset_epoch is not None
            and self._remaining >= 0
        ):
            secs_left = max(0.0, self._reset_epoch - time.time())
            if self._remaining == 0:
                interval = max(interval, secs_left + 0.5)
            elif secs_left > 0:
                interval = max(interval, secs_left / max(self._remaining, 1))
        self._next_allowed_at = time.monotonic() + interval

    def sleep_for_rate_limit(self, response: httpx.Response) -> float:
        headers = response.headers
        retry_after = headers.get("retry-after")
        wait = 0.0
        if retry_after:
            try:
                wait = float(retry_after)
            except ValueError:
                wait = 0.0
        if wait <= 0:
            reset_raw = headers.get("x-ratelimit-reset")
            if reset_raw and reset_raw.isdigit():
                wait = max(0.0, float(reset_raw) - time.time()) + 0.5
        if wait <= 0:
            wait = 60.0
        wait = min(wait, 3600.0)
        time.sleep(wait)
        self._next_allowed_at = time.monotonic()
        return wait


def github_get(
    url: str,
    *,
    params: dict[str, Any] | None = None,
    client: httpx.Client,
    limiter: _GitHubRateLimiter,
) -> httpx.Response:
    """GET with PAT headers and primary/search rate-limit retries."""
    headers = _github_headers()
    r: httpx.Response | None = None
    for attempt in range(_RATE_LIMIT_MAX_RETRIES):
        limiter.wait_before_request()
        r = client.get(url, headers=headers, params=params)
        limiter.observe(r)
        if _is_rate_limited(r):
            if attempt + 1 >= _RATE_LIMIT_MAX_RETRIES:
                raise httpx.HTTPStatusError(
                    f"GitHub rate limit exceeded after {_RATE_LIMIT_MAX_RETRIES} retries",
                    request=r.request,
                    response=r,
                )
            limiter.sleep_for_rate_limit(r)
            continue
        break
    assert r is not None
    return r


def _is_rate_limited(response: httpx.Response) -> bool:
    if response.status_code == 429:
        return True
    if response.status_code != 403:
        return False
    remaining = response.headers.get("x-ratelimit-remaining")
    if remaining == "0":
        return True
    body = (response.text or "").lower()
    return "rate limit" in body or "secondary rate" in body


def since_date(days: int = DEFAULT_SINCE_DAYS) -> str:
    dt = datetime.now(timezone.utc) - timedelta(days=max(1, int(days)))
    return dt.strftime("%Y-%m-%d")


def merge_key(identifier: str) -> str:
    text = (identifier or "").strip()
    m = _CVE_RE.search(text)
    if m:
        return m.group(0).upper()
    m = _GHSA_RE.search(text)
    if m:
        return m.group(0).upper()
    return text.upper() or "UNKNOWN"


def _pick_identifier(adv: dict[str, Any]) -> str:
    cve = adv.get("cve_id")
    if isinstance(cve, str) and cve.strip():
        return cve.strip().upper()
    for ident in adv.get("identifiers") or []:
        if not isinstance(ident, dict):
            continue
        value = str(ident.get("value") or "").strip()
        if ident.get("type") == "CVE" and value:
            return value.upper()
    ghsa = adv.get("ghsa_id")
    if isinstance(ghsa, str) and ghsa.strip():
        return ghsa.strip().upper()
    for ident in adv.get("identifiers") or []:
        if not isinstance(ident, dict):
            continue
        value = str(ident.get("value") or "").strip()
        if ident.get("type") == "GHSA" and value:
            return value.upper()
    return "UNKNOWN"


def _cve_of(adv: dict[str, Any]) -> str | None:
    cve = adv.get("cve_id")
    if isinstance(cve, str) and cve.strip():
        return cve.strip().upper()
    for ident in adv.get("identifiers") or []:
        if not isinstance(ident, dict):
            continue
        if str(ident.get("type") or "").upper() == "CVE":
            value = str(ident.get("value") or "").strip()
            if value:
                return value.upper()
    ident = _pick_identifier(adv)
    if ident.upper().startswith("CVE-"):
        return ident.upper()
    return None


def _affected_versions(adv: dict[str, Any], ecosystem: str | None = None) -> str | None:
    parts: list[str] = []
    for block in adv.get("vulnerabilities") or []:
        if not isinstance(block, dict):
            continue
        pkg = block.get("package") or {}
        eco = (pkg.get("ecosystem") or "").lower()
        if ecosystem and eco and eco != ecosystem.lower():
            continue
        name = pkg.get("name") or ""
        rng = block.get("vulnerable_version_range") or ""
        patched = block.get("first_patched_version")
        chunk = f"{name} {rng}".strip() if name or rng else ""
        if patched:
            chunk = f"{chunk}; fixed {patched}".strip("; ")
        if chunk:
            parts.append(chunk)
        if len(parts) >= 3:
            break
    if not parts:
        return None
    return "; ".join(parts)[:500]


def advisory_to_record(
    adv: dict[str, Any],
    *,
    keyword: str | None = None,
    ecosystem: str | None = None,
) -> dict[str, Any]:
    summary = (adv.get("summary") or "").strip()
    description = (adv.get("description") or "").strip()
    text = summary or description
    if len(text) > 500:
        text = text[:497] + "..."
    identifier = _pick_identifier(adv)
    title = (summary.split("\n")[0] if summary else identifier)[:500]
    source_url = adv.get("html_url") or (
        f"https://github.com/advisories/{adv.get('ghsa_id')}" if adv.get("ghsa_id") else None
    )
    return {
        "identifier": identifier,
        "title": title,
        "summary": text or title,
        "component": (keyword or "").strip() or None,
        "source": "ghsa",
        "fix_status": "patched",
        "source_url": source_url,
        "affected_versions": _affected_versions(adv, ecosystem),
        "ghsa_id": adv.get("ghsa_id"),
        "cve": _cve_of(adv),
        "severity": adv.get("severity"),
        "published_at": adv.get("published_at"),
    }


def fetch_advisories_for_package(
    package: str,
    *,
    ecosystem: str,
    published_since: str,
    per_page: int = 100,
    max_pages: int = 5,
    client: httpx.Client | None = None,
    limiter: _GitHubRateLimiter | None = None,
) -> list[dict[str, Any]]:
    owns_client = client is None
    if owns_client:
        client = http_client(timeout=45.0)
    assert client is not None
    rate = limiter or _GitHubRateLimiter()
    out: list[dict[str, Any]] = []
    after: str | None = None
    try:
        for _ in range(max(1, max_pages)):
            params: dict[str, Any] = {
                "affects": package,
                "ecosystem": ecosystem,
                "type": "reviewed",
                "published": f">{published_since}",
                "per_page": min(max(1, per_page), 100),
                "sort": "published",
                "direction": "desc",
            }
            if after:
                params["after"] = after
            r = github_get(GHSA_ADVISORIES, params=params, client=client, limiter=rate)
            if r.status_code == 404:
                break
            if r.status_code != 200:
                raise httpx.HTTPStatusError(
                    f"GitHub advisories HTTP {r.status_code}",
                    request=r.request,
                    response=r,
                )
            batch = r.json()
            if not isinstance(batch, list) or not batch:
                break
            out.extend(batch)
            link = r.headers.get("link") or ""
            m = re.search(r'[?&]after=([^&>]+)[^>]*>;\s*rel="next"', link)
            if not m:
                break
            after = m.group(1)
            if len(batch) < params["per_page"]:
                break
    finally:
        if owns_client:
            client.close()
    return out


def crawl_ghsa(
    keyword: str,
    *,
    ecosystems: tuple[str, ...] | list[str] = DEFAULT_ECOSYSTEMS,
    since_days: int = DEFAULT_SINCE_DAYS,
    affects: list[str] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    kw = (keyword or "").strip()
    packages = [p.strip() for p in (affects or []) if p and str(p).strip()]
    if kw and kw not in packages:
        packages.insert(0, kw)
    seen_pkg: set[str] = set()
    uniq_packages: list[str] = []
    for p in packages:
        key = p.lower()
        if key in seen_pkg:
            continue
        seen_pkg.add(key)
        uniq_packages.append(p)

    published_since = since_date(since_days)
    merged: dict[str, dict[str, Any]] = {}
    errors: list[str] = []
    limiter = _GitHubRateLimiter()

    with http_client(timeout=45.0) as client:
        for eco in ecosystems:
            eco_l = eco.strip().lower()
            eco_l = ECOSYSTEM_HINTS.get(eco_l, eco_l)
            if not eco_l:
                continue
            for pkg in uniq_packages:
                try:
                    advisories = fetch_advisories_for_package(
                        pkg,
                        ecosystem=eco_l,
                        published_since=published_since,
                        client=client,
                        limiter=limiter,
                    )
                except httpx.HTTPError as exc:
                    errors.append(f"{eco_l}:{pkg}: {exc}")
                    continue
                for adv in advisories:
                    if not isinstance(adv, dict):
                        continue
                    if adv.get("withdrawn_at"):
                        continue
                    rec = advisory_to_record(adv, keyword=kw or pkg, ecosystem=eco_l)
                    key = merge_key(str(rec.get("identifier") or ""))
                    if key == "UNKNOWN":
                        continue
                    merged.setdefault(key, rec)

    results = list(merged.values())
    results.sort(key=lambda x: (x.get("identifier") or "").upper())
    meta = {
        "since": published_since,
        "since_days": since_days,
        "ecosystems": [ECOSYSTEM_HINTS.get(str(e).strip().lower(), str(e).strip().lower()) for e in ecosystems],
        "packages": uniq_packages,
        "fetched": len(results),
        "errors": errors,
        "rate_limit": {
            "assumed_limit_per_hour": limiter._limit,
            "min_interval_sec": round(limiter._min_interval, 4),
            "authenticated": _has_github_token(),
        },
    }
    return results, meta


def crawl_repo_advisories(
    repo: str,
    *,
    since_days: int = DEFAULT_SINCE_DAYS,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Fetch published/closed security advisories for owner/repo."""
    slug = (repo or "").strip().strip("/")
    if slug.count("/") != 1:
        return [], {"repo": slug, "fetched": 0, "errors": ["无效仓库"], "source": "repo_advisories"}
    published_since = since_date(since_days)
    url = REPO_ADVISORIES.format(repo=slug)
    limiter = _GitHubRateLimiter()
    raw: list[dict[str, Any]] = []
    errors: list[str] = []
    with http_client(timeout=45.0) as client:
        for page in range(1, 6):
            try:
                r = github_get(
                    url,
                    params={"per_page": 100, "page": page},
                    client=client,
                    limiter=limiter,
                )
            except httpx.HTTPError as exc:
                errors.append(str(exc))
                break
            if r.status_code == 404:
                break
            if r.status_code == 403:
                errors.append(f"仓库 Advisory 403: {r.text[:200]}")
                break
            if r.status_code != 200:
                errors.append(f"仓库 Advisory HTTP {r.status_code}: {r.text[:200]}")
                break
            batch = r.json()
            if not isinstance(batch, list) or not batch:
                break
            raw.extend(item for item in batch if isinstance(item, dict))
            if len(batch) < 100:
                break
    merged: dict[str, dict[str, Any]] = {}
    for adv in raw:
        state = str(adv.get("state") or "").strip().lower()
        if state in {"draft", "triage", "withdrawn"} or adv.get("withdrawn_at"):
            continue
        published = str(adv.get("published_at") or adv.get("created_at") or "")[:10]
        if published_since and published and published < published_since:
            continue
        rec = advisory_to_record(adv, keyword=slug.split("/")[-1])
        key = merge_key(str(rec.get("identifier") or ""))
        if key == "UNKNOWN":
            continue
        rec.setdefault("source", "ghsa")
        rec.setdefault("fix_status", "patched")
        merged.setdefault(key, rec)
    results = list(merged.values())
    results.sort(key=lambda x: (x.get("identifier") or "").upper())
    meta = {
        "repo": slug,
        "since": published_since,
        "since_days": since_days,
        "fetched": len(results),
        "errors": errors,
        "source": "repo_advisories",
    }
    return results, meta


def filter_new_vulns(
    vulns: list[dict[str, Any]],
    skip_keys: set[str],
) -> tuple[list[dict[str, Any]], int]:
    out: list[dict[str, Any]] = []
    skipped = 0
    seen: set[str] = set()
    skip = {k for k in skip_keys if k and k != "UNKNOWN"}
    for rec in vulns:
        key = merge_key(str(rec.get("identifier") or ""))
        if key in skip or key in seen or key == "UNKNOWN":
            skipped += 1
            continue
        seen.add(key)
        out.append(rec)
    return out, skipped


def write_ghsa_output(
    path: Path,
    vulns: list[dict[str, Any]],
    *,
    keyword: str | None,
    meta: dict[str, Any],
) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "accepted": True,
        "keyword": keyword or "",
        "vulnerabilities": vulns,
        "meta": meta,
    }
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def search_advisories(
    *,
    query: str | None = None,
    ecosystem: str | None = None,
    package: str | None = None,
    per_page: int = 20,
) -> dict[str, Any]:
    headers = _github_headers()
    params: dict[str, Any] = {"per_page": min(100, max(1, per_page))}
    eco = ECOSYSTEM_HINTS.get((ecosystem or "").lower().strip(), (ecosystem or "").strip())
    if eco:
        params["ecosystem"] = eco
    if package:
        params["affects"] = package

    try:
        with http_client(timeout=40.0) as client:
            r = client.get(GHSA_ADVISORIES, headers=headers, params=params)
            if r.status_code == 401:
                return {"ok": False, "error": "GitHub API 401：请在设置页配置 GitHub PAT"}
            if r.status_code == 403:
                return {"ok": False, "error": f"GitHub API 403/限流: {r.text[:300]}"}
            r.raise_for_status()
            items = r.json()
            if not isinstance(items, list):
                return {"ok": False, "error": "意外响应格式"}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)}

    q = (query or "").strip().lower()
    out = []
    for it in items:
        if not isinstance(it, dict):
            continue
        ghsa = it.get("ghsa_id") or it.get("id")
        summary = it.get("summary") or ""
        desc = (it.get("description") or "")[:500]
        cve = _cve_of(it)
        blob = f"{ghsa} {summary} {desc} {cve or ''}".lower()
        if q and q not in blob:
            continue
        out.append(
            {
                "ghsa_id": ghsa,
                "cve": cve,
                "summary": summary,
                "severity": it.get("severity"),
                "published_at": it.get("published_at"),
                "html_url": it.get("html_url"),
                "description": desc,
            }
        )
    return {"ok": True, "count": len(out), "advisories": out[:per_page]}

"""Simplified GHSA lookup for Recon historical vulns."""

from __future__ import annotations

import os
from typing import Any

from ..models import AppSettings, SessionLocal
from .http_client import http_client

GHSA_ADVISORIES = "https://api.github.com/advisories"
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


def search_advisories(
    *,
    query: str | None = None,
    ecosystem: str | None = None,
    package: str | None = None,
    per_page: int = 20,
) -> dict[str, Any]:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "VulnHunter",
    }
    token = _token()
    if token:
        headers["Authorization"] = f"Bearer {token}"

    params: dict[str, Any] = {"per_page": min(100, max(1, per_page))}
    eco = ECOSYSTEM_HINTS.get((ecosystem or "").lower().strip(), (ecosystem or "").strip())
    if eco:
        params["ecosystem"] = eco
    # GitHub advisories API supports affects=package
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
        cve = None
        identifiers = it.get("identifiers") or []
        if isinstance(identifiers, list):
            for ident in identifiers:
                if isinstance(ident, dict) and str(ident.get("type", "")).upper() == "CVE":
                    cve = ident.get("value")
                    break
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

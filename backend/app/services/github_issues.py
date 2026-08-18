"""GitHub Issues search for historical-vuln supplement (pre-CVE disclosures)."""

from __future__ import annotations

import re
from typing import Any

import httpx

from ..models import Project, SessionLocal
from .ghsa_service import (
    DEFAULT_SINCE_DAYS,
    _CVE_RE,
    _GHSA_RE,
    _GitHubRateLimiter,
    github_get,
    merge_key,
    since_date,
)
from .http_client import http_client
from .paths import src_dir

GITHUB_SEARCH_ISSUES = "https://api.github.com/search/issues"
MAX_ISSUE_CANDIDATES = 80
_SEARCH_PER_PAGE = 50
_SEARCH_MAX_PAGES = 2

_REPO_URL_RE = re.compile(
    r"(?:github\.com[:/]|git@github\.com:)(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+)",
    re.I,
)
_SLUG_RE = re.compile(r"^([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)$")
_ISSUE_URL_RE = re.compile(
    r"github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/issues/(\d+)",
    re.I,
)
_ISSUE_REF_RE = re.compile(r"\b([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)#(\d+)\b")
_POLICY_TITLE_RE = re.compile(
    r"(security policy|SECURITY\.md|vulnerability disclosure|responsible disclosure|"
    r"how to report|reporting a (security )?vulnerabilit|"
    r"安全政策|漏洞披露流程|如何报告)",
    re.I,
)
_SIGNAL_RE = re.compile(
    r"(CVE-\d{4}-\d+|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}|"
    r"\bRCE\b|remote code|code execution|SQLi|sql injection|SSRF|XSS|"
    r"path traversal|LFI|RFI|deserialization|unauth|bypass|"
    r"漏洞|未授权|越权|命令执行|任意文件|反序列化)",
    re.I,
)
_SECURITY_LABELS = frozenset(
    {
        "security",
        "vulnerability",
        "vulnerabilities",
        "cve",
        "advisory",
        "vuln",
        "security-issue",
        "kind/security",
        "type:security",
    }
)


def parse_github_repo(raw: str | None) -> str | None:
    """Extract owner/repo from a GitHub URL, git remote, go module, or identity slug."""
    text = (raw or "").strip()
    if not text:
        return None
    normalized = text.replace("git@github.com:", "github.com/")
    m = _REPO_URL_RE.search(normalized)
    if m:
        owner = m.group("owner")
        repo = m.group("repo").removesuffix(".git")
        if owner.lower() not in {"www", "http", "https"}:
            return f"{owner}/{repo}"
    if text.startswith("@"):
        return None
    slug = text.removesuffix(".git").strip().strip("/")
    m = _SLUG_RE.match(slug)
    if not m:
        return None
    owner, repo = m.group(1), m.group(2)
    if "." in owner:
        return None
    return f"{owner}/{repo}"


def resolve_project_github_repo(project_id: int) -> str | None:
    candidates: list[str] = []
    with SessionLocal() as db:
        proj = db.get(Project, int(project_id))
    if proj:
        for raw in (proj.source_url, proj.identity):
            if raw:
                candidates.append(str(raw))
    git_config = src_dir(project_id) / ".git" / "config"
    if git_config.is_file():
        try:
            candidates.append(git_config.read_text(encoding="utf-8", errors="ignore"))
        except OSError:
            pass
    for raw in candidates:
        slug = parse_github_repo(raw)
        if slug:
            return slug
    return None


def issue_ref_key(repo: str, number: int | str) -> str:
    return merge_key(f"{repo}#{number}")


def issue_keys_from_text(text: str) -> set[str]:
    keys: set[str] = set()
    blob = text or ""
    for m in _ISSUE_URL_RE.finditer(blob):
        repo = f"{m.group(1)}/{m.group(2).removesuffix('.git')}"
        keys.add(issue_ref_key(repo, m.group(3)))
    for m in _ISSUE_REF_RE.finditer(blob):
        slug = parse_github_repo(m.group(1))
        if slug:
            keys.add(issue_ref_key(slug, m.group(2)))
    return {k for k in keys if k and k != "UNKNOWN"}


def issue_search_queries(repo: str, since: str) -> list[str]:
    created = f"created:>={since}"
    return [
        f"repo:{repo} is:issue is:open (CVE OR GHSA) {created}",
        (
            f"repo:{repo} is:issue is:open in:title "
            f'(RCE OR SQLi OR SSRF OR XSS OR LFI OR unauth OR advisory OR 漏洞 OR 未授权 OR 越权 OR "code execution") '
            f"{created}"
        ),
        f"repo:{repo} is:issue is:open (label:security OR label:vulnerability OR label:cve) {created}",
    ]


def _label_names(item: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for lab in item.get("labels") or []:
        if isinstance(lab, dict):
            name = str(lab.get("name") or "").strip()
        else:
            name = str(lab or "").strip()
        if name:
            out.append(name)
    return out


def _is_policy_or_pr(item: dict[str, Any]) -> bool:
    if item.get("pull_request"):
        return True
    title = str(item.get("title") or "")
    return bool(_POLICY_TITLE_RE.search(title))


def _has_security_signal(item: dict[str, Any]) -> bool:
    labels = {n.lower() for n in _label_names(item)}
    if labels & _SECURITY_LABELS:
        return True
    blob = f"{item.get('title') or ''} {item.get('body') or ''}"
    return bool(_SIGNAL_RE.search(blob))


def issue_to_record(item: dict[str, Any], *, repo: str | None = None) -> dict[str, Any] | None:
    if not isinstance(item, dict) or _is_policy_or_pr(item):
        return None
    html_url = str(item.get("html_url") or "").strip()
    number = item.get("number")
    parsed_repo = parse_github_repo(html_url) or (repo or "").strip()
    if not parsed_repo or not number:
        return None
    title = str(item.get("title") or "").strip() or f"{parsed_repo}#{number}"
    body = str(item.get("body") or "").strip()
    blob = f"{title}\n{body}"
    cve = None
    m = _CVE_RE.search(blob)
    if m:
        cve = m.group(0).upper()
    ghsa = None
    gm = _GHSA_RE.search(blob)
    if gm:
        ghsa = gm.group(0).upper()
    identifier = cve or ghsa or f"{parsed_repo}#{int(number)}"
    summary = body.replace("\r\n", "\n").strip() or title
    if len(summary) > 500:
        summary = summary[:497] + "..."
    labels = _label_names(item)
    return {
        "identifier": identifier,
        "title": title[:500],
        "summary": summary,
        "source": "github_issue",
        "fix_status": "unpatched",
        "source_url": html_url or f"https://github.com/{parsed_repo}/issues/{int(number)}",
        "repo": parsed_repo,
        "number": int(number),
        "state": item.get("state") or "open",
        "labels": labels,
        "cve": cve,
        "ghsa_id": ghsa,
        "published_at": item.get("created_at"),
        "updated_at": item.get("updated_at"),
    }


def _search_issue_pages(
    query: str,
    *,
    client: httpx.Client,
    limiter: _GitHubRateLimiter,
    per_page: int,
    max_pages: int,
) -> tuple[list[dict[str, Any]], list[str]]:
    errors: list[str] = []
    items: list[dict[str, Any]] = []
    for page in range(1, max(1, max_pages) + 1):
        params = {
            "q": query,
            "per_page": min(max(1, per_page), 100),
            "page": page,
            "sort": "updated",
            "order": "desc",
        }
        try:
            r = github_get(GITHUB_SEARCH_ISSUES, params=params, client=client, limiter=limiter)
        except httpx.HTTPError as exc:
            errors.append(f"{query}: {exc}")
            break
        if r.status_code == 401:
            errors.append("GitHub API 401：请在设置页配置 GitHub PAT")
            break
        if r.status_code == 403:
            errors.append(f"GitHub Search 403/限流: {r.text[:300]}")
            break
        if r.status_code != 200:
            errors.append(f"GitHub Search HTTP {r.status_code}: {r.text[:200]}")
            break
        payload = r.json()
        if not isinstance(payload, dict):
            errors.append("GitHub Search 响应格式异常")
            break
        batch = payload.get("items") or []
        if not isinstance(batch, list) or not batch:
            break
        items.extend(item for item in batch if isinstance(item, dict))
        if len(batch) < params["per_page"]:
            break
    return items, errors


def crawl_github_issues(
    repo: str,
    *,
    since_days: int = DEFAULT_SINCE_DAYS,
    max_candidates: int = MAX_ISSUE_CANDIDATES,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    slug = parse_github_repo(repo) or (repo or "").strip()
    if not slug or "/" not in slug:
        return [], {"repo": "", "fetched": 0, "errors": ["无 GitHub 仓库"], "queries": []}

    published_since = since_date(since_days)
    queries = issue_search_queries(slug, published_since)
    limiter = _GitHubRateLimiter(window_seconds=60.0)
    by_key: dict[str, dict[str, Any]] = {}
    errors: list[str] = []

    with http_client(timeout=45.0) as client:
        for query in queries:
            items, q_errors = _search_issue_pages(
                query,
                client=client,
                limiter=limiter,
                per_page=_SEARCH_PER_PAGE,
                max_pages=_SEARCH_MAX_PAGES,
            )
            errors.extend(q_errors)
            for item in items:
                if str(item.get("state") or "").strip().lower() != "open":
                    continue
                if not _has_security_signal(item):
                    continue
                rec = issue_to_record(item, repo=slug)
                if not rec:
                    continue
                key = merge_key(str(rec.get("identifier") or ""))
                if key == "UNKNOWN" or key in by_key:
                    continue
                by_key[key] = rec
                if len(by_key) >= max(1, max_candidates):
                    break
            if len(by_key) >= max(1, max_candidates):
                break

    results = list(by_key.values())
    results.sort(key=lambda x: (-int(x.get("number") or 0), str(x.get("identifier") or "")))
    meta = {
        "repo": slug,
        "since": published_since,
        "since_days": since_days,
        "queries": queries,
        "fetched": len(results),
        "errors": errors,
        "rate_limit": {
            "window_seconds": 60,
            "authenticated": limiter._limit >= 30,
        },
    }
    return results, meta


def search_github_issues(
    *,
    repo: str | None = None,
    query: str | None = None,
    project_id: int | None = None,
    per_page: int = 20,
) -> dict[str, Any]:
    slug = parse_github_repo(repo) if repo else None
    if not slug and project_id is not None:
        slug = resolve_project_github_repo(int(project_id))
    extra = " ".join(str(query or "").split()).strip()
    if not slug and not extra:
        return {"ok": False, "error": "缺少 repo（owner/repo）或 query"}
    if slug:
        q = f"repo:{slug} is:issue is:open"
        if extra:
            q = f"{q} {extra}"
    else:
        q = f"is:issue is:open {extra}".strip()

    limiter = _GitHubRateLimiter(window_seconds=60.0)
    try:
        with http_client(timeout=40.0) as client:
            items, errors = _search_issue_pages(
                q,
                client=client,
                limiter=limiter,
                per_page=min(100, max(1, per_page)),
                max_pages=1,
            )
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc)}
    if errors and not items:
        return {"ok": False, "error": errors[0], "query": q}

    out: list[dict[str, Any]] = []
    for item in items:
        if str(item.get("state") or "").strip().lower() != "open":
            continue
        rec = issue_to_record(item, repo=slug or "")
        if rec:
            out.append(rec)
        if len(out) >= per_page:
            break
    return {
        "ok": True,
        "query": q,
        "repo": slug or "",
        "count": len(out),
        "issues": out,
        "note": "；".join(errors),
    }

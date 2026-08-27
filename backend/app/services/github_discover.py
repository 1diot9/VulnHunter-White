"""Discover audit-worthy GitHub repos from public GHSA advisories."""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from ..models import GithubCandidate, Project, SessionLocal, utcnow
from ..prompts import load_prompt
from ..target_kind import (
    DEFAULT_TARGET_KIND,
    TARGET_KIND_LABELS,
    TARGET_KIND_LIBRARY,
    TARGET_KIND_MIXED,
    TARGET_KIND_WEB,
    try_parse_target_kind,
)
from .ghsa_service import (
    GHSA_ADVISORIES,
    _GitHubRateLimiter,
    _has_github_token,
    github_get,
)
from .http_client import http_client

logger = logging.getLogger(__name__)

DEFAULT_SEARCH_LIMIT = 5
MIN_SEARCH_LIMIT = 1
MAX_SEARCH_LIMIT = 20
MAX_GHSA_PAGES = 10
GHSA_PER_PAGE = 100
ACTIVE_WITHIN_DAYS = 365
MIN_STARS = 1000

STATUS_ELIGIBLE = "eligible"
STATUS_SKIPPED = "skipped"
STATUS_IMPORTED = "imported"
STATUS_DISMISSED = "dismissed"
LISTABLE_STATUSES = (STATUS_ELIGIBLE, STATUS_IMPORTED)

_OWNER_REPO_RE = re.compile(
    r"(?:github\.com[/:]|api\.github\.com/repos/)(?P<owner>[\w.-]+)/(?P<repo>[\w.-]+)",
    re.I,
)
_REPO_ADVISORY_API_RE = re.compile(
    r"api\.github\.com/repos/(?P<owner>[\w.-]+)/(?P<repo>[\w.-]+)/security-advisories",
    re.I,
)

_WEB_KEYWORDS = (
    "cms",
    "blog",
    "forum",
    "erp",
    "crm",
    "dashboard",
    "admin panel",
    "web application",
    "webapp",
    "web app",
    "spring-boot",
    "spring boot",
    "django",
    "flask",
    "fastapi",
    "laravel",
    "rails",
    "nextjs",
    "next.js",
    "nuxt",
    "express",
    "koa",
    "gin",
    "echo",
    "wordpress",
    "drupal",
    "joomla",
    "strapi",
    "ghost",
    "halo",
    "xwiki",
    "jenkins",
    "grafana",
    "kibana",
    "sonarqube",
    "gitea",
    "gitlab",
    "self-hosted",
    "self hosted",
)

_LIBRARY_KEYWORDS = (
    "library",
    "sdk",
    "parser",
    "codec",
    "serializer",
    "deserializer",
    "npm package",
    "npm-package",
    "maven",
    "pypi",
    "crate",
    "framework component",
    "utility",
    "utilities",
    "client library",
    "api client",
    "binding",
    "bindings",
    "plugin for",
    "middleware",
    "orm",
)

_WEB_TOPICS = frozenset(
    {
        "cms",
        "web",
        "webapp",
        "web-application",
        "django",
        "flask",
        "laravel",
        "rails",
        "spring-boot",
        "nextjs",
        "nuxt",
        "wordpress",
        "self-hosted",
        "dashboard",
        "admin",
        "blog",
        "forum",
    }
)
_LIBRARY_TOPICS = frozenset(
    {
        "library",
        "sdk",
        "parser",
        "codec",
        "npm-package",
        "python-library",
        "java-library",
        "go-library",
        "crate",
        "nuget",
        "maven",
        "pypi",
        "framework",
        "utility",
        "utilities",
        "api-client",
    }
)
_LLM_CLASSIFY_TIMEOUT = 20.0
_LLM_CLASSIFY_MAX_TOKENS = 256
_LLM_CLASSIFY_MAX_ROUNDS = 1
_REASON_MAX = 500
_JSON_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.I | re.M)
_KIND_JSON_RE = re.compile(r"\{[^{}]*\"target_kind\"[^{}]*\}", re.I | re.S)


def clamp_search_limit(raw: Any) -> int:
    try:
        n = int(raw)
    except (TypeError, ValueError):
        n = DEFAULT_SEARCH_LIMIT
    return max(MIN_SEARCH_LIMIT, min(MAX_SEARCH_LIMIT, n))


def parse_owner_repo(*candidates: Any) -> str | None:
    for raw in candidates:
        text = str(raw or "").strip()
        if not text:
            continue
        m = _REPO_ADVISORY_API_RE.search(text) or _OWNER_REPO_RE.search(text)
        if not m:
            continue
        owner = m.group("owner")
        repo = m.group("repo").removesuffix(".git").rstrip("/")
        if owner and repo and owner.lower() != "advisories":
            return f"{owner}/{repo}"
    return None


def full_name_from_advisory(adv: dict[str, Any]) -> str | None:
    return parse_owner_repo(
        adv.get("repository_advisory_url"),
        adv.get("source_code_location"),
        adv.get("html_url"),
        *(
            (v.get("package") or {}).get("name")
            for v in (adv.get("vulnerabilities") or [])
            if isinstance(v, dict)
        ),
    )


def _uniq_hits(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def _keyword_target_kind_hits(
    *,
    description: str | None = None,
    topics: list[str] | None = None,
    full_name: str = "",
    language: str | None = None,
) -> tuple[list[str], list[str]]:
    blob_parts = [
        full_name.lower(),
        (description or "").lower(),
        (language or "").lower(),
        " ".join(t.lower() for t in (topics or []) if t),
    ]
    blob = " ".join(blob_parts)
    topic_set = {t.lower().strip() for t in (topics or []) if t}

    web_hits: list[str] = []
    lib_hits: list[str] = []
    for kw in _WEB_KEYWORDS:
        if kw in blob:
            web_hits.append(kw)
    for kw in _LIBRARY_KEYWORDS:
        if kw in blob:
            lib_hits.append(kw)
    for t in topic_set & _WEB_TOPICS:
        web_hits.append(f"topic:{t}")
    for t in topic_set & _LIBRARY_TOPICS:
        lib_hits.append(f"topic:{t}")
    return _uniq_hits(web_hits), _uniq_hits(lib_hits)


def classify_target_kind(
    *,
    description: str | None = None,
    topics: list[str] | None = None,
    full_name: str = "",
    language: str | None = None,
) -> tuple[str, str]:
    """Keyword-only Web vs library vs mixed classification (no source, no LLM)."""
    web_hits, lib_hits = _keyword_target_kind_hits(
        description=description,
        topics=topics,
        full_name=full_name,
        language=language,
    )
    if web_hits and lib_hits:
        reason = f"同时命中 Web（{', '.join(web_hits[:3])}）与组件（{', '.join(lib_hits[:3])}）"
        return TARGET_KIND_MIXED, reason[:_REASON_MAX]
    if web_hits:
        return TARGET_KIND_WEB, f"命中 Web 特征：{', '.join(web_hits[:4])}"[:_REASON_MAX]
    if lib_hits:
        return TARGET_KIND_LIBRARY, f"命中组件特征：{', '.join(lib_hits[:4])}"[:_REASON_MAX]
    return DEFAULT_TARGET_KIND, "信息不足，默认 Web 应用"


def _clip_reason(text: str) -> str:
    return (text or "").strip()[:_REASON_MAX]


def _parse_target_kind_llm_payload(raw: str | None) -> dict[str, Any] | None:
    body = (raw or "").strip()
    if not body:
        return None
    body = _JSON_FENCE_RE.sub("", body).strip()
    candidates = [body]
    match = _KIND_JSON_RE.search(body)
    if match:
        candidates.append(match.group(0))
    for chunk in candidates:
        try:
            data = json.loads(chunk)
        except json.JSONDecodeError:
            continue
        if isinstance(data, dict) and data.get("target_kind") is not None:
            return data
    return None


def _choice_content(data: dict[str, Any]) -> str:
    choices = data.get("choices")
    if not isinstance(choices, list) or not choices:
        return ""
    first = choices[0]
    if not isinstance(first, dict):
        return ""
    message = first.get("message") or {}
    content = message.get("content") if isinstance(message, dict) else None
    if isinstance(content, list):
        parts: list[str] = []
        for part in content:
            if isinstance(part, str):
                parts.append(part)
            elif isinstance(part, dict):
                parts.append(str(part.get("text") or part.get("content") or ""))
        content = "".join(parts)
    if content is None:
        content = first.get("text") or ""
    return str(content or "").strip()


def _ask_target_kind_llm(*, system: str, user: str) -> str | None:
    """One-shot JSON classification (max 1 round, thinking disabled)."""
    from ..agent.anthropic_compat import (
        anthropic_headers,
        anthropic_message_to_openai,
        anthropic_url,
        build_anthropic_body,
        is_anthropic_wire,
    )
    from ..agent.llm_compat import (
        apply_disable_thinking,
        param_to_drop,
        prepare_chat_body,
        sampling_temperature,
    )
    from ..config import settings
    from ..services.http_client import chat_http_client, chat_http_timeout
    from ..services.llm_settings import bind_llm_to_endpoint, pool_endpoints_resolved, resolve_llm
    from ..services.llm_thread import llm_thread_slot

    try:
        llm = resolve_llm("worker")
    except Exception:  # noqa: BLE001
        logger.warning("discover target-kind LLM resolve failed", exc_info=True)
        return None
    if not (llm.api_key or "").strip() or not (llm.model or "").strip():
        return None

    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]
    timeout = chat_http_timeout(_LLM_CLASSIFY_TIMEOUT, 0)
    try:
        with llm_thread_slot(phase="discover", role="worker") as handle:
            if handle is None:
                return None
            if handle.endpoint_id:
                for ep in pool_endpoints_resolved():
                    if ep.id == handle.endpoint_id:
                        llm = bind_llm_to_endpoint(llm, ep)
                        break
            anthropic = is_anthropic_wire(llm.wire_api)
            if anthropic:
                url = anthropic_url(llm.base_url)
                headers = anthropic_headers(llm.api_key)
                body: dict[str, Any] = build_anthropic_body(
                    model=llm.model,
                    messages=list(messages),
                    temperature=sampling_temperature(llm.model, settings.temperature),
                    max_tokens=_LLM_CLASSIFY_MAX_TOKENS,
                )
            else:
                url = llm.base_url.rstrip("/") + "/chat/completions"
                headers = {
                    "Authorization": f"Bearer {llm.api_key}",
                    "Content-Type": "application/json",
                }
                body = {
                    "model": llm.model,
                    "messages": messages,
                    "max_tokens": _LLM_CLASSIFY_MAX_TOKENS,
                }
                prepare_chat_body(body, llm.model, temperature=settings.temperature)
            apply_disable_thinking(body, llm.model, anthropic=anthropic)

            with chat_http_client(timeout=timeout) as client:
                # One classify round. Extra POSTs are only to drop unknown fields on HTTP 400.
                for _attempt in range(2):
                    res = client.post(url, headers=headers, json=body)
                    if res.status_code == 400:
                        drop_key = param_to_drop(body, res.text)
                        if drop_key:
                            body.pop(drop_key, None)
                            continue
                    if res.status_code >= 400:
                        logger.warning(
                            "discover target-kind LLM HTTP %s: %s",
                            res.status_code,
                            (res.text or "")[:240],
                        )
                        return None
                    try:
                        data = res.json()
                    except (ValueError, json.JSONDecodeError):
                        logger.warning("discover target-kind LLM response is not JSON")
                        return None
                    if not isinstance(data, dict):
                        return None
                    if anthropic or data.get("type") == "message":
                        data = anthropic_message_to_openai(data)
                    return _choice_content(data) or None
    except Exception:  # noqa: BLE001
        logger.warning("discover target-kind LLM call failed", exc_info=True)
        return None
    return None


def refine_target_kind_with_llm(
    *,
    description: str | None = None,
    topics: list[str] | None = None,
    full_name: str = "",
    language: str | None = None,
    keyword_kind: str,
    keyword_reason: str,
) -> tuple[str, str]:
    """LLM reclassification after keyword match; falls back to keyword result."""
    topic_list = [str(t) for t in (topics or []) if str(t).strip()]
    user = "\n".join(
        [
            f"仓库：{full_name or '未知'}",
            f"描述：{(description or '').strip() or '无'}",
            f"语言：{(language or '').strip() or '未知'}",
            f"Topics：{', '.join(topic_list) if topic_list else '无'}",
            f"关键词粗分：{keyword_kind}（{TARGET_KIND_LABELS.get(keyword_kind, keyword_kind)}）",
            f"关键词依据：{keyword_reason}",
        ]
    )
    try:
        system = load_prompt("discover-target-kind.md").strip()
    except FileNotFoundError:
        return keyword_kind, keyword_reason

    raw = _ask_target_kind_llm(system=system, user=user)
    payload = _parse_target_kind_llm_payload(raw)
    if payload is None:
        return keyword_kind, keyword_reason
    kind = try_parse_target_kind(payload.get("target_kind"))
    if kind is None:
        return keyword_kind, keyword_reason
    llm_reason = str(payload.get("reason") or "").strip()
    label = TARGET_KIND_LABELS.get(kind, kind)
    if kind == keyword_kind:
        detail = llm_reason or keyword_reason
        return kind, _clip_reason(f"LLM 确认为「{label}」（{detail}）")
    kw_label = TARGET_KIND_LABELS.get(keyword_kind, keyword_kind)
    detail = llm_reason or f"关键词曾判 {kw_label}"
    return kind, _clip_reason(
        f"LLM 判定为「{label}」（{detail}；关键词：{keyword_reason}）"
    )


def resolve_discovered_target_kind(
    *,
    description: str | None = None,
    topics: list[str] | None = None,
    full_name: str = "",
    language: str | None = None,
) -> tuple[str, str]:
    """Keyword match first, then LLM reclassification."""
    kind, reason = classify_target_kind(
        description=description,
        topics=topics,
        full_name=full_name,
        language=language,
    )
    return refine_target_kind_with_llm(
        description=description,
        topics=topics,
        full_name=full_name,
        language=language,
        keyword_kind=kind,
        keyword_reason=reason,
    )


def _parse_github_datetime(raw: Any) -> datetime | None:
    text = str(raw or "").strip()
    if not text:
        return None
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError:
        return None


def _imported_full_names(db) -> set[str]:
    names: set[str] = set()
    for p in db.query(Project).filter(Project.source_type == "github").all():
        parsed = parse_owner_repo(p.identity, p.source_url)
        if parsed:
            names.add(parsed.lower())
    return names


def _project_id_for_full_name(db, full_name: str) -> int | None:
    key = full_name.lower()
    for p in db.query(Project).filter(Project.source_type == "github").all():
        parsed = parse_owner_repo(p.identity, p.source_url)
        if parsed and parsed.lower() == key:
            return p.id
    return None


def mark_candidate_imported(
    *,
    source_url: str | None = None,
    identity: str | None = None,
    project_id: int | None = None,
) -> int:
    """Mark matching github_candidates rows as imported. Returns updated count."""
    full_name = parse_owner_repo(identity, source_url)
    if not full_name:
        return 0
    with SessionLocal() as db:
        row = (
            db.query(GithubCandidate)
            .filter(GithubCandidate.full_name == full_name)
            .first()
        )
        if row is None:
            # Case-insensitive fallback
            for cand in db.query(GithubCandidate).all():
                if cand.full_name.lower() == full_name.lower():
                    row = cand
                    break
        if row is None:
            return 0
        row.status = STATUS_IMPORTED
        if project_id is not None:
            row.project_id = project_id
        elif row.project_id is None:
            row.project_id = _project_id_for_full_name(db, row.full_name)
        row.updated_at = utcnow()
        db.commit()
        return 1


def _sync_imported_flags(db) -> None:
    imported = _imported_full_names(db)
    if not imported:
        return
    for row in (
        db.query(GithubCandidate)
        .filter(GithubCandidate.status.in_((STATUS_ELIGIBLE, STATUS_IMPORTED)))
        .all()
    ):
        if row.full_name.lower() in imported:
            if row.status != STATUS_IMPORTED:
                row.status = STATUS_IMPORTED
            if row.project_id is None:
                row.project_id = _project_id_for_full_name(db, row.full_name)


def _store_candidate(
    db,
    *,
    full_name: str,
    html_url: str,
    description: str | None,
    language: str | None,
    stars: int,
    pushed_at: datetime | None,
    target_kind: str,
    target_kind_reason: str,
    ghsa_id: str | None,
    ghsa_url: str | None,
    status: str,
    skip_reason: str | None = None,
    project_id: int | None = None,
) -> GithubCandidate:
    existing = (
        db.query(GithubCandidate).filter(GithubCandidate.full_name == full_name).first()
    )
    if existing is None:
        for row in db.query(GithubCandidate).all():
            if row.full_name.lower() == full_name.lower():
                existing = row
                break
    if existing is None:
        existing = GithubCandidate(full_name=full_name, html_url=html_url)
        db.add(existing)
    existing.html_url = html_url or existing.html_url
    existing.description = description
    existing.language = language
    existing.stars = int(stars or 0)
    existing.pushed_at = pushed_at
    existing.target_kind = target_kind
    existing.target_kind_reason = target_kind_reason
    if ghsa_id:
        existing.latest_ghsa_id = ghsa_id
    if ghsa_url:
        existing.latest_ghsa_url = ghsa_url
    if existing.id is None:
        existing.advisory_count = 1
    elif status == STATUS_ELIGIBLE:
        existing.advisory_count = int(existing.advisory_count or 0) + 1
    elif not existing.advisory_count:
        existing.advisory_count = 1
    existing.status = status
    existing.skip_reason = skip_reason
    if project_id is not None:
        existing.project_id = project_id
    existing.updated_at = utcnow()
    if existing.discovered_at is None:
        existing.discovered_at = utcnow()
    db.flush()
    return existing


def _fetch_repo(
    client: httpx.Client,
    limiter: _GitHubRateLimiter,
    full_name: str,
) -> tuple[dict[str, Any] | None, str | None]:
    url = f"https://api.github.com/repos/{full_name}"
    try:
        r = github_get(url, client=client, limiter=limiter)
    except httpx.HTTPError as exc:
        return None, str(exc)
    if r.status_code == 404:
        return None, "仓库不存在"
    if r.status_code >= 400:
        return None, f"仓库 HTTP {r.status_code}: {(r.text or '')[:200]}"
    data = r.json()
    if not isinstance(data, dict):
        return None, "仓库响应格式异常"
    return data, None


def _fetch_topics(
    client: httpx.Client,
    limiter: _GitHubRateLimiter,
    full_name: str,
) -> list[str]:
    # Topics are included in repo payload when Accept includes mercy-preview historically;
    # modern API returns topics in the repo object. Fallback endpoint if missing.
    url = f"https://api.github.com/repos/{full_name}/topics"
    try:
        r = github_get(url, client=client, limiter=limiter)
    except httpx.HTTPError:
        return []
    if r.status_code != 200:
        return []
    data = r.json()
    if isinstance(data, dict):
        names = data.get("names")
        if isinstance(names, list):
            return [str(x) for x in names if x]
    return []


def _iter_ghsa_pages(
    client: httpx.Client,
    limiter: _GitHubRateLimiter,
    *,
    max_pages: int = MAX_GHSA_PAGES,
):
    after: str | None = None
    for _ in range(max(1, max_pages)):
        params: dict[str, Any] = {
            "type": "reviewed",
            "per_page": GHSA_PER_PAGE,
            "sort": "published",
            "direction": "desc",
        }
        if after:
            params["after"] = after
        r = github_get(GHSA_ADVISORIES, params=params, client=client, limiter=limiter)
        if r.status_code == 401:
            raise PermissionError("GitHub API 401：请在设置页配置 GitHub PAT")
        if r.status_code >= 400:
            raise RuntimeError(f"GitHub Advisories HTTP {r.status_code}: {(r.text or '')[:300]}")
        batch = r.json()
        if not isinstance(batch, list) or not batch:
            break
        yield [item for item in batch if isinstance(item, dict)]
        link = r.headers.get("link") or ""
        m = re.search(r'[?&]after=([^&>]+)[^>]*>;\s*rel="next"', link)
        if not m:
            break
        after = m.group(1)
        if len(batch) < GHSA_PER_PAGE:
            break


def search_candidates(*, limit: int = DEFAULT_SEARCH_LIMIT) -> dict[str, Any]:
    """Find up to `limit` new eligible repos and persist them. Returns search summary."""
    want = clamp_search_limit(limit)
    cutoff = datetime.now(timezone.utc) - timedelta(days=ACTIVE_WITHIN_DAYS)
    authenticated = _has_github_token()
    added: list[GithubCandidate] = []
    scanned_advisories = 0
    scanned_repos = 0
    skipped_seen = 0
    pages = 0
    warning: str | None = None
    if not authenticated:
        warning = "未配置 GitHub PAT，匿名额度较低；建议在设置页配置后再搜索"

    limiter = _GitHubRateLimiter()
    with SessionLocal() as db:
        seen_names = {
            row.full_name.lower()
            for row in db.query(GithubCandidate.full_name).all()
        }
        imported_names = _imported_full_names(db)
        seen_names |= imported_names

        try:
            with http_client(timeout=45.0) as client:
                for batch in _iter_ghsa_pages(client, limiter, max_pages=MAX_GHSA_PAGES):
                    pages += 1
                    for adv in batch:
                        if len(added) >= want:
                            break
                        scanned_advisories += 1
                        if adv.get("withdrawn_at"):
                            continue
                        full_name = full_name_from_advisory(adv)
                        if not full_name:
                            continue
                        key = full_name.lower()
                        if key in seen_names:
                            skipped_seen += 1
                            continue
                        seen_names.add(key)
                        scanned_repos += 1

                        repo, err = _fetch_repo(client, limiter, full_name)
                        ghsa_id = str(adv.get("ghsa_id") or "").strip() or None
                        ghsa_url = str(adv.get("html_url") or "").strip() or None
                        if repo is None:
                            _store_candidate(
                                db,
                                full_name=full_name,
                                html_url=f"https://github.com/{full_name}",
                                description=None,
                                language=None,
                                stars=0,
                                pushed_at=None,
                                target_kind=DEFAULT_TARGET_KIND,
                                target_kind_reason="无法读取仓库元数据",
                                ghsa_id=ghsa_id,
                                ghsa_url=ghsa_url,
                                status=STATUS_SKIPPED,
                                skip_reason=(err or "fetch_failed")[:256],
                            )
                            db.commit()
                            continue

                        if repo.get("private"):
                            _store_candidate(
                                db,
                                full_name=full_name,
                                html_url=str(repo.get("html_url") or f"https://github.com/{full_name}"),
                                description=str(repo.get("description") or "") or None,
                                language=str(repo.get("language") or "") or None,
                                stars=int(repo.get("stargazers_count") or 0),
                                pushed_at=_parse_github_datetime(repo.get("pushed_at")),
                                target_kind=DEFAULT_TARGET_KIND,
                                target_kind_reason="私有仓库",
                                ghsa_id=ghsa_id,
                                ghsa_url=ghsa_url,
                                status=STATUS_SKIPPED,
                                skip_reason="private",
                            )
                            db.commit()
                            continue
                        if repo.get("archived"):
                            _store_candidate(
                                db,
                                full_name=full_name,
                                html_url=str(repo.get("html_url") or f"https://github.com/{full_name}"),
                                description=str(repo.get("description") or "") or None,
                                language=str(repo.get("language") or "") or None,
                                stars=int(repo.get("stargazers_count") or 0),
                                pushed_at=_parse_github_datetime(repo.get("pushed_at")),
                                target_kind=DEFAULT_TARGET_KIND,
                                target_kind_reason="已归档",
                                ghsa_id=ghsa_id,
                                ghsa_url=ghsa_url,
                                status=STATUS_SKIPPED,
                                skip_reason="archived",
                            )
                            db.commit()
                            continue
                        if repo.get("fork"):
                            _store_candidate(
                                db,
                                full_name=full_name,
                                html_url=str(repo.get("html_url") or f"https://github.com/{full_name}"),
                                description=str(repo.get("description") or "") or None,
                                language=str(repo.get("language") or "") or None,
                                stars=int(repo.get("stargazers_count") or 0),
                                pushed_at=_parse_github_datetime(repo.get("pushed_at")),
                                target_kind=DEFAULT_TARGET_KIND,
                                target_kind_reason="Fork 仓库",
                                ghsa_id=ghsa_id,
                                ghsa_url=ghsa_url,
                                status=STATUS_SKIPPED,
                                skip_reason="fork",
                            )
                            db.commit()
                            continue

                        pushed_at = _parse_github_datetime(repo.get("pushed_at"))
                        stars = int(repo.get("stargazers_count") or 0)
                        if pushed_at is None or pushed_at < cutoff:
                            _store_candidate(
                                db,
                                full_name=full_name,
                                html_url=str(repo.get("html_url") or f"https://github.com/{full_name}"),
                                description=str(repo.get("description") or "") or None,
                                language=str(repo.get("language") or "") or None,
                                stars=stars,
                                pushed_at=pushed_at,
                                target_kind=DEFAULT_TARGET_KIND,
                                target_kind_reason="近一年无提交",
                                ghsa_id=ghsa_id,
                                ghsa_url=ghsa_url,
                                status=STATUS_SKIPPED,
                                skip_reason="inactive",
                            )
                            db.commit()
                            continue
                        if stars < MIN_STARS:
                            _store_candidate(
                                db,
                                full_name=full_name,
                                html_url=str(repo.get("html_url") or f"https://github.com/{full_name}"),
                                description=str(repo.get("description") or "") or None,
                                language=str(repo.get("language") or "") or None,
                                stars=stars,
                                pushed_at=pushed_at,
                                target_kind=DEFAULT_TARGET_KIND,
                                target_kind_reason=f"Star 不足 {MIN_STARS}",
                                ghsa_id=ghsa_id,
                                ghsa_url=ghsa_url,
                                status=STATUS_SKIPPED,
                                skip_reason="low_stars",
                            )
                            db.commit()
                            continue

                        topics = repo.get("topics") if isinstance(repo.get("topics"), list) else None
                        if not topics:
                            topics = _fetch_topics(client, limiter, full_name)
                        description = str(repo.get("description") or "") or None
                        language = str(repo.get("language") or "") or None
                        kind, reason = resolve_discovered_target_kind(
                            description=description,
                            topics=[str(t) for t in (topics or [])],
                            full_name=full_name,
                            language=language,
                        )
                        project_id = _project_id_for_full_name(db, full_name)
                        status = STATUS_IMPORTED if project_id else STATUS_ELIGIBLE
                        row = _store_candidate(
                            db,
                            full_name=str(repo.get("full_name") or full_name),
                            html_url=str(repo.get("html_url") or f"https://github.com/{full_name}"),
                            description=description,
                            language=language,
                            stars=stars,
                            pushed_at=pushed_at,
                            target_kind=kind,
                            target_kind_reason=reason,
                            ghsa_id=ghsa_id,
                            ghsa_url=ghsa_url,
                            status=status,
                            project_id=project_id,
                        )
                        db.commit()
                        db.refresh(row)
                        if status == STATUS_ELIGIBLE:
                            added.append(row)
                    if len(added) >= want:
                        break
        except PermissionError as exc:
            db.rollback()
            return {
                "ok": False,
                "error": str(exc),
                "added": 0,
                "items": [],
                "scanned_advisories": scanned_advisories,
                "scanned_repos": scanned_repos,
                "pages": pages,
                "authenticated": authenticated,
                "warning": warning,
            }
        except Exception as exc:  # noqa: BLE001
            logger.exception("github discover search failed")
            db.rollback()
            return {
                "ok": False,
                "error": str(exc),
                "added": 0,
                "items": [],
                "scanned_advisories": scanned_advisories,
                "scanned_repos": scanned_repos,
                "pages": pages,
                "authenticated": authenticated,
                "warning": warning,
            }

        items = [candidate_to_dict(row) for row in added]
        return {
            "ok": True,
            "error": None,
            "added": len(added),
            "items": items,
            "scanned_advisories": scanned_advisories,
            "scanned_repos": scanned_repos,
            "skipped_seen": skipped_seen,
            "pages": pages,
            "authenticated": authenticated,
            "warning": warning,
            "limit": want,
        }


def candidate_to_dict(row: GithubCandidate) -> dict[str, Any]:
    return {
        "id": row.id,
        "full_name": row.full_name,
        "html_url": row.html_url,
        "description": row.description,
        "language": row.language,
        "stars": int(row.stars or 0),
        "pushed_at": row.pushed_at,
        "target_kind": row.target_kind or DEFAULT_TARGET_KIND,
        "target_kind_reason": row.target_kind_reason,
        "advisory_count": int(row.advisory_count or 0),
        "latest_ghsa_id": row.latest_ghsa_id,
        "latest_ghsa_url": row.latest_ghsa_url,
        "status": row.status,
        "project_id": row.project_id,
        "skip_reason": row.skip_reason,
        "discovered_at": row.discovered_at,
        "updated_at": row.updated_at,
    }


def list_candidates(
    *,
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    limit = max(1, min(200, int(limit)))
    offset = max(0, int(offset))
    with SessionLocal() as db:
        _sync_imported_flags(db)
        db.commit()
        q = (
            db.query(GithubCandidate)
            .filter(GithubCandidate.status.in_(LISTABLE_STATUSES))
            .order_by(GithubCandidate.discovered_at.desc(), GithubCandidate.id.desc())
        )
        total = q.count()
        rows = q.offset(offset).limit(limit).all()
        return {
            "items": [candidate_to_dict(r) for r in rows],
            "total": total,
            "limit": limit,
            "offset": offset,
        }


def dismiss_candidate(candidate_id: int) -> dict[str, Any] | None:
    """Remove a candidate from the list permanently; future searches skip it."""
    with SessionLocal() as db:
        row = db.query(GithubCandidate).filter(GithubCandidate.id == int(candidate_id)).first()
        if row is None:
            return None
        if row.status == STATUS_DISMISSED:
            return candidate_to_dict(row)
        row.status = STATUS_DISMISSED
        row.skip_reason = "dismissed"
        row.project_id = None
        row.updated_at = utcnow()
        db.commit()
        db.refresh(row)
        return candidate_to_dict(row)

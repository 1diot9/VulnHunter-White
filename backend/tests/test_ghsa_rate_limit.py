"""GHSA 爬虫按 GitHub 主限额最大速率限速。"""

from __future__ import annotations

import time
from unittest.mock import MagicMock

from app.services.ghsa_service import (
    _RATE_LIMIT_AUTH,
    _RATE_LIMIT_UNAUTH,
    _GitHubRateLimiter,
    _default_primary_limit,
    _is_rate_limited,
    filter_new_vulns,
    merge_key,
)


def test_default_primary_limit_follows_token(monkeypatch, tmp_env) -> None:
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)
    assert _default_primary_limit() == _RATE_LIMIT_UNAUTH

    monkeypatch.setenv("GITHUB_TOKEN", "ghp_test")
    assert _default_primary_limit() == _RATE_LIMIT_AUTH


def test_limiter_paces_at_max_steady_rate(monkeypatch, tmp_env) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_test")
    limiter = _GitHubRateLimiter()
    assert abs(limiter._min_interval - 3600.0 / _RATE_LIMIT_AUTH) < 1e-9

    resp = MagicMock()
    resp.headers = {
        "x-ratelimit-limit": "5000",
        "x-ratelimit-remaining": "4999",
        "x-ratelimit-reset": str(int(time.time()) + 3600),
    }
    limiter.observe(resp)
    assert abs(limiter._min_interval - 3600.0 / 5000) < 1e-9

    t0 = time.monotonic()
    limiter.wait_before_request()
    elapsed = time.monotonic() - t0
    assert elapsed >= limiter._min_interval * 0.9


def test_is_rate_limited_variants() -> None:
    r429 = MagicMock()
    r429.status_code = 429
    r429.headers = {}
    r429.text = ""
    assert _is_rate_limited(r429)

    r403 = MagicMock()
    r403.status_code = 403
    r403.headers = {"x-ratelimit-remaining": "0"}
    r403.text = ""
    assert _is_rate_limited(r403)

    r403_secondary = MagicMock()
    r403_secondary.status_code = 403
    r403_secondary.headers = {}
    r403_secondary.text = "You have exceeded a secondary rate limit"
    assert _is_rate_limited(r403_secondary)

    r200 = MagicMock()
    r200.status_code = 200
    r200.headers = {"x-ratelimit-remaining": "10"}
    r200.text = ""
    assert not _is_rate_limited(r200)


def test_sleep_for_rate_limit_honors_retry_after(monkeypatch, tmp_env) -> None:
    slept: list[float] = []
    monkeypatch.setattr(time, "sleep", lambda s: slept.append(s))
    limiter = _GitHubRateLimiter()
    resp = MagicMock()
    resp.headers = {"retry-after": "12"}
    assert limiter.sleep_for_rate_limit(resp) == 12.0
    assert slept == [12.0]


def test_search_limiter_uses_minute_window(monkeypatch, tmp_env) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_test")
    limiter = _GitHubRateLimiter(window_seconds=60.0)
    assert abs(limiter._min_interval - 60.0 / _RATE_LIMIT_AUTH) < 1e-9
    resp = MagicMock()
    resp.headers = {
        "x-ratelimit-limit": "30",
        "x-ratelimit-remaining": "29",
        "x-ratelimit-reset": str(int(time.time()) + 60),
    }
    limiter.observe(resp)
    assert abs(limiter._min_interval - 60.0 / 30) < 1e-9


def test_filter_new_vulns_skips_known_cve() -> None:
    skip = {merge_key("CVE-2024-1"), merge_key("GHSA-aaaa-bbbb-cccc")}
    kept, skipped = filter_new_vulns(
        [
            {"identifier": "CVE-2024-1", "title": "old"},
            {"identifier": "CVE-2024-2", "title": "new"},
            {"identifier": "GHSA-aaaa-bbbb-cccc", "title": "dup"},
        ],
        skip,
    )
    assert skipped == 2
    assert [x["identifier"] for x in kept] == ["CVE-2024-2"]


def test_crawl_repo_advisories_keeps_published_skips_draft(monkeypatch, tmp_env) -> None:
    from app.services.ghsa_service import crawl_repo_advisories

    class DummyResp:
        status_code = 200
        headers = {}

        def json(self):
            return [
                {
                    "ghsa_id": "GHSA-1111-2222-3333",
                    "cve_id": "CVE-2024-5555",
                    "state": "published",
                    "summary": "Halo path traversal",
                    "description": "unauth read",
                    "html_url": "https://github.com/halo-dev/halo/security/advisories/GHSA-1111-2222-3333",
                    "published_at": "2024-02-01T00:00:00Z",
                    "severity": "high",
                },
                {
                    "ghsa_id": "GHSA-aaaa-bbbb-cccc",
                    "cve_id": None,
                    "state": "draft",
                    "summary": "not public",
                    "html_url": "https://github.com/halo-dev/halo/security/advisories/GHSA-aaaa-bbbb-cccc",
                    "published_at": "2024-02-02T00:00:00Z",
                },
            ]

    class DummyCM:
        def __enter__(self):
            return MagicMock()

        def __exit__(self, *args):
            return False

    monkeypatch.setattr("app.services.ghsa_service.http_client", lambda **kwargs: DummyCM())
    monkeypatch.setattr("app.services.ghsa_service.github_get", lambda *args, **kwargs: DummyResp())
    recs, meta = crawl_repo_advisories("halo-dev/halo")
    assert meta["fetched"] == 1
    assert recs[0]["identifier"] == "CVE-2024-5555"
    assert recs[0]["source"] == "ghsa"
    assert recs[0]["fix_status"] == "patched"

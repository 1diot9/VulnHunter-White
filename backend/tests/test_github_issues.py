from __future__ import annotations

from unittest.mock import MagicMock

from app.services.github_issues import (
    crawl_github_issues,
    issue_keys_from_text,
    issue_search_queries,
    issue_to_record,
    parse_github_repo,
    resolve_project_github_repo,
)
from app.services.paths import src_dir


def test_parse_github_repo_from_urls_and_slug():
    assert parse_github_repo("https://github.com/halo-dev/halo.git") == "halo-dev/halo"
    assert parse_github_repo("git@github.com:halo-dev/halo.git") == "halo-dev/halo"
    assert parse_github_repo("halo-dev/halo") == "halo-dev/halo"
    assert parse_github_repo("github.com/halo-dev/halo") == "halo-dev/halo"
    assert parse_github_repo("@halo/cms") is None
    assert parse_github_repo("org.springframework/spring-core") is None
    assert parse_github_repo("halo") is None
    assert parse_github_repo("") is None


def test_resolve_repo_from_identity_and_git_config(tmp_env, project):
    models = tmp_env["models"]
    Session = tmp_env["Session"]
    with Session() as db:
        row = db.get(models.Project, project)
        row.identity = "halo-dev/halo"
        db.commit()
    assert resolve_project_github_repo(project) == "halo-dev/halo"

    with Session() as db:
        row = db.get(models.Project, project)
        row.identity = "halo"
        row.source_url = None
        db.commit()
    git_dir = src_dir(project) / ".git"
    git_dir.mkdir(parents=True, exist_ok=True)
    (git_dir / "config").write_text(
        '[remote "origin"]\n\turl = https://github.com/n8n-io/n8n.git\n',
        encoding="utf-8",
    )
    assert resolve_project_github_repo(project) == "n8n-io/n8n"


def test_issue_to_record_prefers_cve_and_skips_policy():
    rec = issue_to_record(
        {
            "number": 42,
            "title": "Unauth RCE via plugin install",
            "body": "See CVE-2024-9999 for details.",
            "html_url": "https://github.com/halo-dev/halo/issues/42",
            "state": "open",
            "labels": [{"name": "security"}],
            "created_at": "2024-01-01T00:00:00Z",
        },
        repo="halo-dev/halo",
    )
    assert rec is not None
    assert rec["identifier"] == "CVE-2024-9999"
    assert rec["source"] == "github_issue"
    assert rec["fix_status"] == "unpatched"
    assert rec["number"] == 42

    policy = issue_to_record(
        {
            "number": 1,
            "title": "Security policy / how to report",
            "body": "Please use GitHub Security Advisories.",
            "html_url": "https://github.com/halo-dev/halo/issues/1",
            "state": "open",
        },
        repo="halo-dev/halo",
    )
    assert policy is None

    pr = issue_to_record(
        {
            "number": 9,
            "title": "RCE fix",
            "html_url": "https://github.com/halo-dev/halo/pull/9",
            "pull_request": {"url": "https://api.github.com/repos/halo-dev/halo/pulls/9"},
        },
        repo="halo-dev/halo",
    )
    assert pr is None


def test_issue_keys_from_text_and_queries():
    text = "https://github.com/halo-dev/halo/issues/42 and halo-dev/halo#7"
    keys = issue_keys_from_text(text)
    assert "HALO-DEV/HALO#42" in keys
    assert "HALO-DEV/HALO#7" in keys
    queries = issue_search_queries("halo-dev/halo", "2023-01-01")
    assert any("label:security" in q for q in queries)
    assert all("repo:halo-dev/halo" in q for q in queries)
    assert all("is:open" in q for q in queries)


def test_crawl_github_issues_filters_policy_and_dedupes(monkeypatch):
    class DummyCM:
        def __enter__(self):
            return MagicMock()

        def __exit__(self, *args):
            return False

    items = [
        {
            "number": 10,
            "title": "RCE in admin import",
            "body": "unauth file write",
            "html_url": "https://github.com/halo-dev/halo/issues/10",
            "state": "open",
            "labels": [{"name": "security"}],
        },
        {
            "number": 1,
            "title": "Security policy / how to report",
            "body": "use advisories",
            "html_url": "https://github.com/halo-dev/halo/issues/1",
            "state": "open",
            "labels": [{"name": "security"}],
        },
        {
            "number": 10,
            "title": "RCE in admin import",
            "body": "duplicate hit",
            "html_url": "https://github.com/halo-dev/halo/issues/10",
            "state": "open",
            "labels": [{"name": "security"}],
        },
        {
            "number": 11,
            "title": "Closed RCE that was patched",
            "body": "fixed in 1.2",
            "html_url": "https://github.com/halo-dev/halo/issues/11",
            "state": "closed",
            "labels": [{"name": "security"}],
        },
    ]

    monkeypatch.setattr("app.services.github_issues.http_client", lambda **kwargs: DummyCM())
    monkeypatch.setattr(
        "app.services.github_issues._search_issue_pages",
        lambda query, **kwargs: (items, []),
    )
    recs, meta = crawl_github_issues("halo-dev/halo")
    assert meta["repo"] == "halo-dev/halo"
    assert [r["number"] for r in recs] == [10]
    assert recs[0]["source"] == "github_issue"
    assert recs[0]["fix_status"] == "unpatched"

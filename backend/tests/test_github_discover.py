"""Tests for GitHub discovery (GHSA → eligible audit candidates)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import httpx
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services import github_discover as discover


@pytest.fixture(autouse=True)
def _skip_target_kind_llm(monkeypatch):
    """Search tests stay offline; dedicated LLM tests override this stub."""
    monkeypatch.setattr(discover, "_ask_target_kind_llm", lambda **kwargs: None)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _resp(status: int, payload, *, headers: dict | None = None) -> httpx.Response:
    return httpx.Response(
        status,
        json=payload,
        headers=headers or {},
        request=httpx.Request("GET", "https://api.github.com/"),
    )


def test_parse_owner_repo_from_advisory_urls():
    assert (
        discover.parse_owner_repo(
            "https://api.github.com/repos/halo-dev/halo/security-advisories/GHSA-aaaa"
        )
        == "halo-dev/halo"
    )
    assert discover.parse_owner_repo("https://github.com/owner/repo.git") == "owner/repo"
    assert discover.full_name_from_advisory(
        {
            "repository_advisory_url": "https://api.github.com/repos/acme/cms/security-advisories/GHSA-1",
            "source_code_location": "https://github.com/acme/cms",
            "html_url": "https://github.com/advisories/GHSA-1",
        }
    ) == "acme/cms"


def test_blocked_owner_helpers():
    assert discover.is_blocked_owner(full_name="cirosantilli/linux-cheat")
    assert discover.is_blocked_owner(full_name="CiroSantilli/Foo")
    assert discover.is_blocked_owner(owner="cirosantilli")
    assert not discover.is_blocked_owner(full_name="acme/cms")
    assert discover.is_blocked_repo(
        {"full_name": "other/repo", "owner": {"login": "cirosantilli"}},
        "other/repo",
    )
    cutoff = _now() - timedelta(days=1)
    recent = _iso(_now() - timedelta(days=10))
    assert (
        discover._repo_skip_reason(
            {
                "full_name": "cirosantilli/demo",
                "private": False,
                "archived": False,
                "fork": False,
                "stargazers_count": 9000,
                "pushed_at": recent,
            },
            cutoff,
            full_name="cirosantilli/demo",
        )
        == "blocked_owner"
    )


def test_classify_web_vs_library():
    kind, reason = discover.classify_target_kind(
        description="A self-hosted CMS dashboard",
        topics=["cms", "web"],
        full_name="acme/cms",
    )
    assert kind == "web"
    assert "cms" in reason.lower() or "Web" in reason

    kind, reason = discover.classify_target_kind(
        description="JSON parser SDK for Maven",
        topics=["library", "parser"],
        full_name="acme/json-parser",
    )
    assert kind == "library"

    kind, _ = discover.classify_target_kind(
        description="Django library SDK for CMS",
        topics=["django", "library"],
        full_name="acme/mixed",
    )
    assert kind == "mixed"


def test_llm_classify_is_single_round():
    assert discover._LLM_CLASSIFY_MAX_ROUNDS == 1
    assert discover._LLM_CLASSIFY_TIMEOUT <= 20.0


def test_llm_overrides_keyword_classification(monkeypatch):
    monkeypatch.setattr(
        discover,
        "_ask_target_kind_llm",
        lambda **kwargs: '{"target_kind":"library","reason":"公开 API 的 JSON SDK，不是可部署站点"}',
    )
    kind, reason = discover.resolve_discovered_target_kind(
        description="A self-hosted CMS dashboard",
        topics=["cms", "web"],
        full_name="acme/cms-sdk",
    )
    assert kind == "library"
    assert "LLM 判定为「组件库」" in reason
    assert "关键词" in reason


def test_llm_confirms_keyword_classification(monkeypatch):
    monkeypatch.setattr(
        discover,
        "_ask_target_kind_llm",
        lambda **kwargs: "```json\n{\"target_kind\":\"web\",\"reason\":\"自托管 CMS\"}\n```",
    )
    kind, reason = discover.resolve_discovered_target_kind(
        description="A self-hosted CMS dashboard",
        topics=["cms", "web"],
        full_name="acme/cms",
    )
    assert kind == "web"
    assert "LLM 确认为「Web 应用」" in reason


def test_llm_invalid_payload_keeps_keyword(monkeypatch):
    monkeypatch.setattr(discover, "_ask_target_kind_llm", lambda **kwargs: "not json")
    kind, reason = discover.resolve_discovered_target_kind(
        description="JSON parser SDK for Maven",
        topics=["library", "parser"],
        full_name="acme/json-parser",
    )
    assert kind == "library"
    assert reason.startswith("命中组件特征")


def test_llm_unknown_kind_keeps_keyword(monkeypatch):
    monkeypatch.setattr(
        discover,
        "_ask_target_kind_llm",
        lambda **kwargs: '{"target_kind":"desktop","reason":"gui"}',
    )
    kind, _ = discover.resolve_discovered_target_kind(
        description="JSON parser SDK for Maven",
        topics=["library", "parser"],
        full_name="acme/json-parser",
    )
    assert kind == "library"


def test_search_uses_llm_reclassification(tmp_env, monkeypatch):
    recent = _iso(_now() - timedelta(days=10))
    repos = {
        "acme/webapp": {
            "full_name": "acme/webapp",
            "html_url": "https://github.com/acme/webapp",
            "description": "Spring Boot CMS web application",
            "language": "Java",
            "stargazers_count": 2500,
            "pushed_at": recent,
            "private": False,
            "archived": False,
            "fork": False,
            "topics": ["cms", "spring-boot"],
        }
    }
    advisories = [
        {
            "ghsa_id": "GHSA-acme-webapp",
            "html_url": "https://github.com/advisories/GHSA-acme-webapp",
            "repository_advisory_url": "https://api.github.com/repos/acme/webapp/security-advisories/GHSA-x",
            "source_code_location": "https://github.com/acme/webapp",
        }
    ]

    def fake_github_get(url, *, params=None, client=None, limiter=None):
        if "api.github.com/advisories" in url:
            return _resp(200, advisories)
        if url.endswith("/topics"):
            return _resp(200, {"names": repos["acme/webapp"]["topics"]})
        if "/repos/" in url:
            return _resp(200, repos["acme/webapp"])
        return _resp(404, {"message": "Not Found"})

    monkeypatch.setattr(discover, "github_get", fake_github_get)
    monkeypatch.setattr(discover, "_has_github_token", lambda: True)
    monkeypatch.setattr(
        discover,
        "http_client",
        lambda timeout=45.0: MagicMock(__enter__=lambda s: s, __exit__=lambda *a: False),
    )
    monkeypatch.setattr(
        discover,
        "_ask_target_kind_llm",
        lambda **kwargs: '{"target_kind":"mixed","reason":"核心是库，附带管理后台"}',
    )

    result = discover.search_candidates(limit=1)
    assert result["ok"] is True
    assert result["added"] == 1
    item = result["items"][0]
    assert item["full_name"] == "acme/webapp"
    assert item["target_kind"] == "mixed"
    assert "LLM 判定为「混合」" in (item["target_kind_reason"] or "")


def test_search_limit_default_five_and_filters(tmp_env, monkeypatch):
    Session = tmp_env["Session"]
    models = tmp_env["models"]

    recent = _iso(_now() - timedelta(days=10))
    old = _iso(_now() - timedelta(days=400))

    advisories = []
    repos = {
        "acme/webapp": {
            "full_name": "acme/webapp",
            "html_url": "https://github.com/acme/webapp",
            "description": "Spring Boot CMS web application",
            "language": "Java",
            "stargazers_count": 2500,
            "pushed_at": recent,
            "private": False,
            "archived": False,
            "fork": False,
            "topics": ["cms", "spring-boot"],
        },
        "acme/sdk": {
            "full_name": "acme/sdk",
            "html_url": "https://github.com/acme/sdk",
            "description": "HTTP client library SDK",
            "language": "Python",
            "stargazers_count": 1800,
            "pushed_at": recent,
            "private": False,
            "archived": False,
            "fork": False,
            "topics": ["library", "sdk"],
        },
        "acme/old": {
            "full_name": "acme/old",
            "html_url": "https://github.com/acme/old",
            "description": "Old CMS",
            "language": "Java",
            "stargazers_count": 5000,
            "pushed_at": old,
            "private": False,
            "archived": False,
            "fork": False,
            "topics": ["cms"],
        },
        "acme/archived": {
            "full_name": "acme/archived",
            "html_url": "https://github.com/acme/archived",
            "description": "Archived CMS",
            "language": "Java",
            "stargazers_count": 3000,
            "pushed_at": recent,
            "private": False,
            "archived": True,
            "fork": False,
            "topics": ["cms"],
        },
    }
    # Low-star repo should be skipped even if otherwise eligible
    repos["acme/tiny"] = {
        "full_name": "acme/tiny",
        "html_url": "https://github.com/acme/tiny",
        "description": "Self-hosted CMS dashboard tiny",
        "language": "TypeScript",
        "stargazers_count": 999,
        "pushed_at": recent,
        "private": False,
        "archived": False,
        "fork": False,
        "topics": ["cms", "web"],
    }
    # Pad with more eligible repos to verify limit=5
    for i in range(1, 8):
        name = f"acme/app{i}"
        repos[name] = {
            "full_name": name,
            "html_url": f"https://github.com/{name}",
            "description": f"Self-hosted CMS dashboard {i}",
            "language": "TypeScript",
            "stargazers_count": 1000 + i,
            "pushed_at": recent,
            "private": False,
            "archived": False,
            "fork": False,
            "topics": ["cms", "web"],
        }

    for full_name in (
        "acme/webapp",
        "acme/sdk",
        "acme/old",
        "acme/archived",
        "acme/tiny",
        *[f"acme/app{i}" for i in range(1, 8)],
    ):
        advisories.append(
            {
                "ghsa_id": f"GHSA-{full_name.replace('/', '-')}",
                "html_url": f"https://github.com/advisories/GHSA-{full_name.replace('/', '-')}",
                "repository_advisory_url": f"https://api.github.com/repos/{full_name}/security-advisories/GHSA-x",
                "source_code_location": f"https://github.com/{full_name}",
            }
        )

    def fake_github_get(url, *, params=None, client=None, limiter=None):
        if "api.github.com/advisories" in url:
            return _resp(200, advisories)
        if url.endswith("/topics"):
            full = url.split("/repos/")[1].rsplit("/topics", 1)[0]
            return _resp(200, {"names": repos.get(full, {}).get("topics") or []})
        if "/repos/" in url:
            full = url.split("/repos/")[1]
            if full in repos:
                return _resp(200, repos[full])
            return _resp(404, {"message": "Not Found"})
        return _resp(404, {"message": "Not Found"})

    monkeypatch.setattr(discover, "github_get", fake_github_get)
    monkeypatch.setattr(discover, "_has_github_token", lambda: True)
    monkeypatch.setattr(discover, "http_client", lambda timeout=45.0: MagicMock(__enter__=lambda s: s, __exit__=lambda *a: False))

    result = discover.search_candidates(limit=5)
    assert result["ok"] is True
    assert result["added"] == 5
    assert len(result["items"]) == 5

    with Session() as db:
        eligible = (
            db.query(models.GithubCandidate)
            .filter(models.GithubCandidate.status == "eligible")
            .all()
        )
        skipped = (
            db.query(models.GithubCandidate)
            .filter(models.GithubCandidate.status == "skipped")
            .all()
        )
        assert len(eligible) == 5
        skip_names = {r.full_name for r in skipped}
        assert "acme/old" in skip_names
        assert "acme/archived" in skip_names
        assert "acme/tiny" in skip_names
        tiny = next(r for r in skipped if r.full_name == "acme/tiny")
        assert tiny.skip_reason == "low_stars"
        kinds = {r.full_name: r.target_kind for r in eligible}
        # At least one web and one library among the first discovered if they made the cut
        all_rows = db.query(models.GithubCandidate).all()
        by_name = {r.full_name: r for r in all_rows}
        if "acme/webapp" in by_name and by_name["acme/webapp"].status == "eligible":
            assert by_name["acme/webapp"].target_kind == "web"
        if "acme/sdk" in by_name and by_name["acme/sdk"].status == "eligible":
            assert by_name["acme/sdk"].target_kind == "library"


def test_second_search_skips_seen(tmp_env, monkeypatch):
    Session = tmp_env["Session"]
    models = tmp_env["models"]
    recent = _iso(_now() - timedelta(days=5))

    batch1 = [
        {
            "ghsa_id": "GHSA-1",
            "html_url": "https://github.com/advisories/GHSA-1",
            "repository_advisory_url": "https://api.github.com/repos/acme/one/security-advisories/GHSA-1",
        }
    ]
    batch2_extra = [
        {
            "ghsa_id": "GHSA-2",
            "html_url": "https://github.com/advisories/GHSA-2",
            "repository_advisory_url": "https://api.github.com/repos/acme/two/security-advisories/GHSA-2",
        }
    ]
    repos = {
        "acme/one": {
            "full_name": "acme/one",
            "html_url": "https://github.com/acme/one",
            "description": "CMS",
            "language": "Go",
            "stargazers_count": 1200,
            "pushed_at": recent,
            "private": False,
            "archived": False,
            "fork": False,
            "topics": ["cms"],
        },
        "acme/two": {
            "full_name": "acme/two",
            "html_url": "https://github.com/acme/two",
            "description": "parser library",
            "language": "Go",
            "stargazers_count": 3500,
            "pushed_at": recent,
            "private": False,
            "archived": False,
            "fork": False,
            "topics": ["library"],
        },
    }
    state = {"advisories": list(batch1)}

    def fake_github_get(url, *, params=None, client=None, limiter=None):
        if "api.github.com/advisories" in url:
            return _resp(200, state["advisories"])
        if url.endswith("/topics"):
            return _resp(200, {"names": []})
        if "/repos/" in url:
            full = url.split("/repos/")[1]
            return _resp(200, repos[full])
        return _resp(404, {})

    monkeypatch.setattr(discover, "github_get", fake_github_get)
    monkeypatch.setattr(discover, "_has_github_token", lambda: True)
    monkeypatch.setattr(discover, "http_client", lambda timeout=45.0: MagicMock(__enter__=lambda s: s, __exit__=lambda *a: False))

    first = discover.search_candidates(limit=5)
    assert first["added"] == 1
    assert first["items"][0]["full_name"] == "acme/one"

    state["advisories"] = batch1 + batch2_extra
    second = discover.search_candidates(limit=5)
    assert second["added"] == 1
    assert second["items"][0]["full_name"] == "acme/two"

    with Session() as db:
        names = [r.full_name for r in db.query(models.GithubCandidate).all()]
        assert names.count("acme/one") == 1
        assert "acme/two" in names


def test_create_project_marks_imported(tmp_env, monkeypatch):
    Session = tmp_env["Session"]
    models = tmp_env["models"]
    with Session() as db:
        db.add(
            models.GithubCandidate(
                full_name="acme/demo",
                html_url="https://github.com/acme/demo",
                description="CMS",
                target_kind="web",
                status="eligible",
            )
        )
        db.commit()

    monkeypatch.setattr("app.api.projects.start_ingest_and_audit", lambda *a, **k: None)
    monkeypatch.setattr("app.api.projects.ensure_project_dirs", lambda *a, **k: None)

    client = TestClient(app)
    resp = client.post(
        "/api/projects",
        json={"source_type": "github", "source_url": "https://github.com/acme/demo"},
    )
    assert resp.status_code == 200
    pid = resp.json()["id"]

    with Session() as db:
        row = db.query(models.GithubCandidate).filter_by(full_name="acme/demo").one()
        assert row.status == "imported"
        assert row.project_id == pid


def test_list_discoveries_api(tmp_env):
    Session = tmp_env["Session"]
    models = tmp_env["models"]
    with Session() as db:
        db.add(
            models.GithubCandidate(
                full_name="acme/show",
                html_url="https://github.com/acme/show",
                status="eligible",
                target_kind="library",
            )
        )
        db.add(
            models.GithubCandidate(
                full_name="acme/hide",
                html_url="https://github.com/acme/hide",
                status="skipped",
                skip_reason="inactive",
            )
        )
        db.commit()

    client = TestClient(app)
    resp = client.get("/api/discoveries")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 1
    assert body["items"][0]["full_name"] == "acme/show"
    assert body["items"][0]["target_kind"] == "library"


def test_dismiss_candidate_stays_out_of_queue(tmp_env, monkeypatch):
    Session = tmp_env["Session"]
    models = tmp_env["models"]
    recent = _iso(_now() - timedelta(days=5))

    with Session() as db:
        row = models.GithubCandidate(
            full_name="acme/gone",
            html_url="https://github.com/acme/gone",
            description="CMS",
            status="eligible",
            target_kind="web",
            stars=2000,
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        cid = row.id

    client = TestClient(app)
    resp = client.delete(f"/api/discoveries/{cid}")
    assert resp.status_code == 200
    assert resp.json()["status"] == "dismissed"

    listed = client.get("/api/discoveries").json()
    assert listed["total"] == 0
    assert all(i["full_name"] != "acme/gone" for i in listed["items"])

    advisories = [
        {
            "ghsa_id": "GHSA-gone",
            "html_url": "https://github.com/advisories/GHSA-gone",
            "repository_advisory_url": "https://api.github.com/repos/acme/gone/security-advisories/GHSA-gone",
        },
        {
            "ghsa_id": "GHSA-new",
            "html_url": "https://github.com/advisories/GHSA-new",
            "repository_advisory_url": "https://api.github.com/repos/acme/fresh/security-advisories/GHSA-new",
        },
    ]
    repos = {
        "acme/gone": {
            "full_name": "acme/gone",
            "html_url": "https://github.com/acme/gone",
            "description": "CMS",
            "language": "Go",
            "stargazers_count": 5000,
            "pushed_at": recent,
            "private": False,
            "archived": False,
            "fork": False,
            "topics": ["cms"],
        },
        "acme/fresh": {
            "full_name": "acme/fresh",
            "html_url": "https://github.com/acme/fresh",
            "description": "CMS",
            "language": "Go",
            "stargazers_count": 4000,
            "pushed_at": recent,
            "private": False,
            "archived": False,
            "fork": False,
            "topics": ["cms"],
        },
    }

    def fake_github_get(url, *, params=None, client=None, limiter=None):
        if "api.github.com/advisories" in url:
            return _resp(200, advisories)
        if url.endswith("/topics"):
            return _resp(200, {"names": []})
        if "/repos/" in url:
            full = url.split("/repos/")[1]
            return _resp(200, repos[full])
        return _resp(404, {})

    monkeypatch.setattr(discover, "github_get", fake_github_get)
    monkeypatch.setattr(discover, "_has_github_token", lambda: True)
    monkeypatch.setattr(
        discover,
        "http_client",
        lambda timeout=45.0: MagicMock(__enter__=lambda s: s, __exit__=lambda *a: False),
    )

    result = discover.search_candidates(limit=5)
    assert result["ok"] is True
    names = [i["full_name"] for i in result["items"]]
    assert "acme/gone" not in names
    assert "acme/fresh" in names

    with Session() as db:
        gone = db.query(models.GithubCandidate).filter_by(full_name="acme/gone").one()
        assert gone.status == "dismissed"
        assert gone.skip_reason == "dismissed"


def test_clamp_user_prompt_and_fit_query():
    assert discover.clamp_user_prompt("  hello  ") == "hello"
    assert len(discover.clamp_user_prompt("x" * 5000)) == discover.MAX_USER_PROMPT_LEN
    q = discover.fit_search_query("cms language:Java", cutoff_date="2025-09-18")
    assert "cms" in q
    assert "stars:>=" in q
    assert "pushed:>=" in q
    assert "AND" not in q
    assert "-user:cirosantilli" in q.lower()
    stripped = discover.fit_search_query(
        "cms user:cirosantilli", cutoff_date="2025-09-18"
    )
    assert "user:cirosantilli" not in stripped.lower().replace("-user:cirosantilli", "")
    assert "-user:cirosantilli" in stripped.lower()


def test_plan_and_match_prompt_use_llm(monkeypatch):
    monkeypatch.setattr(
        discover,
        "_ask_target_kind_llm",
        lambda **kwargs: '{"queries":["cms language:Java"]}'
        if "queries" in (kwargs.get("system") or "")
        else '{"keep":["acme/cms"]}',
    )
    assert discover.plan_github_search_queries("找 Java CMS") == ["cms language:Java"]
    keep = discover.match_repos_to_prompt(
        "找 Java CMS",
        [
            {"full_name": "acme/cms", "description": "CMS", "language": "Java", "stargazers_count": 2000},
            {"full_name": "acme/sdk", "description": "SDK", "language": "Go", "stargazers_count": 4000},
        ],
        limit=2,
    )
    assert keep == ["acme/cms"]


def test_prompt_search_uses_github_search_not_ghsa(tmp_env, monkeypatch):
    Session = tmp_env["Session"]
    models = tmp_env["models"]
    recent = _iso(_now() - timedelta(days=5))
    repos = {
        "acme/cms": {
            "full_name": "acme/cms",
            "html_url": "https://github.com/acme/cms",
            "description": "Self-hosted CMS dashboard",
            "language": "Java",
            "stargazers_count": 2500,
            "pushed_at": recent,
            "private": False,
            "archived": False,
            "fork": False,
            "topics": ["cms"],
        },
        "acme/sdk": {
            "full_name": "acme/sdk",
            "html_url": "https://github.com/acme/sdk",
            "description": "JSON parser SDK",
            "language": "Go",
            "stargazers_count": 8000,
            "pushed_at": recent,
            "private": False,
            "archived": False,
            "fork": False,
            "topics": ["library"],
        },
    }

    def fake_llm(*, system="", **kwargs):
        if "queries" in system:
            return '{"queries":["cms language:Java"]}'
        if "keep" in system:
            return '{"keep":["acme/cms"]}'
        return '{"target_kind":"web","reason":"CMS"}'

    def fake_github_get(url, *, params=None, client=None, limiter=None):
        if "api.github.com/advisories" in url:
            raise AssertionError("prompt search should not crawl GHSA")
        if "api.github.com/search/repositories" in url:
            return _resp(200, {"total_count": 2, "items": list(repos.values())})
        if url.endswith("/topics"):
            return _resp(200, {"names": []})
        if "/repos/" in url:
            full = url.split("/repos/")[1]
            return _resp(200, repos[full])
        return _resp(404, {})

    monkeypatch.setattr(discover, "_ask_target_kind_llm", fake_llm)
    monkeypatch.setattr(discover, "github_get", fake_github_get)
    monkeypatch.setattr(discover, "_has_github_token", lambda: True)
    monkeypatch.setattr(
        discover,
        "http_client",
        lambda timeout=45.0: MagicMock(__enter__=lambda s: s, __exit__=lambda *a: False),
    )

    result = discover.search_candidates(limit=5, prompt="找 Java 自托管 CMS")
    assert result["ok"] is True
    assert result["prompt"] == "找 Java 自托管 CMS"
    names = [i["full_name"] for i in result["items"]]
    assert names == ["acme/cms"]

    with Session() as db:
        stored = {r.full_name: r.status for r in db.query(models.GithubCandidate).all()}
        assert stored.get("acme/cms") == "eligible"
        assert "acme/sdk" not in stored


def test_ghsa_search_skips_blocked_owner_without_fetch(tmp_env, monkeypatch):
    Session = tmp_env["Session"]
    models = tmp_env["models"]
    recent = _iso(_now() - timedelta(days=5))
    fetched: list[str] = []
    repos = {
        "acme/cms": {
            "full_name": "acme/cms",
            "html_url": "https://github.com/acme/cms",
            "description": "Self-hosted CMS dashboard",
            "language": "Java",
            "stargazers_count": 2500,
            "pushed_at": recent,
            "private": False,
            "archived": False,
            "fork": False,
            "topics": ["cms"],
        }
    }
    advisories = [
        {
            "ghsa_id": "GHSA-blocked",
            "html_url": "https://github.com/advisories/GHSA-blocked",
            "repository_advisory_url": (
                "https://api.github.com/repos/cirosantilli/demo/security-advisories/GHSA-blocked"
            ),
            "source_code_location": "https://github.com/cirosantilli/demo",
        },
        {
            "ghsa_id": "GHSA-ok",
            "html_url": "https://github.com/advisories/GHSA-ok",
            "repository_advisory_url": (
                "https://api.github.com/repos/acme/cms/security-advisories/GHSA-ok"
            ),
            "source_code_location": "https://github.com/acme/cms",
        },
    ]

    def fake_github_get(url, *, params=None, client=None, limiter=None):
        if "api.github.com/advisories" in url:
            return _resp(200, advisories)
        if url.endswith("/topics"):
            return _resp(200, {"names": repos["acme/cms"]["topics"]})
        if "/repos/" in url:
            full = url.split("/repos/")[1]
            fetched.append(full)
            if "cirosantilli" in full.lower():
                raise AssertionError("blocked owner should not be fetched")
            return _resp(200, repos[full])
        return _resp(404, {})

    monkeypatch.setattr(discover, "github_get", fake_github_get)
    monkeypatch.setattr(discover, "_has_github_token", lambda: True)
    monkeypatch.setattr(
        discover,
        "http_client",
        lambda timeout=45.0: MagicMock(__enter__=lambda s: s, __exit__=lambda *a: False),
    )

    result = discover.search_candidates(limit=5)
    assert result["ok"] is True
    names = [i["full_name"] for i in result["items"]]
    assert names == ["acme/cms"]
    assert all("cirosantilli" not in name.lower() for name in names)
    assert fetched == ["acme/cms"]

    with Session() as db:
        blocked = db.query(models.GithubCandidate).filter_by(
            full_name="cirosantilli/demo"
        ).one()
        assert blocked.status == "skipped"
        assert blocked.skip_reason == "blocked_owner"


def test_prompt_search_skips_blocked_owner(tmp_env, monkeypatch):
    Session = tmp_env["Session"]
    models = tmp_env["models"]
    recent = _iso(_now() - timedelta(days=5))
    repos = {
        "cirosantilli/demo": {
            "full_name": "cirosantilli/demo",
            "html_url": "https://github.com/cirosantilli/demo",
            "description": "Self-hosted CMS dashboard",
            "language": "Java",
            "stargazers_count": 9000,
            "pushed_at": recent,
            "private": False,
            "archived": False,
            "fork": False,
            "topics": ["cms"],
            "owner": {"login": "cirosantilli"},
        },
        "acme/cms": {
            "full_name": "acme/cms",
            "html_url": "https://github.com/acme/cms",
            "description": "Self-hosted CMS dashboard",
            "language": "Java",
            "stargazers_count": 2500,
            "pushed_at": recent,
            "private": False,
            "archived": False,
            "fork": False,
            "topics": ["cms"],
        },
    }

    def fake_llm(*, system="", **kwargs):
        if "queries" in system:
            return '{"queries":["cms language:Java"]}'
        if "keep" in system:
            return '{"keep":["cirosantilli/demo","acme/cms"]}'
        return '{"target_kind":"web","reason":"CMS"}'

    def fake_github_get(url, *, params=None, client=None, limiter=None):
        if "api.github.com/search/repositories" in url:
            q = str((params or {}).get("q") or "")
            assert "-user:cirosantilli" in q.lower()
            return _resp(200, {"total_count": 2, "items": list(repos.values())})
        if url.endswith("/topics"):
            return _resp(200, {"names": []})
        if "/repos/" in url:
            full = url.split("/repos/")[1]
            if "cirosantilli" in full.lower():
                raise AssertionError("blocked owner should not be fetched")
            return _resp(200, repos[full])
        return _resp(404, {})

    monkeypatch.setattr(discover, "_ask_target_kind_llm", fake_llm)
    monkeypatch.setattr(discover, "github_get", fake_github_get)
    monkeypatch.setattr(discover, "_has_github_token", lambda: True)
    monkeypatch.setattr(
        discover,
        "http_client",
        lambda timeout=45.0: MagicMock(__enter__=lambda s: s, __exit__=lambda *a: False),
    )

    result = discover.search_candidates(limit=5, prompt="找 Java CMS")
    assert result["ok"] is True
    names = [i["full_name"] for i in result["items"]]
    assert names == ["acme/cms"]

    with Session() as db:
        stored = {r.full_name: r.status for r in db.query(models.GithubCandidate).all()}
        assert stored.get("acme/cms") == "eligible"
        assert stored.get("cirosantilli/demo") == "skipped"


def test_list_hides_blocked_owner(tmp_env):
    Session = tmp_env["Session"]
    models = tmp_env["models"]
    with Session() as db:
        db.add(
            models.GithubCandidate(
                full_name="CiroSantilli/old-hit",
                html_url="https://github.com/CiroSantilli/old-hit",
                status="eligible",
                target_kind="web",
            )
        )
        db.add(
            models.GithubCandidate(
                full_name="acme/cms",
                html_url="https://github.com/acme/cms",
                status="eligible",
                target_kind="web",
            )
        )
        db.commit()

    client = TestClient(app)
    listed = client.get("/api/discoveries").json()
    names = [i["full_name"] for i in listed["items"]]
    assert names == ["acme/cms"]
    assert listed["total"] == 1


def test_search_api_passes_prompt(tmp_env, monkeypatch):
    monkeypatch.setattr(
        discover,
        "search_candidates",
        lambda **kwargs: {
            "ok": True,
            "added": 0,
            "items": [],
            "scanned_advisories": 0,
            "scanned_repos": 0,
            "skipped_seen": 0,
            "pages": 0,
            "authenticated": True,
            "warning": None,
            "limit": kwargs.get("limit") or 5,
            "prompt": kwargs.get("prompt"),
        },
    )
    client = TestClient(app)
    resp = client.post("/api/discoveries/search", json={"limit": 3, "prompt": "  PHP CMS  "})
    assert resp.status_code == 200
    assert resp.json()["prompt"] == "PHP CMS"


def test_dismiss_all_pending_keeps_imported(tmp_env):
    Session = tmp_env["Session"]
    models = tmp_env["models"]
    with Session() as db:
        db.add(
            models.GithubCandidate(
                full_name="acme/pending",
                html_url="https://github.com/acme/pending",
                status="eligible",
                target_kind="web",
            )
        )
        db.add(
            models.GithubCandidate(
                full_name="acme/done",
                html_url="https://github.com/acme/done",
                status="imported",
                target_kind="web",
                project_id=11,
            )
        )
        db.commit()

    client = TestClient(app)
    resp = client.post("/api/discoveries/dismiss-all")
    assert resp.status_code == 200
    assert resp.json()["dismissed"] == 1

    listed = client.get("/api/discoveries").json()
    names = [i["full_name"] for i in listed["items"]]
    assert "acme/pending" not in names
    assert "acme/done" in names

    with Session() as db:
        pending = db.query(models.GithubCandidate).filter_by(full_name="acme/pending").one()
        done = db.query(models.GithubCandidate).filter_by(full_name="acme/done").one()
        assert pending.status == "dismissed"
        assert done.status == "imported"
        assert done.project_id == 11


def test_search_timeout_sec_grows_after_five():
    assert discover.search_timeout_sec(1) == 600
    assert discover.search_timeout_sec(5) == 600
    assert discover.search_timeout_sec(6) == 660
    assert discover.search_timeout_sec(20) == 1500
    msg = discover.search_timeout_message(8)
    assert "780" in msg
    assert "减少" in msg


def test_demo_skip_reason_name_topic_and_description():
    cutoff = _now() - timedelta(days=365)
    recent = _iso(_now() - timedelta(days=10))
    demo_repo = {
        "full_name": "acme/cms-demo",
        "private": False,
        "archived": False,
        "fork": False,
        "stargazers_count": 4000,
        "pushed_at": recent,
        "description": "A self-hosted CMS",
        "topics": ["cms"],
    }
    assert discover.demo_skip_reason(demo_repo, full_name="acme/cms-demo") == "demo"
    assert discover._repo_skip_reason(demo_repo, cutoff, full_name="acme/cms-demo") == "demo"

    topic_repo = {**demo_repo, "full_name": "acme/cms", "topics": ["tutorial"]}
    assert discover.demo_skip_reason(topic_repo, full_name="acme/cms") == "demo"

    desc_repo = {
        **demo_repo,
        "full_name": "acme/cms",
        "topics": ["cms"],
        "description": "Official demo of our CMS",
    }
    assert discover.demo_skip_reason(desc_repo, full_name="acme/cms") == "demo"

    real = {
        **demo_repo,
        "full_name": "acme/cms",
        "topics": ["cms"],
        "description": "Self-hosted CMS dashboard",
    }
    assert discover.demo_skip_reason(real, full_name="acme/cms") is None
    assert discover._repo_skip_reason(real, cutoff, full_name="acme/cms") is None


def test_search_skips_demo_repos(tmp_env, monkeypatch):
    Session = tmp_env["Session"]
    models = tmp_env["models"]
    recent = _iso(_now() - timedelta(days=5))
    repos = {
        "acme/cms-demo": {
            "full_name": "acme/cms-demo",
            "html_url": "https://github.com/acme/cms-demo",
            "description": "Official demo of the CMS",
            "language": "Java",
            "stargazers_count": 8000,
            "pushed_at": recent,
            "private": False,
            "archived": False,
            "fork": False,
            "topics": ["cms", "demo"],
        },
        "acme/cms": {
            "full_name": "acme/cms",
            "html_url": "https://github.com/acme/cms",
            "description": "Self-hosted CMS dashboard",
            "language": "Java",
            "stargazers_count": 2500,
            "pushed_at": recent,
            "private": False,
            "archived": False,
            "fork": False,
            "topics": ["cms"],
        },
    }
    advisories = [
        {
            "ghsa_id": "GHSA-demo",
            "html_url": "https://github.com/advisories/GHSA-demo",
            "repository_advisory_url": (
                "https://api.github.com/repos/acme/cms-demo/security-advisories/GHSA-demo"
            ),
            "source_code_location": "https://github.com/acme/cms-demo",
        },
        {
            "ghsa_id": "GHSA-ok",
            "html_url": "https://github.com/advisories/GHSA-ok",
            "repository_advisory_url": (
                "https://api.github.com/repos/acme/cms/security-advisories/GHSA-ok"
            ),
            "source_code_location": "https://github.com/acme/cms",
        },
    ]

    def fake_github_get(url, *, params=None, client=None, limiter=None):
        if "api.github.com/advisories" in url:
            return _resp(200, advisories)
        if url.endswith("/topics"):
            full = url.split("/repos/")[1].split("/topics")[0]
            return _resp(200, {"names": repos[full]["topics"]})
        if "/repos/" in url:
            full = url.split("/repos/")[1]
            return _resp(200, repos[full])
        return _resp(404, {})

    monkeypatch.setattr(discover, "github_get", fake_github_get)
    monkeypatch.setattr(discover, "_has_github_token", lambda: True)
    monkeypatch.setattr(
        discover,
        "http_client",
        lambda timeout=45.0: MagicMock(__enter__=lambda s: s, __exit__=lambda *a: False),
    )

    result = discover.search_candidates(limit=5)
    assert result["ok"] is True
    names = [i["full_name"] for i in result["items"]]
    assert names == ["acme/cms"]

    with Session() as db:
        skipped = db.query(models.GithubCandidate).filter_by(full_name="acme/cms-demo").one()
        assert skipped.status == "skipped"
        assert skipped.skip_reason == "demo"


def test_prompt_search_skips_demo_repo(tmp_env, monkeypatch):
    Session = tmp_env["Session"]
    models = tmp_env["models"]
    recent = _iso(_now() - timedelta(days=5))
    repos = {
        "acme/cms-example": {
            "full_name": "acme/cms-example",
            "html_url": "https://github.com/acme/cms-example",
            "description": "CMS tutorial project",
            "language": "Java",
            "stargazers_count": 5000,
            "pushed_at": recent,
            "private": False,
            "archived": False,
            "fork": False,
            "topics": ["cms", "tutorial"],
        },
        "acme/cms": {
            "full_name": "acme/cms",
            "html_url": "https://github.com/acme/cms",
            "description": "Self-hosted CMS dashboard",
            "language": "Java",
            "stargazers_count": 2500,
            "pushed_at": recent,
            "private": False,
            "archived": False,
            "fork": False,
            "topics": ["cms"],
        },
    }

    def fake_llm(*, system="", **kwargs):
        if "queries" in system:
            return '{"queries":["cms language:Java"]}'
        if "keep" in system:
            return '{"keep":["acme/cms-example","acme/cms"]}'
        return '{"target_kind":"web","reason":"CMS"}'

    def fake_github_get(url, *, params=None, client=None, limiter=None):
        if "api.github.com/search/repositories" in url:
            return _resp(200, {"total_count": 2, "items": list(repos.values())})
        if url.endswith("/topics"):
            return _resp(200, {"names": []})
        if "/repos/" in url:
            full = url.split("/repos/")[1]
            return _resp(200, repos[full])
        return _resp(404, {})

    monkeypatch.setattr(discover, "_ask_target_kind_llm", fake_llm)
    monkeypatch.setattr(discover, "github_get", fake_github_get)
    monkeypatch.setattr(discover, "_has_github_token", lambda: True)
    monkeypatch.setattr(
        discover,
        "http_client",
        lambda timeout=45.0: MagicMock(__enter__=lambda s: s, __exit__=lambda *a: False),
    )

    result = discover.search_candidates(limit=5, prompt="找 Java CMS")
    assert result["ok"] is True
    names = [i["full_name"] for i in result["items"]]
    assert names == ["acme/cms"]

    with Session() as db:
        stored = {r.full_name: r.status for r in db.query(models.GithubCandidate).all()}
        assert stored.get("acme/cms") == "eligible"
        assert stored.get("acme/cms-example") == "skipped"


def test_search_timeout_keeps_partial_and_api_returns_body(tmp_env, monkeypatch):
    Session = tmp_env["Session"]
    models = tmp_env["models"]
    recent = _iso(_now() - timedelta(days=5))
    added = {"n": 0}
    real_store = discover._store_eligible_from_repo

    def store(*args, **kwargs):
        row, status = real_store(*args, **kwargs)
        if status == "eligible":
            added["n"] += 1
        return row, status

    class AfterOne:
        limit = 8
        budget_sec = 780

        def expired(self):
            return added["n"] >= 1

        def timeout_error(self):
            return discover.search_timeout_message(8, budget_sec=780)

    repos = {
        "acme/one": {
            "full_name": "acme/one",
            "html_url": "https://github.com/acme/one",
            "description": "Self-hosted CMS dashboard",
            "language": "Java",
            "stargazers_count": 2500,
            "pushed_at": recent,
            "private": False,
            "archived": False,
            "fork": False,
            "topics": ["cms"],
        },
        "acme/two": {
            "full_name": "acme/two",
            "html_url": "https://github.com/acme/two",
            "description": "Self-hosted CMS dashboard",
            "language": "Java",
            "stargazers_count": 2600,
            "pushed_at": recent,
            "private": False,
            "archived": False,
            "fork": False,
            "topics": ["cms"],
        },
    }
    advisories = [
        {
            "ghsa_id": "GHSA-one",
            "html_url": "https://github.com/advisories/GHSA-one",
            "repository_advisory_url": (
                "https://api.github.com/repos/acme/one/security-advisories/GHSA-one"
            ),
            "source_code_location": "https://github.com/acme/one",
        },
        {
            "ghsa_id": "GHSA-two",
            "html_url": "https://github.com/advisories/GHSA-two",
            "repository_advisory_url": (
                "https://api.github.com/repos/acme/two/security-advisories/GHSA-two"
            ),
            "source_code_location": "https://github.com/acme/two",
        },
    ]

    def fake_github_get(url, *, params=None, client=None, limiter=None):
        if "api.github.com/advisories" in url:
            return _resp(200, advisories)
        if url.endswith("/topics"):
            full = url.split("/repos/")[1].split("/topics")[0]
            return _resp(200, {"names": repos[full]["topics"]})
        if "/repos/" in url:
            full = url.split("/repos/")[1]
            return _resp(200, repos[full])
        return _resp(404, {})

    monkeypatch.setattr(discover, "_store_eligible_from_repo", store)
    monkeypatch.setattr(discover, "_make_search_deadline", lambda limit: AfterOne())
    monkeypatch.setattr(discover, "github_get", fake_github_get)
    monkeypatch.setattr(discover, "_has_github_token", lambda: True)
    monkeypatch.setattr(
        discover,
        "http_client",
        lambda timeout=45.0: MagicMock(__enter__=lambda s: s, __exit__=lambda *a: False),
    )

    result = discover.search_candidates(limit=8)
    assert result["ok"] is False
    assert result["timed_out"] is True
    assert result["added"] == 1
    assert "减少" in (result["error"] or "")
    names = [i["full_name"] for i in result["items"]]
    assert names == ["acme/one"]

    with Session() as db:
        stored = {r.full_name: r.status for r in db.query(models.GithubCandidate).all()}
        assert stored.get("acme/one") == "eligible"
        assert "acme/two" not in stored

    client = TestClient(app)
    resp = client.post("/api/discoveries/search", json={"limit": 8})
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is False
    assert body["timed_out"] is True
    assert "减少" in (body["error"] or "")

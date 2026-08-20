from __future__ import annotations

import httpx

from app.services import fingerprint_search as fs
from app.tools import ToolContext, registry


def _ctx(project, role: str) -> ToolContext:
    return ToolContext(project_id=project, role=role, phase=role)


class _FakeResp:
    def __init__(self, *, text="", json_data=None, status_code=200):
        self.text = text
        self.content = text.encode("utf-8")
        self.status_code = status_code
        self._json = json_data

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("error", request=None, response=None)

    def json(self):
        if self._json is None:
            raise ValueError("not json")
        return self._json


class _RouteClient:
    def __init__(self, routes: dict[str, object]):
        self.routes = routes
        self.urls: list[str] = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def get(self, url, *args, **kwargs):
        target = str(url)
        self.urls.append(target)
        for needle, payload in self.routes.items():
            if needle in target:
                if isinstance(payload, Exception):
                    raise payload
                return payload
        return _FakeResp(text="")


def test_web_search_falls_back_to_nvd_when_ddg_times_out(monkeypatch, project):
    fs._nvd_cache.clear()
    nvd = _FakeResp(
        json_data={
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2021-46089",
                        "descriptions": [
                            {"lang": "en", "value": "JeecgBoot SQL injection."},
                        ],
                    }
                }
            ]
        }
    )
    client = _RouteClient(
        {
            "duckduckgo.com": httpx.ConnectTimeout("timed out"),
            "nvd.nist.gov": nvd,
        }
    )
    monkeypatch.setattr(fs, "http_client", lambda timeout=None: client)
    out = registry.dispatch(_ctx(project, "recon_old_vuln_ghsa"), "WebSearch", {"query": "jeecgboot CVE"})
    assert out["ok"] is True
    titles = [item["title"] for item in out.get("results") or []]
    assert "CVE-2021-46089" in titles
    assert any("nvd.nist.gov/vuln/detail/CVE-2021-46089" in (item.get("url") or "") for item in out["results"])
    assert any("duckduckgo.com" in url for url in client.urls)
    assert not any("html.duckduckgo.com" in url for url in client.urls)
    assert any("nvd.nist.gov" in url for url in client.urls)


def test_web_search_parses_bing_when_ddg_and_nvd_fail(monkeypatch, project):
    fs._nvd_cache.clear()
    bing_html = """
    <ol id="b_results">
      <li class="b_algo"><h2><a href="https://example.com/fofa">App FOFA title=demo</a></h2>
      <div class="b_caption">icon_hash="-123" body="/demo/"</div></li>
    </ol>
    """
    client = _RouteClient(
        {
            "duckduckgo.com": httpx.ConnectTimeout("timed out"),
            "nvd.nist.gov": httpx.ConnectTimeout("timed out"),
            "bing.com": _FakeResp(text=bing_html),
        }
    )
    monkeypatch.setattr(fs, "http_client", lambda timeout=None: client)
    out = fs.web_search_results("某OA FOFA")
    assert out["ok"] is True
    assert out["results"]
    assert out["results"][0]["url"] == "https://example.com/fofa"
    assert "FOFA" in out["results"][0]["title"]


def test_web_search_missing_query():
    out = fs.web_search_results("  ")
    assert out["ok"] is False
    assert "query" in (out.get("error") or "")


def test_pick_clauses_keeps_title_and_body():
    picked = fs._pick_clauses(
        [
            'title="XXOA"',
            'app="XXOA"',
            'product="XXOA"',
            'body="xxoa-login-wrap"',
            'icon_hash="-123"',
        ]
    )
    assert picked == ['title="XXOA"', 'body="xxoa-login-wrap"']


def test_pick_clauses_skips_duplicate_app_when_no_body():
    picked = fs._pick_clauses(
        [
            'title="XXOA办公系统"',
            'app="XXOA办公系统"',
            'icon_hash="-123"',
        ]
    )
    assert picked[0] == 'title="XXOA办公系统"'
    assert 'app="XXOA办公系统"' not in picked

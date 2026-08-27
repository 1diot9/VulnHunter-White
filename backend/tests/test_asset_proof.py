from __future__ import annotations

from app.services.asset_proof import (
    _body_markers,
    collect_lab_fingerprints,
    collect_source_fingerprints,
    ensure_project_fingerprints,
    fofa_icon_hash,
    fofa_rewrite_candidates,
    fofa_search_variants,
    load_project_fingerprints,
    maybe_enrich_asset_proof,
    murmurhash3_32,
    suggest_queries,
)
from app.services.lab import save_env
from app.services.paths import vuln_dir
from app.tools import ToolContext, registry


def _ctx(project_id: int, role: str) -> ToolContext:
    return ToolContext(project_id=project_id, role=role, phase=role)


SEVERITY_FACTORS = {
    "impact": "sensitive_data_or_privilege",
    "exploit_complexity": "single_request",
    "defense_status": "none",
    "submission_tier": "cve_candidate",
    "submission_reason": "未认证可达且可造成敏感数据/权限影响，有 CVE 价值",
}


def test_murmurhash3_32_empty():
    assert murmurhash3_32(b"") == 0


def test_parse_fingerprint_clauses_from_snippets():
    from app.services.fingerprint_search import parse_fingerprint_clauses, search_app_fingerprints

    text = 'FOFA: title="用友U8" && icon_hash="-247388890" body="/u8g/"'
    clauses = parse_fingerprint_clauses(text)
    assert any(c.startswith('title=') for c in clauses)
    assert any("icon_hash=" in c for c in clauses)
    out = search_app_fingerprints("login")
    assert out["ok"] is False


def test_suggest_queries_skips_generic_title():
    fofa, x = suggest_queries(title="登录", body_markers=["Copyright 2020 XX科技"], icon_hash="-123")
    assert "登录" not in fofa
    assert 'body="Copyright 2020 XX科技"' in fofa
    assert "||" not in fofa
    assert 'body="Copyright 2020 XX科技"' in x


def test_suggest_queries_keeps_title_and_body_without_hash():
    fofa, x = suggest_queries(
        title="XXOA办公系统",
        body_markers=["xxoa-login-wrap"],
        static_paths=["/static/xxoa-app.css"],
        icon_hash="-123",
    )
    assert 'title="XXOA办公系统"' in fofa
    assert 'body="xxoa-login-wrap"' in fofa
    assert "icon_hash" not in fofa
    assert fofa.count("&&") == 1
    assert 'body="xxoa-login-wrap"' in x


def test_collect_lab_fingerprints_from_env(tmp_env, project, monkeypatch):
    save_env(
        project,
        {"accepted": True, "status": "running", "target_url": "http://127.0.0.1:18080"},
    )
    html = (
        b"<html><head><title>XXOA\xe5\x8a\x9e\xe5\x85\xac\xe7\xb3\xbb\xe7\xbb\x9f</title>"
        b'<link rel="icon" href="/favicon.ico">'
        b'<link rel="stylesheet" href="/static/xxoa-app.css"></head>'
        b"<body>Copyright 2020 XX\xe7\xa7\x91\xe6\x8a\x80</body></html>"
    )
    favicon = b"\x00\x00\x01\x00" + b"icon-bytes-here"

    def fake_fetch(url: str, *, timeout: float = 8.0):
        if url.endswith("favicon.ico"):
            return 200, {"content-type": "image/x-icon"}, favicon, url
        return 200, {"content-type": "text/html; charset=utf-8", "server": "XXOA-Gateway"}, html, url

    monkeypatch.setattr("app.services.asset_proof.fetch_bytes", fake_fetch)
    out = collect_lab_fingerprints(project)
    assert out["ok"] is True, out
    assert out["title"] == "XXOA办公系统"
    assert out["header"] == "XXOA-Gateway"
    assert out["icon_hash"] == fofa_icon_hash(favicon)
    assert "xxoa-app.css" in " ".join(out.get("static_paths") or []) or "Copyright" in " ".join(
        out.get("body_markers") or []
    )
    assert 'title="XXOA办公系统"' in out["fofa"]
    assert "body=" in out["fofa"]
    assert "icon_hash=" not in out["fofa"]
    assert "||" not in out["fofa"]
    assert 'title="XXOA办公系统"' in out["x"] or "body=" in out["x"]


def test_collect_lab_fingerprints_without_target(tmp_env, project):
    out = collect_lab_fingerprints(project)
    assert out["ok"] is False
    assert "漏洞环境" in out["error"]


def test_collect_tool_apply_writes_report(tmp_env, project, monkeypatch):
    save_env(
        project,
        {"accepted": True, "status": "running", "target_url": "http://127.0.0.1:18080"},
    )
    payload = {
        "title": "登录处 SQL 注入",
        "vuln_type": "sqli",
        "cwe": "CWE-89",
        "file_path": "app/Main.java",
        "line_no": 1,
        "source_sink": "login -> query",
        "auth_premise": "未授权",
        "http_request": "GET /login?id=1 HTTP/1.1\nHost: x\n",
        "poc_code": "print('poc')\n",
        "expected_evidence": "error based",
        "config_premise": "default",
    }
    submitted = registry.dispatch(_ctx(project, "worker"), "SubmitVuln", payload)
    vuln_id = submitted["vuln_id"]

    def fake_fetch(url: str, *, timeout: float = 8.0):
        html = b"<html><head><title>DemoCMS</title></head><body>Copyright DemoCMS</body></html>"
        return 200, {"content-type": "text/html"}, html, url

    monkeypatch.setattr("app.services.asset_proof.fetch_bytes", fake_fetch)
    out = registry.dispatch(
        ToolContext(project_id=project, role="reviewer", phase="reviewer", vuln_id=vuln_id),
        "CollectLabFingerprints",
        {"apply": True},
    )
    assert out["ok"] is True, out
    assert out["applied"] is True
    report = (vuln_dir(project, vuln_id) / "report.md").read_text(encoding="utf-8")
    section = report.split("## 互联网资产证明", 1)[1].split("## 漏洞技术细节", 1)[0]
    assert "title=" in section or "body=" in section
    assert "待根据应用标题" not in section


def test_confirm_auto_fills_placeholder_from_lab(tmp_env, project, monkeypatch):
    save_env(
        project,
        {"accepted": True, "status": "running", "target_url": "http://127.0.0.1:18080"},
    )
    payload = {
        "title": "登录处 SQL 注入",
        "vuln_type": "sqli",
        "cwe": "CWE-89",
        "file_path": "app/Main.java",
        "line_no": 1,
        "source_sink": "login -> query",
        "auth_premise": "未授权",
        "http_request": "GET /login?id=1 HTTP/1.1\nHost: x\n",
        "poc_code": "print('poc')\n",
        "expected_evidence": "error based",
        "config_premise": "default",
    }
    submitted = registry.dispatch(_ctx(project, "worker"), "SubmitVuln", payload)
    vuln_id = submitted["vuln_id"]

    def fake_fetch(url: str, *, timeout: float = 8.0):
        html = b"<html><head><title>Acme OA</title></head><body>Copyright Acme</body></html>"
        return 200, {"content-type": "text/html"}, html, url

    monkeypatch.setattr("app.services.asset_proof.fetch_bytes", fake_fetch)
    conf = registry.dispatch(
        _ctx(project, "reviewer"),
        "ConfirmVuln",
        {
            "vuln_id": vuln_id,
            "evidence_level": "static_only",
            "attack_surface": "frontend",
            **SEVERITY_FACTORS,
        },
    )
    assert conf["ok"] is True
    assert conf["asset_proof_updated"] is True
    assert "title=" in conf["fofa_fingerprint"] or "body=" in conf["fofa_fingerprint"]
    report = (vuln_dir(project, vuln_id) / "report.md").read_text(encoding="utf-8")
    assert "title=" in report or "body=" in report
    assert "## 审核标注" in report
    assert report.index("## 互联网资产证明") < report.index("## 审核标注")


def test_confirm_uses_explicit_fingerprints(tmp_env, project):
    payload = {
        "title": "登录处 SQL 注入",
        "vuln_type": "sqli",
        "cwe": "CWE-89",
        "file_path": "app/Main.java",
        "line_no": 1,
        "source_sink": "login -> query",
        "auth_premise": "未授权",
        "http_request": "GET /login?id=1 HTTP/1.1\nHost: x\n",
        "poc_code": "print('poc')\n",
        "expected_evidence": "error based",
        "config_premise": "default",
    }
    submitted = registry.dispatch(_ctx(project, "worker"), "SubmitVuln", payload)
    vuln_id = submitted["vuln_id"]
    conf = registry.dispatch(
        _ctx(project, "reviewer"),
        "ConfirmVuln",
        {
            "vuln_id": vuln_id,
            "evidence_level": "static_only",
            "attack_surface": "frontend",
            "fofa_fingerprint": 'title="HandWritten" && body="/static/app.css"',
            "x_fingerprint": 'app="HandWritten" && title="HandWritten"',
            **SEVERITY_FACTORS,
        },
    )
    assert conf["ok"] is True
    assert conf["asset_proof_updated"] is True
    report = (vuln_dir(project, vuln_id) / "report.md").read_text(encoding="utf-8")
    assert 'title="HandWritten"' in report
    assert 'app="HandWritten"' in report


def test_confirm_rejects_or_fingerprint(tmp_env, project):
    payload = {
        "title": "登录处 SQL 注入",
        "vuln_type": "sqli",
        "cwe": "CWE-89",
        "file_path": "app/Main.java",
        "line_no": 1,
        "source_sink": "login -> query",
        "auth_premise": "未授权",
        "http_request": "GET /login?id=1 HTTP/1.1\nHost: x\n",
        "poc_code": "print('poc')\n",
        "expected_evidence": "error based",
        "config_premise": "default",
    }
    submitted = registry.dispatch(_ctx(project, "worker"), "SubmitVuln", payload)
    vuln_id = submitted["vuln_id"]
    conf = registry.dispatch(
        _ctx(project, "reviewer"),
        "ConfirmVuln",
        {
            "vuln_id": vuln_id,
            "evidence_level": "static_only",
            "attack_surface": "frontend",
            "fofa_fingerprint": 'title="A" || title="B"',
            **SEVERITY_FACTORS,
        },
    )
    assert conf["ok"] is False
    assert "或" in conf["error"] or "||" in conf["error"]


def test_maybe_enrich_skips_when_queries_already_good(tmp_env, project, monkeypatch):
    save_env(
        project,
        {"accepted": True, "status": "running", "target_url": "http://127.0.0.1:18080"},
    )
    payload = {
        "title": "登录处 SQL 注入",
        "vuln_type": "sqli",
        "cwe": "CWE-89",
        "file_path": "app/Main.java",
        "line_no": 1,
        "source_sink": "login -> query",
        "auth_premise": "未授权",
        "http_request": "GET /login?id=1 HTTP/1.1\nHost: x\n",
        "poc_code": "print('poc')\n",
        "expected_evidence": "error based",
        "config_premise": "default",
        "fofa_fingerprint": 'title="Kept" && body="stable"',
        "x_fingerprint": 'app="Kept" && title="Kept"',
    }
    submitted = registry.dispatch(_ctx(project, "worker"), "SubmitVuln", payload)
    vuln_id = submitted["vuln_id"]

    def boom(url: str, *, timeout: float = 8.0):
        raise AssertionError("should not fetch when queries already exist")

    monkeypatch.setattr("app.services.asset_proof.fetch_bytes", boom)
    out = maybe_enrich_asset_proof(project, vuln_id)
    assert out["ok"] is True, out
    assert out["updated"] is False
    assert out["fofa"] == 'title="Kept" && body="stable"'


def test_collect_source_fingerprints_from_templates(tmp_env, project):
    from app.services.paths import src_dir

    src = src_dir(project)
    (src / "templates").mkdir(parents=True, exist_ok=True)
    (src / "templates" / "login.html").write_text(
        '<html><head><title>XXOA办公系统</title>'
        '<link rel="stylesheet" href="/static/xxoa-app.css"></head>'
        "<body>Copyright 2020 XX科技</body></html>",
        encoding="utf-8",
    )
    favicon = b"\x00\x00\x01\x00" + b"icon-bytes-here"
    (src / "favicon.ico").write_bytes(favicon)
    out = collect_source_fingerprints(project)
    assert out["ok"] is True, out
    assert out["title"] == "XXOA办公系统"
    assert out["icon_hash"] == fofa_icon_hash(favicon)
    assert 'title="XXOA办公系统"' in out["fofa"]
    assert "body=" in out["fofa"]
    assert "icon_hash=" not in out["fofa"]


def test_ensure_project_fingerprints_runs_once(tmp_env, project, monkeypatch):
    from app.services.paths import src_dir

    src = src_dir(project)
    (src / "index.html").write_text(
        "<html><head><title>DemoCMS</title></head><body>Copyright DemoCMS</body></html>",
        encoding="utf-8",
    )
    hits = {"n": 0}

    def fake_search(query: str):
        hits["n"] += 1
        return {
            "ok": True,
            "query": query,
            "fofa": 'title="DemoCMS" && icon_hash="-111"',
            "x": 'title="DemoCMS"',
            "clauses": ['title="DemoCMS"', 'icon_hash="-111"'],
        }

    monkeypatch.setattr("app.services.fingerprint_search.search_app_fingerprints", fake_search)
    first = ensure_project_fingerprints(project)
    second = ensure_project_fingerprints(project)
    assert first["collected"] is True
    assert first["fofa"] == second["fofa"]
    assert 'title="DemoCMS"' in first["fofa"] or "body=" in first["fofa"]
    assert hits["n"] == 1
    cached = load_project_fingerprints(project)
    assert cached is not None
    assert cached["fofa"] == first["fofa"]


def test_second_vuln_reuses_project_fingerprint(tmp_env, project, monkeypatch):
    monkeypatch.setattr(
        "app.services.fingerprint_search.search_app_fingerprints",
        lambda query: {"ok": False, "error": "skip", "query": query},
    )
    first = registry.dispatch(
        _ctx(project, "worker"),
        "SubmitVuln",
        {
            "title": "登录处 SQL 注入",
            "vuln_type": "sqli",
            "cwe": "CWE-89",
            "file_path": "app/Main.java",
            "line_no": 1,
            "source_sink": "login -> query",
            "auth_premise": "未授权",
            "http_request": "GET /login?id=1 HTTP/1.1\nHost: x\n",
            "poc_code": "print('poc')\n",
            "expected_evidence": "error based",
            "config_premise": "default",
            "fofa_fingerprint": 'title="SharedApp" && body="/static/app.css"',
            "x_fingerprint": 'app="SharedApp" && title="SharedApp"',
        },
    )
    assert first["ok"] is True
    cache = load_project_fingerprints(project)
    assert cache is not None
    assert 'title="SharedApp"' in cache["fofa"]
    second = registry.dispatch(
        _ctx(project, "worker"),
        "SubmitVuln",
        {
            "title": "列表越权",
            "vuln_type": "idor",
            "cwe": "CWE-639",
            "file_path": "app/Main.java",
            "line_no": 2,
            "source_sink": "id -> row",
            "auth_premise": "未授权",
            "http_request": "GET /item?id=1 HTTP/1.1\nHost: x\n",
            "poc_code": "print('poc')\n",
            "expected_evidence": "other user data",
            "config_premise": "default",
        },
    )
    assert second["ok"] is True
    report = (vuln_dir(project, second["vuln_id"]) / "report.md").read_text(encoding="utf-8")
    assert 'title="SharedApp"' in report
    assert "待根据应用标题" not in report.split("## 互联网资产证明", 1)[1].split("##", 1)[0]


def test_body_markers_extract_default_page_html_ids():
    html = (
        '<html><head><title>XXOA</title></head>'
        '<body><div id="xxoa-login-wrap" class="container login-form">'
        '<!-- webpack bundle --><script src="/static/xxoa-login.js"></script>'
        "</div></body></html>"
    )
    markers = _body_markers(html, "XXOA")
    assert "xxoa-login-wrap" in markers
    assert "container" not in markers
    assert "login-form" not in markers
    assert not any("webpack" in m.lower() for m in markers)


def test_collect_source_prefers_login_page_over_widget(tmp_env, project):
    from app.services.paths import src_dir

    src = src_dir(project)
    (src / "templates").mkdir(parents=True, exist_ok=True)
    (src / "templates" / "login.html").write_text(
        '<html><body><div id="xxoa-login-wrap">'
        '<script src="/static/xxoa-login.js"></script></div></body></html>',
        encoding="utf-8",
    )
    (src / "components").mkdir(parents=True, exist_ok=True)
    (src / "components" / "Widget.vue").write_text(
        '<template><div id="random-widget-xyz">inner</div></template>',
        encoding="utf-8",
    )
    out = collect_source_fingerprints(project)
    assert out["ok"] is True, out
    assert "xxoa-login-wrap" in out["fofa"] or "xxoa-login.js" in out["fofa"]
    assert "random-widget-xyz" not in out["fofa"]
    assert "body=" in out["fofa"]


def test_fofa_search_variants_are_title_and_body():
    variants = fofa_search_variants(
        {
            "title": "XXOA办公系统",
            "body_markers": ["xxoa-login-wrap"],
            "static_paths": ["/static/xxoa-app.css"],
            "fofa": 'title="XXOA办公系统" && body="xxoa-login-wrap"',
        }
    )
    assert variants[0] == 'title="XXOA办公系统"'
    assert variants[1] == 'body="xxoa-login-wrap"'


def test_fofa_rewrite_switches_family_instead_of_deepening():
    payload = {
        "title": "XXOA办公系统",
        "body_markers": ["xxoa-login-wrap"],
        "static_paths": ["/static/xxoa-app.css"],
        "fofa": 'title="XXOA办公系统" && body="xxoa-login-wrap"',
    }
    after_title = fofa_rewrite_candidates(payload, attempted=['title="XXOA办公系统"'])
    assert after_title == ['body="xxoa-login-wrap"']
    after_both = fofa_rewrite_candidates(
        payload,
        attempted=['title="XXOA办公系统"', 'body="xxoa-login-wrap"'],
    )
    assert after_both == []

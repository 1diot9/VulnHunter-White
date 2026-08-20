from __future__ import annotations

import json

from app.services.old_vuln_crawl import (
    collect_old_vuln_skip_keys,
    default_product_keyword,
    infer_affected_packages,
    infer_ecosystems,
    resolve_crawl_inputs,
    run_old_vuln_ghsa_crawl,
    save_crawl_spec,
)
from app.services.ghsa_service import advisory_matches_project
from app.services.paths import ghsa_new_path, old_vulns_dir, src_dir
from app.services import pipeline
from app.tools.phase_recon import mark_old_vuln_search_complete, recon_old_vulns_ready


def test_default_keyword_from_identity(tmp_env, project):
    models = tmp_env["models"]
    Session = tmp_env["Session"]
    with Session() as db:
        row = db.get(models.Project, project)
        row.identity = "halo-dev/halo"
        row.name = "Halo CMS"
        db.commit()
    assert default_product_keyword(project) == "halo"


def test_infer_ecosystems_from_pom(tmp_env, project):
    (src_dir(project) / "pom.xml").write_text("<project/>", encoding="utf-8")
    assert infer_ecosystems(project) == ("maven",)


def test_infer_affected_packages_from_pom(tmp_env, project):
    (src_dir(project) / "pom.xml").write_text(
        """
        <project>
          <parent><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-parent</artifactId></parent>
          <groupId>run.halo.app</groupId>
          <artifactId>application</artifactId>
        </project>
        """,
        encoding="utf-8",
    )
    pkgs = infer_affected_packages(project)
    assert "application" in pkgs
    assert "run.halo.app" in pkgs
    assert "run.halo.app:application" in pkgs
    assert "spring-boot-starter-parent" not in pkgs
    assert "org.springframework.boot" not in pkgs
    assert not any(p.lower().startswith("org.springframework") for p in pkgs)


def test_infer_affected_packages_ignores_spring_boot_parent_group(tmp_env, project):
    (src_dir(project) / "pom.xml").write_text(
        """
        <project>
          <parent>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-parent</artifactId>
          </parent>
          <artifactId>demo-app</artifactId>
        </project>
        """,
        encoding="utf-8",
    )
    pkgs = infer_affected_packages(project)
    assert pkgs == ["demo-app"]


def test_infer_affected_packages_keeps_declared_springframework(tmp_env, project):
    (src_dir(project) / "pom.xml").write_text(
        "<project><groupId>org.springframework</groupId><artifactId>spring-core</artifactId></project>",
        encoding="utf-8",
    )
    pkgs = infer_affected_packages(project)
    assert "org.springframework" in pkgs
    assert "spring-core" in pkgs
    assert "org.springframework:spring-core" in pkgs


def test_infer_affected_packages_skips_dependency_groupids(tmp_env, project):
    root = src_dir(project)
    (root / "pom.xml").write_text(
        """
        <project>
          <groupId>cn.iocoder.boot</groupId>
          <artifactId>yudao</artifactId>
        </project>
        """,
        encoding="utf-8",
    )
    common = root / "yudao-framework" / "yudao-common"
    common.mkdir(parents=True)
    (common / "pom.xml").write_text(
        """
        <project>
          <parent>
            <groupId>cn.iocoder.boot</groupId>
            <artifactId>yudao-framework</artifactId>
          </parent>
          <artifactId>yudao-common</artifactId>
          <dependencies>
            <dependency>
              <groupId>org.springframework</groupId>
              <artifactId>spring-core</artifactId>
            </dependency>
          </dependencies>
        </project>
        """,
        encoding="utf-8",
    )
    pkgs = infer_affected_packages(project)
    assert "yudao" in pkgs
    assert "cn.iocoder.boot" in pkgs
    assert "yudao-common" in pkgs
    assert "cn.iocoder.boot:yudao-common" in pkgs
    assert "org.springframework" not in pkgs
    assert "org.springframework:yudao-common" not in pkgs
    assert "spring-core" not in pkgs


def test_resolve_crawl_inputs_drops_spec_dependency_packages(tmp_env, project):
    (src_dir(project) / "pom.xml").write_text(
        "<project><groupId>cn.iocoder.boot</groupId><artifactId>yudao</artifactId></project>",
        encoding="utf-8",
    )
    save_crawl_spec(
        project,
        keyword="ruoyi-vue-pro",
        affects=["org.springframework", "org.springframework:yudao-common", "yudao-common"],
    )
    keyword, affects, _ecos = resolve_crawl_inputs(project)
    assert keyword == "ruoyi-vue-pro"
    assert "yudao" in affects
    assert "yudao-common" in affects
    assert "org.springframework" not in affects
    assert "org.springframework:yudao-common" not in affects


def test_advisory_matches_project_keeps_own_drops_spring():
    own = {
        "vulnerabilities": [
            {"package": {"ecosystem": "maven", "name": "cn.iocoder.boot:yudao-common"}}
        ]
    }
    spring = {
        "summary": "Spring Framework RCE",
        "vulnerabilities": [
            {"package": {"ecosystem": "maven", "name": "org.springframework:spring-web"}}
        ],
    }
    packages = ["yudao", "cn.iocoder.boot", "yudao-common"]
    assert advisory_matches_project(own, packages=packages, keyword="ruoyi-vue-pro") is True
    assert advisory_matches_project(spring, packages=packages, keyword="ruoyi-vue-pro") is False
    assert advisory_matches_project(
        {"summary": "RuoYi-Vue-Pro path traversal", "html_url": "https://example/ruoyi-vue-pro"},
        packages=packages,
        keyword="ruoyi-vue-pro",
    ) is True


def test_collect_skip_keys_from_old_vuln_docs(tmp_env, project):
    old = old_vulns_dir(project)
    old.mkdir(parents=True, exist_ok=True)
    (old / "CVE-2024-0001.md").write_text(
        "---\ntitle: Demo\ncve: CVE-2024-0001\n---\n\n"
        "also https://github.com/halo-dev/halo/issues/42\n",
        encoding="utf-8",
    )
    keys = collect_old_vuln_skip_keys(project)
    assert "CVE-2024-0001" in keys
    assert "HALO-DEV/HALO#42" in keys


def test_run_old_vuln_ghsa_crawl_writes_new_only(tmp_env, project, monkeypatch):
    save_crawl_spec(project, keyword="halo")
    old = old_vulns_dir(project)
    old.mkdir(parents=True, exist_ok=True)
    (old / "CVE-2024-0001.md").write_text(
        "---\ntitle: Known\ncve: CVE-2024-0001\n---\n\nbody\n",
        encoding="utf-8",
    )

    def fake_crawl(keyword, **kwargs):
        assert keyword == "halo"
        return (
            [
                {"identifier": "CVE-2024-0001", "title": "known"},
                {"identifier": "CVE-2024-0002", "title": "fresh", "summary": "x"},
            ],
            {"fetched": 2, "errors": [], "packages": ["halo"]},
        )

    monkeypatch.setattr("app.services.old_vuln_crawl.crawl_ghsa", fake_crawl)
    result = run_old_vuln_ghsa_crawl(project)
    assert result.ok is True
    assert result.new_count == 1
    assert result.skipped == 1
    payload = json.loads(ghsa_new_path(project).read_text(encoding="utf-8"))
    assert payload["keyword"] == "halo"
    assert [v["identifier"] for v in payload["vulnerabilities"]] == ["CVE-2024-0002"]


def test_mark_complete_after_empty_crawl(tmp_env, project):
    mark_old_vuln_search_complete(project, note="GHSA / GitHub Issues 爬虫无新候选")
    assert recon_old_vulns_ready(project) is True
    text = (old_vulns_dir(project) / "index.md").read_text(encoding="utf-8")
    assert "\ncomplete: true\n" in text
    assert "GitHub Issues" in text


def test_run_recon_old_vulns_crawl_then_search(tmp_env, project, monkeypatch):
    order: list[str] = []
    monkeypatch.setattr(pipeline, "recon_old_vuln_llm_ready", lambda pid: False)
    monkeypatch.setattr(pipeline, "recon_old_vulns_ready", lambda pid: False)
    monkeypatch.setattr(
        pipeline,
        "_run_recon_old_vuln_crawl_pass",
        lambda pid, cancel: order.append("crawl-pass") or True,
    )
    monkeypatch.setattr(
        pipeline,
        "_run_recon_old_vuln_ghsa",
        lambda pid, cancel: order.append("search-pass") or True,
    )
    assert pipeline._run_recon_old_vulns(project, __import__("threading").Event()) is True
    assert order == ["crawl-pass", "search-pass"]


def test_run_old_vuln_crawl_merges_github_issues(tmp_env, project, monkeypatch):
    models = tmp_env["models"]
    Session = tmp_env["Session"]
    with Session() as db:
        row = db.get(models.Project, project)
        row.identity = "halo-dev/halo"
        db.commit()
    save_crawl_spec(project, keyword="halo")

    def fake_ghsa(keyword, **kwargs):
        return (
            [{"identifier": "CVE-2024-0001", "title": "ghsa", "source": "ghsa"}],
            {"fetched": 1, "errors": [], "packages": ["halo"]},
        )

    def fake_issues(repo, **kwargs):
        assert repo == "halo-dev/halo"
        return (
            [
                {
                    "identifier": "CVE-2024-0001",
                    "title": "same cve in issue",
                    "source": "github_issue",
                },
                {
                    "identifier": "halo-dev/halo#99",
                    "title": "Unauth RCE",
                    "summary": "no cve yet",
                    "source": "github_issue",
                    "source_url": "https://github.com/halo-dev/halo/issues/99",
                },
            ],
            {"fetched": 2, "errors": [], "repo": repo},
        )

    monkeypatch.setattr("app.services.old_vuln_crawl.crawl_ghsa", fake_ghsa)
    monkeypatch.setattr("app.services.old_vuln_crawl.crawl_github_issues", fake_issues)
    monkeypatch.setattr(
        "app.services.old_vuln_crawl.crawl_repo_advisories",
        lambda repo, **kwargs: ([], {"repo": repo, "fetched": 0, "errors": []}),
    )
    result = run_old_vuln_ghsa_crawl(project)
    assert result.ok is True
    assert result.issue_count == 1
    assert result.ghsa_count == 1
    assert result.new_count == 2
    payload = json.loads(ghsa_new_path(project).read_text(encoding="utf-8"))
    ids = [v["identifier"] for v in payload["vulnerabilities"]]
    assert "CVE-2024-0001" in ids
    assert "halo-dev/halo#99" in ids
    assert payload["meta"]["repo"] == "halo-dev/halo"


def test_run_old_vuln_crawl_merges_repo_advisories(tmp_env, project, monkeypatch):
    models = tmp_env["models"]
    Session = tmp_env["Session"]
    with Session() as db:
        row = db.get(models.Project, project)
        row.identity = "halo-dev/halo"
        db.commit()
    save_crawl_spec(project, keyword="halo")

    monkeypatch.setattr(
        "app.services.old_vuln_crawl.crawl_ghsa",
        lambda keyword, **kwargs: ([], {"fetched": 0, "errors": [], "packages": ["halo"]}),
    )
    monkeypatch.setattr(
        "app.services.old_vuln_crawl.crawl_repo_advisories",
        lambda repo, **kwargs: (
            [
                {
                    "identifier": "CVE-2024-1234",
                    "title": "repo advisory",
                    "source": "ghsa",
                    "fix_status": "patched",
                }
            ],
            {"repo": repo, "fetched": 1, "errors": []},
        ),
    )
    monkeypatch.setattr(
        "app.services.old_vuln_crawl.crawl_github_issues",
        lambda repo, **kwargs: ([], {"fetched": 0, "errors": [], "repo": repo}),
    )
    result = run_old_vuln_ghsa_crawl(project)
    assert result.ok is True
    assert result.ghsa_count == 1
    assert result.new_count == 1
    payload = json.loads(ghsa_new_path(project).read_text(encoding="utf-8"))
    assert payload["vulnerabilities"][0]["identifier"] == "CVE-2024-1234"


def test_run_recon_old_vuln_crawl_pass_hands_results_to_agent(tmp_env, project, monkeypatch):
    from app.services.old_vuln_crawl import GhsaCrawlResult

    called: list[str] = []

    def fake_gated(pid, cancel, **kwargs):
        called.append(kwargs["phase"])
        assert kwargs["prompt_vars"]["issues_count"] == 2
        assert kwargs["prompt_vars"]["ghsa_count"] == 0
        assert kwargs["prompt_vars"]["issues_repo"] == "halo-dev/halo"
        return True

    monkeypatch.setattr(pipeline, "_run_recon_gated_session", fake_gated)
    monkeypatch.setattr(
        "app.services.old_vuln_crawl.run_old_vuln_ghsa_crawl",
        lambda pid: GhsaCrawlResult(
            ok=True, keyword="halo", new_count=2, ghsa_count=0, issue_count=2, repo="halo-dev/halo"
        ),
    )
    assert pipeline._run_recon_old_vuln_crawl_pass(project, __import__("threading").Event()) is True
    assert called == ["recon-old-vuln"]


def test_run_recon_old_vuln_crawl_pass_runs_session_when_empty(tmp_env, project, monkeypatch):
    from app.services.old_vuln_crawl import GhsaCrawlResult

    called: list[str] = []

    def fake_gated(pid, cancel, **kwargs):
        called.append(kwargs["phase"])
        assert kwargs["prompt_vars"]["ghsa_count"] == 0
        assert kwargs["prompt_vars"]["issues_count"] == 0
        return True

    monkeypatch.setattr(
        "app.services.old_vuln_crawl.run_old_vuln_ghsa_crawl",
        lambda pid: GhsaCrawlResult(ok=True, keyword="halo", new_count=0, ghsa_count=0, issue_count=0),
    )
    monkeypatch.setattr(pipeline, "_run_recon_gated_session", fake_gated)
    assert pipeline._run_recon_old_vuln_crawl_pass(project, __import__("threading").Event()) is True
    assert called == ["recon-old-vuln"]
    assert recon_old_vulns_ready(project) is False


def test_run_recon_old_vuln_ghsa_is_search_pass(tmp_env, project, monkeypatch):
    called: list[str] = []

    def fake_gated(pid, cancel, **kwargs):
        called.append(kwargs["phase"])
        assert not kwargs.get("prompt_vars")
        return True

    monkeypatch.setattr(pipeline, "_run_recon_gated_session", fake_gated)
    monkeypatch.setattr(
        "app.services.old_vuln_crawl.run_old_vuln_ghsa_crawl",
        lambda pid: (_ for _ in ()).throw(AssertionError("search pass should not crawl")),
    )
    assert pipeline._run_recon_old_vuln_ghsa(project, __import__("threading").Event()) is True
    assert called == ["recon-old-vuln-ghsa"]

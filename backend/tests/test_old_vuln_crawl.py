from __future__ import annotations

import json

from app.services.old_vuln_crawl import (
    collect_old_vuln_skip_keys,
    default_product_keyword,
    infer_ecosystems,
    run_old_vuln_ghsa_crawl,
    save_crawl_spec,
)
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


def test_collect_skip_keys_from_old_vuln_docs(tmp_env, project):
    old = old_vulns_dir(project)
    old.mkdir(parents=True, exist_ok=True)
    (old / "CVE-2024-0001.md").write_text(
        "---\ntitle: Demo\ncve: CVE-2024-0001\n---\n\nbody\n",
        encoding="utf-8",
    )
    keys = collect_old_vuln_skip_keys(project)
    assert "CVE-2024-0001" in keys


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
    mark_old_vuln_search_complete(project, note="GHSA 爬虫无新候选，沿用 LLM 检索结果")
    assert recon_old_vulns_ready(project) is True
    text = (old_vulns_dir(project) / "index.md").read_text(encoding="utf-8")
    assert "\ncomplete: true\n" in text
    assert "GHSA 爬虫无新候选" in text


def test_run_recon_old_vulns_llm_then_ghsa(tmp_env, project, monkeypatch):
    order: list[str] = []
    monkeypatch.setattr(pipeline, "recon_old_vuln_llm_ready", lambda pid: False)
    monkeypatch.setattr(pipeline, "recon_old_vulns_ready", lambda pid: False)

    def fake_gated(pid, cancel, **kwargs):
        order.append(kwargs["phase"])
        return True

    monkeypatch.setattr(pipeline, "_run_recon_gated_session", fake_gated)
    monkeypatch.setattr(
        pipeline,
        "_run_recon_old_vuln_ghsa",
        lambda pid, cancel: order.append("ghsa-run") or True,
    )
    assert pipeline._run_recon_old_vulns(project, __import__("threading").Event()) is True
    assert order == ["recon-old-vuln", "ghsa-run"]

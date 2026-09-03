from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app
from app.services.demo_seed import (
    DEMO_PROJECT_ID,
    DEMO_PROJECT_NAME,
    seed_bundled_demo_project,
)

FIXTURE_MANIFEST = Path(__file__).resolve().parent / "fixtures" / "demo-project" / "db-seed.json"


def _stage_demo_workspace(projects_dir: Path) -> Path:
    root = projects_dir / str(DEMO_PROJECT_ID)
    (root / "src").mkdir(parents=True, exist_ok=True)
    (root / "src" / "app.py").write_text("# demo\n", encoding="utf-8")
    report_dir = root / "vulns" / "183"
    report_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / "report.md").write_text("## 摘要\n\nfixture report\n", encoding="utf-8")
    showcase = root / "showcase"
    showcase.mkdir(parents=True, exist_ok=True)
    dest = showcase / "db-seed.json"
    dest.write_text(FIXTURE_MANIFEST.read_text(encoding="utf-8"), encoding="utf-8")
    return dest


def test_seed_demo_creates_project_and_vulns(tmp_env):
    manifest = _stage_demo_workspace(tmp_env["projects"])
    out = seed_bundled_demo_project(manifest_path=manifest)
    assert out["seeded"] is True
    assert out["added"].get("projects") == 1
    assert out["added"].get("vulns") == 1

    with TestClient(app) as client:
        projects = client.get("/api/projects", params={"limit": 100}).json()
        assert any(p["id"] == DEMO_PROJECT_ID and p["name"] == DEMO_PROJECT_NAME for p in projects["items"])
        vulns = client.get(f"/api/vulns?project_id={DEMO_PROJECT_ID}").json()["items"]
        assert len(vulns) == 1
        assert vulns[0]["id"] == 183
        assert vulns[0]["status"] == "confirmed"


def test_seed_demo_is_idempotent(tmp_env):
    manifest = _stage_demo_workspace(tmp_env["projects"])
    first = seed_bundled_demo_project(manifest_path=manifest)
    second = seed_bundled_demo_project(manifest_path=manifest)
    assert first["seeded"] is True
    assert second["seeded"] is False
    assert second["reason"] == "already_present"

    Session = tmp_env["Session"]
    models = tmp_env["models"]
    with Session() as db:
        assert db.query(models.Project).filter_by(id=DEMO_PROJECT_ID).count() == 1
        assert db.query(models.Vuln).filter_by(project_id=DEMO_PROJECT_ID).count() == 1
        assert db.query(models.AttackChain).filter_by(project_id=DEMO_PROJECT_ID).count() == 1


def test_seed_demo_skips_when_bundle_missing(tmp_env):
    out = seed_bundled_demo_project()
    assert out["skipped"] is True
    assert out["reason"] in {"manifest_missing", "workspace_missing"}
    Session = tmp_env["Session"]
    models = tmp_env["models"]
    with Session() as db:
        assert db.query(models.Project).count() == 0


def test_seed_demo_skips_when_id_conflict(tmp_env):
    Session = tmp_env["Session"]
    models = tmp_env["models"]
    with Session() as db:
        db.add(
            models.Project(
                id=DEMO_PROJECT_ID,
                name="user-occupied",
                source_type="zip",
                status="paused",
                phase="done",
            )
        )
        db.commit()

    manifest = _stage_demo_workspace(tmp_env["projects"])
    out = seed_bundled_demo_project(manifest_path=manifest)
    assert out["skipped"] is True
    assert out["reason"] == "id_conflict"

    with Session() as db:
        p = db.get(models.Project, DEMO_PROJECT_ID)
        assert p is not None
        assert p.name == "user-occupied"
        assert db.query(models.Vuln).filter_by(project_id=DEMO_PROJECT_ID).count() == 0


def test_demo_not_resumed_by_recover_inflight(tmp_env, monkeypatch):
    manifest = _stage_demo_workspace(tmp_env["projects"])
    seed_bundled_demo_project(manifest_path=manifest)

    calls: list[int] = []

    def _boom(project_id: int) -> None:
        calls.append(project_id)

    import app.services.pipeline as pipeline

    monkeypatch.setattr(pipeline, "start_audit", _boom)
    monkeypatch.setattr(pipeline, "start_ingest_and_audit", _boom)
    pipeline.recover_inflight_projects()
    assert DEMO_PROJECT_ID not in calls


def test_demo_vuln_report_readable(tmp_env):
    manifest = _stage_demo_workspace(tmp_env["projects"])
    seed_bundled_demo_project(manifest_path=manifest)

    with TestClient(app) as client:
        detail = client.get("/api/vulns/183")
        assert detail.status_code == 200
        body = detail.json()
        assert "fixture report" in (body.get("report_md") or "")


def test_bundled_showcase_has_current_advisory_and_cve():
    from app.services.cve_record import list_fillable_fields
    from app.services.report import harness_vuln_code_gap

    root = Path(__file__).resolve().parents[2] / "data" / "projects" / "11" / "vulns"
    files = {
        183: "src/board/engine.py",
        184: "src/board/engine.py",
        185: "src/templates/notes.html",
        186: "src/app.py",
    }
    advisory_need = (
        "## Title",
        "### Summary",
        "### Details",
        "### Vulnerable code",
        "### PoC",
        "### Impact",
        "## Affected products",
        "**CVSS 3.1:**",
        "**CVSS 4.0:**",
        "```http",
    )
    for vid, file_path in files.items():
        d = root / str(vid)
        report = (d / "report.md").read_text(encoding="utf-8")
        advisory = (d / "advisory.md").read_text(encoding="utf-8")
        record = json.loads((d / "cve.json").read_text(encoding="utf-8"))
        assert harness_vuln_code_gap(report, file_path=file_path) is None
        missing = [h for h in advisory_need if h not in advisory]
        assert not missing, f"vuln {vid} advisory missing {missing}"
        pending = [f["path"] for f in list_fillable_fields(record) if f["required"] and f["needs_fill"]]
        assert not pending, f"vuln {vid} cve.json pending {pending}"


def test_seed_respects_demo_seed_setting(tmp_env, monkeypatch):
    monkeypatch.setattr("app.config.settings.demo_seed", False)
    monkeypatch.setattr("app.services.demo_seed.settings.demo_seed", False)
    manifest = _stage_demo_workspace(tmp_env["projects"])
    out = seed_bundled_demo_project(manifest_path=manifest)
    assert out["skipped"] is True
    assert out["reason"] == "disabled"

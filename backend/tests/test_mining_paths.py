from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.mining_paths import (
    MiningPathError,
    mining_path_display,
    mining_path_from_role,
    mining_path_label,
    parse_heuristic_lite,
    parse_mining_paths,
)
from app.services.sink_queue import apply_triage_decisions, freeze_audit_queue, persist_candidates
from app.tools import ROLE_ACL, ToolContext, registry
from app.tools.phase_worker import mining_complete, project_complete_gates


def _ctx(project_id: int, role: str, **kwargs) -> ToolContext:
    return ToolContext(project_id=project_id, role=role, phase=role, **kwargs)


def test_parse_mining_paths_requires_one():
    assert parse_mining_paths() == (True, False, False)
    assert parse_mining_paths(heuristic_enabled=False, fast_enabled=True) == (False, True, False)
    assert parse_mining_paths(heuristic_enabled=False, fast_enabled=False, bypass_enabled=True) == (
        False,
        False,
        True,
    )
    with pytest.raises(MiningPathError, match="至少开启"):
        parse_mining_paths(heuristic_enabled=False, fast_enabled=False, bypass_enabled=False)
    assert parse_heuristic_lite() is False
    assert parse_heuristic_lite("true") is True
    assert mining_path_label(heuristic_enabled=True, fast_enabled=False, heuristic_lite=True) == "启发式轻量"
    assert (
        mining_path_label(heuristic_enabled=True, fast_enabled=True, heuristic_lite=True)
        == "启发式轻量 + 快速扫描"
    )
    assert (
        mining_path_label(heuristic_enabled=False, fast_enabled=False, bypass_enabled=True)
        == "历史漏洞绕过"
    )
    assert (
        mining_path_label(heuristic_enabled=True, fast_enabled=True, bypass_enabled=True)
        == "启发式挖掘 + 快速扫描 + 历史漏洞绕过"
    )
    assert mining_path_from_role("worker") == "heuristic"
    assert mining_path_from_role("fast_worker") == "fast"
    assert mining_path_from_role("bypass_worker") == "bypass"
    assert mining_path_from_role("fix") is None
    assert mining_path_display("fast") == "快速扫描"
    assert mining_path_display("unknown") is None


def test_create_github_mining_path_defaults(tmp_env, monkeypatch):
    from app.main import app

    monkeypatch.setattr("app.api.projects.start_ingest_and_audit", lambda *a, **k: None)
    with TestClient(app) as client:
        created = client.post(
            "/api/projects",
            json={"source_type": "github", "source_url": "https://github.com/owner/demo"},
        )
        assert created.status_code == 200
        body = created.json()
        assert body["heuristic_enabled"] is True
        assert body["heuristic_lite"] is False
        assert body["fast_enabled"] is False
        assert body["bypass_enabled"] is False
        assert body["sinks_queued"] == 0
        assert body["sinks_done"] == 0
        assert body["bypass_queued"] == 0
        assert body["bypass_done"] == 0
        both_off = client.post(
            "/api/projects",
            json={
                "source_type": "github",
                "source_url": "https://github.com/owner/none",
                "heuristic_enabled": False,
                "fast_enabled": False,
            },
        )
        assert both_off.status_code == 400
        fast_only = client.post(
            "/api/projects",
            json={
                "source_type": "github",
                "source_url": "https://github.com/owner/fast",
                "heuristic_enabled": False,
                "fast_enabled": True,
            },
        )
        assert fast_only.status_code == 200
        assert fast_only.json()["heuristic_enabled"] is False
        assert fast_only.json()["heuristic_lite"] is False
        assert fast_only.json()["fast_enabled"] is True
        bypass_only = client.post(
            "/api/projects",
            json={
                "source_type": "github",
                "source_url": "https://github.com/owner/bypass",
                "heuristic_enabled": False,
                "bypass_enabled": True,
            },
        )
        assert bypass_only.status_code == 200
        assert bypass_only.json()["heuristic_enabled"] is False
        assert bypass_only.json()["fast_enabled"] is False
        assert bypass_only.json()["bypass_enabled"] is True
        lite = client.post(
            "/api/projects",
            json={
                "source_type": "github",
                "source_url": "https://github.com/owner/lite",
                "heuristic_lite": True,
            },
        )
        assert lite.status_code == 200
        assert lite.json()["heuristic_enabled"] is True
        assert lite.json()["heuristic_lite"] is True
        assert lite.json()["fast_enabled"] is False


def test_patch_mining_paths_only_when_paused_or_completed(tmp_env, project):
    from app.main import app
    from app.models import Project, SessionLocal

    with TestClient(app) as client:
        denied = client.patch(f"/api/projects/{project}", json={"fast_enabled": True})
        assert denied.status_code == 400
        assert "暂停或完成" in denied.json()["detail"]
        with SessionLocal() as db:
            p = db.get(Project, project)
            p.status = "paused"
            db.commit()
        both_off = client.patch(
            f"/api/projects/{project}",
            json={"heuristic_enabled": False, "fast_enabled": False},
        )
        assert both_off.status_code == 400
        ok = client.patch(f"/api/projects/{project}", json={"fast_enabled": True})
        assert ok.status_code == 200
        assert ok.json()["heuristic_enabled"] is True
        assert ok.json()["fast_enabled"] is True
        bypass = client.patch(f"/api/projects/{project}", json={"bypass_enabled": True})
        assert bypass.status_code == 200
        assert bypass.json()["bypass_enabled"] is True
        assert bypass.json()["fast_enabled"] is True
        lite = client.patch(f"/api/projects/{project}", json={"heuristic_lite": True})
        assert lite.status_code == 200
        assert lite.json()["heuristic_lite"] is True
        assert lite.json()["heuristic_enabled"] is True


def test_mining_complete_heuristic_fast_and_dual(tmp_env, project):
    from app.models import FileWeight, Project
    from app.services.ingest import build_file_index

    build_file_index(project)
    Session = tmp_env["Session"]
    models = tmp_env["models"]
    with Session() as db:
        for fw in db.query(FileWeight).filter(FileWeight.project_id == project).all():
            if fw.skipped:
                continue
            fw.weight = 50
            fw.audited = True
        proj = db.get(Project, project)
        proj.recon_done = True
        proj.heuristic_enabled = True
        proj.fast_enabled = False
        db.commit()
    assert mining_complete(project) is True

    with Session() as db:
        proj = db.get(Project, project)
        proj.heuristic_enabled = False
        proj.fast_enabled = True
        proj.fast_queue_frozen = False
        db.commit()
        for fw in db.query(FileWeight).filter(FileWeight.project_id == project).all():
            fw.audited = False
        db.commit()
    assert mining_complete(project) is False

    with Session() as db:
        proj = db.get(Project, project)
        proj.fast_queue_frozen = True
        db.commit()
    assert mining_complete(project) is True
    assert project_complete_gates(project) is True

    persist_candidates(
        project,
        [
            {
                "file_path": "app/Main.java",
                "line_start": 1,
                "line_end": 1,
                "check_ids": ["rce"],
                "snippet": "Runtime.exec",
                "severity": "ERROR",
                "confidence": "HIGH",
                "mapped_vuln_type": "rce",
                "code_score": 120,
            }
        ],
    )
    freeze_audit_queue(project, limit=60)
    with Session() as db:
        proj = db.get(Project, project)
        proj.heuristic_enabled = True
        proj.fast_enabled = True
        for fw in db.query(FileWeight).filter(FileWeight.project_id == project).all():
            if not fw.skipped:
                fw.audited = True
        db.commit()
    assert mining_complete(project) is False

    with Session() as db:
        for sink in db.query(models.Sink).filter(models.Sink.project_id == project).all():
            sink.status = "done"
            sink.verdict = "noise"
        db.commit()
    assert mining_complete(project) is True


def test_finish_sink_gates_and_wrong_id(tmp_env, project):
    from app.models import Sink, SessionLocal

    persist_candidates(
        project,
        [
            {
                "file_path": "app/Main.java",
                "line_start": 4,
                "line_end": 4,
                "check_ids": ["rce"],
                "snippet": "exec",
                "severity": "ERROR",
                "confidence": "HIGH",
                "mapped_vuln_type": "rce",
                "code_score": 99,
            }
        ],
    )
    freeze_audit_queue(project)
    with SessionLocal() as db:
        sink = db.query(Sink).filter(Sink.project_id == project).first()
        sid = sink.id
        other = Sink(
            project_id=project,
            file_path="app/Other.java",
            line_start=1,
            status="queued",
            code_score=1,
        )
        db.add(other)
        db.commit()
        db.refresh(other)
        other_id = other.id

    ctx = _ctx(project, "fast_worker", file_path=f"sink:{sid}")
    ctx.state["sink_id"] = sid
    ctx.state["injected_sink"] = f"sink:{sid}"
    ctx.state["round_id"] = 1
    blocked = registry.dispatch(ctx, "FinishSink", {"sink_id": other_id, "verdict": "noise"})
    assert blocked["ok"] is False
    assert "只能 FinishSink" in blocked["error"]
    missing = registry.dispatch(ctx, "FinishSink", {"verdict": "vuln_submitted"})
    assert missing["ok"] is False
    done = registry.dispatch(ctx, "FinishSink", {"verdict": "unreachable", "report": "无生产调用"})
    assert done["ok"] is True
    assert ctx.state["sink_finished"] is True
    with SessionLocal() as db:
        row = db.get(Sink, sid)
        assert row.status == "done"
        assert row.verdict == "unreachable"
        other = db.get(Sink, other_id)
        assert other.status == "queued"


def test_triage_cannot_drop_protected_sink(tmp_env, project):
    from app.models import FileWeight, SessionLocal

    with SessionLocal() as db:
        fw = (
            db.query(FileWeight)
            .filter(FileWeight.project_id == project, FileWeight.path == "app/Main.java")
            .first()
        )
        if fw is None:
            db.add(
                FileWeight(
                    project_id=project,
                    path="app/Main.java",
                    weight=90,
                    has_source=True,
                    skipped=False,
                )
            )
        else:
            fw.weight = 90
            fw.has_source = True
            fw.skipped = False
        db.commit()
    persist_candidates(
        project,
        [
            {
                "file_path": "app/Main.java",
                "line_start": 8,
                "line_end": 8,
                "check_ids": ["rce"],
                "snippet": "exec",
                "severity": "ERROR",
                "confidence": "HIGH",
                "mapped_vuln_type": "rce",
                "code_score": 150,
            }
        ],
    )
    with SessionLocal() as db:
        from app.models import Sink

        sink = db.query(Sink).filter(Sink.project_id == project).first()
        sid = sink.id
    apply_triage_decisions(project, [{"id": sid, "decision": "drop", "reason": "noise"}])
    with SessionLocal() as db:
        from app.models import Sink

        sink = db.get(Sink, sid)
        assert sink.agent_decision == "defer"


def test_fast_worker_acl_has_finish_sink_not_finish_file():
    assert "FinishSink" in ROLE_ACL["fast_worker"]
    assert "FinishFile" not in ROLE_ACL["fast_worker"]
    assert "FinishRound" not in ROLE_ACL["fast_worker"]
    assert "Read" in ROLE_ACL["fast_worker"]
    assert ROLE_ACL["sink_triage"] == frozenset({"FinishSinkTriage"})
    names = {t["function"]["name"] for t in registry.openai_tools_for_role("fast_worker")}
    assert names == set(ROLE_ACL["fast_worker"])
    triage = {t["function"]["name"] for t in registry.openai_tools_for_role("sink_triage")}
    assert triage == {"FinishSinkTriage"}
    assert "Read" not in triage
    assert "Grep" not in triage


def test_bypass_worker_acl_has_finish_bypass_not_finish_file():
    assert "FinishBypass" in ROLE_ACL["bypass_worker"]
    assert "FinishFile" not in ROLE_ACL["bypass_worker"]
    assert "FinishRound" not in ROLE_ACL["bypass_worker"]
    assert "FinishSink" not in ROLE_ACL["bypass_worker"]
    assert "Read" in ROLE_ACL["bypass_worker"]
    names = {t["function"]["name"] for t in registry.openai_tools_for_role("bypass_worker")}
    assert names == set(ROLE_ACL["bypass_worker"])


def test_heuristic_lite_complete_and_pick_entry(tmp_env, project):
    from app.models import FileWeight, Project
    from app.services import pipeline
    from app.services.ingest import build_file_index
    from app.tools.phase_worker import heuristic_complete

    build_file_index(project)
    Session = tmp_env["Session"]
    with Session() as db:
        main = (
            db.query(FileWeight)
            .filter(FileWeight.project_id == project, FileWeight.path == "app/Main.java")
            .one()
        )
        main.weight = 80
        main.has_source = True
        main.skipped = False
        main.audited = False
        db.add(
            FileWeight(
                project_id=project,
                path="app/Entry.java",
                weight=100,
                skipped=False,
                audited=False,
                has_source=False,
            )
        )
        db.add(
            FileWeight(
                project_id=project,
                path="app/Low.java",
                weight=50,
                skipped=False,
                audited=False,
            )
        )
        proj = db.get(Project, project)
        proj.recon_done = True
        proj.heuristic_enabled = True
        proj.heuristic_lite = True
        proj.fast_enabled = False
        db.commit()

    picked = pipeline._pick_next_file(project, "worker-lite")
    assert picked is not None
    assert picked.path == "app/Entry.java"
    with Session() as db:
        row = (
            db.query(FileWeight)
            .filter(FileWeight.project_id == project, FileWeight.path == "app/Entry.java")
            .one()
        )
        row.claimed_by = None
        row.claimed_at = None
        row.audited = True
        db.commit()
    assert heuristic_complete(project) is True
    assert mining_complete(project) is True

    with Session() as db:
        proj = db.get(Project, project)
        proj.heuristic_lite = False
        db.commit()
    assert heuristic_complete(project) is False
    assert mining_complete(project) is False
    picked_full = pipeline._pick_next_file(project, "worker-full")
    assert picked_full is not None
    assert picked_full.path == "app/Main.java"


def test_patch_heuristic_lite_reopens_completed_when_scope_grows(tmp_env, project):
    from app.main import app
    from app.models import FileWeight, Project, SessionLocal
    from app.services.ingest import build_file_index

    build_file_index(project)
    with SessionLocal() as db:
        main = (
            db.query(FileWeight)
            .filter(FileWeight.project_id == project, FileWeight.path == "app/Main.java")
            .one()
        )
        main.weight = 100
        main.audited = True
        db.add(
            FileWeight(
                project_id=project,
                path="app/Low.java",
                weight=40,
                skipped=False,
                audited=False,
            )
        )
        proj = db.get(Project, project)
        proj.status = "completed"
        proj.phase = "done"
        proj.recon_done = True
        proj.heuristic_enabled = True
        proj.heuristic_lite = True
        db.commit()

    with TestClient(app) as client:
        stay = client.patch(f"/api/projects/{project}", json={"heuristic_lite": True})
        assert stay.status_code == 200
        assert stay.json()["status"] == "completed"
        widened = client.patch(f"/api/projects/{project}", json={"heuristic_lite": False})
        assert widened.status_code == 200
        body = widened.json()
        assert body["heuristic_lite"] is False
        assert body["status"] == "paused"
        assert body["phase"] == "worker"


def test_ingest_old_vulns_and_finish_bypass(tmp_env, project):
    from app.models import BypassTarget, Project, SessionLocal
    from app.services.bypass_queue import freeze_bypass_queue, parse_bypass_ref, pick_next_bypass
    from app.services.paths import old_vulns_dir

    old_dir = old_vulns_dir(project)
    old_dir.mkdir(parents=True, exist_ok=True)
    (old_dir / "index.md").write_text("---\ncomplete: true\n---\n", encoding="utf-8")
    (old_dir / "cve-2024-1.md").write_text(
        "---\ntitle: 历史 RCE\nsummary: Runtime.exec\ncve: CVE-2024-1\nfix_status: patched\nsource: websearch\n---\n\n正文\n",
        encoding="utf-8",
    )
    queued = freeze_bypass_queue(project)
    assert queued == 1
    row = pick_next_bypass(project, "bypass-1")
    assert row is not None
    bid = row.id
    ctx = _ctx(project, "bypass_worker", file_path=f"bypass:{bid}")
    ctx.state["bypass_id"] = bid
    ctx.state["injected_bypass"] = f"bypass:{bid}"
    ctx.state["round_id"] = 1
    blocked = registry.dispatch(ctx, "FinishBypass", {"bypass_id": bid + 99, "verdict": "still_patched"})
    assert blocked["ok"] is False
    assert "只能 FinishBypass" in blocked["error"]
    done = registry.dispatch(ctx, "FinishBypass", {"verdict": "still_patched", "report": "补丁完整"})
    assert done["ok"] is True
    assert ctx.state["bypass_finished"] is True
    with SessionLocal() as db:
        target = db.get(BypassTarget, bid)
        assert target.status == "done"
        assert target.verdict == "still_patched"
        proj = db.get(Project, project)
        proj.recon_done = True
        proj.heuristic_enabled = False
        proj.fast_enabled = False
        proj.bypass_enabled = True
        db.commit()
    assert mining_complete(project) is True
    assert parse_bypass_ref(f"bypass:{bid}") == bid


def test_pick_next_bypass_newest_cve_first(tmp_env, project):
    from app.services.bypass_queue import freeze_bypass_queue, pick_next_bypass
    from app.services.paths import old_vulns_dir

    old_dir = old_vulns_dir(project)
    old_dir.mkdir(parents=True, exist_ok=True)
    (old_dir / "index.md").write_text("---\ncomplete: true\n---\n", encoding="utf-8")
    (old_dir / "CVE-2022-26619.md").write_text(
        "---\ntitle: 旧洞\nsummary: upload\ncve: CVE-2022-26619\n---\n\n正文\n",
        encoding="utf-8",
    )
    (old_dir / "CVE-2026-67921.md").write_text(
        "---\ntitle: 新洞\nsummary: rce\ncve: CVE-2026-67921\n---\n\n正文\n",
        encoding="utf-8",
    )
    (old_dir / "open-issue.md").write_text(
        "---\ntitle: 无编号 Issue\nsummary: still open\n---\n\n正文\n",
        encoding="utf-8",
    )
    queued = freeze_bypass_queue(project)
    assert queued == 3
    first = pick_next_bypass(project, "bypass-new")
    assert first is not None
    assert first.cve == "CVE-2026-67921"
    second = pick_next_bypass(project, "bypass-old")
    assert second is not None
    assert second.cve == "CVE-2022-26619"
    third = pick_next_bypass(project, "bypass-issue")
    assert third is not None
    assert (third.cve or "") == ""
    assert str(third.file_path).endswith("open-issue.md")


def test_mining_complete_waits_on_bypass_queue(tmp_env, project):
    from app.models import BypassTarget, Project, SessionLocal

    Session = tmp_env["Session"]
    with Session() as db:
        proj = db.get(Project, project)
        proj.recon_done = True
        proj.heuristic_enabled = False
        proj.fast_enabled = False
        proj.bypass_enabled = True
        proj.bypass_queue_frozen = False
        db.commit()
    assert mining_complete(project) is False
    with Session() as db:
        proj = db.get(Project, project)
        proj.bypass_queue_frozen = True
        db.add(
            BypassTarget(
                project_id=project,
                file_path="docs/old-vulns/cve.md",
                title="旧洞",
                status="queued",
            )
        )
        db.commit()
    assert mining_complete(project) is False
    with Session() as db:
        for row in db.query(BypassTarget).filter(BypassTarget.project_id == project).all():
            row.status = "done"
            row.verdict = "still_patched"
        db.commit()
    assert mining_complete(project) is True
    assert project_complete_gates(project) is True


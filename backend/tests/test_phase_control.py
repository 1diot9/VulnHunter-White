"""Project pause / 侦察子阶段重跑 / generation cancel."""

from __future__ import annotations

import pytest

from app.agent.checkpoint import LoopCheckpoint, load_checkpoint, save_checkpoint
from app.services import pipeline
from app.services.ingest import build_file_index
from app.services.live_log import event_matches_phase
from app.services.paths import docs_dir, old_vulns_dir
from app.tools.phase_recon import (
    clear_old_vuln_completion,
    recon_map_ready,
    recon_old_vulns_ready,
)


def _sample_messages() -> list[dict]:
    return [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "orig-task"},
        {"role": "assistant", "content": "I was looking at login"},
    ]


def test_project_pause_pauses_all_phases(tmp_env, project):
    pipeline.request_pause(project)
    assert pipeline._phase_is_paused(project, "recon")
    assert pipeline._phase_is_paused(project, "worker")
    assert pipeline._phase_is_paused(project, "reviewer")
    assert pipeline._phase_is_paused(project, "verifier")
    assert pipeline.get_phase_states(project)["project_paused"] is True


def test_completed_project_pause_keeps_completed_status(tmp_env, project):
    from app.models import Project, SessionLocal

    with SessionLocal() as db:
        p = db.get(Project, project)
        p.status = "completed"
        p.phase = "done"
        db.commit()
    pipeline.request_pause(project)
    with SessionLocal() as db:
        p = db.get(Project, project)
        assert p.status == "completed"
    assert pipeline.get_phase_states(project)["project_paused"] is False


def test_generation_cancel_only_old_loop(tmp_env, project):
    old = pipeline._loop_cancel(project, "worker")
    assert old.is_set() is False
    pipeline._bump_phase_generation(project, "worker")
    assert old.is_set() is True
    nxt = pipeline._loop_cancel(project, "worker")
    assert nxt.is_set() is False


def test_event_matches_mine_excludes_fix():
    assert event_matches_phase({"phase": "worker"}, "mine")
    assert not event_matches_phase({"phase": "fix"}, "mine")
    assert not event_matches_phase({"phase": "fast-worker"}, "mine")
    assert event_matches_phase({"phase": "fast-worker"}, "fast")
    assert event_matches_phase({"phase": "sink-triage"}, "fast")
    assert not event_matches_phase({"phase": "worker"}, "fast")
    assert event_matches_phase({"phase": "fix"}, "fix")
    assert not event_matches_phase({"phase": "worker"}, "fix")
    assert event_matches_phase({"phase": "fix"}, "worker")
    assert event_matches_phase({"phase": "worker"}, "worker")
    assert event_matches_phase({"phase": "fast-worker"}, "worker")
    assert event_matches_phase({"phase": "bypass-worker"}, "bypass")
    assert not event_matches_phase({"phase": "bypass-worker"}, "fast")
    assert event_matches_phase({"phase": "bypass-worker"}, "worker")


def test_recon_map_rerun_keeps_docs_and_starts_refresh(tmp_env, project, monkeypatch):
    docs = docs_dir(project)
    (docs / "code-map.md").write_text("# 地图\n入口\n", encoding="utf-8")
    (docs / "auth.md").write_text("# 鉴权\nJWT\n", encoding="utf-8")
    assert recon_map_ready(project)

    started: list[tuple[int, str]] = []

    def fake_refresh(pid, cancel):
        started.append((pid, "map"))
        assert (docs / "code-map.md").read_text(encoding="utf-8").startswith("# 地图")
        assert (docs / "auth.md").read_text(encoding="utf-8").startswith("# 鉴权")
        return True

    monkeypatch.setattr(pipeline, "_run_recon_map_refresh", fake_refresh)
    out = pipeline.request_recon_subphase_rerun(project, "map")
    assert out["ok"] is True
    assert out["subphase"] == "map"
    t = pipeline._recon_rerun_threads.get(project)
    assert t is not None
    t.join(timeout=5)
    assert started == [(project, "map")]
    assert (docs / "code-map.md").is_file()
    assert (docs / "auth.md").is_file()


def test_recon_old_vulns_rerun_clears_complete_keeps_files(tmp_env, project, monkeypatch):
    from app.tools.phase_recon import mark_old_vuln_search_complete

    old = old_vulns_dir(project)
    old.mkdir(parents=True, exist_ok=True)
    (old / "cve-1.md").write_text(
        "---\ntitle: CVE-1\nsummary: s\nfix_status: patched\n---\n\nbody\n",
        encoding="utf-8",
    )
    mark_old_vuln_search_complete(project, note="done")
    assert recon_old_vulns_ready(project)

    started: list[str] = []

    def fake_old(pid, cancel):
        started.append("old")
        assert not recon_old_vulns_ready(pid)
        assert (old / "cve-1.md").is_file()
        return True

    monkeypatch.setattr(pipeline, "_run_recon_old_vulns", fake_old)
    out = pipeline.request_recon_subphase_rerun(project, "old_vulns")
    assert out["subphase"] == "old_vulns"
    t = pipeline._recon_rerun_threads.get(project)
    assert t is not None
    t.join(timeout=5)
    assert started == ["old"]
    assert (old / "cve-1.md").is_file()
    text = (old / "index.md").read_text(encoding="utf-8")
    assert "complete: false" in text.replace(" ", "") or "complete:false" in text.replace(" ", "")


def test_recon_subphase_rerun_requires_ready(tmp_env, project):
    with pytest.raises(ValueError, match="地图/鉴权尚未完成"):
        pipeline.request_recon_subphase_rerun(project, "map")
    with pytest.raises(ValueError, match="历史漏洞尚未完成"):
        pipeline.request_recon_subphase_rerun(project, "old_vulns")


def test_clear_old_vuln_completion_preserves_docs(tmp_env, project):
    from app.tools.phase_recon import mark_old_vuln_search_complete

    old = old_vulns_dir(project)
    old.mkdir(parents=True, exist_ok=True)
    (old / "keep.md").write_text(
        "---\ntitle: Keep\nsummary: s\nfix_status: patched\n---\n\nx\n",
        encoding="utf-8",
    )
    mark_old_vuln_search_complete(project)
    assert recon_old_vulns_ready(project)
    clear_old_vuln_completion(project)
    assert not recon_old_vulns_ready(project)
    assert (old / "keep.md").is_file()


def test_worker_progress_reset_clears_audit_keeps_vulns_and_recon(tmp_env, project, monkeypatch):
    from app.models import BypassTarget, FileWeight, Project, SessionLocal, Sink, Source, Vuln
    from app.services.paths import summaries_dir, workspace_dir

    monkeypatch.setattr(pipeline, "start_audit", lambda pid: None)
    build_file_index(project)
    docs = docs_dir(project)
    (docs / "code-map.md").write_text("# 地图\n入口 Main.java\n", encoding="utf-8")
    (docs / "auth.md").write_text("# 鉴权\nJWT\n", encoding="utf-8")
    rounds = workspace_dir(project) / "rounds"
    rounds.mkdir(parents=True, exist_ok=True)
    (rounds / "round-1.md").write_text("## 本轮入口\nMain.java\n", encoding="utf-8")
    (rounds / "fast-round-1.md").write_text("## Sink\nexec\n", encoding="utf-8")
    (rounds / "bypass-round-1.md").write_text("## 绕过\nCVE\n", encoding="utf-8")
    summaries = summaries_dir(project)
    (summaries / "worker-round-1.md").write_text("压缩：已审完。\n", encoding="utf-8")
    (summaries / "fast-worker-round-1.md").write_text("快速扫描摘要应保留。\n", encoding="utf-8")
    (summaries / "bypass-worker-round-1.md").write_text("绕过摘要应保留。\n", encoding="utf-8")
    (summaries / "sink-triage-1.md").write_text("Sink 筛选摘要应保留。\n", encoding="utf-8")
    (summaries / "recon-1.md").write_text("侦察摘要应保留。\n", encoding="utf-8")
    (workspace_dir(project) / "todos-worker-w1.json").write_text("[]", encoding="utf-8")

    with SessionLocal() as db:
        fw = db.query(FileWeight).filter(FileWeight.project_id == project, FileWeight.path.contains("Main.java")).first()
        assert fw is not None
        fw.audited = True
        fw.claimed_by = "worker-old"
        fw.audit_attempts = 3
        skipped = db.query(FileWeight).filter(FileWeight.project_id == project, FileWeight.skipped.is_(True)).first()
        db.add(Source(project_id=project, file_path="app/Main.java", method_name="login", note="入口"))
        db.add(
            Vuln(
                project_id=project,
                title="已确认洞",
                vuln_type="sqli",
                status="confirmed",
                file_path="app/Main.java",
            )
        )
        db.add(
            Vuln(
                project_id=project,
                title="修复中",
                vuln_type="rce",
                status="fixing",
                file_path="app/Main.java",
            )
        )
        db.add(
            Sink(
                project_id=project,
                file_path="app/Main.java",
                line_start=4,
                status="done",
                verdict="noise",
            )
        )
        db.add(
            BypassTarget(
                project_id=project,
                file_path="docs/old-vulns/cve.md",
                title="旧洞",
                status="done",
                verdict="still_patched",
            )
        )
        p = db.get(Project, project)
        p.status = "completed"
        p.phase = "done"
        p.recon_done = True
        db.commit()
        skipped_path = skipped.path if skipped else None

    run_id = pipeline._new_phase_run(project, "worker", "worker", file_path="app/Main.java")
    save_checkpoint(
        LoopCheckpoint(
            project_id=project,
            phase_run_id=run_id,
            role="worker",
            phase="worker",
            system_prompt="s",
            user_prompt="u",
            messages=_sample_messages(),
            file_path="app/Main.java",
        ),
        status="paused",
    )
    fast_run = pipeline._new_phase_run(project, "fast-worker", "fast_worker", file_path="sink:1")
    save_checkpoint(
        LoopCheckpoint(
            project_id=project,
            phase_run_id=fast_run,
            role="fast_worker",
            phase="fast-worker",
            system_prompt="s",
            user_prompt="u",
            messages=_sample_messages(),
            file_path="sink:1",
        ),
        status="paused",
    )
    bypass_run = pipeline._new_phase_run(project, "bypass-worker", "bypass_worker", file_path="bypass:1")
    save_checkpoint(
        LoopCheckpoint(
            project_id=project,
            phase_run_id=bypass_run,
            role="bypass_worker",
            phase="bypass-worker",
            system_prompt="s",
            user_prompt="u",
            messages=_sample_messages(),
            file_path="bypass:1",
        ),
        status="paused",
    )

    states = pipeline.request_worker_progress_reset(project)
    assert states["project_paused"] is True
    assert states["phases"]["worker"]["paused"] is True
    assert load_checkpoint(project, run_id) is None
    assert load_checkpoint(project, fast_run) is not None
    assert load_checkpoint(project, bypass_run) is not None
    assert not pipeline._should_skip_checkpoint(project, "worker")
    assert not (rounds / "round-1.md").exists()
    assert (rounds / "fast-round-1.md").is_file()
    assert (rounds / "bypass-round-1.md").is_file()
    assert not (summaries / "worker-round-1.md").exists()
    assert (summaries / "fast-worker-round-1.md").is_file()
    assert (summaries / "bypass-worker-round-1.md").is_file()
    assert (summaries / "sink-triage-1.md").is_file()
    assert pipeline._next_worker_round_id(project) == 1
    assert not (workspace_dir(project) / "todos-worker-w1.json").exists()
    assert (docs / "code-map.md").is_file()
    assert (docs / "auth.md").is_file()
    assert (summaries / "recon-1.md").is_file()

    with SessionLocal() as db:
        p = db.get(Project, project)
        assert p.status == "paused"
        assert p.phase == "worker"
        assert p.recon_done is True
        files = db.query(FileWeight).filter(FileWeight.project_id == project).all()
        assert files
        assert all(not f.audited and f.claimed_by is None and int(f.audit_attempts or 0) == 0 for f in files)
        if skipped_path:
            skipped = db.query(FileWeight).filter(FileWeight.project_id == project, FileWeight.path == skipped_path).one()
            assert skipped.skipped is True
        assert db.query(Source).filter(Source.project_id == project).count() == 1
        vulns = {v.title: v.status for v in db.query(Vuln).filter(Vuln.project_id == project)}
        assert vulns["已确认洞"] == "confirmed"
        assert vulns["修复中"] == "returned"
        sink = db.query(Sink).filter(Sink.project_id == project).one()
        assert sink.status == "done"
        assert sink.verdict == "noise"
        bypass = db.query(BypassTarget).filter(BypassTarget.project_id == project).one()
        assert bypass.status == "done"
        assert bypass.verdict == "still_patched"


def test_worker_progress_reset_requires_pause(tmp_env, project):
    from app.models import Project, SessionLocal

    with SessionLocal() as db:
        p = db.get(Project, project)
        p.status = "auditing"
        p.phase = "worker"
        db.commit()
    with pytest.raises(ValueError, match="暂停"):
        pipeline.request_worker_progress_reset(project)

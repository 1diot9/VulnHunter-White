from __future__ import annotations

import pytest
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import sessionmaker


@pytest.fixture()
def tmp_env(tmp_path, monkeypatch):
    """Isolate DB + project workspaces under tmp_path."""
    db_path = tmp_path / "test.db"
    projects = tmp_path / "projects"
    projects.mkdir()
    data = tmp_path / "data"
    data.mkdir()

    monkeypatch.setattr("app.config.DB_PATH", db_path)
    monkeypatch.setattr("app.config.PROJECTS_DIR", projects)
    monkeypatch.setattr("app.config.DATA_DIR", data)
    monkeypatch.setattr("app.services.paths.PROJECTS_DIR", projects)
    cli_tools = tmp_path / "cli-tools"
    cli_tools.mkdir()
    monkeypatch.setattr("app.config.settings.cli_tools_dir", str(cli_tools))

    import app.models as models

    # Windows-safe SQLite URL
    url = "sqlite:///" + db_path.resolve().as_posix()
    engine = create_engine(url, connect_args={"check_same_thread": False})
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    models.engine = engine
    models.SessionLocal = Session
    models.Base.metadata.drop_all(bind=engine)
    models.Base.metadata.create_all(bind=engine)

    # Rebind every consumer that already imported SessionLocal
    import app.agent.checkpoint as agent_checkpoint
    import app.agent.loop as agent_loop
    import app.api.auth as api_auth
    import app.api.docker as api_docker
    import app.api.projects as api_projects
    import app.api.settings as api_settings
    import app.api.vulns as api_vulns
    import app.services.asset_proof as asset_proof
    import app.services.ghsa_service as ghsa_service
    import app.services.fofa as fofa_service
    import app.services.http_client as http_client_mod
    import app.services.ingest as ingest
    import app.services.access_token as access_token
    import app.services.llm_settings as llm_settings
    import app.services.old_vuln_crawl as old_vuln_crawl
    import app.services.github_issues as github_issues
    import app.services.github_probe as github_probe
    import app.services.pipeline as pipeline
    import app.services.token_budget as token_budget
    import app.services.verifier as verifier_service
    import app.services.vuln_followup as vuln_followup
    import app.tools as tools
    import app.tools.phase_fast as phase_fast
    import app.tools.phase_bypass as phase_bypass
    import app.tools.phase_recon as phase_recon
    import app.tools.phase_reviewer as phase_reviewer
    import app.tools.phase_verifier as phase_verifier
    import app.tools.phase_attack_chain as phase_attack_chain
    import app.tools.phase_cve_record as phase_cve_record
    import app.tools.phase_worker as phase_worker
    import app.api.discoveries as api_discoveries
    import app.services.github_discover as github_discover
    import app.services.sink_queue as sink_queue
    import app.services.demo_seed as demo_seed
    import app.services.bypass_queue as bypass_queue
    import app.services.conversation as conversation_service
    import app.services.cve_record as cve_record

    for mod in (
        models,
        tools,
        phase_recon,
        phase_worker,
        phase_fast,
        phase_bypass,
        phase_reviewer,
        phase_verifier,
        phase_attack_chain,
        phase_cve_record,
        ingest,
        llm_settings,
        access_token,
        old_vuln_crawl,
        github_issues,
        github_probe,
        github_discover,
        vuln_followup,
        ghsa_service,
        fofa_service,
        http_client_mod,
        verifier_service,
        asset_proof,
        pipeline,
        token_budget,
        sink_queue,
        bypass_queue,
        conversation_service,
        cve_record,
        demo_seed,
        agent_loop,
        agent_checkpoint,
        api_projects,
        api_vulns,
        api_settings,
        api_auth,
        api_docker,
        api_discoveries,
    ):
        monkeypatch.setattr(mod, "SessionLocal", Session, raising=False)

    monkeypatch.setattr("app.config.settings.access_token", "")
    access_token.clear_access_token_cache()
    ingest.reset_indexed_weight_exts_cache()

    from app.services import decompile_java as decompile_java
    from app.services import decompile_store as decompile_store

    decompile_store.reset_engine()
    decompile_java._bytecode_present_mem.clear()

    assert inspect(engine).has_table("projects")
    assert inspect(engine).has_table("vulns")
    assert inspect(engine).has_table("sinks")
    assert inspect(engine).has_table("bypass_targets")
    assert inspect(engine).has_table("attack_chains")
    assert inspect(engine).has_table("custom_audit_modes")
    assert inspect(engine).has_table("github_candidates")

    with Session() as db:
        if db.query(models.AppSettings).first() is None:
            db.add(models.AppSettings())
            db.commit()
        row = db.query(models.AppSettings).first()
        if row is not None:
            row.cli_tools_dir = str(cli_tools)
            db.commit()

    from app.tools import register_all_tools

    register_all_tools()
    http_client_mod.reset_proxy_skip()
    pipeline.reset_runtime_state()
    from app.services.live_log import live_log

    live_log.reset_runtime_state()

    yield {
        "db_path": db_path,
        "projects": projects,
        "cli_tools": cli_tools,
        "Session": Session,
        "models": models,
        "engine": engine,
    }

    for ev in list(pipeline._cancel_events.values()):
        ev.set()
    pipeline.reset_runtime_state()
    models.Base.metadata.drop_all(bind=engine)
    engine.dispose()


@pytest.fixture()
def project(tmp_env):
    models = tmp_env["models"]
    Session = tmp_env["Session"]
    with Session() as db:
        p = models.Project(name="demo", source_type="zip", status="recon", phase="recon")
        db.add(p)
        db.commit()
        db.refresh(p)
        pid = p.id
    from app.services.paths import ensure_project_dirs, src_dir

    ensure_project_dirs(pid)
    src = src_dir(pid)
    (src / "app").mkdir(parents=True, exist_ok=True)
    (src / "app" / "Main.java").write_text(
        "public class Main { public void login() {} }\n",
        encoding="utf-8",
    )
    (src / "node_modules" / "x").mkdir(parents=True, exist_ok=True)
    (src / "node_modules" / "x" / "index.js").write_text("module.exports=1\n", encoding="utf-8")
    (src / "tests").mkdir(parents=True, exist_ok=True)
    (src / "tests" / "a_test.py").write_text("def test_x(): pass\n", encoding="utf-8")
    return pid

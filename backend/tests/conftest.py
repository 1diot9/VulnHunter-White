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
    import app.api.projects as api_projects
    import app.api.settings as api_settings
    import app.api.vulns as api_vulns
    import app.services.ghsa_service as ghsa_service
    import app.services.ingest as ingest
    import app.services.llm_settings as llm_settings
    import app.services.pipeline as pipeline
    import app.tools as tools
    import app.tools.phase_recon as phase_recon
    import app.tools.phase_reviewer as phase_reviewer
    import app.tools.phase_worker as phase_worker

    for mod in (
        models,
        tools,
        phase_recon,
        phase_worker,
        phase_reviewer,
        ingest,
        llm_settings,
        ghsa_service,
        pipeline,
        agent_loop,
        agent_checkpoint,
        api_projects,
        api_vulns,
        api_settings,
    ):
        monkeypatch.setattr(mod, "SessionLocal", Session, raising=False)

    assert inspect(engine).has_table("projects")
    assert inspect(engine).has_table("vulns")

    with Session() as db:
        if db.query(models.AppSettings).first() is None:
            db.add(models.AppSettings())
            db.commit()

    from app.tools import register_all_tools

    register_all_tools()
    pipeline.reset_runtime_state()
    from app.services.live_log import live_log

    live_log.reset_runtime_state()

    yield {
        "db_path": db_path,
        "projects": projects,
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

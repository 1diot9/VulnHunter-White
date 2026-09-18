from sqlalchemy import inspect, text


def test_legacy_source_baseline_status_is_dropped_and_insert_works(tmp_env):
    """DBs created while source_baseline_status was mapped keep a NOT NULL
    column with no SQLite DEFAULT. Current INSERT omits it unless we drop it."""
    models = tmp_env["models"]
    engine = tmp_env["engine"]
    Session = tmp_env["Session"]

    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE projects ADD COLUMN source_baseline_status VARCHAR(32) NOT NULL"))
    cols = {c["name"] for c in inspect(engine).get_columns("projects")}
    assert "source_baseline_status" in cols

    models.ensure_schema()
    insp = inspect(engine)
    insp.clear_cache()
    cols = {c["name"] for c in insp.get_columns("projects")}
    assert "source_baseline_status" not in cols

    with Session() as db:
        p = models.Project(
            name="agentscope-java",
            source_type="github",
            source_url="https://github.com/agentscope-ai/agentscope-java",
        )
        db.add(p)
        db.commit()
        db.refresh(p)
        assert p.id >= 1


def test_legacy_source_baseline_status_with_rows_is_dropped(tmp_env, project):
    models = tmp_env["models"]
    engine = tmp_env["engine"]
    Session = tmp_env["Session"]

    with engine.begin() as conn:
        conn.execute(
            text(
                "ALTER TABLE projects ADD COLUMN source_baseline_status "
                "VARCHAR(32) NOT NULL DEFAULT 'pending'"
            )
        )

    models.ensure_schema()
    insp = inspect(engine)
    insp.clear_cache()
    cols = {c["name"] for c in insp.get_columns("projects")}
    assert "source_baseline_status" not in cols

    with Session() as db:
        existing = db.get(models.Project, project)
        assert existing is not None
        extra = models.Project(name="next", source_type="zip")
        db.add(extra)
        db.commit()
        db.refresh(extra)
        assert extra.id != project

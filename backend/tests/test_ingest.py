from __future__ import annotations

from app.services.ingest import (
    build_file_index,
    detect_identity,
    expand_file_index,
    indexed_weight_exts,
    is_test_path,
    path_source_ext,
)
from app.services.paths import src_dir


def test_is_test_path():
    assert is_test_path("tests/a_test.py")
    assert is_test_path("src/foo.test.ts")
    assert not is_test_path("app/Main.java")


def test_path_source_ext():
    assert path_source_ext("app/Main.java") == ".java"
    assert path_source_ext("app\\job.FTL") == ".ftl"
    assert path_source_ext("Makefile") is None


def test_build_file_index_skips_deps_and_tests(tmp_env, project):
    models = tmp_env["models"]
    Session = tmp_env["Session"]
    n = build_file_index(project)
    assert n >= 1
    with Session() as db:
        rows = db.query(models.FileWeight).filter(models.FileWeight.project_id == project).all()
        paths = {r.path.replace("\\", "/") for r in rows}
        assert any(p.endswith("Main.java") for p in paths)
        assert not any("node_modules" in p for p in paths)
        test_rows = [r for r in rows if "test" in r.path.lower()]
        assert test_rows
        assert all(r.skipped for r in test_rows)


def test_expand_file_index_appends_templates_without_wiping(tmp_env, project):
    models = tmp_env["models"]
    Session = tmp_env["Session"]
    src = src_dir(project)
    (src / "app" / "job.ftl").write_text("<#-- view -->\n", encoding="utf-8")
    (src / "app" / "mapper.xml").write_text("<mapper/>\n", encoding="utf-8")
    (src / "app" / "pom.xml").write_text("<project/>\n", encoding="utf-8")
    (src / ".flattened-pom.xml").write_text("<project/>\n", encoding="utf-8")
    (src / "tests" / "job.ftl").write_text("<#-- test -->\n", encoding="utf-8")
    n = build_file_index(project)
    with Session() as db:
        java = (
            db.query(models.FileWeight)
            .filter(models.FileWeight.project_id == project, models.FileWeight.path == "app/Main.java")
            .one()
        )
        java.weight = 80
        db.commit()

    out = expand_file_index(project, [".FTL", "xml", ".png"])
    assert out["exts"] == [".ftl", ".xml"]
    assert out["rejected"] == [".png"]
    assert out["added_count"] == 3
    assert out["skipped_test"] == 1
    paths = set(out["added"])
    assert "app/job.ftl" in paths
    assert "app/mapper.xml" in paths
    assert "tests/job.ftl" in paths
    assert "app/pom.xml" not in paths
    assert ".flattened-pom.xml" not in paths

    with Session() as db:
        rows = {r.path.replace("\\", "/"): r for r in db.query(models.FileWeight).filter(models.FileWeight.project_id == project).all()}
        assert len(rows) == n + 3
        assert rows["app/Main.java"].weight == 80
        assert rows["app/job.ftl"].weight is None
        assert rows["app/job.ftl"].skipped is False
        assert rows["tests/job.ftl"].skipped is True
        assert rows["tests/job.ftl"].weight == 0

    again = expand_file_index(project, [".ftl"])
    assert again["added_count"] == 0

    with Session() as db:
        exts = indexed_weight_exts(db, [project])[project]
    by_ext = {row["ext"]: row for row in exts}
    assert by_ext[".java"]["agent_added"] is False
    assert by_ext[".ftl"] == {"ext": ".ftl", "agent_added": True, "files": 2}
    assert by_ext[".xml"] == {"ext": ".xml", "agent_added": True, "files": 1}


def test_detect_identity_from_package_json(tmp_env, project):
    src = src_dir(project)
    (src / "package.json").write_text('{"name":"demo-app"}\n', encoding="utf-8")
    assert detect_identity(src) == "demo-app"
    assert detect_identity(src, "https://github.com/acme/widget.git") == "acme/widget"


def test_clone_github_replaces_nonempty_src(tmp_env, project, monkeypatch):
    from pathlib import Path

    from app.services.ingest import clone_github
    from app.services.paths import project_root

    dest = project_root(project) / "src"
    gitdir = dest / ".git"
    gitdir.mkdir(parents=True, exist_ok=True)
    head = gitdir / "HEAD"
    head.write_text("ref: refs/heads/main\n", encoding="utf-8")
    head.chmod(0o444)

    def fake_run(cmd, **kwargs):
        target = Path(cmd[-1])
        assert cmd[:3] == ["git", "clone", "--depth"]
        assert not target.exists()
        target.mkdir(parents=True, exist_ok=True)
        (target / "README.md").write_text("ok\n", encoding="utf-8")

        class P:
            returncode = 0
            stderr = ""
            stdout = "cloned"

        return P()

    monkeypatch.setattr("app.services.ingest.subprocess.run", fake_run)
    out = clone_github(project, "https://github.com/halo-dev/halo")
    assert out == dest
    assert (out / "README.md").read_text(encoding="utf-8") == "ok\n"

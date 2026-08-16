from __future__ import annotations

from app.services.ingest import build_file_index, detect_identity, is_test_path
from app.services.paths import src_dir


def test_is_test_path():
    assert is_test_path("tests/a_test.py")
    assert is_test_path("src/foo.test.ts")
    assert not is_test_path("app/Main.java")


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

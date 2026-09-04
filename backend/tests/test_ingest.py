from __future__ import annotations

import os
from pathlib import Path

import pytest

from app.services.ingest import (
    backfill_missing_source_exts,
    build_file_index,
    detect_identity,
    expand_file_index,
    indexed_weight_exts,
    is_test_path,
    path_source_ext,
    refresh_file_index_after_sync,
    sync_github_source,
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

    lua = expand_file_index(project, [".lua"])
    assert lua["rejected"] == []
    assert lua["exts"] == [".lua"]

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
        assert cmd[:6] == [
            "git",
            "-c",
            "core.longpaths=true",
            "clone",
            "-c",
            "core.longpaths=true",
        ]
        assert "--depth" in cmd
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


def test_windows_long_path_prefix():
    from app.services.paths import strip_windows_long_path, windows_long_path

    p = Path("C:/tmp/repo") if os.name == "nt" else Path("/tmp/repo")
    out = windows_long_path(p)
    if os.name != "nt":
        assert out == p
        return
    text = str(out)
    assert text.startswith("\\\\?\\")
    stripped = strip_windows_long_path(out)
    assert stripped == Path(os.path.abspath(p))
    assert strip_windows_long_path(out) == strip_windows_long_path(windows_long_path(out))


@pytest.mark.skipif(os.name != "nt", reason="MAX_PATH is a Windows limitation")
def test_collect_and_rmtree_long_paths(tmp_env, project):
    from app.services.ingest import _collect
    from app.services.paths import force_rmtree, src_dir, windows_long_path

    src = src_dir(project)
    rel_parts = ["deep"] + ["n" * 12] * 18
    dest_dir = src.joinpath(*rel_parts)
    long_dir = windows_long_path(dest_dir)
    long_dir.mkdir(parents=True, exist_ok=True)
    (long_dir / "DeepMain.java").write_text("class DeepMain {}\n", encoding="utf-8")
    files = _collect(src)
    rels = {str(p.relative_to(src)).replace("\\", "/") for p in files}
    expected = "/".join(rel_parts + ["DeepMain.java"])
    assert expected in rels

    force_rmtree(src / "deep")
    assert not windows_long_path(src / "deep").exists()


def test_build_file_index_includes_clojure(tmp_env, project):
    models = tmp_env["models"]
    Session = tmp_env["Session"]
    src = src_dir(project)
    (src / "metabase").mkdir(parents=True, exist_ok=True)
    (src / "metabase" / "api.clj").write_text("(ns metabase.api)\n", encoding="utf-8")
    n = build_file_index(project)
    assert n >= 2
    with Session() as db:
        paths = {
            r.path.replace("\\", "/")
            for r in db.query(models.FileWeight).filter(models.FileWeight.project_id == project)
        }
        assert "metabase/api.clj" in paths
        assert any(p.endswith("Main.java") for p in paths)


def test_backfill_missing_source_exts_indexes_new_languages(tmp_env, project, monkeypatch):
    models = tmp_env["models"]
    Session = tmp_env["Session"]
    src = src_dir(project)
    (src / "metabase").mkdir(parents=True, exist_ok=True)
    (src / "metabase" / "api.clj").write_text("(ns metabase.api)\n", encoding="utf-8")
    from app.services import ingest as ingest_mod

    original = ingest_mod.SOURCE_EXTS
    monkeypatch.setattr(
        ingest_mod,
        "SOURCE_EXTS",
        frozenset(ext for ext in original if ext not in {".clj", ".cljs", ".cljc"}),
    )
    build_file_index(project)
    with Session() as db:
        paths = {
            r.path.replace("\\", "/")
            for r in db.query(models.FileWeight).filter(models.FileWeight.project_id == project)
        }
        assert "metabase/api.clj" not in paths

    monkeypatch.setattr(ingest_mod, "SOURCE_EXTS", original)
    out = backfill_missing_source_exts(project)
    assert ".clj" in out["exts"]
    assert out["added_count"] >= 1
    assert "metabase/api.clj" in out["added"]
    again = backfill_missing_source_exts(project)
    assert again["added_count"] == 0


def test_parse_ls_remote_head_and_auth_url():
    from app.services.ingest import _authenticated_github_url, _parse_ls_remote_head

    assert _parse_ls_remote_head("abc1234deadbeef\tHEAD\n") == "abc1234deadbeef"
    assert (
        _parse_ls_remote_head("ref: refs/heads/main\tHEAD\nabc1234deadbeef\tHEAD\n")
        == "abc1234deadbeef"
    )
    assert _authenticated_github_url("https://github.com/acme/demo", pat="ghp_x") == (
        "https://ghp_x@github.com/acme/demo.git"
    )


class _GitProc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_refresh_file_index_after_sync_add_remove_unaudit(tmp_env, project):
    models = tmp_env["models"]
    Session = tmp_env["Session"]
    src = src_dir(project)
    (src / "app" / "Old.java").write_text("class Old {}\n", encoding="utf-8")
    build_file_index(project)
    with Session() as db:
        main = (
            db.query(models.FileWeight)
            .filter(models.FileWeight.project_id == project, models.FileWeight.path == "app/Main.java")
            .one()
        )
        main.audited = True
        main.weight = 100
        main.claimed_by = "w1"
        old = (
            db.query(models.FileWeight)
            .filter(models.FileWeight.project_id == project, models.FileWeight.path == "app/Old.java")
            .one()
        )
        old.audited = True
        old.weight = 80
        db.commit()

    (src / "app" / "Old.java").unlink()
    (src / "app" / "New.java").write_text("class New {}\n", encoding="utf-8")
    (src / "app" / "Main.java").write_text("public class Main { public void login() { int x = 1; } }\n", encoding="utf-8")

    out = refresh_file_index_after_sync(project, ["app/Main.java", "app/Old.java", "app/New.java"])
    assert out["added"] == 1
    assert out["removed"] == 1
    assert out["unaudited"] == 1

    with Session() as db:
        rows = {
            r.path.replace("\\", "/"): r
            for r in db.query(models.FileWeight).filter(models.FileWeight.project_id == project)
        }
        assert "app/Old.java" not in rows
        assert rows["app/New.java"].audited is False
        assert rows["app/New.java"].weight is None
        assert rows["app/Main.java"].audited is False
        assert rows["app/Main.java"].claimed_by is None
        assert rows["app/Main.java"].weight == 100


def test_sync_github_source_skips_zip(tmp_env, project):
    out = sync_github_source(project)
    assert out["skipped"] is True
    assert out["updated"] is False
    assert out["error"] is None


def test_sync_github_source_no_update(tmp_env, project, monkeypatch):
    from app.models import Project, SessionLocal
    from app.services import ingest as ingest_mod
    from app.services.paths import src_dir as src_of

    with SessionLocal() as db:
        p = db.get(Project, project)
        p.source_type = "github"
        p.source_url = "https://github.com/owner/demo"
        db.commit()
    (src_of(project) / ".git").mkdir(parents=True, exist_ok=True)

    def fake_git(args, **kwargs):
        if args[:1] == ["ls-remote"]:
            return _GitProc(stdout="abc1234deadbeef\tHEAD\n")
        if args[:2] == ["rev-parse", "HEAD"]:
            return _GitProc(stdout="abc1234deadbeef\n")
        raise AssertionError(args)

    monkeypatch.setattr(ingest_mod, "_run_git", fake_git)
    out = sync_github_source(project)
    assert out["skipped"] is False
    assert out["updated"] is False
    assert out["error"] is None


def test_sync_github_source_fetches_when_head_moved(tmp_env, project, monkeypatch):
    from app.models import FileWeight, Project, SessionLocal
    from app.services import ingest as ingest_mod
    from app.services.paths import src_dir as src_of

    src = src_of(project)
    (src / ".git").mkdir(parents=True, exist_ok=True)
    build_file_index(project)
    with SessionLocal() as db:
        p = db.get(Project, project)
        p.source_type = "github"
        p.source_url = "https://github.com/owner/demo"
        main = (
            db.query(FileWeight)
            .filter(FileWeight.project_id == project, FileWeight.path == "app/Main.java")
            .one()
        )
        main.audited = True
        main.weight = 100
        db.commit()

    commands: list[str] = []

    def fake_git(args, **kwargs):
        commands.append(args[0])
        if args[:1] == ["ls-remote"]:
            return _GitProc(stdout="ffffffffffffffffffffffffffffffffffffffff\tHEAD\n")
        if args[:2] == ["rev-parse", "HEAD"]:
            if "fetch" in commands:
                return _GitProc(stdout="ffffffffffffffffffffffffffffffffffffffff\n")
            return _GitProc(stdout="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n")
        if args[:1] == ["fetch"]:
            return _GitProc()
        if args[:1] == ["diff"]:
            return _GitProc(stdout="app/Main.java\0app/New.java\0")
        if args[:1] == ["reset"]:
            (src / "app" / "New.java").write_text("class New {}\n", encoding="utf-8")
            (src / "app" / "Main.java").write_text("class Main { void n() {} }\n", encoding="utf-8")
            return _GitProc()
        raise AssertionError(args)

    monkeypatch.setattr(ingest_mod, "_run_git", fake_git)
    out = sync_github_source(project)
    assert out["updated"] is True
    assert out["old_sha"].startswith("aaa")
    assert out["new_sha"].startswith("fff")
    assert "app/Main.java" in out["changed_paths"]
    assert out["index"]["added"] == 1
    assert out["index"]["unaudited"] == 1
    with SessionLocal() as db:
        rows = {
            r.path: r
            for r in db.query(FileWeight).filter(FileWeight.project_id == project)
        }
        assert rows["app/Main.java"].audited is False
        assert rows["app/New.java"].weight is None


def test_sync_github_source_ls_remote_failure(tmp_env, project, monkeypatch):
    from app.models import Project, SessionLocal
    from app.services import ingest as ingest_mod
    from app.services.paths import src_dir as src_of

    with SessionLocal() as db:
        p = db.get(Project, project)
        p.source_type = "github"
        p.source_url = "https://github.com/owner/demo"
        db.commit()
    (src_of(project) / ".git").mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(
        ingest_mod,
        "_run_git",
        lambda args, **kwargs: _GitProc(returncode=1, stderr="Repository not found"),
    )
    out = sync_github_source(project)
    assert out["updated"] is False
    assert "Repository not found" in (out["error"] or "")

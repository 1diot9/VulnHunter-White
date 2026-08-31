"""Tests for extension filtering and AddSourceExt with remove support."""

from __future__ import annotations

import pytest

from app.services.ingest import (
    NOISY_EXT_THRESHOLD,
    BROAD_SCAN_EXTS,
    NOISY_EXTS,
    SOURCE_EXTS,
    build_file_index_with_exts,
    prefilter_extensions,
    is_test_path,
)
from app.services.paths import docs_dir, src_dir
from app.tools import ToolContext, registry


def _ctx(project_id: int, role: str = "recon_source_ext", **kwargs) -> ToolContext:
    return ToolContext(project_id=project_id, role=role, phase=role, **kwargs)


class TestPreFilterExtensions:
    """Test code-based pre-filtering of extensions."""

    def test_prefilter_identifies_noisy_exts(self, tmp_env, project):
        """Test that prefilter identifies noisy extensions correctly."""
        src = src_dir(project)
        # Create files with noisy extensions (more than threshold)
        for i in range(NOISY_EXT_THRESHOLD + 100):
            (src / f"config_{i}.json").write_text("{}", encoding="utf-8")
        for i in range(100):
            (src / f"data_{i}.xml").write_text("<xml/>", encoding="utf-8")
        for i in range(50):
            (src / f"prop_{i}.properties").write_text("key=value\n", encoding="utf-8")
        # Create some source files (already have Main.java from fixture)

        result = prefilter_extensions(project)

        assert ".json" in result["noisy_exts"]
        assert ".xml" in result["active_exts"]  # Below threshold
        assert ".properties" in result["active_exts"]  # Below threshold
        assert ".java" in result["active_exts"]  # SOURCE_EXT
        assert result["skipped_count"] >= NOISY_EXT_THRESHOLD + 100

    def test_prefilter_always_includes_source_exts(self, tmp_env, project):
        """Test that SOURCE_EXTS are always included, even if in NOISY_EXTS."""
        src = src_dir(project)
        # Create many Java files (SOURCE_EXTS but also in BROAD_SCAN_EXTS)
        for i in range(1000):
            (src / f"Service_{i}.java").write_text("public class Service {}", encoding="utf-8")

        result = prefilter_extensions(project)

        # Java should be in active, not noisy
        assert ".java" in result["active_exts"]
        assert ".java" not in result["noisy_exts"]

    def test_prefilter_counts_extensions(self, tmp_env, project):
        """Test prefilter counts files correctly."""
        src = src_dir(project)
        # Clear existing files and create specific ones
        for f in list(src.glob("*.java")):
            if f.name != "Main.java":
                f.unlink()
        (src / "extra.java").write_text("public class Extra {}", encoding="utf-8")
        (src / "config.json").write_text("{}", encoding="utf-8")

        result = prefilter_extensions(project)

        # Should count both .java files
        java_count = result["counts"].get(".java", 0)
        assert java_count >= 2  # Main.java + extra.java
        assert ".json" in result["counts"]


class TestIsTestPath:
    """Test is_test_path function."""

    def test_is_test_path_recognizes_test_dirs(self):
        """Test that is_test_path recognizes test directories."""
        assert is_test_path("tests/MainTest.java") is True
        assert is_test_path("test/MainTest.java") is True
        assert is_test_path("__tests__/MainTest.java") is True
        assert is_test_path("spec/MainTest.java") is True
        assert is_test_path("specs/MainTest.java") is True

    def test_is_test_path_recognizes_test_files(self):
        """Test that is_test_path recognizes test file patterns."""
        assert is_test_path("Main_test.java") is True
        assert is_test_path("Main.test.java") is True
        assert is_test_path("Main.spec.java") is True

    def test_is_test_path_rejects_normal_files(self):
        """Test that is_test_path rejects normal files."""
        assert is_test_path("Production.java") is False
        assert is_test_path("Main.java") is False
        assert is_test_path("test_data/Data.java") is False


class TestBuildFileIndexWithExts:
    """Test file indexing with specific extensions."""

    def test_build_with_specific_exts(self, tmp_env, project):
        """Test building file index with specific extension list."""
        src = src_dir(project)
        models = tmp_env["models"]
        Session = tmp_env["Session"]

        # Clean up all files recursively
        import shutil

        for item in src.iterdir():
            if item.is_dir() and item.name not in (".", ".."):
                shutil.rmtree(item)
            elif item.is_file():
                item.unlink()

        # Clear DB entries
        with Session() as db:
            db.query(models.FileWeight).filter(
                models.FileWeight.project_id == project
            ).delete()
            db.commit()

        # Create specific files
        (src / "Service.java").write_text("public class Service {}", encoding="utf-8")
        (src / "template.ftl").write_text("<#-- template -->", encoding="utf-8")
        (src / "config.json").write_text("{}", encoding="utf-8")
        (src / "ignored.md").write_text("# Readme", encoding="utf-8")

        count = build_file_index_with_exts(project, [".java", ".ftl"])

        assert count == 2  # Service.java and template.ftl

    def test_build_skips_test_paths(self, tmp_env, project):
        """Test that test paths are skipped in indexing."""
        src = src_dir(project)
        models = tmp_env["models"]
        Session = tmp_env["Session"]

        # Clean up
        import shutil

        for item in src.iterdir():
            if item.is_dir() and item.name not in (".", ".."):
                shutil.rmtree(item)
            elif item.is_file():
                item.unlink()

        # Clear DB entries
        with Session() as db:
            db.query(models.FileWeight).filter(
                models.FileWeight.project_id == project
            ).delete()
            db.commit()

        # Create files - using exact directory names that match the test path regex
        (src / "Production.java").write_text("public class Production {}", encoding="utf-8")
        (src / "tests").mkdir(parents=True, exist_ok=True)
        (src / "tests" / "MainTest.java").write_text("public class MainTest {}", encoding="utf-8")
        (src / "__tests__").mkdir(parents=True, exist_ok=True)
        (src / "__tests__" / "Data.java").write_text("public class Data {}", encoding="utf-8")

        # Verify test paths are recognized
        assert is_test_path("tests/MainTest.java") is True
        assert is_test_path("__tests__/Data.java") is True
        assert is_test_path("Production.java") is False

        # Use build_file_index (which wipes existing) instead to test properly
        from app.services.ingest import build_file_index

        build_file_index(project)

        # Now check the DB
        with Session() as db:
            rows = db.query(models.FileWeight).filter(
                models.FileWeight.project_id == project
            ).all()
            non_skipped = [r for r in rows if not r.skipped]
            skipped = [r for r in rows if r.skipped]

        # Should have 1 non-skipped (Production.java) and 2 skipped (test files)
        assert len(non_skipped) == 1
        assert non_skipped[0].path == "Production.java"
        assert len(skipped) == 2


class TestAddSourceExtRemoveSupport:
    """Test AddSourceExt with remove_exts parameter."""

    def test_add_source_ext_removes_extensions(self, tmp_env, project):
        """Test that AddSourceExt can remove extensions."""
        # First add .json using AddSourceExt (not expand_file_index)
        result = registry.dispatch(
            _ctx(project),
            "AddSourceExt",
            {"exts": [".json"]},
        )
        assert result["ok"] is True

        # Now remove it
        result = registry.dispatch(
            _ctx(project),
            "AddSourceExt",
            {"remove_exts": [".json"], "done": True},
        )

        assert result["ok"] is True
        assert ".json" in result["removed_exts"]
        assert ".json" not in result["exts"]

    def test_add_and_remove_same_session(self, tmp_env, project):
        """Test adding and removing extensions in same session."""
        # First add .json using AddSourceExt
        registry.dispatch(
            _ctx(project),
            "AddSourceExt",
            {"exts": [".json"]},
        )

        # Remove .json and add .ftl
        result = registry.dispatch(
            _ctx(project),
            "AddSourceExt",
            {"exts": [".ftl"], "remove_exts": [".json"], "done": True},
        )

        assert result["ok"] is True
        assert ".ftl" in result["exts"]
        assert ".json" in result["removed_exts"]
        assert ".json" not in result["exts"]

    def test_add_source_ext_done_triggers_scan(self, tmp_env, project):
        """Test that AddSourceExt(done=true) triggers file scan."""
        result = registry.dispatch(
            _ctx(project),
            "AddSourceExt",
            {"exts": [".ftl"], "done": True},
        )

        assert result["ok"] is True
        assert result["done"] is True
        # scanned should be >= 0 since we're adding .ftl (may be 0 if no .ftl files exist)
        assert "scanned" in result

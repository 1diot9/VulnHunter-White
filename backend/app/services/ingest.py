"""Ingest GitHub / zip into project src/, build file weight index."""

from __future__ import annotations

import re
import shutil
import subprocess
import zipfile
from pathlib import Path

from ..models import FileWeight, Project, SessionLocal
from .paths import ensure_project_dirs, force_rmtree, project_root, src_dir

SOURCE_EXTS = frozenset(
    {
        ".java",
        ".kt",
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".mjs",
        ".cjs",
        ".py",
        ".php",
        ".go",
        ".rb",
        ".cs",
        ".aspx",
        ".jsp",
        ".vue",
    }
)

IGNORE_DIR_NAMES = frozenset(
    {
        ".git",
        "node_modules",
        "vendor",
        "target",
        "dist",
        "build",
        ".venv",
        "venv",
        "__pycache__",
        ".idea",
        ".vscode",
        "coverage",
        ".next",
        "out",
        "bin",
        "obj",
        ".gradle",
        ".mvn",
    }
)

IGNORE_FILE_SUFFIXES = (
    ".min.js",
    ".min.css",
    ".map",
    ".lock",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".jar",
    ".war",
    ".zip",
    ".tar",
    ".gz",
    ".class",
    ".o",
    ".so",
    ".dll",
    ".exe",
)

TEST_PATH_RE = re.compile(
    r"(^|[/\\])(test|tests|__tests__|spec|specs)([/\\]|$)|_test\.|\.test\.|\.spec\.",
    re.I,
)


def _should_ignore_dir(name: str) -> bool:
    return name in IGNORE_DIR_NAMES or name.startswith(".")


def _should_ignore_file(path: Path) -> bool:
    name = path.name.lower()
    if name in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "composer.lock"):
        return True
    return any(name.endswith(suf) for suf in IGNORE_FILE_SUFFIXES)


def is_test_path(rel: str) -> bool:
    return bool(TEST_PATH_RE.search(rel.replace("\\", "/")))


def iter_source_files(src_root: Path) -> list[Path]:
    results: list[Path] = []
    if not src_root.exists():
        return results
    for dirpath, dirnames, filenames in src_root.walk() if hasattr(src_root, "walk") else _walk(src_root):
        # pathlib.Path.walk is 3.12+; fallback below
        pass
    # Use os.walk style via fallback always for compatibility
    return _collect(src_root)


def _walk(root: Path):
    import os

    for dirpath, dirnames, filenames in os.walk(root):
        yield Path(dirpath), dirnames, filenames


def _collect(src_root: Path) -> list[Path]:
    import os

    results: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(src_root):
        dirnames[:] = [d for d in dirnames if not _should_ignore_dir(d)]
        for fn in filenames:
            p = Path(dirpath) / fn
            if _should_ignore_file(p):
                continue
            if p.suffix.lower() not in SOURCE_EXTS:
                continue
            results.append(p)
    return results


def detect_identity(src_root: Path, github_url: str | None = None) -> str | None:
    if github_url:
        m = re.search(r"github\.com[/:]([^/]+)/([^/\.]+)", github_url)
        if m:
            return f"{m.group(1)}/{m.group(2)}"
    for candidate in (
        src_root / "pom.xml",
        src_root / "package.json",
        src_root / "pyproject.toml",
        src_root / "composer.json",
        src_root / "go.mod",
    ):
        if candidate.exists():
            try:
                text = candidate.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if candidate.name == "package.json":
                m = re.search(r'"name"\s*:\s*"([^"]+)"', text)
                if m:
                    return m.group(1)
            if candidate.name == "go.mod":
                m = re.search(r"^module\s+(\S+)", text, re.M)
                if m:
                    return m.group(1)
            if candidate.name == "pyproject.toml":
                m = re.search(r'name\s*=\s*"([^"]+)"', text)
                if m:
                    return m.group(1)
            if candidate.name == "pom.xml":
                m = re.search(r"<artifactId>([^<]+)</artifactId>", text)
                if m:
                    return m.group(1)
            if candidate.name == "composer.json":
                m = re.search(r'"name"\s*:\s*"([^"]+)"', text)
                if m:
                    return m.group(1)
    return None


def clone_github(project_id: int, url: str, pat: str | None = None) -> Path:
    dest = project_root(project_id) / "src"
    dest.parent.mkdir(parents=True, exist_ok=True)
    # git clone 要求目标不存在或为空；Windows 上残留 .git 只读文件常导致 rmtree 不干净
    force_rmtree(dest)
    clone_url = url.strip()
    if pat and "github.com" in clone_url:
        # https://TOKEN@github.com/owner/repo.git
        clone_url = re.sub(
            r"https://(www\.)?github\.com/",
            f"https://{pat}@github.com/",
            clone_url,
        )
    if not clone_url.endswith(".git") and "github.com" in clone_url:
        clone_url = clone_url.rstrip("/") + ".git"
    proc = subprocess.run(
        ["git", "clone", "--depth", "1", clone_url, str(dest)],
        capture_output=True,
        text=True,
        timeout=600,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"git clone 失败: {proc.stderr or proc.stdout}")
    return dest


def extract_zip(project_id: int, zip_path: Path) -> Path:
    dest = src_dir(project_id)
    force_rmtree(dest)
    dest.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(dest)
    # If zip has a single top-level dir, flatten
    children = [c for c in dest.iterdir() if not c.name.startswith(".")]
    if len(children) == 1 and children[0].is_dir():
        top = children[0]
        for item in top.iterdir():
            shutil.move(str(item), dest / item.name)
        top.rmdir()
    return dest


def build_file_index(project_id: int) -> int:
    """Create FileWeight rows for all source files. Returns count."""
    ensure_project_dirs(project_id)
    root = src_dir(project_id)
    files = _collect(root)
    with SessionLocal() as db:
        db.query(FileWeight).filter(FileWeight.project_id == project_id).delete()
        for fp in files:
            rel = str(fp.relative_to(root)).replace("\\", "/")
            skip = is_test_path(rel)
            db.add(
                FileWeight(
                    project_id=project_id,
                    path=rel,
                    weight=None if not skip else 0,
                    skipped=skip,
                    audited=False,
                    has_source=False,
                )
            )
        proj = db.get(Project, project_id)
        if proj:
            proj.identity = detect_identity(root, proj.source_url)
        db.commit()
    return len(files)

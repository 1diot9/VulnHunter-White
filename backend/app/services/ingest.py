"""Ingest GitHub / zip into project src/, build file weight index."""

from __future__ import annotations

import re
import shutil
import subprocess
import zipfile
from collections import Counter, defaultdict
from pathlib import Path, PurePosixPath
from typing import Any

from sqlalchemy import func

from ..models import FileWeight, Project, SessionLocal
from .paths import (
    ensure_project_dirs,
    force_rmtree,
    project_root,
    src_dir,
    strip_windows_long_path,
    windows_long_path,
)

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
        ".clj",
        ".cljs",
        ".cljc",
        ".scala",
        ".groovy",
        ".rs",
    }
)

# Agent 可按侦察文档追加的模板/映射/配置扩展名（并集，不按语言裁掉 SOURCE_EXTS）
EXTRA_SOURCE_EXTS = frozenset(
    {
        ".ftl",
        ".ftlh",
        ".vm",
        ".jspx",
        ".xml",
        ".html",
        ".htm",
        ".xhtml",
        ".properties",
        ".yml",
        ".yaml",
        ".sql",
        ".json",
        ".twig",
        ".erb",
        ".ejs",
        ".hbs",
        ".mustache",
        ".jinja",
        ".j2",
        ".njk",
        ".phtml",
    }
)

INDEX_SKIP_NAMES = frozenset(
    {
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "poetry.lock",
        "composer.lock",
        "pom.xml",
        "ivy.xml",
        "build.gradle",
        "settings.gradle",
        "build.gradle.kts",
        "settings.gradle.kts",
    }
)

# Extensions that are too numerous and not important - skip by default
# These are high-volume/low-value file types that clutter the index
NOISY_EXTS = frozenset(
    {
        # Configuration files that are rarely security-relevant
        ".properties",
        ".yml",
        ".yaml",
        # Data/interchange formats
        ".json",
        ".xml",
        ".sql",
    }
)

# Broad scan extensions - used for initial pre-filtering only
# Includes SOURCE_EXTS + template/mapping files + extended coverage
BROAD_SCAN_EXTS = SOURCE_EXTS | EXTRA_SOURCE_EXTS

_EXT_RE = re.compile(r"\.[a-z0-9]{1,12}$")
WORKER_ADDED_WEIGHT = 50

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
    if name.startswith(".") or name in INDEX_SKIP_NAMES:
        return True
    return any(name.endswith(suf) for suf in IGNORE_FILE_SUFFIXES)


def normalize_source_ext(ext: str) -> str | None:
    raw = str(ext or "").strip().lower()
    if not raw:
        return None
    if not raw.startswith("."):
        raw = "." + raw
    if "/" in raw or "\\" in raw or ".." in raw:
        return None
    if not _EXT_RE.fullmatch(raw):
        return None
    return raw


def is_indexable_ext(ext: str) -> bool:
    return ext in SOURCE_EXTS or ext in EXTRA_SOURCE_EXTS


def path_source_ext(path: str) -> str | None:
    """Return the lowercase suffix of an indexed path, or None if missing."""
    name = PurePosixPath(str(path or "").replace("\\", "/")).name
    suffix = Path(name).suffix.lower()
    return suffix or None


_INDEXED_EXTS = SOURCE_EXTS | EXTRA_SOURCE_EXTS
_weight_exts_cache: dict[int, tuple[int, list[dict[str, Any]]]] = {}


def reset_indexed_weight_exts_cache() -> None:
    _weight_exts_cache.clear()


def indexed_weight_exts(db, project_ids: list[int]) -> dict[int, list[dict[str, Any]]]:
    """Distinct FileWeight suffixes per project; extras beyond SOURCE_EXTS are Agent-added."""
    ids = list(dict.fromkeys(int(i) for i in project_ids))
    out: dict[int, list[dict[str, Any]]] = {pid: [] for pid in ids}
    if not ids:
        return out
    file_counts = {
        int(pid): int(n or 0)
        for pid, n in (
            db.query(FileWeight.project_id, func.count(FileWeight.id))
            .filter(FileWeight.project_id.in_(ids))
            .group_by(FileWeight.project_id)
        )
    }
    pending: list[int] = []
    for pid in ids:
        n = file_counts.get(pid, 0)
        cached = _weight_exts_cache.get(pid)
        if cached and cached[0] == n:
            out[pid] = cached[1]
        elif n:
            pending.append(pid)
    if not pending:
        return out
    counts: dict[int, Counter[str]] = defaultdict(Counter)
    for pid, path in (
        db.query(FileWeight.project_id, FileWeight.path).filter(FileWeight.project_id.in_(pending)).all()
    ):
        ext = path_source_ext(path)
        if not ext or ext not in _INDEXED_EXTS:
            continue
        counts[int(pid)][ext] += 1
    for pid in pending:
        counter = counts.get(pid) or Counter()
        rows = [
            {
                "ext": ext,
                "agent_added": ext not in SOURCE_EXTS,
                "files": int(n),
            }
            for ext, n in counter.items()
        ]
        rows.sort(key=lambda r: (bool(r["agent_added"]), -int(r["files"]), str(r["ext"])))
        out[pid] = rows
        _weight_exts_cache[pid] = (file_counts.get(pid, 0), rows)
    return out


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


def _collect(src_root: Path, exts: frozenset[str] | None = None) -> list[Path]:
    import os

    allowed = SOURCE_EXTS if exts is None else frozenset(exts)
    results: list[Path] = []
    walk_root = windows_long_path(src_root)
    for dirpath, dirnames, filenames in os.walk(walk_root):
        dirnames[:] = [d for d in dirnames if not _should_ignore_dir(d)]
        for fn in filenames:
            p = strip_windows_long_path(Path(dirpath) / fn)
            if _should_ignore_file(p):
                continue
            if p.suffix.lower() not in allowed:
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
    try:
        from .decompile_java import clear_decompiled

        clear_decompiled(project_id)
    except Exception:  # noqa: BLE001
        pass
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
    # git -c 让本次 clone 的 checkout 绕过 Windows MAX_PATH；clone -c 写入新仓
    # 本地配置，后续 git 操作同样生效。XWiki 等深层树否则会 Filename too long。
    proc = subprocess.run(
        [
            "git",
            "-c",
            "core.longpaths=true",
            "clone",
            "-c",
            "core.longpaths=true",
            "--depth",
            "1",
            clone_url,
            str(dest),
        ],
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
    try:
        from .decompile_java import clear_decompiled

        clear_decompiled(project_id)
    except Exception:  # noqa: BLE001
        pass
    dest.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(windows_long_path(dest))
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


def expand_file_index(
    project_id: int,
    extra_exts: list[str],
    *,
    assign_weight: int | None = None,
) -> dict:
    """Append FileWeight rows for extra extensions without wiping existing marks."""
    accepted: list[str] = []
    rejected: list[str] = []
    seen: set[str] = set()
    for raw in extra_exts:
        ext = normalize_source_ext(raw)
        if ext is None or not is_indexable_ext(ext):
            rejected.append(str(raw))
            continue
        if ext in seen:
            continue
        seen.add(ext)
        accepted.append(ext)
    if not accepted:
        return {
            "added": [],
            "added_count": 0,
            "skipped_test": 0,
            "exts": [],
            "rejected": rejected,
        }

    ensure_project_dirs(project_id)
    root = src_dir(project_id)
    files = _collect(root, frozenset(accepted))
    added: list[str] = []
    skipped_test = 0
    with SessionLocal() as db:
        existing = {
            str(r[0])
            for r in db.query(FileWeight.path).filter(FileWeight.project_id == project_id).all()
        }
        for fp in files:
            rel = str(fp.relative_to(root)).replace("\\", "/")
            if rel in existing:
                continue
            skip = is_test_path(rel)
            weight: int | None
            if skip:
                weight = 0
                skipped_test += 1
            elif assign_weight is not None:
                weight = int(assign_weight)
            else:
                weight = None
            db.add(
                FileWeight(
                    project_id=project_id,
                    path=rel,
                    weight=weight,
                    skipped=skip,
                    audited=False,
                    has_source=False,
                )
            )
            added.append(rel)
            existing.add(rel)
        db.commit()
    return {
        "added": added,
        "added_count": len(added),
        "skipped_test": skipped_test,
        "exts": accepted,
        "rejected": rejected,
    }


def backfill_missing_source_exts(project_id: int) -> dict:
    """Index newly added SOURCE_EXTS without wiping existing marks.

    Older projects were ingested before languages like Clojure landed in the
    default whitelist; recon MarkSource then reports 「未找到文件索引」 for real files.
    """
    with SessionLocal() as db:
        present = {row["ext"] for row in indexed_weight_exts(db, [project_id]).get(project_id) or []}
    missing = [ext for ext in sorted(SOURCE_EXTS) if ext not in present]
    if not missing:
        return {"added": [], "added_count": 0, "skipped_test": 0, "exts": [], "rejected": []}
    return expand_file_index(project_id, missing)


def _count_exts(src_root: Path, exts: frozenset[str]) -> dict[str, int]:
    """Count files per extension in the given set."""
    from collections import Counter

    counts: Counter[str] = Counter()
    if not src_root.exists():
        return dict(counts)
    for dirpath, dirnames, filenames in _walk(src_root):
        dirnames[:] = [d for d in dirnames if not _should_ignore_dir(d)]
        for fn in filenames:
            p = Path(dirpath) / fn
            if _should_ignore_file(p):
                continue
            ext = p.suffix.lower()
            if ext in exts:
                counts[ext] += 1
    return dict(counts)


# Threshold for skipping noisy extensions: if an extension has more files than this, skip it by default
NOISY_EXT_THRESHOLD = 500


def prefilter_extensions(project_id: int) -> dict[str, Any]:
    """Code-based pre-filtering of extensions before Agent review.

    Returns:
        - active_exts: extensions to scan (SOURCE_EXTS + validated EXTRA_SOURCE_EXTS, minus noisy)
        - noisy_exts: extensions skipped due to high volume
        - counts: file counts per extension
        - skipped_count: total files skipped due to noisy extensions
    """
    ensure_project_dirs(project_id)
    root = src_dir(project_id)

    # Count all files with BROAD_SCAN_EXTS
    all_counts = _count_exts(root, BROAD_SCAN_EXTS)

    # Determine which noisy extensions to skip
    noisy: list[str] = []
    active: list[str] = []
    skipped_count = 0

    for ext, count in sorted(all_counts.items(), key=lambda x: -x[1]):
        if count > NOISY_EXT_THRESHOLD and ext in NOISY_EXTS:
            noisy.append(ext)
            skipped_count += count
        else:
            active.append(ext)

    # For SOURCE_EXTS, always include them (they are important source files)
    # Only noisy non-source extensions are skipped
    source_exts_list = list(SOURCE_EXTS)
    for ext in source_exts_list:
        if ext in noisy:
            noisy.remove(ext)
            skipped_count -= all_counts.get(ext, 0)
            active.append(ext)

    return {
        "active_exts": sorted(active),
        "noisy_exts": sorted(noisy),
        "counts": all_counts,
        "skipped_count": skipped_count,
        "threshold": NOISY_EXT_THRESHOLD,
    }


def build_file_index_with_exts(project_id: int, exts: list[str]) -> int:
    """Build FileWeight rows for specified extensions only. Returns count."""
    ensure_project_dirs(project_id)
    root = src_dir(project_id)
    allowed = frozenset(exts)
    files = _collect(root, allowed)
    added = 0
    with SessionLocal() as db:
        existing = {
            str(r[0])
            for r in db.query(FileWeight.path).filter(FileWeight.project_id == project_id).all()
        }
        for fp in files:
            rel = str(fp.relative_to(root)).replace("\\", "/")
            if rel in existing:
                continue
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
            added += 1
            existing.add(rel)
        db.commit()
    return added

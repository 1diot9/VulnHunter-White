"""Historical-vuln GHSA crawl: product keyword from project identity, then Agent writes docs."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..models import Project, SessionLocal
from .ghsa_service import (
    DEFAULT_ECOSYSTEMS,
    DEFAULT_SINCE_DAYS,
    crawl_ghsa,
    filter_new_vulns,
    merge_key,
    write_ghsa_output,
)
from .github_issues import crawl_github_issues, issue_keys_from_text, resolve_project_github_repo
from .live_log import live_log
from .paths import ghsa_new_path, old_vuln_crawl_spec_path, old_vulns_dir, src_dir

_ECOSYSTEM_MARKERS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("maven", ("pom.xml", "build.gradle", "build.gradle.kts")),
    ("npm", ("package.json",)),
    ("pip", ("requirements.txt", "pyproject.toml", "setup.py", "Pipfile")),
    ("composer", ("composer.json",)),
    ("go", ("go.mod",)),
)
_SKIP_DIR_NAMES = frozenset(
    {"node_modules", "target", "dist", "build", ".git", "vendor", "__pycache__", ".venv"}
)


@dataclass
class GhsaCrawlResult:
    ok: bool
    keyword: str
    new_count: int = 0
    skipped: int = 0
    fetched: int = 0
    ghsa_count: int = 0
    issue_count: int = 0
    repo: str = ""
    path: str = "workspace/ghsa_new.json"
    error: str = ""
    errors: list[str] = field(default_factory=list)
    packages: list[str] = field(default_factory=list)


def _slug_keyword(raw: str) -> str:
    text = (raw or "").strip()
    text = re.sub(r"\.git$", "", text, flags=re.I)
    if "/" in text:
        text = text.rstrip("/").rsplit("/", 1)[-1]
    text = text.strip()
    return text[:128]


def default_product_keyword(project_id: int) -> str:
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
    if not proj:
        return ""
    return _slug_keyword(proj.identity or "") or _slug_keyword(proj.name or "")


def infer_ecosystems(project_id: int) -> tuple[str, ...]:
    root = src_dir(project_id)
    if not root.exists():
        return DEFAULT_ECOSYSTEMS
    found: list[str] = []
    seen: set[str] = set()
    name_to_eco = {name.lower(): eco for eco, names in _ECOSYSTEM_MARKERS for name in names}
    for dirpath, dirnames, filenames in os_walk_limited(root, max_depth=3):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIR_NAMES]
        for name in filenames:
            eco = name_to_eco.get(name.lower())
            if eco and eco not in seen:
                seen.add(eco)
                found.append(eco)
        if len(found) >= len(_ECOSYSTEM_MARKERS):
            break
    return tuple(found) if found else DEFAULT_ECOSYSTEMS


def os_walk_limited(root: Path, *, max_depth: int):
    root = root.resolve()
    for dirpath, dirnames, filenames in os.walk(root):
        rel = Path(dirpath).resolve().relative_to(root)
        depth = 0 if str(rel) == "." else len(rel.parts)
        if depth >= max_depth:
            dirnames[:] = []
        yield dirpath, dirnames, filenames


def load_crawl_spec(project_id: int) -> dict[str, Any]:
    path = old_vuln_crawl_spec_path(project_id)
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def save_crawl_spec(
    project_id: int,
    *,
    keyword: str | None = None,
    affects: list[str] | None = None,
    ecosystems: list[str] | None = None,
) -> Path:
    path = old_vuln_crawl_spec_path(project_id)
    existing = load_crawl_spec(project_id)
    kw = _slug_keyword(keyword or "") or str(existing.get("keyword") or "").strip()
    pkgs: list[str] = []
    seen: set[str] = set()
    for raw in list(affects or []) + list(existing.get("affects") or []):
        item = str(raw or "").strip()
        key = item.lower()
        if not item or key in seen:
            continue
        seen.add(key)
        pkgs.append(item)
    ecos = [str(e).strip().lower() for e in (ecosystems or existing.get("ecosystems") or []) if str(e).strip()]
    payload = {
        "keyword": kw,
        "affects": pkgs,
        "ecosystems": ecos,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def collect_old_vuln_skip_keys(project_id: int) -> set[str]:
    keys: set[str] = set()
    old_dir = old_vulns_dir(project_id)
    if not old_dir.exists():
        return keys
    for fp in old_dir.glob("*.md"):
        try:
            text = fp.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        keys.add(merge_key(fp.stem))
        if text.startswith("---"):
            parts = text.split("---", 2)
            blob = parts[1] if len(parts) >= 3 else text
        else:
            blob = text[:800]
        for m in re.finditer(r"CVE-\d{4}-\d+", blob, re.I):
            keys.add(merge_key(m.group(0)))
        for m in re.finditer(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", blob, re.I):
            keys.add(merge_key(m.group(0)))
        keys.update(issue_keys_from_text(text))
    return {k for k in keys if k and k != "UNKNOWN"}


def resolve_crawl_inputs(project_id: int) -> tuple[str, list[str], tuple[str, ...]]:
    spec = load_crawl_spec(project_id)
    keyword = _slug_keyword(str(spec.get("keyword") or "")) or default_product_keyword(project_id)
    affects: list[str] = []
    seen: set[str] = set()
    for raw in spec.get("affects") or []:
        item = str(raw or "").strip()
        key = item.lower()
        if not item or key in seen:
            continue
        seen.add(key)
        affects.append(item)
    ecos_raw = [str(e).strip().lower() for e in (spec.get("ecosystems") or []) if str(e).strip()]
    ecosystems = tuple(ecos_raw) if ecos_raw else infer_ecosystems(project_id)
    return keyword, affects, ecosystems


def run_old_vuln_ghsa_crawl(project_id: int) -> GhsaCrawlResult:
    """Crawl GHSA + GitHub Issues; write workspace/ghsa_new.json for the first Agent pass."""
    keyword, affects, ecosystems = resolve_crawl_inputs(project_id)
    repo = resolve_project_github_repo(project_id)
    out_path = ghsa_new_path(project_id)
    rel = "workspace/ghsa_new.json"
    if not keyword and not repo:
        write_ghsa_output(
            out_path,
            [],
            keyword="",
            meta={"error": "无产品关键词且无 GitHub 仓库", "packages": [], "fetched": 0, "errors": []},
        )
        return GhsaCrawlResult(
            ok=False,
            keyword="",
            error="无产品关键词，无法启动 GHSA / Issues 爬虫",
            path=rel,
        )

    live_log.system(
        project_id,
        "启动 GHSA / GitHub Issues 爬虫收集（"
        + (f"关键词 {keyword}" if keyword else "无关键词")
        + (f"；仓库 {repo}" if repo else "；无 GitHub 仓库，跳过 Issues")
        + (f"；额外包 {', '.join(affects)}" if affects else "")
        + (f"；生态 {','.join(ecosystems)}" if keyword else "")
        + "）",
        source="crawler",
        phase="recon-old-vuln",
        role="recon_old_vuln",
    )

    ghsa_vulns: list[dict[str, Any]] = []
    ghsa_meta: dict[str, Any] = {"fetched": 0, "errors": [], "packages": [keyword, *affects] if keyword else []}
    ghsa_exc: str = ""
    if keyword:
        try:
            ghsa_vulns, ghsa_meta = crawl_ghsa(
                keyword,
                ecosystems=ecosystems,
                since_days=DEFAULT_SINCE_DAYS,
                affects=affects,
            )
        except Exception as exc:  # noqa: BLE001
            ghsa_exc = str(exc)
            ghsa_meta = {
                "error": ghsa_exc,
                "packages": [keyword, *affects],
                "fetched": 0,
                "errors": [ghsa_exc],
            }
            live_log.error(
                project_id,
                f"GHSA 爬虫失败: {exc}",
                phase="recon-old-vuln",
                role="recon_old_vuln",
            )
        else:
            for rec in ghsa_vulns:
                rec.setdefault("source", "ghsa")

    issue_vulns: list[dict[str, Any]] = []
    issue_meta: dict[str, Any] = {"fetched": 0, "errors": [], "repo": repo or ""}
    if repo:
        try:
            issue_vulns, issue_meta = crawl_github_issues(repo, since_days=DEFAULT_SINCE_DAYS)
        except Exception as exc:  # noqa: BLE001
            issue_meta = {"error": str(exc), "repo": repo, "fetched": 0, "errors": [str(exc)]}
            live_log.error(
                project_id,
                f"GitHub Issues 爬虫失败: {exc}",
                phase="recon-old-vuln",
                role="recon_old_vuln",
            )
    else:
        issue_meta = {"repo": "", "fetched": 0, "errors": [], "skipped": "无 GitHub 仓库"}

    skip = collect_old_vuln_skip_keys(project_id)
    combined: list[dict[str, Any]] = []
    seen: set[str] = set()
    for rec in list(ghsa_vulns) + list(issue_vulns):
        key = merge_key(str(rec.get("identifier") or ""))
        if not key or key == "UNKNOWN" or key in seen:
            continue
        seen.add(key)
        combined.append(rec)
    new_vulns, skipped = filter_new_vulns(combined, skip)
    ghsa_new = sum(1 for v in new_vulns if str(v.get("source") or "ghsa") != "github_issue")
    issue_new = sum(1 for v in new_vulns if str(v.get("source") or "") == "github_issue")
    errors = [
        str(e)
        for e in list(ghsa_meta.get("errors") or []) + list(issue_meta.get("errors") or [])
        if e
    ]
    if ghsa_exc and ghsa_exc not in errors:
        errors.insert(0, ghsa_exc)
    fetched = int(ghsa_meta.get("fetched") or 0) + int(issue_meta.get("fetched") or 0)
    meta = {
        **ghsa_meta,
        "skipped": skipped,
        "new": len(new_vulns),
        "ghsa_fetched": int(ghsa_meta.get("fetched") or 0),
        "ghsa_new": ghsa_new,
        "issues": issue_meta,
        "issues_fetched": int(issue_meta.get("fetched") or 0),
        "issues_new": issue_new,
        "repo": repo or "",
        "fetched": fetched,
        "errors": errors,
    }
    write_ghsa_output(out_path, new_vulns, keyword=keyword, meta=meta)

    ghsa_failed = bool(keyword) and bool(ghsa_exc)
    issues_failed = bool(repo) and bool(issue_meta.get("error"))
    ok = not ghsa_failed and not issues_failed
    warn = "; ".join(errors[:3]) if errors and not new_vulns else ""

    live_log.system(
        project_id,
        f"GHSA / Issues 爬虫完成：GHSA 拉取 {meta.get('ghsa_fetched', 0)} 条、Issues 拉取 {meta.get('issues_fetched', 0)} 条，"
        f"去重后新候选 {len(new_vulns)} 条（GHSA {ghsa_new} / Issues {issue_new}）"
        + (f"；跳过已落盘 {skipped}" if skipped else "")
        + (f"；警告 {len(errors)}" if errors else ""),
        source="crawler",
        phase="recon-old-vuln",
        role="recon_old_vuln",
    )
    return GhsaCrawlResult(
        ok=ok,
        keyword=keyword,
        new_count=len(new_vulns),
        skipped=skipped,
        fetched=fetched,
        ghsa_count=ghsa_new,
        issue_count=issue_new,
        repo=repo or "",
        path=rel,
        errors=errors,
        packages=list(ghsa_meta.get("packages") or ([keyword, *affects] if keyword else [])),
        error=warn or (ghsa_exc if ghsa_failed and not new_vulns else ""),
    )

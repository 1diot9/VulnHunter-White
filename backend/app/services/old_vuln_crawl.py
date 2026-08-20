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
    crawl_repo_advisories,
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
# Inherited / leftover groupIds that belong to dependencies, not this product.
# Declared module groupIds still win so mining Spring itself keeps org.springframework.
_THIRD_PARTY_GROUP_PREFIXES = (
    "org.springframework",
    "org.apache",
    "org.hibernate",
    "org.slf4j",
    "ch.qos.logback",
    "org.eclipse",
    "org.junit",
    "org.mockito",
    "org.projectlombok",
    "org.ow2",
    "org.aspectj",
    "org.mybatis",
    "com.baomidou",
    "com.alibaba",
    "com.fasterxml",
    "com.google",
    "com.mysql",
    "com.zaxxer",
    "io.netty",
    "io.lettuce",
    "io.micrometer",
    "io.opentelemetry",
    "io.projectreactor",
    "io.swagger",
    "io.jsonwebtoken",
    "io.grpc",
    "io.vertx",
    "jakarta",
    "javax",
    "redis.clients",
    "org.redisson",
    "org.postgresql",
    "org.mongodb",
    "org.flywaydb",
    "org.liquibase",
    "org.thymeleaf",
    "org.bouncycastle",
    "org.jboss",
    "org.glassfish",
    "org.codehaus",
    "org.yaml",
    "com.nimbusds",
    "com.squareup",
    "org.seleniumhq",
)
_XML_COMMENT_RE = re.compile(r"<!--.*?-->", re.S)
_XML_TAG_BLOCK_RE = {
    tag: re.compile(rf"<{tag}\b[^>]*>.*?</{tag}>", re.I | re.S)
    for tag in (
        "parent",
        "dependencyManagement",
        "dependencies",
        "build",
        "profiles",
        "reporting",
        "pluginManagement",
    )
}
_FIRST_DEP_OR_PLUGIN_RE = re.compile(r"<(dependency|plugin)\b", re.I)


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


def _xml_tag_value(text: str, tag: str) -> str:
    m = re.search(rf"<{tag}>([^<]+)</{tag}>", text, flags=re.I)
    return m.group(1).strip() if m else ""


def _strip_xml_blocks(text: str, *tags: str) -> str:
    out = text
    for tag in tags:
        pattern = _XML_TAG_BLOCK_RE.get(tag)
        if pattern is None:
            pattern = re.compile(rf"<{tag}\b[^>]*>.*?</{tag}>", re.I | re.S)
        out = pattern.sub("", out)
    return out


def is_third_party_maven_group(group_id: str, *, own_groups: set[str] | None = None) -> bool:
    group = (group_id or "").strip().lower()
    if not group:
        return False
    if ":" in group:
        group = group.split(":", 1)[0]
    owned = {g.strip().lower() for g in (own_groups or set()) if str(g).strip()}
    if any(group == g or group.startswith(g + ".") for g in owned):
        return False
    return any(group == prefix or group.startswith(prefix + ".") for prefix in _THIRD_PARTY_GROUP_PREFIXES)


def _package_group_id(pkg: str) -> str:
    text = (pkg or "").strip().lower()
    if not text:
        return ""
    if ":" in text:
        return text.split(":", 1)[0]
    return text if "." in text else ""


def is_dependency_package(pkg: str, *, own_groups: set[str] | None = None) -> bool:
    """True when a GHSA affects= value is a third-party coordinate, not this product."""
    group = _package_group_id(pkg)
    if not group:
        return False
    return is_third_party_maven_group(group, own_groups=own_groups)


def _pom_identity(text: str) -> tuple[str, str, str]:
    """Return (search_group, artifact_id, declared_group).

    Only the module identity is used. Dependency / parent-BOM groupIds are ignored.
    """
    raw = _XML_COMMENT_RE.sub("", text or "")
    parent_block = ""
    parent_m = _XML_TAG_BLOCK_RE["parent"].search(raw)
    if parent_m:
        parent_block = parent_m.group(0)
    parent_group = _xml_tag_value(parent_block, "groupId")
    remainder = _strip_xml_blocks(
        raw,
        "parent",
        "dependencyManagement",
        "dependencies",
        "build",
        "profiles",
        "reporting",
        "pluginManagement",
    )
    cut = _FIRST_DEP_OR_PLUGIN_RE.search(remainder)
    header = remainder[: cut.start()] if cut else remainder
    declared = _xml_tag_value(header, "groupId")
    artifact = _xml_tag_value(header, "artifactId")
    if declared:
        search_group = declared
    elif parent_group and not is_third_party_maven_group(parent_group):
        search_group = parent_group
    else:
        search_group = ""
    return search_group, artifact, declared


def _packages_from_pom(text: str) -> tuple[list[str], str]:
    group_id, artifact, declared = _pom_identity(text)
    out: list[str] = []
    if artifact:
        out.append(artifact)
    if group_id:
        out.append(group_id)
        if artifact:
            out.append(f"{group_id}:{artifact}")
    return out, declared


def infer_affected_packages(project_id: int) -> list[str]:
    """Best-effort *project* package names from pom.xml / package.json for GHSA affects=.

    Does not include third-party dependencies (Spring, Tomcat, …).
    """
    root = src_dir(project_id)
    if not root.exists():
        return []
    found: list[str] = []
    seen: set[str] = set()
    own_groups: set[str] = set()
    pending: list[str] = []

    def remember(raw: str) -> None:
        item = (raw or "").strip()
        if not item:
            return
        pending.append(item)

    for dirpath, dirnames, filenames in os_walk_limited(root, max_depth=3):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIR_NAMES]
        names = {n.lower(): n for n in filenames}
        if "pom.xml" in names:
            try:
                text = (Path(dirpath) / names["pom.xml"]).read_text(encoding="utf-8", errors="ignore")
            except OSError:
                text = ""
            pkgs, declared = _packages_from_pom(text)
            if declared:
                own_groups.add(declared.lower())
            for pkg in pkgs:
                remember(pkg)
        if "package.json" in names:
            try:
                text = (Path(dirpath) / names["package.json"]).read_text(encoding="utf-8", errors="ignore")
            except OSError:
                text = ""
            m = re.search(r'"name"\s*:\s*"([^"]+)"', text)
            if m:
                remember(m.group(1))
        if len(pending) >= 24:
            break
    for item in pending:
        key = item.lower()
        if not item or key in seen:
            continue
        if is_dependency_package(item, own_groups=own_groups):
            continue
        seen.add(key)
        found.append(item)
        if len(found) >= 8:
            break
    return found


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
    inferred = infer_affected_packages(project_id)
    own_groups: set[str] = set()
    for pkg in inferred:
        group = _package_group_id(pkg)
        if group:
            own_groups.add(group)
    affects: list[str] = []
    seen: set[str] = set()
    for raw in list(spec.get("affects") or []) + inferred:
        item = str(raw or "").strip()
        key = item.lower()
        if not item or key in seen:
            continue
        if is_dependency_package(item, own_groups=own_groups):
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

    if repo:
        try:
            repo_vulns, repo_adv_meta = crawl_repo_advisories(repo)
        except Exception as exc:  # noqa: BLE001
            repo_adv_meta = {"error": str(exc), "repo": repo, "fetched": 0, "errors": [str(exc)]}
            live_log.error(
                project_id,
                f"仓库 Advisory 爬虫失败: {exc}",
                phase="recon-old-vuln",
                role="recon_old_vuln",
            )
            repo_vulns = []
            ghsa_meta["errors"] = list(ghsa_meta.get("errors") or []) + [str(exc)]
        else:
            ghsa_meta.setdefault("errors", [])
            ghsa_meta["errors"] = list(ghsa_meta.get("errors") or []) + list(repo_adv_meta.get("errors") or [])
            ghsa_meta["repo_advisories"] = {
                "fetched": int(repo_adv_meta.get("fetched") or 0),
                "repo": repo,
            }
            seen_ghsa = {merge_key(str(v.get("identifier") or "")) for v in ghsa_vulns}
            for rec in repo_vulns:
                rec.setdefault("source", "ghsa")
                key = merge_key(str(rec.get("identifier") or ""))
                if not key or key == "UNKNOWN" or key in seen_ghsa:
                    continue
                seen_ghsa.add(key)
                ghsa_vulns.append(rec)
            ghsa_meta["fetched"] = len(ghsa_vulns)
            ghsa_meta["packages"] = list(ghsa_meta.get("packages") or ([keyword, *affects] if keyword else []))

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

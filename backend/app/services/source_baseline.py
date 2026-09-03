"""Detect when imported source is below upstream security-fix versions for known patched CVEs."""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..models import Project, SessionLocal
from ..tools.common import _normalize_fix_status, _old_vuln_entries, _parse_frontmatter
from .paths import docs_dir, ghsa_new_path, project_root, src_dir, workspace_dir

CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
VERSION_RE = re.compile(r"\d+(?:\.\d+){1,3}")

BASELINE_PENDING = "pending"
BASELINE_OK = "ok"
BASELINE_STALE = "stale"
BASELINE_ACKNOWLEDGED = "acknowledged"

FP_KIND_KNOWN_CVE_PATCHED = "known_cve_patched"


@dataclass
class BaselineIssue:
    cve: str
    title: str
    fix_status: str
    affected_range: str
    fix_version: str
    source_version: str
    reason: str
    source: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SourceBaselineReport:
    checked_at: str
    status: str
    source_version: str = ""
    source_commit: str = ""
    source_ref: str = ""
    issues: list[BaselineIssue] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "checked_at": self.checked_at,
            "status": self.status,
            "source_version": self.source_version,
            "source_commit": self.source_commit,
            "source_ref": self.source_ref,
            "issues": [i.to_dict() for i in self.issues],
        }


def _baseline_json_path(project_id: int) -> Path:
    return docs_dir(project_id) / "source-baseline.json"


def _baseline_md_path(project_id: int) -> Path:
    return docs_dir(project_id) / "source-baseline.md"


def version_tuple(raw: str) -> tuple[int, ...]:
    parts = VERSION_RE.findall(str(raw or ""))
    if not parts:
        return (0,)
    nums = [int(p) for p in parts[-1].split(".")]
    while len(nums) < 3:
        nums.append(0)
    return tuple(nums[:4])


def version_compare(a: str, b: str) -> int:
    ta, tb = version_tuple(a), version_tuple(b)
    return (ta > tb) - (ta < tb)


def _extract_cves(*chunks: Any) -> set[str]:
    out: set[str] = set()
    for chunk in chunks:
        if not chunk:
            continue
        out.update(m.upper() for m in CVE_RE.findall(str(chunk)))
    return out


def _parse_affected_range(text: str) -> tuple[str | None, str | None, str | None]:
    """Return (min_version, max_version, fix_version) when parseable."""
    raw = str(text or "").strip()
    if not raw:
        return None, None, None
    fixed = re.search(r"fixed\s+([0-9]+(?:\.[0-9]+){1,3})", raw, re.I)
    if fixed:
        return None, None, fixed.group(1)
    lt = re.search(r"<\s*=?\s*([0-9]+(?:\.[0-9]+){1,3})", raw)
    if lt:
        return None, lt.group(1), lt.group(1)
    lte = re.search(r"<=\s*([0-9]+(?:\.[0-9]+){1,3})", raw)
    if lte:
        return None, lte.group(1), lte.group(1)
    between = re.search(
        r">=\s*([0-9]+(?:\.[0-9]+){1,3}).*<=\s*([0-9]+(?:\.[0-9]+){1,3})",
        raw,
        re.I,
    )
    if between:
        return between.group(1), between.group(2), between.group(2)
    return None, None, None


def _version_in_affected_range(source_version: str, affected_range: str) -> bool:
    if not source_version:
        return False
    min_v, max_v, fix_v = _parse_affected_range(affected_range)
    if fix_v and "<" in affected_range and "<=" not in affected_range.split("<", 1)[0]:
        return version_compare(source_version, fix_v) < 0
    if fix_v and "<=" in affected_range:
        return version_compare(source_version, fix_v) <= 0
    if min_v and max_v:
        return version_compare(min_v, source_version) <= 0 and version_compare(source_version, max_v) <= 0
    if max_v:
        return version_compare(source_version, max_v) <= 0
    return False


def detect_source_version(project_id: int) -> str:
    root = src_dir(project_id)
    if not root.is_dir():
        return ""
    candidates: list[tuple[int, str]] = []

    def add_score(path: Path, pattern: str, *, score: int) -> None:
        if not path.is_file():
            return
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return
        m = re.search(pattern, text)
        if m:
            candidates.append((score, m.group(1)))

    add_score(root / "application/constants/constants.go", r'BackendVersion\s*=\s*"([^"]+)"', score=100)
    add_score(root / "package.json", r'"version"\s*:\s*"([^"]+)"', score=90)
    add_score(root / "pyproject.toml", r'version\s*=\s*"([^"]+)"', score=90)
    add_score(root / "pom.xml", r"<version>([^<]+)</version>", score=80)
    if not candidates:
        return ""
    candidates.sort(key=lambda item: item[0], reverse=True)
    return candidates[0][1].strip()


def detect_git_snapshot(project_id: int) -> tuple[str, str]:
    root = src_dir(project_id)
    git_dir = root / ".git"
    if not git_dir.is_dir():
        return "", ""
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        commit = proc.stdout.strip() if proc.returncode == 0 else ""
    except (OSError, subprocess.TimeoutExpired):
        commit = ""
    ref = ""
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), "branch", "--show-current"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        ref = proc.stdout.strip() if proc.returncode == 0 else ""
    except (OSError, subprocess.TimeoutExpired):
        ref = ""
    return commit, ref


def _collect_patched_entries(project_id: int) -> list[dict[str, Any]]:
    seen: set[str] = set()
    out: list[dict[str, Any]] = []

    def add(entry: dict[str, Any]) -> None:
        cve = str(entry.get("cve") or entry.get("identifier") or "").strip().upper()
        key = cve or str(entry.get("title") or "").strip().lower()
        if not key or key in seen:
            return
        seen.add(key)
        out.append(entry)

    for entry in _old_vuln_entries(project_id):
        if _normalize_fix_status(entry.get("fix_status")) != "patched":
            continue
        meta = entry.get("meta") or {}
        add(
            {
                "cve": meta.get("cve") or "",
                "title": entry.get("title") or "",
                "fix_status": "patched",
                "affected_range": str(meta.get("affected_version") or ""),
                "source": f"old-vulns/{entry.get('file')}",
            }
        )

    ghsa_path = ghsa_new_path(project_id)
    if ghsa_path.is_file():
        try:
            payload = json.loads(ghsa_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            payload = {}
        for row in payload.get("vulnerabilities") or []:
            if not isinstance(row, dict):
                continue
            if _normalize_fix_status(row.get("fix_status")) != "patched":
                continue
            add(
                {
                    "cve": row.get("cve") or row.get("identifier") or "",
                    "title": row.get("title") or "",
                    "fix_status": "patched",
                    "affected_range": str(row.get("affected_versions") or ""),
                    "source": "workspace/ghsa_new.json",
                }
            )
    return out


def build_source_baseline_report(project_id: int) -> SourceBaselineReport:
    checked_at = datetime.now(timezone.utc).isoformat()
    source_version = detect_source_version(project_id)
    source_commit, source_ref = detect_git_snapshot(project_id)
    issues: list[BaselineIssue] = []

    for entry in _collect_patched_entries(project_id):
        affected_range = str(entry.get("affected_range") or "").strip()
        if not affected_range or not source_version:
            continue
        if not _version_in_affected_range(source_version, affected_range):
            continue
        _, _, fix_version = _parse_affected_range(affected_range)
        fix_version = fix_version or "unknown"
        cve = str(entry.get("cve") or "").strip().upper()
        title = str(entry.get("title") or cve or "patched historical vulnerability").strip()
        reason = (
            f"当前源码版本 {source_version} 仍落在上游已修复 CVE 的受影响范围内（{affected_range}）。"
            f"该漏洞在上游已标记 patched，继续按新洞提交会被判为误报。"
        )
        issues.append(
            BaselineIssue(
                cve=cve,
                title=title,
                fix_status="patched",
                affected_range=affected_range,
                fix_version=fix_version,
                source_version=source_version,
                reason=reason,
                source=str(entry.get("source") or ""),
            )
        )

    status = BASELINE_STALE if issues else BASELINE_OK
    return SourceBaselineReport(
        checked_at=checked_at,
        status=status,
        source_version=source_version,
        source_commit=source_commit,
        source_ref=source_ref,
        issues=issues,
    )


def _render_baseline_md(report: SourceBaselineReport) -> str:
    lines = [
        "# 源码基线检查",
        "",
        f"- 检查时间：{report.checked_at}",
        f"- 结论：`{report.status}`",
        f"- 当前源码版本：{report.source_version or '（未识别）'}",
        f"- Git commit：{report.source_commit or '（无）'}",
        f"- Git 分支：{report.source_ref or '（无）'}",
        "",
    ]
    if not report.issues:
        lines.append("未发现「上游已修复、当前快照仍落在受影响版本范围」的已知 CVE。")
        return "\n".join(lines) + "\n"
    lines.extend(
        [
            "## 需要人工判定",
            "",
            "以下已知 CVE 在上游已修复，但当前导入的 `src/` 版本仍落在官方受影响范围内。",
            "这通常表示默认分支快照落后于安全发行版，而不是靶场使用了旧镜像。",
            "",
            "请在项目详情页选择：",
            "",
            "1. **继续审计当前快照** — 已知 CVE 提交时会被系统自动判为误报；",
            "2. **手动更新 `src/` 后重新检查** — 例如切换到含修复的 release tag 后点「重新检查」。",
            "",
        ]
    )
    for issue in report.issues:
        lines.extend(
            [
                f"### {issue.cve or issue.title}",
                "",
                f"- 标题：{issue.title}",
                f"- 受影响范围：{issue.affected_range}",
                f"- 上游修复版本：{issue.fix_version}",
                f"- 来源：{issue.source}",
                f"- 说明：{issue.reason}",
                "",
            ]
        )
    return "\n".join(lines)


def write_source_baseline_artifacts(project_id: int, report: SourceBaselineReport) -> None:
    docs_dir(project_id).mkdir(parents=True, exist_ok=True)
    _baseline_json_path(project_id).write_text(
        json.dumps(report.to_dict(), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    _baseline_md_path(project_id).write_text(_render_baseline_md(report), encoding="utf-8")


def load_source_baseline_report(project_id: int) -> SourceBaselineReport | None:
    path = _baseline_json_path(project_id)
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    issues = [BaselineIssue(**item) for item in data.get("issues") or [] if isinstance(item, dict)]
    return SourceBaselineReport(
        checked_at=str(data.get("checked_at") or ""),
        status=str(data.get("status") or BASELINE_PENDING),
        source_version=str(data.get("source_version") or ""),
        source_commit=str(data.get("source_commit") or ""),
        source_ref=str(data.get("source_ref") or ""),
        issues=issues,
    )


def get_project_baseline_status(project_id: int) -> str:
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        if not proj:
            return BASELINE_PENDING
        return str(getattr(proj, "source_baseline_status", None) or BASELINE_PENDING)


def source_baseline_blocks_mining(project_id: int) -> bool:
    status = get_project_baseline_status(project_id)
    return status == BASELINE_STALE


def run_source_baseline_check(project_id: int) -> SourceBaselineReport:
    report = build_source_baseline_report(project_id)
    write_source_baseline_artifacts(project_id, report)
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        if not proj:
            return report
        prev = str(getattr(proj, "source_baseline_status", None) or BASELINE_PENDING)
        if report.status == BASELINE_STALE:
            proj.source_baseline_status = BASELINE_STALE
        else:
            proj.source_baseline_status = BASELINE_OK
        if prev == BASELINE_ACKNOWLEDGED and report.status == BASELINE_OK:
            proj.source_baseline_status = BASELINE_OK
        db.commit()
    return report


def acknowledge_source_baseline(project_id: int) -> str:
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        if not proj:
            raise ValueError("项目不存在")
        proj.source_baseline_status = BASELINE_ACKNOWLEDGED
        db.commit()
    return BASELINE_ACKNOWLEDGED


def _issue_for_cve(project_id: int, cve: str) -> BaselineIssue | None:
    report = load_source_baseline_report(project_id)
    if not report:
        return None
    needle = cve.strip().upper()
    for issue in report.issues:
        if issue.cve.upper() == needle:
            return issue
    return None


def match_known_patched_cve_issues(project_id: int, *texts: Any) -> list[BaselineIssue]:
    report = load_source_baseline_report(project_id)
    if not report or not report.issues:
        return []
    cves = _extract_cves(*texts)
    if not cves:
        return []
    out: list[BaselineIssue] = []
    for issue in report.issues:
        if issue.cve and issue.cve.upper() in cves:
            out.append(issue)
    return out


def known_patched_cve_submit_block_reason(
    project_id: int,
    args: dict[str, Any],
    *,
    mining_path: str | None = None,
) -> str | None:
    status = get_project_baseline_status(project_id)
    if status not in (BASELINE_STALE, BASELINE_ACKNOWLEDGED):
        return None
    issues = match_known_patched_cve_issues(
        project_id,
        args.get("title"),
        args.get("report_md"),
        args.get("http_request"),
        args.get("source_sink"),
        args.get("expected_evidence"),
    )
    if not issues:
        return None
    cve_list = ", ".join(i.cve or i.title for i in issues[:3])
    if mining_path == "bypass":
        return (
            f"已知 CVE（{cve_list}）在上游已修复，当前源码快照仍落在受影响版本范围内。"
            "这不是补丁绕过或新洞，请 FinishBypass(verdict=still_patched)，不要 SubmitVuln。"
        )
    return (
        f"已知 CVE（{cve_list}）在上游已修复，当前源码快照仍落在受影响版本范围内。"
        "系统会将此类提交判为误报，请勿重复提交。"
    )


def known_patched_cve_false_positive_reason(project_id: int, vuln) -> str | None:
    status = get_project_baseline_status(project_id)
    if status not in (BASELINE_STALE, BASELINE_ACKNOWLEDGED):
        return None
    issues = match_known_patched_cve_issues(
        project_id,
        getattr(vuln, "title", None),
        getattr(vuln, "source_sink", None),
        getattr(vuln, "http_request", None),
        getattr(vuln, "submission_reason", None),
    )
    if not issues:
        report_path = getattr(vuln, "report_path", None)
        if report_path:
            rel = str(report_path).replace("\\", "/")
            p = project_root(project_id) / rel
            if p.is_file():
                issues = match_known_patched_cve_issues(
                    project_id,
                    p.read_text(encoding="utf-8", errors="ignore"),
                )
    if not issues:
        return None
    cve_list = ", ".join(i.cve or i.title for i in issues[:3])
    return (
        f"已知 CVE（{cve_list}）在上游已修复；当前导入源码版本仍落在官方受影响范围内，"
        "属于在旧快照上复现已知漏洞，系统自动判为误报。"
    )


def source_baseline_out(project_id: int) -> dict[str, Any]:
    report = load_source_baseline_report(project_id)
    status = get_project_baseline_status(project_id)
    return {
        "status": status,
        "blocks_mining": source_baseline_blocks_mining(project_id),
        "report": report.to_dict() if report else None,
        "doc_path": "docs/source-baseline.md",
    }

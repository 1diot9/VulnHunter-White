"""Deterministic Semgrep finding filter and scoring (no LLM)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..audit_mode import bounty_submit_block_reason
from ..vuln_types import infer_vuln_type_from_text, normalize_vuln_type

CANDIDATE_LIMIT = 200
AUDIT_QUEUE_LIMIT = 60

_NOISE_PATH_PARTS = (
    "/test/",
    "/tests/",
    "/__tests__/",
    "/spec/",
    "/specs/",
    "/node_modules/",
    "/vendor/",
    "/dist/",
    "/build/",
    "/target/classes/",
    "/.venv/",
    "/venv/",
    "/generated/",
    "/__pycache__/",
    "/resources/static/",
    "/bower_components/",
    "/webjars/",
    "/ckeditor/",
)
_NOISE_NAME_MARKERS = (".spec.", ".test.", ".min.", ".generated.")
_ROOT_SCRIPT_EXTS = frozenset({".py", ".sh", ".bat", ".cmd", ".ps1"})
# Official pack hits that are crypto hygiene / CSRF / mapping nits, not backtraceable sinks.
_NOISE_RULE_MARKERS = (
    "unrestricted-request-mapping",
    "des-is-deprecated",
    "cbc-padding-oracle",
    "use-of-md5",
    "use-of-weak-rsa-key",
    "weak-random",
    "weak-ssl-context",
    "insecure-trust-manager",
    "spring-csrf-disabled",
    "wildcard-postmessage-configuration",
    "npm-missing-minimum-release-age",
    "bad-hexa-conversion",
    "unvalidated-redirect",
)
_PLACEHOLDER_SNIPPETS = frozenset({"", "requires login", "login required", "<unknown>"})
_NON_SECURITY_CATEGORIES = frozenset(
    {"correctness", "best-practice", "best_practice", "maintainability", "performance", "style"}
)
_SEV_SCORE = {
    "ERROR": 80,
    "HIGH": 80,
    "CRITICAL": 90,
    "WARNING": 50,
    "MEDIUM": 50,
    "INFO": 15,
    "LOW": 15,
    "EXPERIMENT": 5,
}
_CONF_SCORE = {"HIGH": 20, "MEDIUM": 10, "LOW": 0}
_TYPE_BONUS = {
    "rce": 35,
    "ssti": 35,
    "deserialization": 35,
    "jndi_injection": 35,
    "jdbc_attack": 30,
    "sqli": 30,
    "xxe": 25,
    "path_traversal": 25,
    "file_read": 25,
    "file_upload": 25,
    "file_delete": 25,
    "ssrf": 20,
    "auth_bypass": 20,
    "hardcoded_secret": 15,
}


@dataclass
class FilterContext:
    skipped_paths: set[str] = field(default_factory=set)
    file_weights: dict[str, int] = field(default_factory=dict)
    has_source: set[str] = field(default_factory=set)
    source_files: set[str] = field(default_factory=set)
    bounty: bool = False


def normalize_path(path: str) -> str:
    p = str(path or "").replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    p = p.lstrip("/")
    if p.startswith("src/"):
        p = p[4:]
    return p


def is_noise_path(path: str) -> bool:
    norm = normalize_path(path)
    lowered = f"/{norm.lower()}/"
    name = Path(norm).name.lower()
    if any(part in lowered for part in _NOISE_PATH_PARTS):
        return True
    if any(marker in name for marker in _NOISE_NAME_MARKERS):
        return True
    parts = [p for p in norm.split("/") if p]
    if len(parts) == 1 and Path(parts[0]).suffix.lower() in _ROOT_SCRIPT_EXTS:
        return True
    return False


def is_noise_rule(check_id: str) -> bool:
    lowered = str(check_id or "").lower()
    if not lowered:
        return False
    return any(marker in lowered for marker in _NOISE_RULE_MARKERS)


def is_placeholder_snippet(text: str | None) -> bool:
    return str(text or "").strip().lower() in _PLACEHOLDER_SNIPPETS


def finding_snippet(extra: dict[str, Any] | None) -> str:
    extra = extra if isinstance(extra, dict) else {}
    lines = str(extra.get("lines") or "").strip()
    if not is_placeholder_snippet(lines):
        return lines
    return str(extra.get("message") or "").strip()


def source_snippet(
    src_root: Path | None,
    path: str,
    line_start: int,
    line_end: int,
    *,
    radius: int = 2,
) -> str:
    if src_root is None:
        return ""
    file_path = src_root / normalize_path(path)
    if not file_path.is_file():
        return ""
    try:
        rows = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    if not rows:
        return ""
    start = max(1, int(line_start or 1) - radius)
    finish = min(len(rows), max(int(line_end or line_start or 1) + radius, start))
    return "\n".join(rows[start - 1 : finish])[:2000]


def _meta(extra: dict[str, Any] | None) -> dict[str, Any]:
    extra = extra if isinstance(extra, dict) else {}
    meta = extra.get("metadata")
    return meta if isinstance(meta, dict) else {}


def finding_severity(extra: dict[str, Any] | None) -> str:
    extra = extra if isinstance(extra, dict) else {}
    raw = str(extra.get("severity") or "").strip().upper()
    return raw or "WARNING"


def finding_confidence(extra: dict[str, Any] | None) -> str:
    meta = _meta(extra)
    raw = str(meta.get("confidence") or "").strip().upper()
    return raw if raw in _CONF_SCORE else "MEDIUM"


def finding_category(extra: dict[str, Any] | None) -> str:
    meta = _meta(extra)
    return str(meta.get("category") or "").strip().lower()


def map_vuln_type(check_id: str, extra: dict[str, Any] | None) -> str:
    extra = extra if isinstance(extra, dict) else {}
    meta = _meta(extra)
    parts = [
        str(check_id or ""),
        str(extra.get("message") or ""),
        str(meta.get("cwe") or ""),
        str(meta.get("owasp") or ""),
        str(meta.get("vulnerability_class") or ""),
    ]
    return normalize_vuln_type(infer_vuln_type_from_text(" ".join(parts)))


def drop_reason(
    *,
    path: str,
    extra: dict[str, Any] | None,
    ctx: FilterContext,
    vuln_type: str,
    check_id: str = "",
) -> str | None:
    norm = normalize_path(path)
    if not norm:
        return "empty_path"
    if norm in ctx.skipped_paths:
        return "skipped"
    if is_noise_path(norm):
        return "noise_path"
    if is_noise_rule(check_id):
        return "noise_rule"
    category = finding_category(extra)
    if category and category in _NON_SECURITY_CATEGORIES:
        return "non_security"
    if category and category != "security" and finding_severity(extra) in {"INFO", "LOW"}:
        return "info_non_security"
    if ctx.bounty:
        blocked = bounty_submit_block_reason(vuln_type, file_path=norm)
        if blocked:
            return "bounty_blocked"
    return None


def protected_from_drop(
    *,
    severity: str,
    confidence: str,
    path: str,
    ctx: FilterContext,
) -> bool:
    sev = severity.upper()
    conf = confidence.upper()
    if sev not in {"ERROR", "HIGH", "CRITICAL"}:
        return False
    if conf != "HIGH":
        return False
    norm = normalize_path(path)
    weight = int(ctx.file_weights.get(norm) or 0)
    return weight >= 70 or norm in ctx.has_source or norm in ctx.source_files


def score_sink(
    *,
    severity: str,
    confidence: str,
    path: str,
    ctx: FilterContext,
    vuln_type: str = "other",
) -> int:
    norm = normalize_path(path)
    mapped = normalize_vuln_type(vuln_type)
    score = int(_SEV_SCORE.get(severity.upper(), 40))
    score += int(_CONF_SCORE.get(confidence.upper(), 10))
    score += int(_TYPE_BONUS.get(mapped, 0))
    if mapped != "other":
        weight = int(ctx.file_weights.get(norm) or 0)
        score += min(max(weight, 0), 100) * 3 // 10
        if norm in ctx.has_source or norm in ctx.source_files:
            score += 25
        else:
            parent = str(Path(norm).parent).replace("\\", "/")
            if parent and any(src.startswith(f"{parent}/") or src == parent for src in ctx.source_files):
                score += 10
    return max(0, min(200, score))


def _resolve_snippet(
    extra: dict[str, Any] | None,
    *,
    src_root: Path | None,
    path: str,
    line_start: int,
    line_end: int,
) -> str:
    filled = source_snippet(src_root, path, line_start, line_end)
    if filled:
        return filled[:2000]
    return finding_snippet(extra)[:2000]


def _prefer_snippet(current: str, candidate: str) -> str:
    if is_placeholder_snippet(current):
        return candidate or current
    if is_placeholder_snippet(candidate):
        return current
    if len(candidate) > len(current):
        return candidate
    return current


def merge_findings(
    results: list[Any],
    ctx: FilterContext,
    *,
    src_root: Path | None = None,
) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, int], dict[str, Any]] = {}
    for raw in results:
        if not isinstance(raw, dict):
            continue
        extra = raw.get("extra") if isinstance(raw.get("extra"), dict) else {}
        start = raw.get("start") if isinstance(raw.get("start"), dict) else {}
        end = raw.get("end") if isinstance(raw.get("end"), dict) else {}
        path = normalize_path(str(raw.get("path") or ""))
        try:
            line_start = int(start.get("line") or 0)
        except (TypeError, ValueError):
            line_start = 0
        try:
            line_end = int(end.get("line") or line_start)
        except (TypeError, ValueError):
            line_end = line_start
        check_id = str(raw.get("check_id") or "").strip()
        vuln_type = map_vuln_type(check_id, extra)
        reason = drop_reason(
            path=path, extra=extra, ctx=ctx, vuln_type=vuln_type, check_id=check_id
        )
        if reason:
            continue
        severity = finding_severity(extra)
        confidence = finding_confidence(extra)
        snippet = _resolve_snippet(
            extra, src_root=src_root, path=path, line_start=line_start, line_end=line_end
        )
        key = (path, line_start)
        item = grouped.get(key)
        scored = score_sink(
            severity=severity, confidence=confidence, path=path, ctx=ctx, vuln_type=vuln_type
        )
        if item is None:
            grouped[key] = {
                "file_path": path,
                "line_start": line_start,
                "line_end": line_end,
                "check_ids": [check_id] if check_id else [],
                "snippet": snippet,
                "severity": severity,
                "confidence": confidence,
                "mapped_vuln_type": vuln_type,
                "code_score": scored,
            }
            continue
        if check_id and check_id not in item["check_ids"]:
            item["check_ids"].append(check_id)
        if _SEV_SCORE.get(severity.upper(), 0) > _SEV_SCORE.get(str(item["severity"]).upper(), 0):
            item["severity"] = severity
            item["mapped_vuln_type"] = vuln_type
        if _CONF_SCORE.get(confidence.upper(), 0) > _CONF_SCORE.get(str(item["confidence"]).upper(), 0):
            item["confidence"] = confidence
        item["snippet"] = _prefer_snippet(str(item.get("snippet") or ""), snippet)
        item["code_score"] = score_sink(
            severity=str(item["severity"]),
            confidence=str(item["confidence"]),
            path=path,
            ctx=ctx,
            vuln_type=str(item.get("mapped_vuln_type") or vuln_type),
        )
        item["line_end"] = max(int(item.get("line_end") or 0), line_end)
    merged = list(grouped.values())
    merged.sort(key=lambda row: (-int(row.get("code_score") or 0), row.get("file_path") or "", int(row.get("line_start") or 0)))
    return merged


def select_candidates(merged: list[dict[str, Any]], *, limit: int = CANDIDATE_LIMIT) -> list[dict[str, Any]]:
    return list(merged[: max(0, int(limit))])

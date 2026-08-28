"""Same-root-cause helpers: attach duplicate reports onto a parent key."""

from __future__ import annotations

import re
from typing import Any

_STOP = frozenset(
    {
        "controller",
        "service",
        "filter",
        "util",
        "utils",
        "impl",
        "config",
        "handler",
        "action",
        "api",
        "other",
        "requirespermissions",
        "missing",
        "permissions",
    }
)
_FILE_SUFFIX = re.compile(
    r"(Mapper|ServiceImpl|Service|Controller|Endpoint|Impl|Helper|Filter|Util|Utils|Config)$",
    re.I,
)


def canonical_root_cause_key(raw: str | None) -> str:
    return (raw or "").strip().lower().replace("：", ":").replace(" ", "")


def _file_norm(path: str | None) -> str:
    return (path or "").replace("\\", "/").lower()


def _file_family(path: str | None) -> str:
    base = _file_norm(path).rsplit("/", 1)[-1]
    no_ext = base.rsplit(".", 1)[0] if base else ""
    return _FILE_SUFFIX.sub("", no_ext).lower()


def _key_tokens(key: str | None) -> list[str]:
    parts = re.split(r"[:_./\\-]+", canonical_root_cause_key(key))
    return [p for p in parts if len(p) >= 6 and p not in _STOP]


def _same_file(a: str | None, b: str | None) -> bool:
    return bool(a and b and _file_norm(a) == _file_norm(b))


def _same_family(a: str | None, b: str | None) -> bool:
    fa, fb = _file_family(a), _file_family(b)
    if len(fa) < 6 or len(fb) < 6:
        return False
    return fa == fb or fa in fb or fb in fa


def _token_hits_file(path: str | None, tokens: list[str]) -> bool:
    norm = _file_norm(path)
    return bool(norm) and any(token in norm for token in tokens)


def _is_duplicate(item: Any) -> bool:
    return getattr(item, "submission_tier", None) == "duplicate_grouped"


def _shares_root(left: Any, right: Any) -> bool:
    if getattr(left, "id", None) == getattr(right, "id", None):
        return False
    if getattr(left, "project_id", None) != getattr(right, "project_id", None):
        return False
    if getattr(left, "vuln_type", None) and getattr(right, "vuln_type", None) != left.vuln_type:
        return False
    left_key = canonical_root_cause_key(getattr(left, "root_cause_key", None))
    right_key = canonical_root_cause_key(getattr(right, "root_cause_key", None))
    if left_key and left_key == right_key:
        return True
    left_path = getattr(left, "file_path", None)
    right_path = getattr(right, "file_path", None)
    return (
        _same_file(left_path, right_path)
        or _same_family(left_path, right_path)
        or _token_hits_file(right_path, _key_tokens(getattr(left, "root_cause_key", None)))
        or _token_hits_file(left_path, _key_tokens(getattr(right, "root_cause_key", None)))
    )


def existing_family_root_cause_key(dup: Any, candidates: list[Any]) -> str | None:
    """Return the key a duplicate must reuse if a related sibling already has one."""
    parent = pick_parent_for_duplicate(dup, candidates)
    if parent is not None:
        key = (getattr(parent, "root_cause_key", None) or "").strip()
        if key:
            return key
    for item in candidates:
        key = (getattr(item, "root_cause_key", None) or "").strip()
        if key and _shares_root(dup, item):
            return key
    return None


def mismatched_root_cause_key_error(dup: Any, candidates: list[Any], submitted: str | None) -> str | None:
    required = existing_family_root_cause_key(dup, candidates)
    if not required:
        return None
    if canonical_root_cause_key(required) == canonical_root_cause_key(submitted):
        return None
    return f"同根因重复必须原样复用已有 root_cause_key={required}，不要另写新键"


def pick_parent_for_duplicate(dup: Any, candidates: list[Any]) -> Any | None:
    """Pick a non-duplicate sibling that shares file, key token, or file family."""
    others = [
        item
        for item in candidates
        if getattr(item, "id", None) != getattr(dup, "id", None)
        and getattr(item, "project_id", None) == getattr(dup, "project_id", None)
    ]
    pool = [item for item in others if not _is_duplicate(item)]
    if not pool:
        return None
    tokens = _key_tokens(getattr(dup, "root_cause_key", None))
    ranked: list[tuple[Any, ...]] = []
    for item in pool:
        if getattr(dup, "vuln_type", None) and getattr(item, "vuln_type", None) != dup.vuln_type:
            continue
        same_file = 1 if _same_file(getattr(dup, "file_path", None), getattr(item, "file_path", None)) else 0
        token = 1 if _token_hits_file(getattr(item, "file_path", None), tokens) else 0
        family = 1 if _same_family(getattr(dup, "file_path", None), getattr(item, "file_path", None)) else 0
        if not (same_file or token or family):
            continue
        confirmed = 1 if getattr(item, "status", None) in ("confirmed", "static_only") else 0
        empty_key = 1 if not (getattr(item, "root_cause_key", None) or "").strip() else 0
        cve = 1 if getattr(item, "submission_tier", None) == "cve_candidate" else 0
        ranked.append(
            (
                confirmed,
                cve,
                same_file,
                token,
                family,
                empty_key,
                int(getattr(item, "cvss_score", None) or getattr(item, "severity_score", None) or 0),
                -int(getattr(item, "id", 0) or 0),
                item,
            )
        )
    if not ranked:
        return None
    ranked.sort(reverse=True)
    return ranked[0][-1]


def stamp_root_cause_on_parent(db: Any, vuln: Any) -> int | None:
    """If this confirm is a duplicate, copy its key onto a matching parent that still has none."""
    if getattr(vuln, "submission_tier", None) != "duplicate_grouped":
        return None
    key = (getattr(vuln, "root_cause_key", None) or "").strip()
    if not key:
        return None
    from ..models import Vuln

    canon = canonical_root_cause_key(key)
    siblings = (
        db.query(Vuln)
        .filter(Vuln.project_id == vuln.project_id, Vuln.id != vuln.id)
        .all()
    )
    if any(
        canonical_root_cause_key(item.root_cause_key) == canon and not _is_duplicate(item)
        for item in siblings
    ):
        return None
    parent = pick_parent_for_duplicate(vuln, siblings)
    if parent is None or (parent.root_cause_key or "").strip():
        return None
    parent.root_cause_key = key
    return int(parent.id)


def backfill_parent_root_cause_keys(db: Any) -> int:
    from ..models import Vuln

    dups = db.query(Vuln).filter(Vuln.submission_tier == "duplicate_grouped").all()
    stamped = 0
    for dup in dups:
        if stamp_root_cause_on_parent(db, dup):
            stamped += 1
    return stamped

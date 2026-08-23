"""CVE JSON record helpers (templates/cve.json)."""

from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..config import TEMPLATES_DIR
from .paths import vuln_dir

CVE_FIELD_PLACEHOLDER = "VULNHUNTER_PENDING"
_CVE_TEMPLATE_PATH = TEMPLATES_DIR / "cve.json"
_EXAMPLE_RE = re.compile(r"\[EXAMPLE", re.IGNORECASE)
_PATH_TOKEN_RE = re.compile(r"([^.\[\]]+)|\[(\d+)\]")


@dataclass(frozen=True)
class FillableField:
    path: str
    description: str
    required: bool = True


FILLABLE_FIELDS: tuple[FillableField, ...] = (
    FillableField("cveMetadata.cveId", "CVE ID；未分配时保持占位符", required=False),
    FillableField(
        "containers.cna.problemTypes[0].descriptions[0].description",
        "CWE 弱点描述（英文）",
    ),
    FillableField(
        "containers.cna.affected[0].versions[0].version",
        "受影响产品版本（如 <=1.2.3 或 all versions）",
    ),
    FillableField(
        "containers.cna.descriptions[0].value",
        "漏洞英文描述（纯文本）",
    ),
    FillableField(
        "containers.cna.descriptions[0].supportingMedia[0].value",
        "漏洞英文描述（HTML，可与 value 相同）",
    ),
    FillableField(
        "containers.cna.references[0].url",
        "参考链接（公告、修复 PR、厂商页面等）",
    ),
    FillableField(
        "containers.cna.metrics[0].cvssV4_0.baseScore",
        "CVSS v4.0 基础分",
        required=False,
    ),
    FillableField(
        "containers.cna.metrics[0].cvssV4_0.baseSeverity",
        "CVSS v4.0 严重度（CRITICAL/HIGH/MEDIUM/LOW）",
        required=False,
    ),
    FillableField(
        "containers.cna.metrics[0].cvssV4_0.vectorString",
        "CVSS v4.0 向量字符串",
        required=False,
    ),
)

_FILLABLE_PATHS = frozenset(f.path for f in FILLABLE_FIELDS)
_FILLABLE_BY_PATH = {f.path: f for f in FILLABLE_FIELDS}


def cve_record_path(project_id: int, vuln_id: int) -> Path:
    return vuln_dir(project_id, vuln_id) / "cve.json"


def load_cve_template() -> dict[str, Any]:
    return json.loads(_CVE_TEMPLATE_PATH.read_text(encoding="utf-8"))


def _parse_path(path: str) -> list[str | int]:
    parts: list[str | int] = []
    for segment in str(path or "").strip().split("."):
        if not segment:
            continue
        pos = 0
        while pos < len(segment):
            match = _PATH_TOKEN_RE.match(segment, pos)
            if not match:
                raise ValueError(f"无效字段路径: {path}")
            if match.group(1):
                parts.append(match.group(1))
            else:
                parts.append(int(match.group(2)))
            pos = match.end()
    if not parts:
        raise ValueError(f"无效字段路径: {path}")
    return parts


def get_by_path(doc: Any, path: str) -> Any:
    cur = doc
    for part in _parse_path(path):
        if isinstance(part, int):
            if not isinstance(cur, list) or part >= len(cur):
                raise KeyError(path)
            cur = cur[part]
        else:
            if not isinstance(cur, dict) or part not in cur:
                raise KeyError(path)
            cur = cur[part]
    return cur


def set_by_path(doc: dict[str, Any], path: str, value: Any) -> None:
    parts = _parse_path(path)
    cur: Any = doc
    for part in parts[:-1]:
        if isinstance(part, int):
            cur = cur[part]
        else:
            cur = cur[part]
    last = parts[-1]
    if isinstance(last, int):
        cur[last] = value
    else:
        cur[last] = value


def is_unfilled_value(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return True
        if text == CVE_FIELD_PLACEHOLDER:
            return True
        if text == "https://":
            return True
        if _EXAMPLE_RE.search(text):
            return True
    return False


def _apply_placeholders(record: dict[str, Any]) -> None:
    for spec in FILLABLE_FIELDS:
        try:
            current = get_by_path(record, spec.path)
        except KeyError:
            continue
        if is_unfilled_value(current):
            set_by_path(record, spec.path, CVE_FIELD_PLACEHOLDER)


def initialize_cve_record(project_id: int, vuln_id: int) -> dict[str, Any]:
    """Create cve.json from template with unified placeholders for agent-fillable fields."""
    record = copy.deepcopy(load_cve_template())
    _apply_placeholders(record)
    write_cve_record(project_id, vuln_id, record)
    return record


def read_cve_record(project_id: int, vuln_id: int) -> dict[str, Any] | None:
    path = cve_record_path(project_id, vuln_id)
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def write_cve_record(project_id: int, vuln_id: int, record: dict[str, Any]) -> Path:
    path = cve_record_path(project_id, vuln_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path


def ensure_cve_record(project_id: int, vuln_id: int) -> dict[str, Any]:
    existing = read_cve_record(project_id, vuln_id)
    if existing is not None:
        return existing
    return initialize_cve_record(project_id, vuln_id)


def list_fillable_fields(record: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for spec in FILLABLE_FIELDS:
        try:
            current = get_by_path(record, spec.path)
        except KeyError:
            rows.append(
                {
                    "path": spec.path,
                    "description": spec.description,
                    "required": spec.required,
                    "current_value": None,
                    "needs_fill": spec.required,
                    "missing": True,
                }
            )
            continue
        needs_fill = is_unfilled_value(current)
        rows.append(
            {
                "path": spec.path,
                "description": spec.description,
                "required": spec.required,
                "current_value": current,
                "needs_fill": needs_fill if spec.required else needs_fill,
                "missing": False,
            }
        )
    return rows


def set_cve_field(project_id: int, vuln_id: int, path: str, value: Any) -> dict[str, Any]:
    normalized = str(path or "").strip()
    if normalized not in _FILLABLE_PATHS:
        return {
            "ok": False,
            "error": f"字段 {normalized!r} 不可写入；请使用 ReadCveRecord 返回的 path。",
        }
    record = ensure_cve_record(project_id, vuln_id)
    try:
        set_by_path(record, normalized, value)
    except (KeyError, IndexError, TypeError, ValueError) as e:
        return {"ok": False, "error": f"写入失败: {e}"}
    write_cve_record(project_id, vuln_id, record)
    spec = _FILLABLE_BY_PATH[normalized]
    current = get_by_path(record, normalized)
    return {
        "ok": True,
        "path": normalized,
        "current_value": current,
        "needs_fill": is_unfilled_value(current) if spec.required else False,
    }


def cve_record_status(project_id: int, vuln_id: int) -> dict[str, Any]:
    record = ensure_cve_record(project_id, vuln_id)
    fields = list_fillable_fields(record)
    required_pending = [f for f in fields if f["required"] and f["needs_fill"]]
    return {
        "placeholder": CVE_FIELD_PLACEHOLDER,
        "fields": fields,
        "required_pending": [f["path"] for f in required_pending],
        "all_required_filled": not required_pending,
    }


def format_cve_record_json(project_id: int, vuln_id: int) -> str | None:
    record = read_cve_record(project_id, vuln_id)
    if record is None:
        return None
    return json.dumps(record, ensure_ascii=False, indent=2)

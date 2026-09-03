"""CVE JSON record helpers (templates/cve.json)."""

from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass
from html import unescape as unescape_html
from pathlib import Path
from typing import Any

from ..config import TEMPLATES_DIR
from ..models import SessionLocal, Vuln
from ..cvss31 import (
    CVE_SCORE_PATH,
    CVE_SEVERITY_PATH,
    CVE_VECTOR_PATH,
    Cvss31Error,
    apply_cvss31_to_cve_record,
    cvss_pr_alignment_error,
    parse_cvss31,
)
from ..cvss40 import (
    CVE_VECTOR_PATH as CVE4_VECTOR_PATH,
    Cvss40Error,
    apply_cvss40_to_cve_record,
    cvss40_pr_alignment_error,
    parse_cvss40,
)
from .paths import vuln_dir

CVE_FIELD_PLACEHOLDER = "VULNHUNTER_PENDING"
_CVE_TEMPLATE_PATH = TEMPLATES_DIR / "cve.json"
_EXAMPLE_RE = re.compile(r"\[EXAMPLE", re.IGNORECASE)
_PATH_TOKEN_RE = re.compile(r"([^.\[\]]+)|\[(\d+)\]")
_HTML_TAG_RE = re.compile(r"<[^>]+>")
_HTTP_REQ_RE = re.compile(
    r"(?im)(?:^|>)\s*(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+\S+[^\n]*HTTP/"
)
_LIB_POC_RE = re.compile(
    r"(?i)\b(harness|public api|api call|invoke\b|function\s+[A-Za-z_][\w.]*\s*\(|"
    r"class\s+[A-Za-z_])"
)
_CHAIN_RE = re.compile(
    r"(?i)(source\s*(?:→|->|to)\s*sink|attack (?:path|chain)|call chain|"
    r"entrypoint|end ?point|parameter|controller|sink\b)"
)
_REL_FILE_RE = re.compile(
    r"(?:[\w.+-]+/){1,}[\w.+-]+\.[A-Za-z][A-Za-z0-9]{0,8}(?::\d+)?"
)
_PRE_BLOCK_RE = re.compile(r"(?is)<pre[^>]*>(.*?)</pre>")
_FENCE_BLOCK_RE = re.compile(r"```[^\n]*\n(.*?)```", re.DOTALL)
_SOURCE_HINT_RE = re.compile(
    r"(?i)(\{|\};|;\s*$|"
    r"\b(?:public|private|protected|static|final|def|function|func|fn|class|"
    r"return|import|package|const|let|var)\b)"
)
_DESC_MIN_CHARS = 400
_MIN_SOURCE_CHARS = 8
_PLAIN_DESC_PATH = "containers.cna.descriptions[0].value"
_HTML_DESC_PATH = "containers.cna.descriptions[0].supportingMedia[0].value"
_DETAIL_DESC_PATHS = frozenset({_PLAIN_DESC_PATH, _HTML_DESC_PATH})
CVE_VALUE_MAX_LEN = 4096
CVE_HTML_VALUE_MAX_LEN = 16384
CVE_VALUE_TRUNC_SUFFIX = "\n...[truncated to CVE 4096 limit; see advisory.md]"
_AFFECTED_BASE_PATH = "containers.cna.affected[0]"
_AFFECTED_VENDOR_PATH = f"{_AFFECTED_BASE_PATH}.vendor"
_AFFECTED_PRODUCT_PATH = f"{_AFFECTED_BASE_PATH}.product"
_AFFECTED_PACKAGE_PATH = f"{_AFFECTED_BASE_PATH}.packageName"
_AFFECTED_COLLECTION_PATH = f"{_AFFECTED_BASE_PATH}.collectionURL"
_AFFECTED_IDENTITY_PATHS = frozenset(
    {
        _AFFECTED_VENDOR_PATH,
        _AFFECTED_PRODUCT_PATH,
        _AFFECTED_PACKAGE_PATH,
        _AFFECTED_COLLECTION_PATH,
    }
)
_ADVISORY_AFFECTED_SECTION_RE = re.compile(
    r"(?is)##\s+affected products\s*\n+(.*?)(?=\n##\s|\Z)"
)
_ADVISORY_TABLE_ROW_RE = re.compile(r"^\|\s*([^|]+?)\s*\|\s*`?([^|`]*?)`?\s*\|", re.M)
_LONG_TOKEN_RE = re.compile(r"(?i)([A-Za-z0-9+/=_-]{80,})")
_ECOSYSTEM_COLLECTION_URLS: dict[str, str] = {
    "pip": "https://pypi.python.org",
    "pypi": "https://pypi.python.org",
    "npm": "https://registry.npmjs.org",
    "maven": "https://repo.maven.apache.org/maven2",
    "nuget": "https://nuget.org/packages",
    "packagist": "https://packagist.org",
    "composer": "https://packagist.org",
    "cargo": "https://crates.io",
    "crates": "https://crates.io",
    "rubygems": "https://rubygems.org",
    "gem": "https://rubygems.org",
    "go": "https://pkg.go.dev",
    "golang": "https://pkg.go.dev",
    "github": "https://github.com",
    "gitlab": "https://gitlab.com/explore",
    "docker": "https://hub.docker.com",
}


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
        _AFFECTED_VENDOR_PATH,
        "受影响厂商/项目（与 product 成对；开源包可改填 packageName + collectionURL）",
    ),
    FillableField(
        _AFFECTED_PRODUCT_PATH,
        "受影响产品名（与 vendor 成对；开源包可改填 packageName + collectionURL）",
    ),
    FillableField(
        _AFFECTED_PACKAGE_PATH,
        "开源包名（与 collectionURL 成对；填写后 vendor/product 可留占位符）",
        required=False,
    ),
    FillableField(
        _AFFECTED_COLLECTION_PATH,
        "包集合 URL（如 https://pypi.python.org、https://registry.npmjs.org；与 packageName 成对）",
        required=False,
    ),
    FillableField(
        "containers.cna.descriptions[0].value",
        "漏洞英文详述（纯文本）：产品与版本、根因、入口→sink 链路、漏洞代码"
        "（完整相对路径 + 源码原文）、完整 HTTP 请求包（无 HTTP 面则写 API/调用链）、"
        "危害；长串用占位符。不要一句话摘要。",
    ),
    FillableField(
        "containers.cna.descriptions[0].supportingMedia[0].value",
        "同上内容的 HTML：段落用 <p>，漏洞代码与 HTTP/API PoC 均放在 <pre> 中。",
    ),
    FillableField(
        "containers.cna.references[0].url",
        "参考链接（公告、修复 PR、厂商页面等）",
    ),
    FillableField(
        "containers.cna.metrics[0].cvssV3_1.vectorString",
        "CVSS 3.1 基础向量（只填度量，如 CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H；"
        "分数由系统计算，不要手填 baseScore）。"
        "PR 须与已确认的 attack_surface 一致：前台 PR:N，后台 user PR:L，admin PR:H。"
        "XSS 默认 UI:R/S:C/C:L/I:L/A:N，不要因 Cookie/账户接管把 C/I 标 H。",
        required=False,
    ),
    FillableField(
        "containers.cna.metrics[0].cvssV4_0.vectorString",
        "CVSS 4.0 基础向量（只填度量，如 CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N；"
        "分数由系统计算，不要手填 baseScore）。"
        "PR 须与已确认的 attack_surface 一致。XSS 默认 UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N。",
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


def _plain_text(value: Any, *, html: bool) -> str:
    text = str(value or "")
    if html:
        text = _HTML_TAG_RE.sub(" ", text)
    return " ".join(text.split()).strip()


def fit_cve_value(value: str, *, max_len: int = CVE_VALUE_MAX_LEN) -> tuple[str, bool]:
    """Fit a CVE description/plain value into schema max length."""
    text = str(value or "")
    if len(text) <= max_len:
        return text, False
    shortened = _LONG_TOKEN_RE.sub(lambda m: f"<{m.group(1)[:24]}...>", text)
    if len(shortened) <= max_len:
        return shortened, True
    suffix = CVE_VALUE_TRUNC_SUFFIX
    budget = max_len - len(suffix)
    if budget < 256:
        return text[: max_len - len(suffix)] + suffix, True
    head = int(budget * 0.7)
    tail = max(0, budget - head - 3)
    fitted = f"{shortened[:head]}...{shortened[-tail:]}{suffix}"
    if len(fitted) > max_len:
        fitted = f"{shortened[: budget - 3]}...{suffix}"
    return fitted[:max_len], True


def _affected_entry(record: dict[str, Any]) -> dict[str, Any] | None:
    try:
        entry = get_by_path(record, _AFFECTED_BASE_PATH)
    except KeyError:
        return None
    return entry if isinstance(entry, dict) else None


def affected_identity_ok(record: dict[str, Any]) -> bool:
    entry = _affected_entry(record)
    if not entry:
        return False
    vendor_ok = not is_unfilled_value(entry.get("vendor"))
    product_ok = not is_unfilled_value(entry.get("product"))
    package_ok = not is_unfilled_value(entry.get("packageName"))
    collection_ok = not is_unfilled_value(entry.get("collectionURL"))
    return (vendor_ok and product_ok) or (package_ok and collection_ok)


def affected_identity_issues(record: dict[str, Any]) -> list[str]:
    if affected_identity_ok(record):
        return []
    return [
        "affected[0] 须填写 vendor+product，或 packageName+collectionURL（CVE 5.2 必填其一）"
    ]


def _collection_url_for_ecosystem(raw: str) -> str | None:
    key = re.sub(r"[^a-z0-9]+", " ", str(raw or "").lower()).strip()
    if not key:
        return None
    for token in key.split():
        url = _ECOSYSTEM_COLLECTION_URLS.get(token)
        if url:
            return url
    return None


def parse_advisory_affected(advisory_md: str) -> dict[str, str]:
    """Parse advisory ## Affected products into CVE affected hints."""
    section_match = _ADVISORY_AFFECTED_SECTION_RE.search(advisory_md or "")
    if not section_match:
        return {}
    section = section_match.group(1).strip()
    rows: dict[str, str] = {}
    for match in _ADVISORY_TABLE_ROW_RE.finditer(section):
        key = match.group(1).strip().lower()
        val = match.group(2).strip()
        if not key or key in {"field", "---"} or not val:
            continue
        rows[key] = val
    out: dict[str, str] = {}
    ecosystem = rows.get("ecosystem") or rows.get("package ecosystem")
    package_name = rows.get("package name") or rows.get("package")
    version = rows.get("affected versions") or rows.get("affected version")
    if package_name and ecosystem:
        collection = _collection_url_for_ecosystem(ecosystem)
        if collection:
            out["packageName"] = package_name
            out["collectionURL"] = collection
    if version and "version" not in out:
        out["version"] = version
    if out:
        return out
    line = _hint_line(section)
    if not line:
        return {}
    product = line.split(" through ", 1)[0].split(" version", 1)[0].split(" latest", 1)[0].strip()
    product = re.sub(r"\s*\(.*\)$", "", product).strip(" .")
    if not product:
        return {}
    token = product.split()[0]
    vendor = token if token else product
    out["vendor"] = vendor
    out["product"] = product
    version_match = re.search(
        r"(?i)(?:through|<=|version|v)\s*([0-9][0-9A-Za-z.+_-]*)",
        line,
    )
    if version_match:
        out["version"] = version_match.group(1)
    return out


def _hint_line(raw: str) -> str:
    line = ""
    for row in str(raw or "").splitlines():
        text = row.strip().lstrip("-* ").strip()
        if text and not text.startswith("|"):
            line = text
            break
    line = re.sub(r"[`*_]+", "", line)
    line = re.sub(r"\s+", " ", line).strip()
    if len(line) > 120:
        line = line[:120].strip()
    return line


def seed_affected_from_advisory(project_id: int, vuln_id: int, record: dict[str, Any]) -> bool:
    """Fill affected vendor/product or package fields from advisory.md when still pending."""
    advisory_path = vuln_dir(project_id, vuln_id) / "advisory.md"
    if not advisory_path.is_file():
        return False
    try:
        advisory_md = advisory_path.read_text(encoding="utf-8")
    except OSError:
        return False
    hints = parse_advisory_affected(advisory_md)
    if not hints:
        return False
    entry = _affected_entry(record)
    if not entry:
        return False
    changed = False
    for key in ("vendor", "product", "packageName", "collectionURL"):
        val = hints.get(key)
        if not val or not is_unfilled_value(entry.get(key)):
            continue
        entry[key] = val
        changed = True
    version = hints.get("version")
    if version:
        try:
            current = get_by_path(record, "containers.cna.affected[0].versions[0].version")
            if is_unfilled_value(current):
                set_by_path(record, "containers.cna.affected[0].versions[0].version", version)
                changed = True
        except KeyError:
            pass
    return changed


def normalize_cve_record(record: dict[str, Any]) -> bool:
    """Apply schema-oriented fixes in place (affected identity placeholders, value length)."""
    changed = False
    entry = _affected_entry(record)
    if entry is not None:
        entry.pop("x_CopyOfCNAUnderAffected", None)
        for key in ("vendor", "product", "packageName", "collectionURL"):
            if key not in entry:
                entry[key] = CVE_FIELD_PLACEHOLDER
                changed = True
            elif entry[key] in ("", None):
                entry[key] = CVE_FIELD_PLACEHOLDER
                changed = True
    try:
        plain = get_by_path(record, _PLAIN_DESC_PATH)
        if isinstance(plain, str) and len(plain) > CVE_VALUE_MAX_LEN:
            fitted, _ = fit_cve_value(plain)
            set_by_path(record, _PLAIN_DESC_PATH, fitted)
            changed = True
    except KeyError:
        pass
    try:
        html = get_by_path(record, _HTML_DESC_PATH)
        if isinstance(html, str) and len(html) > CVE_HTML_VALUE_MAX_LEN:
            fitted, _ = fit_cve_value(html, max_len=CVE_HTML_VALUE_MAX_LEN)
            set_by_path(record, _HTML_DESC_PATH, fitted)
            changed = True
    except KeyError:
        pass
    return changed


def _looks_like_source(text: str) -> bool:
    body = str(text or "").strip()
    if len(body) < _MIN_SOURCE_CHARS:
        return False
    if _HTTP_REQ_RE.search(body):
        return False
    return bool(_SOURCE_HINT_RE.search(body))


def _code_blocks(raw: str, *, html: bool) -> list[str]:
    blocks: list[str] = []
    if html:
        for inner in _PRE_BLOCK_RE.findall(raw):
            blocks.append(unescape_html(_HTML_TAG_RE.sub("", inner)))
    for inner in _FENCE_BLOCK_RE.findall(raw):
        blocks.append(inner)
    return blocks


def _has_rel_file_path(text: str) -> bool:
    return bool(_REL_FILE_RE.search(str(text or "").replace("\\", "/")))


def _has_vuln_source(raw: str, *, html: bool) -> tuple[bool, bool]:
    """Return (has_source_snippet, source_is_in_pre_when_html)."""
    in_block = False
    for block in _code_blocks(raw, html=html):
        if _looks_like_source(block):
            in_block = True
            break
    if in_block:
        return True, True
    remainder = _PRE_BLOCK_RE.sub(" ", raw) if html else raw
    remainder = _FENCE_BLOCK_RE.sub(" ", remainder)
    remainder = _HTTP_REQ_RE.sub(" ", remainder)
    if html:
        remainder = _HTML_TAG_RE.sub(" ", remainder)
    return _looks_like_source(remainder), False


def description_detail_issues(value: Any, *, html: bool = False) -> list[str]:
    """Return reasons a CVE description is too thin for CNA review."""
    if is_unfilled_value(value):
        return ["尚未填写或仍是占位符/示例"]
    raw = str(value)
    plain = _plain_text(raw, html=html)
    issues: list[str] = []
    if len(plain) < _DESC_MIN_CHARS:
        issues.append("描述过短，须写清产品/版本、根因、入口→sink 链路、漏洞代码、PoC 与危害")
    has_http = bool(_HTTP_REQ_RE.search(raw))
    has_lib = bool(_LIB_POC_RE.search(raw))
    if not has_http and not has_lib:
        issues.append("须含完整 HTTP 请求包，或无 HTTP 面时写清 API/调用链 PoC")
    if not _CHAIN_RE.search(raw):
        issues.append("须写明入口→sink 漏洞链路（端点/参数/文件或 sink）")
    path_ok = _has_rel_file_path(raw) or _has_rel_file_path(plain)
    has_source, source_in_block = _has_vuln_source(raw, html=html)
    if not path_ok:
        issues.append("须给出漏洞代码对应的仓库内完整相对路径（不要只写类名/方法名）")
    if not has_source:
        issues.append("须粘贴漏洞相关源码原文（路径对应的代码段，不要只概述）")
    if html and not re.search(r"(?i)<(p|pre|br|div)\b", raw):
        issues.append("supportingMedia 须为 HTML（段落用 <p>，漏洞代码与 PoC 放 <pre>）")
    if html and has_http and "<pre" not in raw.lower():
        issues.append("HTML 描述中的 HTTP 请求包须放在 <pre> 中")
    if html and has_source and not source_in_block:
        issues.append("HTML 描述中的漏洞代码须放在 <pre> 中")
    return issues


def _quality_issues_for(path: str, value: Any, *, record: dict[str, Any] | None = None) -> list[str]:
    issues: list[str] = []
    if path in _DETAIL_DESC_PATHS:
        issues.extend(description_detail_issues(value, html=path == _HTML_DESC_PATH))
        if path == _PLAIN_DESC_PATH and isinstance(value, str) and len(value) > CVE_VALUE_MAX_LEN:
            issues.append(f"纯文本描述超过 CVE 上限 {CVE_VALUE_MAX_LEN} 字符（写入时会自动截断）")
        if (
            path == _HTML_DESC_PATH
            and isinstance(value, str)
            and len(value) > CVE_HTML_VALUE_MAX_LEN
        ):
            issues.append(f"HTML 描述超过 CVE 上限 {CVE_HTML_VALUE_MAX_LEN} 字符（写入时会自动截断）")
    if record is not None and path in _AFFECTED_IDENTITY_PATHS:
        issues.extend(affected_identity_issues(record))
    return issues


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
    normalize_cve_record(record)
    seed_affected_from_advisory(project_id, vuln_id, record)
    write_cve_record(project_id, vuln_id, record)
    return record


def read_cve_record(project_id: int, vuln_id: int) -> dict[str, Any] | None:
    path = cve_record_path(project_id, vuln_id)
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def write_cve_record(project_id: int, vuln_id: int, record: dict[str, Any]) -> Path:
    normalize_cve_record(record)
    path = cve_record_path(project_id, vuln_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path


def ensure_cve_record(project_id: int, vuln_id: int) -> dict[str, Any]:
    existing = read_cve_record(project_id, vuln_id)
    if existing is not None:
        changed = normalize_cve_record(existing)
        if not affected_identity_ok(existing):
            changed = seed_affected_from_advisory(project_id, vuln_id, existing) or changed
        if changed:
            write_cve_record(project_id, vuln_id, existing)
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
                    "quality_issues": ["字段缺失"],
                }
            )
            continue
        issues = _quality_issues_for(spec.path, current, record=record)
        identity_ok = affected_identity_ok(record)
        if spec.path in _AFFECTED_IDENTITY_PATHS and identity_ok:
            needs_fill = bool(issues)
        else:
            needs_fill = is_unfilled_value(current) or bool(issues)
        rows.append(
            {
                "path": spec.path,
                "description": spec.description,
                "required": spec.required,
                "current_value": current,
                "needs_fill": needs_fill,
                "missing": False,
                "quality_issues": issues,
            }
        )
    return rows


def set_cve_field(project_id: int, vuln_id: int, path: str, value: Any) -> dict[str, Any]:
    normalized = str(path or "").strip()
    if normalized in (CVE_SCORE_PATH, CVE_SEVERITY_PATH) or normalized.endswith(
        (
            ".cvssV3_1.baseScore",
            ".cvssV3_1.baseSeverity",
            ".cvssV3_0.baseScore",
            ".cvssV3_0.baseSeverity",
            ".cvssV4_0.baseScore",
            ".cvssV4_0.baseSeverity",
        )
    ):
        return {
            "ok": False,
            "error": (
                "不要手填 CVSS 分数或严重度标签。"
                f"请写入 {CVE_VECTOR_PATH} 或 {CVE4_VECTOR_PATH}，分数由系统计算。"
            ),
        }
    if normalized.endswith(".cvssV3_0.vectorString"):
        return {
            "ok": False,
            "error": f"请使用 CVSS 3.1 向量路径 {CVE_VECTOR_PATH} 或 CVSS 4.0 路径 {CVE4_VECTOR_PATH}，不要写 3.0。",
        }
    if normalized not in _FILLABLE_PATHS:
        return {
            "ok": False,
            "error": f"字段 {normalized!r} 不可写入；请使用 ReadCveRecord 返回的 path。",
        }
    record = ensure_cve_record(project_id, vuln_id)
    if normalized == CVE_VECTOR_PATH:
        if is_unfilled_value(value):
            set_by_path(record, normalized, CVE_FIELD_PLACEHOLDER)
            write_cve_record(project_id, vuln_id, record)
            return {
                "ok": True,
                "path": normalized,
                "current_value": CVE_FIELD_PLACEHOLDER,
                "needs_fill": False,
                "quality_issues": [],
            }
        try:
            parsed = parse_cvss31(value)
        except Cvss31Error as exc:
            return {"ok": False, "error": str(exc)}
        with SessionLocal() as db:
            vuln = db.get(Vuln, int(vuln_id))
            surface = (getattr(vuln, "attack_surface", None) or "").strip() if vuln else ""
            account = (getattr(vuln, "required_account", None) or "").strip() or None if vuln else None
        if surface:
            pr_mismatch = cvss_pr_alignment_error(parsed, surface, account)
            if pr_mismatch:
                return {"ok": False, "error": pr_mismatch}
        apply_cvss31_to_cve_record(record, parsed)
        write_cve_record(project_id, vuln_id, record)
        return {
            "ok": True,
            "path": normalized,
            "current_value": parsed.vector,
            "needs_fill": False,
            "quality_issues": [],
            "cvss_vector": parsed.vector,
            "severity_score": parsed.score,
            "severity": parsed.severity,
            "message": f"已写入向量，系统计分为 {parsed.score:.1f} {parsed.severity_en}",
        }
    if normalized == CVE4_VECTOR_PATH:
        if is_unfilled_value(value):
            set_by_path(record, normalized, CVE_FIELD_PLACEHOLDER)
            write_cve_record(project_id, vuln_id, record)
            return {
                "ok": True,
                "path": normalized,
                "current_value": CVE_FIELD_PLACEHOLDER,
                "needs_fill": False,
                "quality_issues": [],
            }
        try:
            parsed40 = parse_cvss40(value)
        except Cvss40Error as exc:
            return {"ok": False, "error": str(exc)}
        with SessionLocal() as db:
            vuln = db.get(Vuln, int(vuln_id))
            surface = (getattr(vuln, "attack_surface", None) or "").strip() if vuln else ""
            account = (getattr(vuln, "required_account", None) or "").strip() or None if vuln else None
        if surface:
            pr_mismatch = cvss40_pr_alignment_error(parsed40, surface, account)
            if pr_mismatch:
                return {"ok": False, "error": pr_mismatch}
        apply_cvss40_to_cve_record(record, parsed40)
        write_cve_record(project_id, vuln_id, record)
        return {
            "ok": True,
            "path": normalized,
            "current_value": parsed40.vector,
            "needs_fill": False,
            "quality_issues": [],
            "cvss4_vector": parsed40.vector,
            "cvss4_score": parsed40.score,
            "severity": parsed40.severity,
            "message": f"已写入 CVSS 4.0 向量，系统计分为 {parsed40.score:.1f} {parsed40.severity_en}",
        }
    write_value: Any = value
    truncated = False
    if normalized == _PLAIN_DESC_PATH and isinstance(value, str):
        write_value, truncated = fit_cve_value(value)
    elif normalized == _HTML_DESC_PATH and isinstance(value, str) and len(value) > CVE_HTML_VALUE_MAX_LEN:
        write_value, truncated = fit_cve_value(value, max_len=CVE_HTML_VALUE_MAX_LEN)
    elif normalized == _AFFECTED_COLLECTION_PATH and not is_unfilled_value(value):
        collection = str(value).strip()
        if collection not in set(_ECOSYSTEM_COLLECTION_URLS.values()) and not collection.startswith(
            "https://"
        ):
            return {
                "ok": False,
                "error": (
                    "collectionURL 须为 CVE 认可的包集合 URL"
                    "（如 https://pypi.python.org、https://registry.npmjs.org）。"
                ),
            }
    try:
        set_by_path(record, normalized, write_value)
    except (KeyError, IndexError, TypeError, ValueError) as e:
        return {"ok": False, "error": f"写入失败: {e}"}
    write_cve_record(project_id, vuln_id, record)
    spec = _FILLABLE_BY_PATH[normalized]
    current = get_by_path(record, normalized)
    issues = _quality_issues_for(normalized, current, record=record)
    identity_ok = affected_identity_ok(record)
    if normalized in _AFFECTED_IDENTITY_PATHS and identity_ok:
        needs_fill = bool(issues)
    else:
        needs_fill = (is_unfilled_value(current) or bool(issues)) if spec.required else bool(issues)
    out: dict[str, Any] = {
        "ok": True,
        "path": normalized,
        "current_value": current,
        "needs_fill": needs_fill,
        "quality_issues": issues,
    }
    if truncated:
        out["message"] = (
            f"内容超过 CVE 字段长度上限，已自动截断至 {CVE_VALUE_MAX_LEN if normalized == _PLAIN_DESC_PATH else CVE_HTML_VALUE_MAX_LEN} 字符；"
            "长 payload 请改用 <BASE64_PAYLOAD> 等占位符。"
        )
    return out


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

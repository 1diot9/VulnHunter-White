"""Vulnerability report.md helpers."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

_CST = timezone(timedelta(hours=8))
_PRODUCED_LINE_RE = re.compile(r"(?m)^\*\*产出时间\*\*[：:].+$")
_H1_RE = re.compile(r"(?m)^(# .+)\n")
ASSET_PROOF_HEADING = "## 互联网资产证明"
SEARCH_FINGERPRINT_HEADING = ASSET_PROOF_HEADING
_ASSET_PROOF_HEADING_RE = re.compile(r"(?m)^##\s+(互联网资产证明|应用搜索指纹)\s*$")
_NEXT_H2_RE = re.compile(r"(?m)^##\s+")
_FOFA_BLOCK_RE = re.compile(
    r"####\s*FOFA\s*\n+```(?:text|fofa)?\n(.*?)```",
    re.IGNORECASE | re.DOTALL,
)
_X_BLOCK_RE = re.compile(
    r"####\s*X\s*情报社区\s*\n+```(?:text)?\n(.*?)```",
    re.IGNORECASE | re.DOTALL,
)
_PLACEHOLDER_QUERY_RE = re.compile(
    r"(待根据|待运行|待确认|待补采|待补全|TODO|TBD)",
    re.IGNORECASE,
)
_ASSET_PROOF_INSERT_MARKERS = (
    "\n## 漏洞技术细节\n",
    "\n## 复现证明\n",
    "\n## 修复方案\n",
    "\n## 备注\n",
    "\n## PoC\n",
    "\n## 环境\n",
    "\n## 结论\n",
)


def _fingerprint_value(raw: object, fallback: str) -> str:
    value = str(raw or "").strip()
    return value or fallback


def search_fingerprint_section(
    *,
    fofa: object = None,
    x: object = None,
    basis: object = None,
) -> str:
    """Build the required internet-asset proof section (FOFA + X queries)."""
    del basis  # kept for call-site compatibility; no longer rendered
    fofa_query = _fingerprint_value(fofa, "待根据应用标题、稳定 body/header 特征、favicon hash 等确认")
    x_query = _fingerprint_value(x, "待根据 app/title/body/cert/icon_hash 等资产测绘字段确认")
    return f"""{ASSET_PROOF_HEADING}
> 用于在公开资产测绘平台定位同类应用资产；优先使用应用自身稳定特征，不把漏洞路径、PoC 参数或一次性业务数据当作唯一指纹。测绘语句不允许出现「或」关系。

### 精准测绘语法

#### FOFA
```text
{fofa_query}
```

#### X 情报社区
```text
{x_query}
```
"""


def _normalize_query(raw: object) -> str:
    return " ".join(str(raw or "").split()).strip()


def extract_asset_queries(text: str) -> tuple[str, str]:
    """Return (fofa, x) queries from the internet-asset proof section."""
    body = text or ""
    fofa = _FOFA_BLOCK_RE.search(body)
    x = _X_BLOCK_RE.search(body)
    return (
        _normalize_query(fofa.group(1) if fofa else ""),
        _normalize_query(x.group(1) if x else ""),
    )


_HINT_SKIP_RE = re.compile(
    r"(暂未明确|待补|待根据|待确认|待运行|第一段|第二段|TODO|TBD)",
    re.IGNORECASE,
)
_VULN_TITLE_RE = re.compile(
    r"(注入|未授权|漏洞|XSS|SQLi|RCE|SSRF|上传|遍历|绕过)",
    re.IGNORECASE,
)
_VENDOR_SECTION_RE = re.compile(
    r"(?ms)^##\s+漏洞厂商全称\s*\n+(.+?)(?=\n##\s|\Z)"
)
_PRODUCT_SECTION_RE = re.compile(
    r"(?ms)^##\s+已知受影响产品及版本\s*\n+(.+?)(?=\n##\s|\Z)"
)


def is_placeholder_query(raw: object) -> bool:
    value = _normalize_query(raw)
    if not value or value in {"-", "n/a", "N/A"}:
        return True
    return bool(_PLACEHOLDER_QUERY_RE.search(value))


def _hint_line(raw: str) -> str:
    line = ""
    for row in str(raw or "").splitlines():
        text = row.strip().lstrip("-* ").strip()
        if text:
            line = text
            break
    line = re.sub(r"[`*_]+", "", line)
    line = re.sub(r"\s+", " ", line).strip()
    if len(line) > 80:
        line = line[:80].strip()
    return line


def extract_product_hints(report_md: str) -> list[str]:
    """Vendor / product names from the report, skipping placeholders and vuln titles."""
    body = report_md or ""
    hints: list[str] = []
    for pattern in (_VENDOR_SECTION_RE, _PRODUCT_SECTION_RE):
        match = pattern.search(body)
        if not match:
            continue
        value = _hint_line(match.group(1))
        if not value or _HINT_SKIP_RE.search(value) or value in {"-", "n/a", "N/A"}:
            continue
        if value not in hints:
            hints.append(value)
    h1 = _H1_RE.search(body)
    if h1:
        title = _hint_line(h1.group(1).lstrip("#"))
        if (
            title
            and not _HINT_SKIP_RE.search(title)
            and not _VULN_TITLE_RE.search(title)
            and title not in hints
        ):
            hints.append(title)
    return hints


def fingerprint_query_error(raw: object, *, label: str) -> str | None:
    value = _normalize_query(raw)
    if not value:
        return f"{label}测绘语句不能为空"
    if "||" in value or re.search(r"或", value):
        return f"{label}测绘语句不允许出现「或」/||"
    return None


def replace_search_fingerprint_section(
    text: str,
    *,
    fofa: object = None,
    x: object = None,
    basis: object = None,
) -> str:
    """Insert or replace the internet-asset proof section in place."""
    body = text or ""
    section = search_fingerprint_section(fofa=fofa, x=x, basis=basis).strip()
    match = _ASSET_PROOF_HEADING_RE.search(body)
    if not match:
        return ensure_search_fingerprint_section(body, fofa=fofa, x=x, basis=basis)
    rest = body[match.end() :]
    nxt = _NEXT_H2_RE.search(rest)
    end = match.end() + nxt.start() if nxt else len(body)
    prefix = body[: match.start()].rstrip()
    suffix = body[end:].lstrip()
    if prefix and suffix:
        return prefix + "\n\n" + section + "\n\n" + suffix
    if prefix:
        return prefix + "\n\n" + section + "\n"
    if suffix:
        return section + "\n\n" + suffix
    return section + "\n"


def write_search_fingerprint_section(
    path: Path,
    *,
    fofa: object = None,
    x: object = None,
    basis: object = None,
) -> str:
    """Rewrite the asset-proof section on disk; keep the rest of the report."""
    text = path.read_text(encoding="utf-8", errors="ignore") if path.exists() else ""
    updated = replace_search_fingerprint_section(text, fofa=fofa, x=x, basis=basis)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(updated, encoding="utf-8")
    return updated


def ensure_search_fingerprint_section(
    text: str,
    *,
    fofa: object = None,
    x: object = None,
    basis: object = None,
) -> str:
    """Ensure vulnerability reports carry FOFA and X asset search fingerprints."""
    body = text or ""
    if _ASSET_PROOF_HEADING_RE.search(body):
        return body
    section = search_fingerprint_section(fofa=fofa, x=x, basis=basis).strip()
    for marker in _ASSET_PROOF_INSERT_MARKERS:
        idx = body.find(marker)
        if idx != -1:
            return body[:idx].rstrip() + "\n\n" + section + "\n" + body[idx:]
    if not body.strip():
        return section + "\n"
    return body.rstrip() + "\n\n" + section + "\n"


def format_produced_at(dt: datetime | None = None) -> str:
    if dt is None:
        dt = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(_CST).strftime("%Y-%m-%d %H:%M:%S")


def produced_at_line(dt: datetime | None = None) -> str:
    return f"**产出时间**：{format_produced_at(dt)}"


def stamp_produced_at(text: str, dt: datetime | None = None) -> str:
    """Ensure report markdown has a single 产出时间 line near the top."""
    line = produced_at_line(dt)
    body = text or ""
    existing = _PRODUCED_LINE_RE.search(body)
    if existing:
        after = body[existing.end() :]
        if after.startswith("\n\n") or after in ("", "\n"):
            rest = after if after else "\n"
        else:
            rest = "\n\n" + after.lstrip("\n")
        return body[: existing.start()] + line + rest
    m = _H1_RE.search(body)
    if m:
        return body[: m.end()] + "\n" + line + "\n\n" + body[m.end() :].lstrip("\n")
    if body.startswith("---"):
        end = body.find("\n---\n", 3)
        if end != -1:
            pos = end + 5
            return body[:pos] + "\n" + line + "\n\n" + body[pos:].lstrip("\n")
    if not body.strip():
        return line + "\n"
    return line + "\n\n" + body.lstrip()


def write_report_md(path: Path, text: str, produced_at: datetime | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(stamp_produced_at(text, produced_at), encoding="utf-8")


def write_advisory_md(path: Path, text: str) -> None:
    """Write the English GitHub Advisory fill-in (no 产出时间 stamp)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    body = (text or "").replace("\r\n", "\n").strip()
    path.write_text((body + "\n") if body else "", encoding="utf-8")


def default_advisory_md(args: dict[str, Any]) -> str:
    """Skeleton GitHub Advisory fill-in from SubmitVuln fields."""
    title = str(args.get("title") or "Untitled vulnerability").strip()
    cwe = str(args.get("cwe") or "").strip() or "(CWE pending)"
    file_path = str(args.get("file_path") or "").replace("\\", "/")
    line_no = args.get("line_no")
    loc = f"`{file_path}:{line_no}`" if file_path else "(location pending)"
    source_sink = str(args.get("source_sink") or "").strip() or "(source → sink pending)"
    auth = str(args.get("auth_premise") or "").strip() or "(auth pending)"
    evidence = str(args.get("expected_evidence") or "").strip() or "(evidence pending)"
    http_request = str(args.get("http_request") or "").strip()
    http_block = f"```http\n{http_request}\n```" if http_request else "(HTTP request pending)"
    return f"""# GitHub Security Advisory

Copy from `### Summary` through Impact into the GitHub Advisory Description field. Leave Patched versions empty if there is no upstream fix.

---

## Title

```
{title}
```

---

## Description

Copy from the next `### Summary` through the end of Impact.

### Summary

{title}. Location: {loc}. Data flow: {source_sink}. Auth: {auth}.

### Details

Reviewer should replace this skeleton with the root cause, the intended control that failed, same-root-cause siblings, and a suggested fix. Align with `templates/vuln-advisory.md`.

Expected evidence: {evidence}

### PoC

Requires a running instance you are authorized to test. Do not include real secrets.

Must include at least one raw HTTP request packet below. Replace long header/body values (roughly 80+ characters) with descriptive placeholders such as `<BASE64_PAYLOAD>`.

{http_block}

```text
python poc.py -u http://TARGET:PORT
python poc.py -u http://TARGET:PORT --proxy http://127.0.0.1:8080
```

Do not run this against systems you do not own or have authorization to test.

### Impact

({cwe}) Replace this paragraph with who is affected, who can exploit it, and what it enables. Do not overclaim.

---

## Affected products

| Field | Value |
| --- | --- |
| Ecosystem | |
| Package name | |
| Affected versions | |
| Patched versions | (leave empty if unpatched) |

---

## Severity / CWE

- **Severity:** (Reviewer)
- **CVSS 3.1:** (Reviewer)
- **CVSS 4.0:** (Reviewer)
- **CWE:** {cwe}
- **Related:**
"""


REPORT_REQUIRED_H2: tuple[str, ...] = (
    "## 摘要",
    "## 漏洞描述",
    "## 漏洞危害",
    "## 漏洞厂商全称",
    "## 已知受影响产品及版本",
    "## 互联网资产证明",
    "## 漏洞技术细节",
    "## 同根因受影响点",
    "## 复现证明",
    "## 修复方案",
    "## 备注",
)

BYPASS_PATCH_BYPASS_HEADING = "### 补丁绕过简析"
VULN_CODE_HEADING = "### 漏洞代码"
ASSET_PROOF_HEADING_ALIASES = (ASSET_PROOF_HEADING, "## 应用搜索指纹")
_VULN_CODE_HEADING_RE = re.compile(r"(?m)^###\s+漏洞代码\s*$")
_NEXT_H23_RE = re.compile(r"(?m)^#{2,3}\s+")
_CODE_FENCE_RE = re.compile(r"```[^\n]*\n(.*?)```", re.DOTALL)
_BACKTICK_PATH_RE = re.compile(r"`([^`\n]+)`")
_BARE_PATH_RE = re.compile(
    r"(?m)(?:完整路径|文件路径|路径|文件)\s*[：:]\s*`?([^\s`\n]+)`?"
)
_MIN_HARNESS_CODE_CHARS = 8


def _has_report_heading(text: str, heading: str) -> bool:
    if heading == ASSET_PROOF_HEADING:
        return any(alias in text for alias in ASSET_PROOF_HEADING_ALIASES)
    return heading in text


def missing_report_headings(text: str, *, bypass: bool = False) -> list[str]:
    """Return required markdown headings missing from a Chinese report body."""
    body = text or ""
    missing = [h for h in REPORT_REQUIRED_H2 if not _has_report_heading(body, h)]
    if bypass and BYPASS_PATCH_BYPASS_HEADING not in body:
        missing.append(BYPASS_PATCH_BYPASS_HEADING)
    return missing


def _extract_vuln_code_section(text: str) -> str | None:
    match = _VULN_CODE_HEADING_RE.search(text or "")
    if not match:
        return None
    rest = text[match.end() :]
    nxt = _NEXT_H23_RE.search(rest)
    return rest[: nxt.start()] if nxt else rest


def _norm_report_path(raw: str) -> str:
    value = str(raw or "").replace("\\", "/").strip().strip("`").strip()
    if ":" in value:
        # strip trailing :line or :line-line
        head, _, tail = value.rpartition(":")
        if tail.isdigit() or re.fullmatch(r"\d+-\d+", tail or ""):
            value = head
    return value.lstrip("./")


def _section_path_candidates(section: str) -> list[str]:
    found: list[str] = []
    for raw in _BACKTICK_PATH_RE.findall(section):
        norm = _norm_report_path(raw)
        if norm:
            found.append(norm)
    for raw in _BARE_PATH_RE.findall(section):
        norm = _norm_report_path(raw)
        if norm:
            found.append(norm)
    return found


def _path_covers_vuln(candidate: str, file_path: str | None) -> bool:
    cand = _norm_report_path(candidate)
    if not cand:
        return False
    # Alone class/method names are not "完整路径"
    looks_complete = "/" in cand or re.search(r"\.[A-Za-z0-9]+$", cand) is not None
    if not looks_complete:
        return False
    expected = _norm_report_path(file_path or "")
    if not expected:
        return True
    if cand == expected or cand.endswith("/" + expected) or expected.endswith("/" + cand):
        return True
    # Allow src/ prefix differences: src/app/X.java vs app/X.java
    for left, right in ((cand, expected), (expected, cand)):
        if left.endswith("/" + right) or left == right:
            return True
        if left.startswith("src/") and left[4:] == right:
            return True
        if right.startswith("src/") and right[4:] == left:
            return True
    base = expected.rsplit("/", 1)[-1]
    return bool(base) and (cand == base or cand.endswith("/" + base))


def harness_vuln_code_gap(report_text: str, *, file_path: str | None = None) -> str | None:
    """If harness Confirm lacks vuln code + full path in report.md, return error text."""
    section = _extract_vuln_code_section(report_text or "")
    if section is None:
        return (
            "局部验证（harness）确认前，报告须含「### 漏洞代码」章节："
            "写明漏洞代码段对应的仓库内完整相对路径，并粘贴源码原文。"
        )
    fences = _CODE_FENCE_RE.findall(section)
    code_ok = any(len((body or "").strip()) >= _MIN_HARNESS_CODE_CHARS for body in fences)
    if not code_ok:
        return (
            "「### 漏洞代码」须含非空 fenced 代码段（源码原文，勿只写路径或一句话概述）。"
            "请 Write 报告后再 ConfirmVuln(evidence_level=harness)。"
        )
    paths = _section_path_candidates(section)
    if not any(_path_covers_vuln(p, file_path) for p in paths):
        hint = f"（应对齐 `{_norm_report_path(file_path)}`）" if file_path else ""
        return (
            "「### 漏洞代码」须给出代码段对应的完整文件路径"
            f"{hint}，不要只写类名/方法名。"
            "请 Write 报告后再 ConfirmVuln(evidence_level=harness)。"
        )
    return None


def upsert_report_section(path: Path, heading: str, body: str) -> None:
    """Replace or append a trailing markdown section under ``heading``."""
    section = f"{heading}\n\n{body.strip()}\n"
    if path.exists():
        text = path.read_text(encoding="utf-8", errors="ignore")
        idx = text.find(f"\n{heading}\n")
        if idx == -1 and text.startswith(f"{heading}\n"):
            idx = 0
        if idx != -1:
            text = text[:idx]
        text = text.rstrip() + "\n\n---\n\n" + section
        path.write_text(text, encoding="utf-8")
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(section, encoding="utf-8")

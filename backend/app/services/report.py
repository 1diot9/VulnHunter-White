"""Vulnerability report.md helpers."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

_CST = timezone(timedelta(hours=8))
_PRODUCED_LINE_RE = re.compile(r"(?m)^\*\*产出时间\*\*[：:].+$")
_H1_RE = re.compile(r"(?m)^(# .+)\n")
ASSET_PROOF_HEADING = "## 互联网资产证明"
SEARCH_FINGERPRINT_HEADING = ASSET_PROOF_HEADING
_ASSET_PROOF_HEADING_RE = re.compile(r"(?m)^##\s+(互联网资产证明|应用搜索指纹)\s*$")
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

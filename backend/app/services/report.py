"""Vulnerability report.md helpers."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

_CST = timezone(timedelta(hours=8))
_PRODUCED_LINE_RE = re.compile(r"(?m)^\*\*产出时间\*\*[：:].+$")
_H1_RE = re.compile(r"(?m)^(# .+)\n")


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

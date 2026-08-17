"""Append / merge 「同根因受影响点」 sections on vulnerability reports."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .report import upsert_report_section

AFFECTED_LOCATIONS_HEADING = "## 同根因受影响点"

_BULLET_RE = re.compile(
    r"^-\s*`(?P<path>[^`]+)`(?:\s+(?P<method>\S+))?(?:\s*[—\-–]\s*(?P<note>.+))?\s*$"
)


def normalize_location(raw: Any) -> dict[str, Any] | None:
    """Normalize one location dict; return None if unusable."""
    if not isinstance(raw, dict):
        return None
    path = str(raw.get("file_path") or raw.get("path") or "").replace("\\", "/").strip()
    if not path:
        return None
    method = str(raw.get("method") or raw.get("method_name") or "").strip() or None
    note = str(raw.get("note") or raw.get("diff") or "").strip() or None
    line_no = raw.get("line_no")
    if line_no is not None and line_no != "":
        try:
            line_no = int(line_no)
        except (TypeError, ValueError):
            return None
    else:
        line_no = None
    return {"file_path": path, "line_no": line_no, "method": method, "note": note}


def parse_locations(raw: Any) -> tuple[list[dict[str, Any]], str | None]:
    """Parse locations list; return (items, error)."""
    if raw is None:
        return [], "缺少 locations"
    if not isinstance(raw, list):
        return [], "locations 必须是数组"
    if not raw:
        return [], "locations 不能为空"
    out: list[dict[str, Any]] = []
    for i, item in enumerate(raw):
        loc = normalize_location(item)
        if loc is None:
            return [], f"locations[{i}] 无效，须含 file_path，可选 line_no/method/note"
        out.append(loc)
    return out, None


def location_key(loc: dict[str, Any]) -> str:
    path = str(loc.get("file_path") or "").replace("\\", "/").lower()
    line = loc.get("line_no")
    method = str(loc.get("method") or "").lower()
    return f"{path}:{line if line is not None else ''}:{method}"


def format_location_line(loc: dict[str, Any]) -> str:
    path = str(loc.get("file_path") or "").replace("\\", "/")
    line = loc.get("line_no")
    loc_label = f"{path}:{line}" if line is not None else path
    method = loc.get("method")
    note = loc.get("note")
    parts = [f"- `{loc_label}`"]
    if method:
        parts.append(str(method))
    line_out = " ".join(parts)
    if note:
        line_out = f"{line_out} — {note}"
    return line_out


def parse_section_body(body: str) -> list[dict[str, Any]]:
    """Best-effort parse existing bullet locations from a section body."""
    found: list[dict[str, Any]] = []
    for raw_line in (body or "").splitlines():
        line = raw_line.strip()
        if not line.startswith("-"):
            continue
        m = _BULLET_RE.match(line)
        if not m:
            # fallback: - `path:line` rest
            tick = re.match(r"^-\s*`([^`]+)`(?:\s+(.*))?$", line)
            if not tick:
                continue
            loc_label = tick.group(1).strip()
            rest = (tick.group(2) or "").strip()
            path, line_no = loc_label, None
            if ":" in loc_label:
                left, right = loc_label.rsplit(":", 1)
                if right.isdigit():
                    path, line_no = left, int(right)
            method, note = None, None
            if "—" in rest or "–" in rest or " - " in rest:
                for sep in ("—", "–", " - "):
                    if sep in rest:
                        method_part, note = rest.split(sep, 1)
                        method = method_part.strip() or None
                        note = note.strip() or None
                        break
            else:
                method = rest or None
            found.append(
                {
                    "file_path": path.replace("\\", "/"),
                    "line_no": line_no,
                    "method": method,
                    "note": note,
                }
            )
            continue
        loc_label = m.group("path").strip()
        path, line_no = loc_label, None
        if ":" in loc_label:
            left, right = loc_label.rsplit(":", 1)
            if right.isdigit():
                path, line_no = left, int(right)
        found.append(
            {
                "file_path": path.replace("\\", "/"),
                "line_no": line_no,
                "method": (m.group("method") or "").strip() or None,
                "note": (m.group("note") or "").strip() or None,
            }
        )
    return found


def read_existing_locations(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    text = path.read_text(encoding="utf-8", errors="ignore")
    heading = AFFECTED_LOCATIONS_HEADING
    idx = text.find(f"\n{heading}\n")
    if idx == -1 and text.startswith(f"{heading}\n"):
        idx = 0
    if idx == -1:
        return []
    start = idx + (0 if idx == 0 else 1)
    rest = text[start + len(heading) :]
    # next ## heading ends the section (after optional ---)
    end = re.search(r"\n##\s+", rest)
    body = rest[: end.start()] if end else rest
    body = body.strip().lstrip("-").strip()
    # drop leading --- separators that upsert may leave
    if body.startswith("---"):
        body = body[3:].lstrip()
    return parse_section_body(body)


def merge_locations(
    existing: list[dict[str, Any]],
    incoming: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], int]:
    """Merge incoming into existing; return (combined, added_count)."""
    seen = {location_key(x) for x in existing}
    combined = list(existing)
    added = 0
    for loc in incoming:
        key = location_key(loc)
        if key in seen:
            continue
        seen.add(key)
        combined.append(loc)
        added += 1
    return combined, added


def format_section_body(locations: list[dict[str, Any]]) -> str:
    if not locations:
        return "（无）"
    return "\n".join(format_location_line(loc) for loc in locations)


def append_affected_locations(path: Path, locations: list[dict[str, Any]]) -> dict[str, Any]:
    """Dedup-append locations into the report section. Returns stats."""
    existing = read_existing_locations(path)
    combined, added = merge_locations(existing, locations)
    upsert_report_section(path, AFFECTED_LOCATIONS_HEADING, format_section_body(combined))
    return {
        "added": added,
        "total": len(combined),
        "skipped_duplicate": len(locations) - added,
    }


def location_from_vuln(vuln: Any, note: str | None = None) -> dict[str, Any] | None:
    """Build a location dict from a Vuln row's primary file/line."""
    path = getattr(vuln, "file_path", None)
    if not path:
        return None
    return normalize_location(
        {
            "file_path": path,
            "line_no": getattr(vuln, "line_no", None),
            "note": note or f"来自漏洞 #{getattr(vuln, 'id', '?')}",
        }
    )

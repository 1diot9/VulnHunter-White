"""Verifier queue: after Reviewer confirms a frontend vuln, hunt lookalikes via FOFA."""

from __future__ import annotations

import json
import re
from typing import Any

from ..models import Project, SessionLocal, Vuln
from ..vuln_types import normalize_vuln_type
from .paths import docs_dir, fofa_cache_path, vuln_dir
from .report import upsert_report_section

VERIFIER_NONE = "none"
VERIFIER_PENDING = "pending"
VERIFIER_VERIFIED = "verified"
VERIFIER_FAILED = "failed"
VERIFIER_SKIPPED = "skipped"
VERIFIER_STATUSES = frozenset(
    {VERIFIER_NONE, VERIFIER_PENDING, VERIFIER_VERIFIED, VERIFIER_FAILED, VERIFIER_SKIPPED}
)
CONFIRMED_STATUSES = frozenset({"confirmed", "static_only"})
_FOFA_BLOCK = re.compile(
    r"####\s*FOFA\s*\n+```(?:text|fofa)?\n(.*?)```",
    re.IGNORECASE | re.DOTALL,
)
_EVIDENCE_MAX = 32000
_HTTP_START = re.compile(r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+\S+", re.IGNORECASE)
_REVIEW_HEADING = "## 互联网验证"
# Types that inherently interrupt business or rewrite files on a third-party host.
INTERNET_UNSAFE_TYPE_REASONS: dict[str, str] = {
    "file_delete": "任意文件删除会破坏对方业务文件，禁止互联网复测",
    "dos": "DoS/拒绝服务会导致业务中断，禁止互联网复测",
    "file_upload": "任意文件上传会改写对方文件，禁止互联网复测",
}
_SQL_WRITE_RE = re.compile(
    r"(?is)("
    r"\bINSERT\s+INTO\b"
    r"|\bDELETE\s+FROM\b"
    r"|\bDROP\s+(TABLE|DATABASE|SCHEMA|INDEX|VIEW)\b"
    r"|\bTRUNCATE\s+(TABLE\b)?"
    r"|\bALTER\s+TABLE\b"
    r"|\bREPLACE\s+INTO\b"
    r"|\bINTO\s+(OUTFILE|DUMPFILE)\b"
    r"|\bUPDATE\s+(?!XML\b)[A-Za-z_][\w.]*\s+SET\b"
    r"|删库|删表|清库|写入数据库|篡改数据|SQL\s*增删改|增删改"
    r")"
)
_FILE_DELETE_RE = re.compile(
    r"(?is)(任意文件删除|file\s*delet|unlink\s*\(|Files\.delete|os\.remove|"
    r"\brm\s+-rf\b)"
)
_DOS_RE = re.compile(
    r"(?is)(\bdenial[\s_-]*of[\s_-]*service\b|\bslowloris\b|fork\s*bomb|拒绝服务)"
)
TARGET_STATUSES = ("success", "fail", "untested")
TARGET_STATUS_LABELS = {"success": "成功", "fail": "失败", "untested": "未测"}
_TARGET_STATUS_ALIASES = {
    "success": "success",
    "ok": "success",
    "hit": "success",
    "verified": "success",
    "成功": "success",
    "fail": "fail",
    "failed": "fail",
    "failure": "fail",
    "失败": "fail",
    "untested": "untested",
    "skip": "untested",
    "skipped": "untested",
    "pending": "untested",
    "未测": "untested",
    "没测": "untested",
    "未测试": "untested",
}
_HOST_KEY_RE = re.compile(r"^https?://", re.I)


def normalize_verifier_status(raw: Any) -> str:
    s = str(raw or "").strip().lower()
    return s if s in VERIFIER_STATUSES else VERIFIER_NONE


def is_verifier_enabled(project_id: int) -> bool:
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        return bool(proj and proj.verifier_enabled)


def clip_evidence(raw: Any, *, limit: int = _EVIDENCE_MAX) -> str:
    text = str(raw or "").strip()
    if len(text) <= limit:
        return text
    return text[:limit].rstrip() + "\n…(truncated)"


def _fence(text: str, lang: str = "") -> str:
    body = (text or "").replace("```", "``\u200b`").rstrip()
    opener = f"```{lang}" if lang else "```"
    return f"{opener}\n{body}\n```"


def _poc_lang(poc: str) -> str:
    first = (poc or "").lstrip()
    if _HTTP_START.match(first) or first.upper().startswith("HTTP/"):
        return "http"
    if first.startswith("#!") or first.startswith("import ") or first.startswith("def "):
        return "python"
    return "text"


def format_verifier_report(
    *,
    verdict: str,
    fofa_query: str = "",
    tested_count: int = 0,
    verified_url: str = "",
    poc: str = "",
    response: str = "",
    notes: str = "",
    targets: list[dict[str, Any]] | None = None,
) -> str:
    """Human-readable 互联网验证 section: target list, PoC, and response."""
    rows = list(targets or [])
    success_n = sum(1 for t in rows if t.get("status") == "success")
    fail_n = sum(1 for t in rows if t.get("status") == "fail")
    untested_n = sum(1 for t in rows if t.get("status") == "untested")
    lines = [
        f"- 结论：{verdict}",
        f"- FOFA 语法：`{fofa_query or '（未提供）'}`",
        f"- 实测条数：{tested_count}",
    ]
    if rows:
        lines.append(f"- FOFA 目标：共 {len(rows)}（成功 {success_n} · 失败 {fail_n} · 未测 {untested_n}）")
    if verified_url:
        lines.append(f"- 打通目标：{verified_url}")
    if fofa_query:
        lines.extend(["", "### FOFA 搜索语法", "", _fence(fofa_query, "text")])
    if rows:
        lines.extend(["", "### FOFA 目标", "", "| 状态 | 目标 | 标题 | 说明 |", "| --- | --- | --- | --- |"])
        for item in rows:
            status = TARGET_STATUS_LABELS.get(str(item.get("status") or ""), str(item.get("status") or "未测"))
            host = _md_cell(str(item.get("host") or item.get("url") or ""))
            title = _md_cell(str(item.get("title") or ""))
            note = _md_cell(str(item.get("note") or ""))
            lines.append(f"| {status} | {host} | {title} | {note} |")
    if poc:
        lines.extend(["", "### 使用的 PoC", "", _fence(poc, _poc_lang(poc))])
    if response:
        lines.extend(["", "### 实际响应", "", _fence(response)])
    if notes:
        lines.extend(["", "### 说明", "", notes])
    return "\n".join(lines).strip() + "\n"


def _md_cell(text: str) -> str:
    return (text or "").replace("|", "\\|").replace("\n", " ").strip() or "—"


def target_key(raw: Any) -> str:
    s = str(raw or "").strip().lower()
    if not s:
        return ""
    s = _HOST_KEY_RE.sub("", s)
    s = s.split("/")[0].split("?")[0].strip()
    return s


def normalize_target_status(raw: Any) -> str:
    key = str(raw or "").strip().lower()
    return _TARGET_STATUS_ALIASES.get(key, "") or "untested"


def _target_row(raw: Any, *, default_status: str = "untested") -> dict[str, str] | None:
    if isinstance(raw, str):
        raw = {"host": raw}
    if not isinstance(raw, dict):
        return None
    host = str(raw.get("host") or raw.get("url") or raw.get("ip") or "").strip()
    if not host:
        return None
    protocol = str(raw.get("protocol") or "").strip()
    if protocol and "://" not in host:
        host_disp = f"{protocol}://{host}"
    else:
        host_disp = host
    status = normalize_target_status(raw.get("status") or default_status)
    return {
        "host": host_disp[:512],
        "ip": str(raw.get("ip") or "")[:128],
        "port": str(raw.get("port") or "")[:16],
        "title": str(raw.get("title") or "")[:120],
        "protocol": protocol[:16],
        "status": status,
        "note": str(raw.get("note") or raw.get("reason") or "")[:500],
    }


def merge_verifier_targets(
    *,
    fofa_sample: list[Any] | None = None,
    submitted: list[Any] | None = None,
    verified_url: str = "",
) -> list[dict[str, str]]:
    """Keep every FOFA hit; overlay LLM statuses; mark verified_url as success."""
    by_key: dict[str, dict[str, str]] = {}
    order: list[str] = []

    def _put(row: dict[str, str], *, overlay: bool) -> None:
        key = target_key(row.get("host")) or target_key(row.get("ip"))
        if not key:
            return
        if key not in by_key:
            by_key[key] = row
            order.append(key)
            return
        if not overlay:
            return
        cur = by_key[key]
        for field in ("ip", "port", "title", "protocol"):
            if row.get(field) and not cur.get(field):
                cur[field] = row[field]
        if row.get("host"):
            if not cur.get("host"):
                cur["host"] = row["host"]
            elif "://" in row["host"] and "://" not in (cur.get("host") or ""):
                cur["host"] = row["host"]
        if row.get("status"):
            cur["status"] = row["status"]
        if row.get("note"):
            cur["note"] = row["note"]

    for item in fofa_sample or []:
        row = _target_row(item, default_status="untested")
        if row:
            _put(row, overlay=False)
    for item in submitted or []:
        row = _target_row(item, default_status="untested")
        if row:
            _put(row, overlay=True)
    if verified_url:
        vkey = target_key(verified_url)
        if vkey:
            matched = False
            vhost = vkey.split(":")[0]
            for key, row in by_key.items():
                if key == vkey or key.split(":")[0] == vhost:
                    row["status"] = "success"
                    if not row.get("note"):
                        row["note"] = "复测成功"
                    matched = True
            if not matched:
                row = _target_row({"host": verified_url, "status": "success", "note": "复测成功"})
                if row:
                    _put(row, overlay=True)
    return [by_key[k] for k in order]


def load_project_fofa_cache(project_id: int) -> dict[str, Any] | None:
    """Return the project-wide FOFA search cache, or None if this project has not searched yet."""
    path = fofa_cache_path(project_id)
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, TypeError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    sample = data.get("sample")
    if not isinstance(sample, list):
        sample = []
    query = str(data.get("query") or "").strip()
    try:
        size = int(data.get("size") or 0)
    except (TypeError, ValueError):
        size = 0
    return {
        "query": query,
        "size": size,
        "returned": int(data.get("returned") or len(sample)),
        "sample": sample,
    }


def save_project_fofa_cache(
    project_id: int,
    *,
    query: str,
    sample: list[Any] | None,
    size: int = 0,
) -> dict[str, Any]:
    """Freeze the first successful FOFA search so later vulns reuse it."""
    rows = list(sample or [])
    payload = {
        "query": str(query or "").strip(),
        "size": int(size or 0),
        "returned": len(rows),
        "sample": rows,
    }
    path = fofa_cache_path(project_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return payload


def seed_fofa_state(state: dict[str, Any], project_id: int) -> None:
    """Copy project FOFA cache into the agent loop so FinishVerifier works without re-search."""
    cache = load_project_fofa_cache(project_id)
    if not cache:
        return
    if not str(state.get("fofa_query") or "").strip() and cache.get("query"):
        state["fofa_query"] = cache["query"]
    if not state.get("fofa_targets"):
        state["fofa_targets"] = list(cache.get("sample") or [])
        state["fofa_cached"] = True


def resolve_fofa_sample(project_id: int, state: dict[str, Any] | None = None) -> tuple[str, list[Any]]:
    state = state or {}
    query = str(state.get("fofa_query") or "").strip()
    sample = list(state.get("fofa_targets") or [])
    if query and sample:
        return query, sample
    cache = load_project_fofa_cache(project_id)
    if not cache:
        return query, sample
    if not query:
        query = str(cache.get("query") or "").strip()
    if not sample:
        sample = list(cache.get("sample") or [])
    return query, sample


def format_shared_fofa_hint(cache: dict[str, Any] | None) -> str:
    if not cache:
        return (
            "本项目尚无共享 FOFA 结果。本条漏洞 FofaSearch 一次即可（默认 10 条），"
            "结果写入 docs/fofa-targets.json，后续漏洞直接复用。不要搜第二次。"
        )
    query = cache.get("query") or "（未记录）"
    n = cache.get("returned") or len(cache.get("sample") or [])
    sample_json = json.dumps(cache.get("sample") or [], ensure_ascii=False)
    return (
        f"本项目已有共享 FOFA 结果（语法 `{query}`，{n} 条）。禁止再调用 FofaSearch。"
        f"直接用下列目标按本条报告复测：\n{sample_json}"
    )


def dump_verifier_targets(targets: list[dict[str, str]] | None) -> str | None:
    if not targets:
        return None
    return json.dumps(targets, ensure_ascii=False)


def parse_verifier_targets(raw: Any) -> list[dict[str, str]]:
    if isinstance(raw, list):
        out = []
        for item in raw:
            row = _target_row(item)
            if row:
                out.append(row)
        return out
    text = str(raw or "").strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except (TypeError, json.JSONDecodeError):
        return []
    return parse_verifier_targets(data)


def internet_test_block_reason(
    *,
    vuln_type: str | None = None,
    title: str = "",
    http_request: str = "",
    poc_code: str = "",
    expected_evidence: str = "",
    report_md: str = "",
) -> str | None:
    """Return a skip reason if internet retest could interrupt business or tamper data."""
    vtype = normalize_vuln_type(vuln_type)
    if vtype in INTERNET_UNSAFE_TYPE_REASONS:
        return INTERNET_UNSAFE_TYPE_REASONS[vtype]
    blob = "\n".join(
        str(part or "")
        for part in (title, http_request, poc_code, expected_evidence, report_md)
    )
    if _SQL_WRITE_RE.search(blob):
        return "SQL 增删改/结构变更会篡改对方业务数据，禁止互联网复测"
    if _FILE_DELETE_RE.search(blob):
        return "任意文件删除会破坏对方业务文件，禁止互联网复测"
    if _DOS_RE.search(blob):
        return "DoS/拒绝服务会导致业务中断，禁止互联网复测"
    return None


def internet_test_block_reason_for_vuln(vuln: Vuln, report_md: str | None = None) -> str | None:
    text = report_md if report_md is not None else read_report_md(vuln.project_id, vuln.id)
    return internet_test_block_reason(
        vuln_type=vuln.vuln_type,
        title=vuln.title or "",
        http_request=vuln.http_request or "",
        poc_code=vuln.poc_code or "",
        expected_evidence=vuln.expected_evidence or "",
        report_md=text,
    )


def write_verifier_skip(project_id: int, vuln_id: int, reason: str) -> None:
    body = format_verifier_report(verdict="skipped", notes=reason)
    path = verifier_report_path(project_id, int(vuln_id))
    path.write_text(f"# Verifier · 漏洞 #{int(vuln_id)}\n\n{body}", encoding="utf-8")
    upsert_report_section(vuln_dir(project_id, int(vuln_id)) / "report.md", _REVIEW_HEADING, body)


def mark_internet_unsafe_skipped(project_id: int, vuln_id: int, reason: str) -> None:
    with SessionLocal() as db:
        vuln = db.get(Vuln, int(vuln_id))
        if not vuln or vuln.project_id != project_id:
            return
        vuln.verifier_status = VERIFIER_SKIPPED
        db.commit()
    write_verifier_skip(project_id, int(vuln_id), reason)


def extract_fofa_query(report_md: str) -> str:
    m = _FOFA_BLOCK.search(report_md or "")
    if not m:
        return ""
    return " ".join(m.group(1).split()).strip()


def read_report_md(project_id: int, vuln_id: int) -> str:
    path = vuln_dir(project_id, vuln_id) / "report.md"
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def verifier_report_rel(vuln_id: int) -> str:
    return f"docs/verifier/{int(vuln_id)}.md"


def verifier_report_path(project_id: int, vuln_id: int):
    path = docs_dir(project_id) / "verifier" / f"{int(vuln_id)}.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def enqueue_frontend_vuln(project_id: int, vuln_id: int) -> dict[str, Any]:
    """Queue one confirmed frontend vuln if Verifier is enabled.

    Returns ``queued`` / ``skipped`` / ``reason``. Unsafe types are marked skipped
    instead of pending so the agent never hits internet targets.
    """
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        if not proj or not proj.verifier_enabled:
            return {"queued": False, "skipped": False, "reason": ""}
        vuln = db.get(Vuln, int(vuln_id))
        if not vuln or vuln.project_id != project_id:
            return {"queued": False, "skipped": False, "reason": ""}
        if vuln.status not in CONFIRMED_STATUSES:
            return {"queued": False, "skipped": False, "reason": ""}
        if (vuln.attack_surface or "") != "frontend":
            return {"queued": False, "skipped": False, "reason": ""}
        current = normalize_verifier_status(vuln.verifier_status)
        if current not in (VERIFIER_NONE, VERIFIER_PENDING, ""):
            return {
                "queued": False,
                "skipped": current == VERIFIER_SKIPPED,
                "reason": "",
            }
        reason = internet_test_block_reason_for_vuln(vuln)
        if reason:
            vuln.verifier_status = VERIFIER_SKIPPED
            db.commit()
            write_verifier_skip(project_id, int(vuln_id), reason)
            return {"queued": False, "skipped": True, "reason": reason}
        vuln.verifier_status = VERIFIER_PENDING
        db.commit()
        return {"queued": True, "skipped": False, "reason": ""}


def enqueue_confirmed_frontend(project_id: int) -> int:
    """When enabling Verifier, queue already-confirmed frontend vulns. Returns queued count."""
    n = 0
    skips: list[tuple[int, str]] = []
    with SessionLocal() as db:
        proj = db.get(Project, project_id)
        if not proj or not proj.verifier_enabled:
            return 0
        rows = (
            db.query(Vuln)
            .filter(
                Vuln.project_id == project_id,
                Vuln.status.in_(tuple(CONFIRMED_STATUSES)),
                Vuln.attack_surface == "frontend",
            )
            .all()
        )
        for vuln in rows:
            current = normalize_verifier_status(vuln.verifier_status)
            if current not in (VERIFIER_NONE, ""):
                continue
            reason = internet_test_block_reason_for_vuln(vuln)
            if reason:
                vuln.verifier_status = VERIFIER_SKIPPED
                skips.append((int(vuln.id), reason))
                continue
            vuln.verifier_status = VERIFIER_PENDING
            n += 1
        if n or skips:
            db.commit()
    for vuln_id, reason in skips:
        write_verifier_skip(project_id, vuln_id, reason)
    return n


def pending_verifier_count(project_id: int) -> int:
    with SessionLocal() as db:
        return (
            db.query(Vuln)
            .filter(
                Vuln.project_id == project_id,
                Vuln.verifier_status == VERIFIER_PENDING,
                Vuln.status.in_(tuple(CONFIRMED_STATUSES)),
                Vuln.attack_surface == "frontend",
            )
            .count()
        )


def pick_pending_verifier_vuln(project_id: int, prefer_id: int | None = None) -> Vuln | None:
    with SessionLocal() as db:
        vuln = None
        if prefer_id is not None:
            vuln = db.get(Vuln, int(prefer_id))
            if vuln and (
                vuln.project_id != project_id
                or vuln.verifier_status != VERIFIER_PENDING
                or vuln.status not in CONFIRMED_STATUSES
            ):
                vuln = None
        if vuln is None:
            vuln = (
                db.query(Vuln)
                .filter(
                    Vuln.project_id == project_id,
                    Vuln.verifier_status == VERIFIER_PENDING,
                    Vuln.status.in_(tuple(CONFIRMED_STATUSES)),
                    Vuln.attack_surface == "frontend",
                )
                .order_by(Vuln.id.asc())
                .first()
            )
        if not vuln:
            return None
        db.expunge(vuln)
        return vuln

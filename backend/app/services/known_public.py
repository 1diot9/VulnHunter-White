"""Soft gate: current finding looks like a already-public historical vuln (kind=old).

Matches distinctive HTTP/API path anchors (not generic auth endpoints) against
recon old-vuln docs of a compatible vuln class. First Submit/Confirm reminds;
``confirm_not_known_public=true`` is accepted only after that reminder.
"""

from __future__ import annotations

import re
from typing import Any

from ..tools.common import _old_vuln_entries, _search_blob

_STATE_KEY = "known_public_soft_warned"
_PARAM = "confirm_not_known_public"

_PATH_RE = re.compile(
    r"(?:(?:GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s+)?"
    r"(/(?:[A-Za-z0-9._\-]+|\{[A-Za-z0-9_]+})(?:/(?:[A-Za-z0-9._\-]+|\{[A-Za-z0-9_]+}))*)",
    re.IGNORECASE,
)

_GENERIC_SEGMENTS = frozenset(
    {
        "api",
        "v1",
        "v2",
        "v3",
        "v4",
        "rest",
        "src",
        "backend",
        "frontend",
        "static",
        "assets",
        "public",
        "private",
        "index",
        "app",
        "web",
        "http",
        "https",
    }
)

# Auth / session plumbing is shared by many unrelated chains; do not treat as sink.
_AUTH_SEGMENTS = frozenset(
    {
        "login",
        "logout",
        "auto_login",
        "signin",
        "signout",
        "signup",
        "register",
        "token",
        "refresh",
        "oauth",
        "authorize",
        "callback",
        "session",
        "sso",
        "auth",
        "authenticate",
    }
)

_TYPE_ALIASES: dict[str, tuple[str, ...]] = {
    "rce": ("rce", "code execution", "remote code", "command injection", "exec", "代码执行", "命令执行", "远程代码"),
    "sqli": ("sqli", "sql injection", "sql注入"),
    "ssrf": ("ssrf", "server-side request"),
    "xss": ("xss", "cross-site scripting", "跨站"),
    "idor": ("idor", "bola", "broken object", "越权", "未授权"),
    "path_traversal": ("path traversal", "directory traversal", "路径遍历", "目录穿越", "lfi"),
    "auth_bypass": ("auth bypass", "authentication bypass", "认证绕过", "未授权"),
    "file_read": ("file read", "arbitrary file", "任意文件读", "文件读取"),
    "file_write": ("file write", "arbitrary write", "任意文件写", "文件写入"),
    "csrf": ("csrf", "cross-site request"),
}


def _truthy(raw: Any) -> bool:
    if isinstance(raw, bool):
        return raw
    if raw is None:
        return False
    return str(raw).strip().lower() in {"1", "true", "yes", "y", "on"}


def _norm(text: str) -> str:
    return (text or "").lower().replace("-", "_").replace("\\", "/")


def extract_path_anchors(*chunks: Any) -> list[str]:
    """Distinctive last path segments from HTTP/API routes in the current finding."""
    blob = "\n".join(str(c or "") for c in chunks)
    out: list[str] = []
    seen: set[str] = set()
    for match in _PATH_RE.finditer(blob):
        raw = match.group(1).split("?")[0].split("#")[0].rstrip("/")
        segs = []
        for part in raw.split("/"):
            if not part or part.startswith("{"):
                continue
            key = _norm(part)
            if key in _GENERIC_SEGMENTS or key in _AUTH_SEGMENTS:
                continue
            segs.append(key)
        if not segs:
            continue
        last = segs[-1]
        if len(last) < 4:
            continue
        if last not in seen:
            seen.add(last)
            out.append(last)
    return out


def _old_type_blob(entry: dict[str, Any]) -> str:
    meta = entry.get("meta") or {}
    return _norm(
        " ".join(
            str(x or "")
            for x in (
                entry.get("title"),
                entry.get("summary"),
                entry.get("content"),
                meta.get("type"),
                meta.get("component"),
                meta.get("cwe"),
            )
        )
    )


def _types_compatible(current_type: str | None, entry: dict[str, Any]) -> bool:
    cur = _norm(current_type or "")
    if not cur:
        return True
    old = _old_type_blob(entry)
    aliases = _TYPE_ALIASES.get(cur, ())
    if cur and cur in old:
        return True
    if any(alias in old for alias in aliases):
        return True
    # Old doc type field may be a Chinese/English phrase that includes current type.
    old_type = _norm(str((entry.get("meta") or {}).get("type") or ""))
    if old_type and (cur in old_type or old_type in cur):
        return True
    if not old_type and not aliases:
        return True
    return False


def _anchor_in_blob(anchor: str, blob: str) -> bool:
    if not anchor:
        return False
    if anchor in blob:
        return True
    dashed = anchor.replace("_", "-")
    return dashed != anchor and dashed in blob


def find_known_public_matches(
    project_id: int,
    *,
    title: str | None = None,
    source_sink: str | None = None,
    http_request: str | None = None,
    file_path: str | None = None,
    vuln_type: str | None = None,
) -> list[dict[str, Any]]:
    """kind=old docs that share a distinctive sink/endpoint with this finding."""
    anchors = extract_path_anchors(title, source_sink, http_request, file_path)
    if not anchors:
        return []
    out: list[dict[str, Any]] = []
    for entry in _old_vuln_entries(project_id):
        if entry.get("kind") != "old":
            continue
        blob = _norm(_search_blob(entry))
        meta = entry.get("meta") or {}
        blob = f"{blob}\n{_norm(str(meta.get('component') or ''))}\n{_norm(str(meta.get('type') or ''))}"
        hit = [a for a in anchors if _anchor_in_blob(a, blob)]
        if not hit:
            continue
        if not _types_compatible(vuln_type, entry):
            continue
        item = {
            "title": entry.get("title"),
            "file": entry.get("file"),
            "kind": "old",
            "fix_status": entry.get("fix_status") or "",
            "fix_status_label": entry.get("fix_status_label") or "",
            "summary": (entry.get("summary") or "")[:240],
            "matched_anchors": hit,
        }
        cve = str(meta.get("cve") or "").strip()
        if cve:
            item["cve"] = cve
        out.append(item)
    return out[:8]


def fingerprint(anchors: list[str], *, tool: str, exclude_vuln_id: int | None) -> str:
    return "|".join([tool, ",".join(sorted(anchors)), str(exclude_vuln_id or 0)])


def soft_known_public_gate(
    ctx: Any,
    args: dict[str, Any],
    *,
    tool: str,
    title: str | None,
    source_sink: str | None,
    http_request: str | None,
    file_path: str | None,
    vuln_type: str | None,
    exclude_vuln_id: int | None = None,
    mining_path: str | None = None,
) -> dict[str, Any] | None:
    """Return an error payload if Confirm/Submit should be reminded; else None."""
    candidates = find_known_public_matches(
        ctx.project_id,
        title=title,
        source_sink=source_sink,
        http_request=http_request,
        file_path=file_path,
        vuln_type=vuln_type,
    )
    if not candidates:
        return None

    anchors: list[str] = []
    seen: set[str] = set()
    for item in candidates:
        for a in item.get("matched_anchors") or []:
            if a not in seen:
                seen.add(a)
                anchors.append(a)
    token = fingerprint(anchors, tool=tool, exclude_vuln_id=exclude_vuln_id)
    warned: dict[str, Any] = ctx.state.setdefault(_STATE_KEY, {})
    want_confirm = _truthy(args.get(_PARAM))

    if want_confirm and not warned.get(token):
        return {
            "ok": False,
            "error": (
                f"{_PARAM}=true 仅在本会话已因疑似已公开同类洞被提醒过一次后才可传入；"
                "请先不带该参数调用一次，按返回的 candidates 用 SearchOldVuln(title=...) 读全文。"
                "入口/sink 同类则不要当新洞；确认是公开文未覆盖的新链后再带上。"
            ),
            "need_confirm_not_known_public": True,
            "confirm_param": _PARAM,
            "candidates": candidates,
            "known_public_soft_gate": True,
        }

    if want_confirm and warned.get(token):
        warned.pop(token, None)
        return None

    warned[token] = True
    names = "；".join(
        f"{c.get('cve') or c.get('title')}（{c.get('file')}）" for c in candidates[:4]
    )
    if mining_path == "bypass":
        action = (
            "若只是原洞仍可打，FinishBypass(verdict=still_patched)，不要 SubmitVuln；"
            "仅当补丁可绕过且公开公告未覆盖该变体时，读完全文后再带 "
            f"{_PARAM}=true 提交。"
        )
    elif tool == "ConfirmVuln":
        action = (
            "请 MarkFalsePositive（已公开同类洞），不要 Confirm 成新 CVE。"
            f"仅当危害或鉴权明显不同、公开文未覆盖时，再 Confirm 并传 {_PARAM}=true。"
        )
    else:
        action = (
            "请不要提交；这是侦察阶段已收录的公开同类洞。"
            f"确认是公开文未覆盖的新链时，再次调用并传 {_PARAM}=true。"
        )
    return {
        "ok": False,
        "error": (
            f"疑似与已公开历史漏洞同类（{names}）：同一入口/sink 路径。"
            f"{action}"
        ),
        "need_confirm_not_known_public": True,
        "confirm_param": _PARAM,
        "candidates": candidates,
        "known_public_soft_gate": True,
        "hint": (
            "SearchOldVuln 用 title 读 candidates 全文。patched 只表示上游曾公告修复，"
            "不代表可以当成当前快照上的新 CVE。"
        ),
    }

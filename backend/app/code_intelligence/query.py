"""Structured short-result queries over the CodeGraph CLI."""

from __future__ import annotations

import json
from typing import Any

from .cli import find_codegraph, run_codegraph
from .service import index_ready, src_root, status_payload

SYMBOL_LIMIT = 20
EDGE_LIMIT = 40
TRACE_LIMIT = 8
OUTPUT_MAX_CHARS = 12000
QUERY_TIMEOUT = 30


def _unavailable(project_id: int, extra: str = "") -> dict[str, Any]:
    payload = status_payload(project_id)
    status = payload.get("status") or "pending"
    if status == "building":
        msg = "代码库正在构建，请改用 Read / Grep"
    elif status == "degraded":
        err = payload.get("error") or "构建失败"
        msg = f"代码库不可用（已降级）: {err}。请用 Read / Grep"
    elif status == "pending":
        msg = "代码库尚未构建，请用 Read / Grep"
    else:
        msg = "代码库索引不存在，请用 Read / Grep"
    if extra:
        msg = f"{msg}；{extra}"
    return {"ok": False, "unavailable": True, "error": msg, "status": status}


def _trim(obj: Any, limit: int = OUTPUT_MAX_CHARS) -> Any:
    text = json.dumps(obj, ensure_ascii=False)
    if len(text) <= limit:
        return obj
    if isinstance(obj, dict):
        clipped = dict(obj)
        clipped["truncated"] = True
        for key in ("items", "paths", "callers", "callees", "results", "nodes"):
            if isinstance(clipped.get(key), list):
                clipped[key] = clipped[key][: max(1, len(clipped[key]) // 2)]
                text = json.dumps(clipped, ensure_ascii=False)
                if len(text) <= limit:
                    return clipped
        clipped["preview"] = text[: limit - 80] + "…"
        clipped.pop("items", None)
        clipped.pop("paths", None)
        return clipped
    if isinstance(obj, list):
        return {"ok": True, "truncated": True, "items": obj[:8], "note": "结果过长已截断"}
    return {"ok": True, "truncated": True, "preview": text[: limit - 20] + "…"}


def _parse_json(stdout: str, stderr: str) -> Any:
    text = (stdout or "").strip()
    if not text:
        err = (stderr or "").strip()
        return {"ok": False, "error": err or "空输出"}
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        start_list = text.find("[")
        idx = min(x for x in (start, start_list) if x >= 0) if (start >= 0 or start_list >= 0) else -1
        if idx >= 0:
            try:
                return json.loads(text[idx:])
            except json.JSONDecodeError:
                pass
        return {"raw": text[:OUTPUT_MAX_CHARS]}


def _normalize_symbol(item: Any) -> dict[str, Any]:
    if isinstance(item, str):
        return {"name": item}
    if not isinstance(item, dict):
        return {"name": str(item)}
    name = item.get("name") or item.get("symbol") or item.get("qualifiedName") or item.get("id") or ""
    file_path = item.get("file") or item.get("path") or item.get("filePath") or item.get("filepath") or ""
    line = item.get("line") or item.get("startLine") or item.get("lineno") or item.get("lineNumber")
    kind = item.get("kind") or item.get("type") or item.get("nodeType") or ""
    out: dict[str, Any] = {"name": str(name)}
    if file_path:
        out["file"] = str(file_path).replace("\\", "/")
    if line not in (None, ""):
        try:
            out["line"] = int(line)
        except (TypeError, ValueError):
            out["line"] = line
    if kind:
        out["kind"] = str(kind)
    return out


def _as_list(data: Any) -> list[Any]:
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("results", "items", "nodes", "symbols", "callers", "callees", "matches"):
            val = data.get(key)
            if isinstance(val, list):
                return val
    return [data] if data not in (None, "", {}) else []


def _run_query(project_id: int, args: list[str]) -> dict[str, Any]:
    if not index_ready(project_id):
        return _unavailable(project_id)
    binary = find_codegraph()
    if binary is None:
        return _unavailable(project_id, extra="CLI 丢失")
    from ..config import settings

    timeout = int(getattr(settings, "timeout_codegraph_query", QUERY_TIMEOUT) or QUERY_TIMEOUT)
    try:
        proc = run_codegraph(
            args,
            cwd=src_root(project_id),
            timeout=timeout,
            binary=binary,
        )
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc), "unavailable": False}
    parsed = _parse_json(proc.stdout or "", proc.stderr or "")
    if proc.returncode != 0 and isinstance(parsed, dict) and parsed.get("error"):
        parsed["ok"] = False
        parsed["exit_code"] = proc.returncode
        return parsed
    if isinstance(parsed, dict) and parsed.get("ok") is False:
        return parsed
    return {"ok": True, "data": parsed, "exit_code": proc.returncode}


def find_symbol(project_id: int, query: str, *, limit: int = SYMBOL_LIMIT) -> dict[str, Any]:
    q = (query or "").strip()
    if not q:
        return {"ok": False, "error": "query 不能为空"}
    cap = max(1, min(int(limit or SYMBOL_LIMIT), SYMBOL_LIMIT))
    raw = _run_query(project_id, ["query", q, "--json", "--limit", str(cap)])
    if not raw.get("ok"):
        return raw
    items = [_normalize_symbol(x) for x in _as_list(raw.get("data"))[:cap]]
    stale = status_payload(project_id).get("status") == "stale"
    return _trim({"ok": True, "query": q, "items": items, "count": len(items), "index_stale": stale})


def callers(project_id: int, symbol: str, *, limit: int = EDGE_LIMIT) -> dict[str, Any]:
    return _edges(project_id, "callers", symbol, limit=limit)


def callees(project_id: int, symbol: str, *, limit: int = EDGE_LIMIT) -> dict[str, Any]:
    return _edges(project_id, "callees", symbol, limit=limit)


def _edges(project_id: int, kind: str, symbol: str, *, limit: int) -> dict[str, Any]:
    name = (symbol or "").strip()
    if not name:
        return {"ok": False, "error": "symbol 不能为空"}
    cap = max(1, min(int(limit or EDGE_LIMIT), EDGE_LIMIT))
    raw = _run_query(project_id, [kind, name, "--json", "--limit", str(cap)])
    if not raw.get("ok"):
        return raw
    items = [_normalize_symbol(x) for x in _as_list(raw.get("data"))[:cap]]
    stale = status_payload(project_id).get("status") == "stale"
    return _trim(
        {
            "ok": True,
            "symbol": name,
            kind: items,
            "count": len(items),
            "index_stale": stale,
        }
    )


def trace(project_id: int, source: str, sink: str, *, max_hops: int = TRACE_LIMIT) -> dict[str, Any]:
    src = (source or "").strip()
    dst = (sink or "").strip()
    if not src or not dst:
        return {"ok": False, "error": "source 与 sink 均不能为空"}
    hops = max(1, min(int(max_hops or TRACE_LIMIT), TRACE_LIMIT))
    raw = _run_query(
        project_id,
        ["explore", f"{src} -> {dst}", "--json"],
    )
    stale = status_payload(project_id).get("status") == "stale"
    if not raw.get("ok"):
        return raw
    data = raw.get("data")
    paths: list[Any] = []
    if isinstance(data, dict):
        for key in ("paths", "call_paths", "callPaths", "flows", "routes"):
            val = data.get(key)
            if isinstance(val, list):
                paths = val[:3]
                break
        if not paths:
            rel = data.get("relationships") or data.get("map") or data.get("edges")
            if isinstance(rel, list):
                paths = rel[:3]
    elif isinstance(data, list):
        paths = data[:3]
    compact: list[Any] = []
    for path in paths:
        if isinstance(path, list):
            compact.append([_normalize_symbol(n) for n in path[: hops + 1]])
        elif isinstance(path, dict):
            hops_list = path.get("hops") or path.get("nodes") or path.get("steps") or path.get("path")
            if isinstance(hops_list, list):
                compact.append([_normalize_symbol(n) for n in hops_list[: hops + 1]])
            else:
                compact.append(_normalize_symbol(path))
        else:
            compact.append(str(path)[:400])
    result: dict[str, Any] = {
        "ok": True,
        "source": src,
        "sink": dst,
        "max_hops": hops,
        "paths": compact,
        "index_stale": stale,
    }
    if not compact and isinstance(data, dict):
        # Keep a short structural hint, drop verbatim source blobs.
        hint = {
            k: data[k]
            for k in ("summary", "path", "flow", "note", "message")
            if k in data and not isinstance(data[k], (dict, list))
        }
        if hint:
            result["hint"] = hint
        elif data.get("raw"):
            result["preview"] = str(data.get("raw"))[:1500]
    return _trim(result)

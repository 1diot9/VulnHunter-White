"""Route FindSymbol / callers / callees / trace across CodeGraph and Jar Analyzer."""

from __future__ import annotations

from typing import Any

from . import query_codegraph as cg
from .backends import jar_analyzer as ja
from .service import requested_backends, status_payload

OUTPUT_MAX_CHARS = 12000


def _trim(obj: Any, limit: int = OUTPUT_MAX_CHARS) -> Any:
    import json

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


def _unavailable(project_id: int, extra: str = "") -> dict[str, Any]:
    payload = status_payload(project_id)
    status = payload.get("status") or "pending"
    if status == "building":
        msg = "代码库正在构建，请改用 Read / Grep"
    elif status == "degraded":
        err = payload.get("error") or "构建失败"
        msg = f"代码库不可用（已降级）: {err}。请用 Read / Grep"
    elif status == "skipped":
        msg = "本项目未开启代码库，请用 Read / Grep"
    elif status == "pending":
        msg = "代码库尚未由侦察点名构建，请用 Read / Grep"
    else:
        msg = "代码库索引不存在，请用 Read / Grep"
    if extra:
        msg = f"{msg}；{extra}"
    return {"ok": False, "unavailable": True, "error": msg, "status": status}


def _backends_ready(project_id: int) -> tuple[bool, bool]:
    req = requested_backends(project_id)
    cg_on = "codegraph" in req and cg.index_ready(project_id)
    ja_on = "jar_analyzer" in req and ja.index_ready(project_id)
    # If Agent has not chosen yet, fall back to whatever exists on disk
    if not req:
        cg_on = cg.index_ready(project_id)
        ja_on = ja.index_ready(project_id)
    return cg_on, ja_on


def _tag_backend(result: dict[str, Any], backend: str) -> dict[str, Any]:
    if not isinstance(result, dict):
        return result
    out = dict(result)
    out.setdefault("backend", backend)
    for key in ("items", "callers", "callees"):
        val = out.get(key)
        if isinstance(val, list):
            tagged = []
            for item in val:
                if isinstance(item, dict):
                    row = dict(item)
                    row.setdefault("backend", backend)
                    tagged.append(row)
                else:
                    tagged.append(item)
            out[key] = tagged
    paths = out.get("paths")
    if isinstance(paths, list):
        tagged_paths = []
        for path in paths:
            if isinstance(path, list):
                tagged_paths.append(
                    [
                        {**n, "backend": n.get("backend") or backend} if isinstance(n, dict) else n
                        for n in path
                    ]
                )
            else:
                tagged_paths.append(path)
        out["paths"] = tagged_paths
    return out


def _merge_lists(a: list[Any], b: list[Any], *, cap: int) -> list[Any]:
    seen: set[str] = set()
    out: list[Any] = []
    for item in list(a or []) + list(b or []):
        if isinstance(item, dict):
            key = f"{item.get('backend')}|{item.get('name')}|{item.get('file')}|{item.get('line')}"
        else:
            key = str(item)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
        if len(out) >= cap:
            break
    return out


def find_symbol(project_id: int, query: str, *, limit: int = 20) -> dict[str, Any]:
    from .query_codegraph import SYMBOL_LIMIT

    cap = max(1, min(int(limit or SYMBOL_LIMIT), SYMBOL_LIMIT))
    cg_on, ja_on = _backends_ready(project_id)
    if not cg_on and not ja_on:
        return _unavailable(project_id)

    prefer_ja = ja_on and ja.symbol_likely_in_index(project_id, query)
    results: list[dict[str, Any]] = []

    def run_cg() -> dict[str, Any] | None:
        if not cg_on:
            return None
        return _tag_backend(cg.find_symbol(project_id, query, limit=cap), "codegraph")

    def run_ja() -> dict[str, Any] | None:
        if not ja_on:
            return None
        return _tag_backend(ja.find_symbol(project_id, query, limit=cap), "jar_analyzer")

    if prefer_ja:
        r = run_ja()
        if r and r.get("ok") and r.get("items"):
            results.append(r)
        r2 = run_cg()
        if r2 and r2.get("ok"):
            results.append(r2)
    else:
        r = run_cg()
        if r and r.get("ok") and r.get("items"):
            results.append(r)
        elif r and r.get("ok"):
            results.append(r)
        r2 = run_ja()
        if r2 and r2.get("ok"):
            results.append(r2)

    ok_results = [r for r in results if r and r.get("ok")]
    if not ok_results:
        failed = [r for r in results if r] or [_unavailable(project_id)]
        return failed[0]

    if len(ok_results) == 1:
        return _trim(ok_results[0])

    items = _merge_lists(ok_results[0].get("items") or [], ok_results[1].get("items") or [], cap=cap)
    return _trim(
        {
            "ok": True,
            "query": query,
            "items": items,
            "count": len(items),
            "backends": [r.get("backend") for r in ok_results],
            "index_stale": bool(ok_results[0].get("index_stale") or ok_results[1].get("index_stale")),
        }
    )


def _edges(project_id: int, kind: str, symbol: str, *, limit: int) -> dict[str, Any]:
    from .query_codegraph import EDGE_LIMIT

    cap = max(1, min(int(limit or EDGE_LIMIT), EDGE_LIMIT))
    cg_on, ja_on = _backends_ready(project_id)
    if not cg_on and not ja_on:
        return _unavailable(project_id)

    prefer_ja = ja_on and ja.symbol_likely_in_index(project_id, symbol)

    def run_cg() -> dict[str, Any] | None:
        if not cg_on:
            return None
        fn = cg.callers if kind == "callers" else cg.callees
        return _tag_backend(fn(project_id, symbol, limit=cap), "codegraph")

    def run_ja() -> dict[str, Any] | None:
        if not ja_on:
            return None
        fn = ja.callers if kind == "callers" else ja.callees
        return _tag_backend(fn(project_id, symbol, limit=cap), "jar_analyzer")

    ordered = [run_ja, run_cg] if prefer_ja else [run_cg, run_ja]
    results = [fn() for fn in ordered]
    ok_results = [r for r in results if r and r.get("ok")]
    if not ok_results:
        failed = [r for r in results if r] or [_unavailable(project_id)]
        return failed[0]
    if len(ok_results) == 1:
        return _trim(ok_results[0])
    key = "callers" if kind == "callers" else "callees"
    merged = _merge_lists(ok_results[0].get(key) or [], ok_results[1].get(key) or [], cap=cap)
    return _trim(
        {
            "ok": True,
            "symbol": symbol,
            key: merged,
            "count": len(merged),
            "backends": [r.get("backend") for r in ok_results],
            "index_stale": bool(ok_results[0].get("index_stale") or ok_results[1].get("index_stale")),
        }
    )


def callers(project_id: int, symbol: str, *, limit: int = 40) -> dict[str, Any]:
    return _edges(project_id, "callers", symbol, limit=limit)


def callees(project_id: int, symbol: str, *, limit: int = 40) -> dict[str, Any]:
    return _edges(project_id, "callees", symbol, limit=limit)


def trace(project_id: int, source: str, sink: str, *, max_hops: int = 8) -> dict[str, Any]:
    from .query_codegraph import TRACE_LIMIT

    hops = max(1, min(int(max_hops or TRACE_LIMIT), TRACE_LIMIT))
    cg_on, ja_on = _backends_ready(project_id)
    if not cg_on and not ja_on:
        return _unavailable(project_id)

    # Same-backend only (no cross-artifact stitching in v1)
    prefer_ja = ja_on and (
        ja.symbol_likely_in_index(project_id, source) or ja.symbol_likely_in_index(project_id, sink)
    )
    if prefer_ja and ja_on:
        result = _tag_backend(ja.trace(project_id, source, sink, max_hops=hops), "jar_analyzer")
        if result.get("ok") and result.get("paths"):
            return _trim(result)
        if cg_on:
            alt = _tag_backend(cg.trace(project_id, source, sink, max_hops=hops), "codegraph")
            if alt.get("ok") and alt.get("paths"):
                return _trim(alt)
        return _trim(result)
    if cg_on:
        result = _tag_backend(cg.trace(project_id, source, sink, max_hops=hops), "codegraph")
        if result.get("ok") and result.get("paths"):
            return _trim(result)
        if ja_on:
            alt = _tag_backend(ja.trace(project_id, source, sink, max_hops=hops), "jar_analyzer")
            if alt.get("ok"):
                return _trim(alt)
        return _trim(result)
    return _trim(_tag_backend(ja.trace(project_id, source, sink, max_hops=hops), "jar_analyzer"))

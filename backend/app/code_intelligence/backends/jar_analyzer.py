"""Query jar-analyzer-engine SQLite databases (bytecode call graphs)."""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path
from typing import Any

from ...services.paths import code_intel_dir, workspace_dir

SYMBOL_LIMIT = 20
EDGE_LIMIT = 40
TRACE_LIMIT = 8
OUTPUT_MAX_CHARS = 12000

_SLASH_FQCN = re.compile(r"^[a-zA-Z_][\w]*(?:/[a-zA-Z_][\w$]*)+$")
_DOT_FQCN = re.compile(r"^[a-zA-Z_][\w]*(?:\.[a-zA-Z_][\w$]*)+$")


def jars_root(project_id: int) -> Path:
    path = code_intel_dir(project_id) / "jars"
    path.mkdir(parents=True, exist_ok=True)
    return path


def artifact_dir(project_id: int, digest: str) -> Path:
    return jars_root(project_id) / digest[:64]


def db_path_for(project_id: int, digest: str) -> Path:
    return artifact_dir(project_id, digest) / "jar-analyzer.db"


def list_ready_dbs(project_id: int) -> list[dict[str, Any]]:
    """Return [{digest, db, source, artifact}] for ready jar graphs."""
    root = jars_root(project_id)
    if not root.is_dir():
        return []
    out: list[dict[str, Any]] = []
    for child in sorted(root.iterdir()):
        if not child.is_dir():
            continue
        db = child / "jar-analyzer.db"
        if not db.is_file():
            continue
        meta_path = child / "meta.json"
        source = ""
        try:
            import json

            if meta_path.is_file():
                data = json.loads(meta_path.read_text(encoding="utf-8"))
                source = str((data or {}).get("source") or "")
        except (OSError, json.JSONDecodeError, TypeError):
            source = ""
        out.append(
            {
                "digest": child.name,
                "db": db,
                "source": source,
                "artifact": source or child.name,
            }
        )
    return out


def index_ready(project_id: int) -> bool:
    return bool(list_ready_dbs(project_id))


def _to_slash(name: str) -> str:
    text = (name or "").strip().replace(".", "/")
    return text.strip("/")


def _to_dot(name: str) -> str:
    return (name or "").strip().replace("/", ".")


def parse_symbol(raw: str) -> dict[str, str]:
    """Normalize Agent symbol strings into class/method pieces.

    Accepts: Foo.bar, com.example.Foo#bar, com/example/Foo.bar, Runtime.exec, Foo
    """
    text = (raw or "").strip()
    if not text:
        return {"raw": "", "class_slash": "", "class_dot": "", "method": "", "simple": ""}
    method = ""
    class_part = text
    if "#" in text:
        class_part, _, method = text.partition("#")
        method = method.strip()
    elif "(" in text:
        head, _, _ = text.partition("(")
        class_part = head.strip()
    # last-dot split for Class.method when class looks FQCN or Simple.method
    if not method and "." in class_part and not class_part.endswith("."):
        left, _, right = class_part.rpartition(".")
        # Heuristic: method is short identifier without package dots in right
        if right and re.match(r"^[a-zA-Z_][\w$]*$", right) and left:
            # If left is SimpleName (no dots) and right looks like method → Class.method
            # If left has dots → FQCN.method
            if "/" not in left:
                class_part = left
                method = right
            elif _DOT_FQCN.match(left.replace("/", ".")) or _SLASH_FQCN.match(left.replace(".", "/")):
                class_part = left
                method = right
            elif re.match(r"^[A-Z][\w$]*$", left) and re.match(r"^[a-zA-Z_][\w$]*$", right):
                class_part = left
                method = right
    class_slash = _to_slash(class_part)
    class_dot = _to_dot(class_part)
    simple = class_slash.rsplit("/", 1)[-1] if class_slash else ""
    return {
        "raw": text,
        "class_slash": class_slash,
        "class_dot": class_dot,
        "method": method,
        "simple": simple,
    }


def _connect(db: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(f"file:{db.as_posix()}?mode=ro", uri=True, timeout=5)
    conn.row_factory = sqlite3.Row
    return conn


def _decompiled_file_hint(project_id: int, class_slash: str, artifact_source: str) -> str:
    """Prefer workspace/decompiled path when jadx already produced it."""
    root = workspace_dir(project_id) / "decompiled"
    if not root.is_dir() or not class_slash:
        return f"{artifact_source}!{class_slash}.class" if artifact_source else class_slash
    simple = class_slash.rsplit("/", 1)[-1]
    # Fast path: search a few levels for ClassName.java
    hits: list[Path] = []
    try:
        for path in root.rglob(f"{simple}.java"):
            if path.is_file():
                hits.append(path)
                if len(hits) >= 3:
                    break
    except OSError:
        hits = []
    if hits:
        try:
            rel = hits[0].relative_to(workspace_dir(project_id).parent).as_posix()
        except ValueError:
            rel = hits[0].as_posix()
        # Prefer paths under workspace/
        for h in hits:
            try:
                rel_h = h.relative_to(workspace_dir(project_id).parent).as_posix()
            except ValueError:
                continue
            if "decompiled" in rel_h:
                return rel_h.replace("\\", "/")
        return rel.replace("\\", "/")
    if artifact_source:
        return f"{artifact_source}!{class_slash}.class"
    return class_slash


def _row_symbol(
    project_id: int,
    *,
    class_name: str,
    method_name: str = "",
    line: Any = None,
    artifact: str = "",
    kind: str = "",
) -> dict[str, Any]:
    class_slash = _to_slash(class_name)
    class_dot = _to_dot(class_name)
    name = f"{class_dot}.{method_name}" if method_name else class_dot
    out: dict[str, Any] = {
        "name": name,
        "file": _decompiled_file_hint(project_id, class_slash, artifact),
        "kind": kind or ("method" if method_name else "class"),
        "backend": "jar_analyzer",
        "artifact": artifact,
    }
    if line not in (None, ""):
        try:
            out["line"] = int(line)
        except (TypeError, ValueError):
            out["line"] = line
    return out


def find_symbol(project_id: int, query: str, *, limit: int = SYMBOL_LIMIT) -> dict[str, Any]:
    q = (query or "").strip()
    if not q:
        return {"ok": False, "error": "query 不能为空"}
    cap = max(1, min(int(limit or SYMBOL_LIMIT), SYMBOL_LIMIT))
    parsed = parse_symbol(q)
    dbs = list_ready_dbs(project_id)
    if not dbs:
        return {"ok": False, "unavailable": True, "error": "Jar Analyzer 索引不可用", "backend": "jar_analyzer"}
    items: list[dict[str, Any]] = []
    needle_class = parsed["class_slash"] or _to_slash(q)
    needle_method = parsed["method"]
    simple = parsed["simple"] or needle_class.rsplit("/", 1)[-1]
    for entry in dbs:
        if len(items) >= cap:
            break
        try:
            conn = _connect(entry["db"])
        except sqlite3.Error:
            continue
        try:
            if needle_method:
                rows = conn.execute(
                    """
                    SELECT class_name, method_name, line_number FROM method_table
                    WHERE (class_name = ? OR class_name LIKE ? OR class_name LIKE ?)
                      AND method_name LIKE ?
                    LIMIT ?
                    """,
                    (
                        needle_class,
                        f"%/{simple}",
                        f"%{simple}",
                        f"%{needle_method}%",
                        cap - len(items),
                    ),
                ).fetchall()
                for row in rows:
                    items.append(
                        _row_symbol(
                            project_id,
                            class_name=row["class_name"],
                            method_name=row["method_name"],
                            line=row["line_number"],
                            artifact=entry["artifact"],
                            kind="method",
                        )
                    )
            else:
                rows = conn.execute(
                    """
                    SELECT class_name FROM class_table
                    WHERE class_name = ? OR class_name LIKE ? OR class_name LIKE ?
                    LIMIT ?
                    """,
                    (needle_class, f"%/{simple}", f"%{simple}", cap - len(items)),
                ).fetchall()
                for row in rows:
                    items.append(
                        _row_symbol(
                            project_id,
                            class_name=row["class_name"],
                            artifact=entry["artifact"],
                            kind="class",
                        )
                    )
                if len(items) < cap:
                    mrows = conn.execute(
                        """
                        SELECT class_name, method_name, line_number FROM method_table
                        WHERE method_name LIKE ? OR class_name LIKE ?
                        LIMIT ?
                        """,
                        (f"%{simple}%", f"%{simple}%", cap - len(items)),
                    ).fetchall()
                    for row in mrows:
                        items.append(
                            _row_symbol(
                                project_id,
                                class_name=row["class_name"],
                                method_name=row["method_name"],
                                line=row["line_number"],
                                artifact=entry["artifact"],
                                kind="method",
                            )
                        )
        except sqlite3.Error:
            continue
        finally:
            conn.close()
    return {
        "ok": True,
        "query": q,
        "items": items[:cap],
        "count": len(items[:cap]),
        "backend": "jar_analyzer",
    }


def _edge_query(
    project_id: int,
    kind: str,
    symbol: str,
    *,
    limit: int,
) -> dict[str, Any]:
    name = (symbol or "").strip()
    if not name:
        return {"ok": False, "error": "symbol 不能为空"}
    cap = max(1, min(int(limit or EDGE_LIMIT), EDGE_LIMIT))
    parsed = parse_symbol(name)
    dbs = list_ready_dbs(project_id)
    if not dbs:
        return {"ok": False, "unavailable": True, "error": "Jar Analyzer 索引不可用", "backend": "jar_analyzer"}
    class_slash = parsed["class_slash"]
    method = parsed["method"]
    simple = parsed["simple"]
    items: list[dict[str, Any]] = []
    for entry in dbs:
        if len(items) >= cap:
            break
        try:
            conn = _connect(entry["db"])
        except sqlite3.Error:
            continue
        try:
            if kind == "callers":
                # Who calls this symbol (as callee)
                if method:
                    sql = """
                        SELECT caller_class_name, caller_method_name
                        FROM method_call_table
                        WHERE (callee_class_name = ? OR callee_class_name LIKE ?)
                          AND callee_method_name = ?
                        LIMIT ?
                    """
                    params: tuple[Any, ...] = (
                        class_slash,
                        f"%/{simple}" if simple else class_slash,
                        method,
                        cap - len(items),
                    )
                else:
                    sql = """
                        SELECT caller_class_name, caller_method_name
                        FROM method_call_table
                        WHERE callee_class_name = ? OR callee_class_name LIKE ?
                           OR callee_method_name = ?
                        LIMIT ?
                    """
                    params = (
                        class_slash,
                        f"%/{simple}" if simple else class_slash,
                        simple or class_slash,
                        cap - len(items),
                    )
                rows = conn.execute(sql, params).fetchall()
                for row in rows:
                    items.append(
                        _row_symbol(
                            project_id,
                            class_name=row["caller_class_name"],
                            method_name=row["caller_method_name"],
                            artifact=entry["artifact"],
                            kind="method",
                        )
                    )
            else:
                if method:
                    sql = """
                        SELECT callee_class_name, callee_method_name
                        FROM method_call_table
                        WHERE (caller_class_name = ? OR caller_class_name LIKE ?)
                          AND caller_method_name = ?
                        LIMIT ?
                    """
                    params = (
                        class_slash,
                        f"%/{simple}" if simple else class_slash,
                        method,
                        cap - len(items),
                    )
                else:
                    sql = """
                        SELECT callee_class_name, callee_method_name
                        FROM method_call_table
                        WHERE caller_class_name = ? OR caller_class_name LIKE ?
                        LIMIT ?
                    """
                    params = (
                        class_slash,
                        f"%/{simple}" if simple else class_slash,
                        cap - len(items),
                    )
                rows = conn.execute(sql, params).fetchall()
                for row in rows:
                    items.append(
                        _row_symbol(
                            project_id,
                            class_name=row["callee_class_name"],
                            method_name=row["callee_method_name"],
                            artifact=entry["artifact"],
                            kind="method",
                        )
                    )
        except sqlite3.Error:
            continue
        finally:
            conn.close()
    key = "callers" if kind == "callers" else "callees"
    return {
        "ok": True,
        "symbol": name,
        key: items[:cap],
        "count": len(items[:cap]),
        "backend": "jar_analyzer",
    }


def callers(project_id: int, symbol: str, *, limit: int = EDGE_LIMIT) -> dict[str, Any]:
    return _edge_query(project_id, "callers", symbol, limit=limit)


def callees(project_id: int, symbol: str, *, limit: int = EDGE_LIMIT) -> dict[str, Any]:
    return _edge_query(project_id, "callees", symbol, limit=limit)


def _node_key(class_name: str, method_name: str) -> str:
    return f"{_to_slash(class_name)}#{method_name or ''}"


def _load_edges(project_id: int) -> tuple[dict[str, list[str]], dict[str, dict[str, Any]]]:
    """Build adjacency (caller_key -> [callee_keys]) and node metadata."""
    adj: dict[str, list[str]] = {}
    nodes: dict[str, dict[str, Any]] = {}
    for entry in list_ready_dbs(project_id):
        try:
            conn = _connect(entry["db"])
        except sqlite3.Error:
            continue
        try:
            rows = conn.execute(
                """
                SELECT caller_class_name, caller_method_name,
                       callee_class_name, callee_method_name
                FROM method_call_table
                """
            ).fetchall()
            for row in rows:
                ck = _node_key(row["caller_class_name"], row["caller_method_name"])
                dk = _node_key(row["callee_class_name"], row["callee_method_name"])
                adj.setdefault(ck, []).append(dk)
                if ck not in nodes:
                    nodes[ck] = _row_symbol(
                        project_id,
                        class_name=row["caller_class_name"],
                        method_name=row["caller_method_name"],
                        artifact=entry["artifact"],
                        kind="method",
                    )
                if dk not in nodes:
                    nodes[dk] = _row_symbol(
                        project_id,
                        class_name=row["callee_class_name"],
                        method_name=row["callee_method_name"],
                        artifact=entry["artifact"],
                        kind="method",
                    )
        except sqlite3.Error:
            continue
        finally:
            conn.close()
    return adj, nodes


def _match_keys(parsed: dict[str, str], nodes: dict[str, dict[str, Any]]) -> list[str]:
    class_slash = parsed["class_slash"]
    method = parsed["method"]
    simple = parsed["simple"]
    keys: list[str] = []
    for key in nodes:
        cpart, _, mpart = key.partition("#")
        if method:
            if mpart != method:
                continue
            if cpart == class_slash or cpart.endswith("/" + simple) or cpart.endswith(simple):
                keys.append(key)
        else:
            if (
                cpart == class_slash
                or cpart.endswith("/" + simple)
                or mpart == simple
                or cpart.endswith(simple)
            ):
                keys.append(key)
    return keys


def trace(project_id: int, source: str, sink: str, *, max_hops: int = TRACE_LIMIT) -> dict[str, Any]:
    src = (source or "").strip()
    dst = (sink or "").strip()
    if not src or not dst:
        return {"ok": False, "error": "source 与 sink 均不能为空"}
    hops = max(1, min(int(max_hops or TRACE_LIMIT), TRACE_LIMIT))
    if not list_ready_dbs(project_id):
        return {"ok": False, "unavailable": True, "error": "Jar Analyzer 索引不可用", "backend": "jar_analyzer"}
    adj, nodes = _load_edges(project_id)
    start_keys = _match_keys(parse_symbol(src), nodes)
    end_keys = set(_match_keys(parse_symbol(dst), nodes))
    # Also match sink by callee name even if never a caller node
    sink_parsed = parse_symbol(dst)
    if sink_parsed["method"]:
        end_keys.add(_node_key(sink_parsed["class_slash"], sink_parsed["method"]))
    paths: list[list[dict[str, Any]]] = []
    if not start_keys:
        return {
            "ok": True,
            "source": src,
            "sink": dst,
            "max_hops": hops,
            "paths": [],
            "backend": "jar_analyzer",
            "note": "起点不在 Jar Analyzer 索引中；跨源码/字节码拼接本期不做，请 Grep 或换符号",
        }

    def dfs(cur: str, stack: list[str], seen: set[str]) -> None:
        if len(paths) >= 3:
            return
        if len(stack) - 1 > hops:
            return
        if cur in end_keys and len(stack) > 1:
            paths.append([nodes.get(k) or {"name": k, "backend": "jar_analyzer"} for k in stack])
            return
        for nxt in adj.get(cur, []):
            if nxt in seen:
                continue
            seen.add(nxt)
            stack.append(nxt)
            dfs(nxt, stack, seen)
            stack.pop()
            seen.discard(nxt)
            if len(paths) >= 3:
                return

    for start in start_keys[:8]:
        dfs(start, [start], {start})
        if len(paths) >= 3:
            break
    return {
        "ok": True,
        "source": src,
        "sink": dst,
        "max_hops": hops,
        "paths": paths,
        "backend": "jar_analyzer",
        "note": None
        if paths
        else "未找到路径（仅在已点名业务 jar 的字节码图内搜索；跨 CodeGraph 边界请分查）",
    }


def symbol_likely_in_index(project_id: int, symbol: str) -> bool:
    """Cheap existence check for resolver routing."""
    parsed = parse_symbol(symbol)
    if not parsed["class_slash"] and not parsed["simple"]:
        return False
    dbs = list_ready_dbs(project_id)
    simple = parsed["simple"] or parsed["class_slash"]
    class_slash = parsed["class_slash"]
    for entry in dbs:
        try:
            conn = _connect(entry["db"])
        except sqlite3.Error:
            continue
        try:
            row = conn.execute(
                """
                SELECT 1 FROM class_table
                WHERE class_name = ? OR class_name LIKE ? OR class_name LIKE ?
                LIMIT 1
                """,
                (class_slash, f"%/{simple}", f"%{simple}%"),
            ).fetchone()
            if row:
                return True
            if parsed["method"]:
                row = conn.execute(
                    """
                    SELECT 1 FROM method_call_table
                    WHERE callee_method_name = ? OR caller_method_name = ?
                    LIMIT 1
                    """,
                    (parsed["method"], parsed["method"]),
                ).fetchone()
                if row:
                    return True
                row = conn.execute(
                    """
                    SELECT 1 FROM method_table
                    WHERE method_name = ?
                    LIMIT 1
                    """,
                    (parsed["method"],),
                ).fetchone()
                if row:
                    return True
        except sqlite3.Error:
            continue
        finally:
            conn.close()
    return False

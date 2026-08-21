"""SQLite helpers for notes and users."""

from __future__ import annotations

from typing import Any

from board.engine import _connect


def find_user(username: str, password: str) -> dict[str, Any] | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT id, name, role, email FROM users WHERE name = ? AND password = ?",
            (username, password),
        ).fetchone()
    return dict(row) if row else None


def list_users() -> list[dict[str, Any]]:
    with _connect() as conn:
        rows = conn.execute("SELECT id, name, role, email FROM users").fetchall()
    return [dict(r) for r in rows]


def list_notes() -> list[dict[str, Any]]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT id, author, title, body FROM notes ORDER BY id DESC"
        ).fetchall()
    return [dict(r) for r in rows]


def get_note(note_id: int) -> dict[str, Any] | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT id, author, title, body FROM notes WHERE id = ?",
            (note_id,),
        ).fetchone()
    return dict(row) if row else None


def create_note(*, author: str, title: str, body: str) -> int:
    with _connect() as conn:
        cur = conn.execute(
            "INSERT INTO notes(author, title, body) VALUES (?, ?, ?)",
            (author, title, body),
        )
        conn.commit()
        return int(cur.lastrowid)

"""Data access and dangerous helpers used by HTTP routes."""

from __future__ import annotations

import os
import sqlite3
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
DB_PATH = DATA_DIR / "board.db"


def _connect() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with _connect() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL,
                email TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY,
                author TEXT NOT NULL,
                title TEXT NOT NULL,
                body TEXT NOT NULL
            );
            """
        )


def seed_if_needed() -> None:
    with _connect() as conn:
        n = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if n:
            return
        conn.executemany(
            "INSERT INTO users(name, password, role, email) VALUES (?, ?, ?, ?)",
            [
                ("alice", "alice123", "user", "alice@memoboard.lab"),
                ("bob", "bob123", "user", "bob@memoboard.lab"),
                ("admin", "admin123", "admin", "admin@memoboard.lab"),
            ],
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


def run_user_lookup(name: str) -> list[dict]:
    # String-concatenated SQL. `name` is a query parameter.
    sql = f"SELECT id, name, role, email, password FROM users WHERE name = '{name}'"
    with _connect() as conn:
        rows = conn.execute(sql).fetchall()
    return [dict(r) for r in rows]


def ping_host(host: str) -> str:
    # Host is interpolated into a shell command and the output is returned.
    return subprocess.getoutput(f"echo MEMO-PING {host}")


os.environ.setdefault("MEMOBOARD_DB", str(DB_PATH))

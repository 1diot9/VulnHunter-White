#!/usr/bin/env python3
"""Check the four sinks and the SQLi → admin ping chain."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import app


def main() -> None:
    client = app.test_client()

    health = client.get("/healthz")
    assert health.status_code == 200 and health.get_json()["ok"] is True

    users = client.get("/api/users", query_string={"name": "alice"})
    assert users.status_code == 200
    assert users.get_json()["users"][0]["name"] == "alice"

    denied = client.get("/api/tools/ping", query_string={"host": "lab"})
    assert denied.status_code == 401

    alice_login = client.post("/api/login", json={"username": "alice", "password": "alice123"})
    assert alice_login.status_code == 200
    forbidden = client.get("/api/tools/ping", query_string={"host": "lab"})
    assert forbidden.status_code == 403

    dumped = client.get("/api/users", query_string={"name": "admin"})
    admin_row = dumped.get_json()["users"][0]
    assert admin_row["name"] == "admin"
    admin_password = admin_row["password"]
    assert admin_password

    chained = app.test_client()
    login = chained.post(
        "/api/login",
        json={"username": "admin", "password": admin_password},
    )
    assert login.status_code == 200
    ping = chained.get("/api/tools/ping", query_string={"host": "lab"})
    assert ping.status_code == 200
    assert b"MEMO-PING lab" in ping.data

    created = client.post(
        "/api/notes",
        json={"title": "smoke", "body": "<b>stored</b>", "author": "alice"},
    )
    assert created.status_code == 201
    page = client.get("/notes")
    assert b"<b>stored</b>" in page.data

    bob = client.get("/api/notes/2", headers={"X-User": "alice"})
    assert bob.status_code == 200
    assert bob.get_json()["author"] == "bob"
    assert "128000" in bob.get_json()["body"]

    print("smoke ok")


if __name__ == "__main__":
    main()

"""MemoBoard — Flask intranet app with four planted bugs, two of which chain.

White-box audit target for VulnHunter (including attack-chain). Not production.
"""

from __future__ import annotations

import os
from pathlib import Path

from flask import Flask, Response, abort, jsonify, render_template, request, session

from board.engine import DATA_DIR, init_db, ping_host, run_user_lookup, seed_if_needed
from board.store import create_note, find_user, get_note, list_notes, list_users

ROOT = Path(__file__).resolve().parent

app = Flask(
    __name__,
    template_folder=str(ROOT / "templates"),
    static_folder=str(ROOT / "static"),
)
# Rotated on each process start. Not a planted hardcoded_secret.
app.secret_key = os.urandom(32)


@app.get("/")
def index() -> str:
    return render_template("index.html", notes=list_notes())


@app.get("/healthz")
def healthz():
    return jsonify({"ok": True, "service": "memoboard"})


@app.get("/notes")
def notes_page() -> str:
    return render_template("notes.html", notes=list_notes())


@app.post("/api/login")
def api_login():
    payload = request.get_json(silent=True) or {}
    username = str(payload.get("username") or request.form.get("username") or "")
    password = str(payload.get("password") or request.form.get("password") or "")
    user = find_user(username, password)
    if not user:
        abort(401)
    session["name"] = user["name"]
    session["role"] = user["role"]
    return jsonify({"ok": True, "name": user["name"], "role": user["role"]})


@app.get("/api/me")
def api_me():
    name = session.get("name")
    if not name:
        abort(401)
    return jsonify({"name": name, "role": session.get("role")})


@app.get("/api/users")
def api_users():
    name = request.args.get("name", "")
    if name:
        rows = run_user_lookup(name)
    else:
        rows = list_users()
    return jsonify({"users": rows})


@app.get("/api/notes/<int:note_id>")
def api_note(note_id: int):
    """Fetch one memo. X-User is the logged-in identity.

    Intended rule: only the author may read their own note.
    Bug: ownership is never checked — any id is returned (IDOR).
    """
    _current = (request.headers.get("X-User") or "").strip()
    row = get_note(note_id)
    if not row:
        abort(404)
    return jsonify(row)


@app.post("/api/notes")
def api_create_note():
    payload = request.get_json(silent=True) or {}
    title = str(payload.get("title") or request.form.get("title") or "untitled")
    body = str(payload.get("body") or request.form.get("body") or "")
    author = str(payload.get("author") or request.form.get("author") or "anonymous")
    note_id = create_note(author=author, title=title, body=body)
    return jsonify({"id": note_id, "ok": True}), 201


@app.get("/api/tools/ping")
def api_ping():
    """Ops ping. Admin session required; host is still interpolated into a shell."""
    if not session.get("name"):
        abort(401)
    if session.get("role") != "admin":
        abort(403)
    host = request.args.get("host", "127.0.0.1")
    return Response(ping_host(host), mimetype="text/plain")


def _boot() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    init_db()
    seed_if_needed()


_boot()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)

# Advisory: MemoBoard IDOR — Unauthenticated Access to Arbitrary User Notes

## Summary

MemoBoard v0.5.0 contains an Insecure Direct Object Reference (IDOR) vulnerability in the `GET /api/notes/<id>` endpoint. The endpoint reads the `X-User` request header but never uses it for ownership verification. Any unauthenticated attacker can read any user's private notes by enumerating note IDs, exposing sensitive data such as salary information.

## Severity

High

## CVE Candidate

Yes — unauthenticated IDOR exposing sensitive user data.

## Vulnerable Component

- **File**: `src/app.py`
- **Function**: `api_note` (lines 73–84)
- **Supporting sink**: `src/board/store.py`, `get_note` (lines 33–39)

## Affected Versions

MemoBoard v0.5.0

## Root Cause

The `api_note` route handler reads the `X-User` header into a local variable `_current` (line 80) but never compares it against the note's `author` field. The handler calls `get_note(note_id)` which queries the database solely by ID with no author filter (`SELECT id, author, title, body FROM notes WHERE id = ?`). The full row — including other users' private content — is returned to the caller via `jsonify(row)`.

## Attack Surface

Frontend (unauthenticated). No session, login, or valid `X-User` header is required. The endpoint is publicly accessible.

## Impact

An attacker can:
- Read any user's private notes by enumerating `note_id` (1, 2, 3, …)
- Access sensitive data such as salary information ("Confidential: bob salary review = 128000. Do not share.")
- Enumerate all notes in the system, causing broad sensitive data exposure

## Exploit Complexity

Single request — a single `GET /api/notes/<id>` with any or no `X-User` header suffices.

## Defense Status

No authentication or authorization check exists on the endpoint.

## Proof of Concept

```bash
# Read bob's private salary note as alice (or anonymously)
curl -H "X-User: alice" http://TARGET:5000/api/notes/2

# Response:
# {"id":2,"author":"bob","title":"private-salary",
#  "body":"Confidential: bob salary review = 128000. Do not share."}
```

Automated PoC script:
```bash
python poc.py -u http://TARGET:5000
```

## Remediation

Add ownership verification in `api_note`:

```python
@app.get("/api/notes/<int:note_id>")
def api_note(note_id: int):
    current = (request.headers.get("X-User") or "").strip()
    row = get_note(note_id)
    if not row:
        abort(404)
    if row["author"] != current:
        abort(403)
    return jsonify(row)
```

Preferably, replace the client-supplied `X-User` header with server-side session authentication and add an author filter to the database query.

## References

- CWE-639: Authorization Bypass Through User-Controlled Key

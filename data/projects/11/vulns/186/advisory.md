# GitHub Security Advisory

Write all fill-in content in English (GitHub Advisory form). Do not use Chinese in Title, Description, or Severity notes. Copy from `### Summary` through Impact into the Description field. Leave Patched versions empty if there is no upstream fix.

Do not render this file as HTML in the product UI; keep it as copy-paste Markdown source.

---

## Title

```
MemoBoard IDOR on GET /api/notes allows reading any user's private memo
```

---

## Description

Copy from the next `### Summary` through the end of Impact.

### Summary

An unauthenticated caller can `GET /api/notes/<id>` and receive another user's private memo, including confidential salary text. The handler reads `X-User` but never compares it to `author`, and `get_note` loads the row by id only.

### Details

MemoBoard 0.5.0 documents the intended rule on `api_note` in `src/app.py`: only the author may read their note. The function assigns `_current` from the `X-User` header and never uses it. `get_note` in `src/board/store.py` runs `SELECT ... FROM notes WHERE id = ?` with no owner predicate and returns `author`, `title`, and `body`. Seed data includes bob's `private-salary` note.

Same-root-cause sibling: `get_note` has no author filter. Suggested fix: authorize from a server-side session (not a client-supplied header) and abort 403 when `row["author"]` does not match the authenticated user; optionally add `AND author = ?` in the query.

### Vulnerable code

- Path: `src/app.py:73`

```python
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
```

Lookup with no owner check:

- Path: `src/board/store.py:33`

```python
def get_note(note_id: int) -> dict[str, Any] | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT id, author, title, body FROM notes WHERE id = ?",
            (note_id,),
        ).fetchone()
    return dict(row) if row else None
```

### PoC

Requires a running instance you are authorized to test. Do not include real secrets.

```http
GET /api/notes/2 HTTP/1.1
Host: TARGET:5000
X-User: alice
Accept: application/json
Connection: close
```

Expected JSON is bob's private salary note (`Confidential: bob salary review = 128000. Do not share.`). The same body is returned without `X-User`. Reproducible CLI in the same directory:

```text
python poc.py -u http://TARGET:5000
python poc.py -u http://TARGET:5000 --proxy http://127.0.0.1:8080
```

Do not run this against systems you do not own or have authorization to test.

### Impact

CWE-639. Any network caller who can reach the default MemoBoard HTTP port can enumerate note ids and read other users' memo bodies, including confidential HR content in the seed dataset. Remaining controls: none; the unused `X-User` header is not an access check.

---

## Affected products

| Field | Value |
| --- | --- |
| Ecosystem | `pip` |
| Package name | memoboard |
| Affected versions | 0.5.0 |
| Patched versions | |

---

## Severity / CWE

- **Severity:** High
- **CVSS 3.1:** 7.5 High — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
- **CWE:** CWE-639 Authorization Bypass Through User-Controlled Key
- **Related:**

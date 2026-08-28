# GitHub Security Advisory

Write all fill-in content in English (GitHub Advisory form). Do not use Chinese in Title, Description, or Severity notes. Copy from `### Summary` through Impact into the Description field. Leave Patched versions empty if there is no upstream fix.

Do not render this file as HTML in the product UI; keep it as copy-paste Markdown source.

---

## Title

```
MemoBoard unauthenticated SQL injection in GET /api/users leaks user passwords
```

---

## Description

Copy from the next `### Summary` through the end of Impact.

### Summary

An unauthenticated caller can send a crafted `name` query parameter to `GET /api/users` and dump every row in `users`, including plaintext `password` values for the administrator account. The route performs no authentication, and the lookup concatenates the parameter into SQL instead of using a bound query.

### Details

MemoBoard 0.5.0 is a Flask intranet memo board. `api_users` in `src/app.py` reads `request.args.get("name")` with no session or token check and passes it to `run_user_lookup` in `src/board/engine.py`. That helper builds `SELECT id, name, role, email, password FROM users WHERE name = '{name}'` with an f-string and executes it. The intended control is a parameterized `WHERE name = ?` query (already used by `list_users` in `src/board/store.py`) and omission of `password` from any public SELECT list.

Same-root-cause sibling: `src/app.py` `api_users` (unauthenticated JSON return of the injected result set). Suggested fix: bind the name with `?`, drop `password` from the projection, and require an authenticated session on `/api/users`.

### Vulnerable code

- Path: `src/board/engine.py:71`

```python
def run_user_lookup(name: str) -> list[dict]:
    # String-concatenated SQL. `name` is a query parameter.
    sql = f"SELECT id, name, role, email, password FROM users WHERE name = '{name}'"
    with _connect() as conn:
        rows = conn.execute(sql).fetchall()
    return [dict(r) for r in rows]
```

Entry point that forwards the unsanitized query parameter:

- Path: `src/app.py:63`

```python
@app.get("/api/users")
def api_users():
    name = request.args.get("name", "")
    if name:
        rows = run_user_lookup(name)
    else:
        rows = list_users()
    return jsonify({"users": rows})
```

### PoC

Requires a running instance you are authorized to test. Do not include real secrets.

**Must include at least one raw HTTP request packet** in a `http` fenced block (method, path, headers, and body if any). Do not rely on curl one-liners or screenshots alone.

```http
GET /api/users?name=' OR 1=1 -- HTTP/1.1
Host: TARGET:5000
Accept: application/json
Connection: close
```

Expected JSON includes every seeded user and plaintext passwords (including `admin`). Reproducible CLI in the same directory:

```text
python poc.py -u http://TARGET:5000
python poc.py -u http://TARGET:5000 --proxy http://127.0.0.1:8080
```

Do not run this against systems you do not own or have authorization to test.

### Impact

CWE-89. Any network caller who can reach the default MemoBoard HTTP port can read all user records, including administrator credentials. Remaining controls: none on the default deployment; SQLite `execute` here is a single statement, so this issue is demonstrated as data disclosure rather than stacked-query writes. Leaked admin credentials can be reused on `POST /api/login`; that follow-on is a separate finding.

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
- **CWE:** CWE-89 Improper Neutralization of Special Elements used in an SQL Command ("SQL Injection")
- **Related:**

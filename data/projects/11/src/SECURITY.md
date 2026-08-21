# Security policy

MemoBoard is an intentionally vulnerable lab.

Planted bugs:

1. SQL injection on `GET /api/users?name=` (dumps passwords, including admin)
2. Command injection on `GET /api/tools/ping?host=` (admin session required)
3. Stored XSS on `/notes`
4. IDOR on `GET /api/notes/<id>`

Intended chain: (1) dump admin password → login → (2) RCE.

See [INTENDED_VULNS.md](INTENDED_VULNS.md).

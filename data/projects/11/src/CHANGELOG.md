# Changelog

## 0.5.0

- Ping RCE now requires an admin session (`POST /api/login`).
- SQLi still dumps `users.password`, so SQLi → login → ping is a real attack chain.

## 0.4.0

- Slim lab: SQLi, ping RCE, stored XSS, notes IDOR.

## 0.1.0

- Initial intranet memo prototype.

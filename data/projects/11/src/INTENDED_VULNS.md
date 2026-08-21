# Intended findings (ground truth)

Answer key for a VulnHunter run against MemoBoard **default config**.

| ID | Type | Reachability | Where | Why it is real |
| --- | --- | --- | --- | --- |
| MB-01 | `sqli` | unauthenticated | `GET /api/users?name=` → `run_user_lookup` | Query string concatenated into SQL; response includes `password` (including `admin`). |
| MB-02 | `rce` | admin session | `GET /api/tools/ping?host=` after `POST /api/login` | `host` interpolated into `subprocess.getoutput`. Independently reachable with the default admin account in seed data. |
| MB-03 | `stored_xss` | unauthenticated write, other users read | `POST /api/notes` + `GET /notes` | Body stored and rendered with `\| safe`. |
| MB-04 | `privilege_escalation` (IDOR) | low privilege | `GET /api/notes/<id>` with `X-User` | No owner check; alice can read bob's private memo. |

## Intended attack chain (enable 攻击链串联)

**MB-01 → MB-02**

1. Unauthenticated SQLi on `/api/users` dumps `users.password` for `admin`.
2. `POST /api/login` with that password creates an admin session.
3. `GET /api/tools/ping?host=` is admin-only and yields command injection / RCE.

This matches the product rule: 匿名入口泄露后台凭证 → 登录后台 → 打后台高危接口.

Do **not** treat MB-03 / MB-04 as prerequisites for ping. They are standalone.

Do **not** expect confirms for: SSRF, SSTI, pickle, XXE, file read/upload, hardcoded JWT, CORS, reflected XSS.

